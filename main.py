import os
import socket
import heapq
import zlib

LARGEST_POSSIBLE_TRANSMISSION_SIZE = 1432
CUSTOM_HEADER_SIZE = 13

# SWITCHES
SHOW_EACH_FRAGMENT_INFO = True
SHOW_ADDITIONAL_FRAGMENT_INFO = False

# PACKET TYPES
INF = 0
ACK = 1
NACK = 2
DAT = 3
KPA = 4


def create_custom_header(sequence_number, fragment_count, fragment_size, packet_type):
    sn = sequence_number.to_bytes(3, 'big')
    fc = fragment_count.to_bytes(3, 'big')
    fs = fragment_size.to_bytes(2, 'big')
    pt = packet_type.to_bytes(1, 'big')
    return sn + fc + fs + pt


def decode_data(data):
    parsed_data = {'sequence_number': int.from_bytes(data[0:3], 'big'),
                   'fragment_count': int.from_bytes(data[3:6], 'big'),
                   'fragment_size': int.from_bytes(data[6:8], 'big'),
                   'packet_type': int.from_bytes(data[8:9], 'big'),
                   'crc': int.from_bytes(data[9:13], 'big'),
                   'data': data[13:], }
    return parsed_data


def set_up_fragment_size():
    fragment_size = input("Enter the size of the fragments:\n")
    while int(fragment_size) < 1 or int(fragment_size) > LARGEST_POSSIBLE_TRANSMISSION_SIZE - CUSTOM_HEADER_SIZE:
        fragment_size = input("[!] You have entered an invalid size. The max fragment size is 1419. Please enter the "
                              "fragment size again:\n")
    return fragment_size


def calculate_fragment_count(file_size, fragment_size):
    fragment_count = 1
    if int(file_size) > int(fragment_size):
        fragment_count = int(file_size) / int(fragment_size)
        if int(file_size) % int(fragment_size) != 0:
            fragment_count += 1

    return fragment_count


def calculate_data_length(buffer, file_size, fragment_size):
    if int(fragment_size) * (buffer + 1) < file_size:
        data_length = fragment_size
    else:
        data_length = int(fragment_size) - ((int(fragment_size) * (buffer + 1)) - file_size)
    return data_length


def create_directory():
    directory = input("[3] Enter the name of the folder where you want to save the files:\n")
    parent_directory = "C:\\Users\\destr\\PycharmProjects\\PKS_Zadanie2"
    path = os.path.join(parent_directory, directory)
    mode = 0o777
    try:
        os.makedirs(name=path, mode=mode, exist_ok=True)
    except OSError as e:
        quit("Cannot create folder\n" + str(e))
    print("The files will be saved in the directory %s\n" % path)
    return path


def set_up_server():
    print(">>> SERVER <<<\n")
    server_ip = input("[1] Enter the IP address of the server:\n")
    server_port = input("[2] Enter the port:\n")
    path = create_directory()

    # creating the socket
    sock = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)

    # bind IP address
    sock.bind((server_ip, int(server_port)))

    while True:
        buffer = server(server_ip, server_port, sock, path)
        if buffer == 0:
            sock.close()
            return


def server(server_ip, server_port, sock, path):
    decoded_data = ""
    addr = ""
    received_message = []
    heapq.heapify(received_message)
    final_message = ""

    choice2 = input("Server has IP address set to %s.\n"
                    "Choose from the options:\n"
                    "[0] Sign out\n"
                    "[1] Listen on port %s\n" % (server_ip, server_port))

    if int(choice2) == 0:
        return 0

    print(">>> The server is waiting to receive data <<<")

    # receiving the information message
    try:
        data, addr = sock.recvfrom(LARGEST_POSSIBLE_TRANSMISSION_SIZE)
        decoded_data = decode_data(data)
    except socket.error as e:
        quit("[x] The information message was NOT received from the client\n" + str(e))

    type_of_message = str(decoded_data['data'], 'utf-8')
    fragment_count = decoded_data['fragment_count']

    # sending ACK for the informational message
    if decoded_data['packet_type'] == INF:
        if SHOW_EACH_FRAGMENT_INFO:
            print("[ ] The information message was received from the client")
            if SHOW_ADDITIONAL_FRAGMENT_INFO:
                print(decoded_data, "\n")

        ack_header = create_custom_header(decoded_data['sequence_number'], decoded_data['fragment_count'],
                                          decoded_data['fragment_size'], ACK)
        crc = 0
        ack_message = ack_header + crc.to_bytes(4, 'big') + decoded_data['data']
        sent_decoded_ack = decode_data(ack_message)

        try:
            sock.sendto(ack_message, (addr[0], addr[1]))
            if SHOW_EACH_FRAGMENT_INFO:
                print("[√] ACK has been sent to the client for the information message")
                if SHOW_ADDITIONAL_FRAGMENT_INFO:
                    print(sent_decoded_ack, "\n")
        except socket.error as e:
            quit("[x] Failed to send ACK to the client for the information message\n" + str(e))

    print("[i] The server expects a %lu byte message from the client, divided into %d packets. The message is "
          "fragmented by %lu bytes. A total of %lu bytes will be transferred." % (decoded_data['sequence_number'],
                                                                                  fragment_count, decoded_data[
                                                                                                'fragment_size'],
                                                                                  (fragment_count * int(
                                                                                      CUSTOM_HEADER_SIZE)) +
                                                                                  decoded_data['sequence_number']))

    successfully_received_fragments = 0
    while successfully_received_fragments < fragment_count:
        try:
            data, addr = sock.recvfrom(LARGEST_POSSIBLE_TRANSMISSION_SIZE)

            decoded_data = decode_data(data)
            data_without_crc = data[:9] + data[13:]
            if decoded_data['packet_type'] == DAT:

                # crc is correct
                if decoded_data['crc'] == zlib.crc32(data_without_crc):

                    if SHOW_EACH_FRAGMENT_INFO:
                        print("[ ] Packet no. %d | %lu bytes received" % (
                            decoded_data['sequence_number'], decoded_data['fragment_size'] + CUSTOM_HEADER_SIZE))
                        if SHOW_ADDITIONAL_FRAGMENT_INFO:
                            print(decoded_data, "\n")

                    heapq.heappush(received_message, (decoded_data['sequence_number'], decoded_data['data']))

                    if type_of_message == "<text>":
                        final_message += heapq.heappop(received_message)[1].decode('utf-8')

                    # sending ACK for the fragment
                    fr_ack_header = create_custom_header(decoded_data['sequence_number'],
                                                         decoded_data['fragment_count'],
                                                         decoded_data['fragment_size'], ACK)
                    crc = 0
                    ack_data = 0
                    fr_ack_message = fr_ack_header + crc.to_bytes(4, 'big') + ack_data.to_bytes(1, 'big')
                    sent_decoded_fr_ack_message = decode_data(fr_ack_message)

                    try:
                        sock.sendto(fr_ack_message, (addr[0], addr[1]))
                        if SHOW_EACH_FRAGMENT_INFO:
                            print("[√] ACK for Packet no. %d has been sent" % (
                                sent_decoded_fr_ack_message['sequence_number']))
                            if SHOW_ADDITIONAL_FRAGMENT_INFO:
                                print(sent_decoded_fr_ack_message, "\n")
                        successfully_received_fragments += 1
                    except socket.error as e:
                        quit("[x] Failed to send ACK for Packet no. %d\n" % (
                            sent_decoded_fr_ack_message['sequence_number']) + str(
                            e))

                # crc is NOT correct
                elif decoded_data['crc'] != zlib.crc32(data_without_crc):
                    if SHOW_EACH_FRAGMENT_INFO:
                        print("[!] Packet no. %d | %lu bytes received >>> INVALID CRC <<<" % (
                            (decoded_data['sequence_number']), decoded_data['fragment_size'] + CUSTOM_HEADER_SIZE))
                        if SHOW_ADDITIONAL_FRAGMENT_INFO:
                            print(decoded_data, "\n")

                    # sending NACK for the fragment
                    fr_nack_header = create_custom_header(decoded_data['sequence_number'],
                                                          decoded_data['fragment_count'],
                                                          decoded_data['fragment_size'], NACK)

                    crc = 0
                    nack_data = 0
                    fr_nack_message = fr_nack_header + crc.to_bytes(4, 'big') + nack_data.to_bytes(1, 'big')
                    sent_decoded_fr_nack_message = decode_data(fr_nack_message)
                    try:
                        sock.sendto(fr_nack_message, (addr[0], addr[1]))
                        if SHOW_EACH_FRAGMENT_INFO:
                            print("[√] NACK for Packet no. %d has been sent" % (
                                sent_decoded_fr_nack_message['sequence_number']))
                            if SHOW_ADDITIONAL_FRAGMENT_INFO:
                                print(sent_decoded_fr_nack_message, "\n")
                    except socket.error as e:
                        quit(
                            "[x] Failed to send NACK for Packet no. %d\n" % (
                                fr_nack_message['sequence_number']) + str(e))

        except socket.error as e:
            quit("[x] Packet no. %d was NOT received.\n" % (decoded_data['sequence_number']) + str(e))

    if type_of_message == "<text>":
        print("\n[i] Received message from %s: '%s'\n" % (addr[0], final_message))

    else:
        with open(os.path.join(path, type_of_message), 'wb') as file:
            while received_message:
                file.write(heapq.heappop(received_message)[1])
        print("\n[i] Received file from %s: '%s' has been saved under directory %s\n" % (addr[0], type_of_message, path))


def set_up_client():
    print(">>> CLIENT <<<\n")
    server_ip = input("[1] Enter the IP address of the server:\n")
    server_port = input("[2] Enter the port:\n")

    # creating the socket
    sock = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)

    while True:
        buffer = client(server_ip, server_port, sock)
        if buffer == 0:
            sock.close()
            return


def client(server_ip, server_port, sock):
    fragment_size = 0
    message = ""
    file_size = 0
    file_name = ""
    defected = False
    packet_type = 0
    response_to_fragment = ""
    byte_array = bytearray()

    action = input("Choose from the options:\n"
                   "[0] - Sign out\n"
                   "[1] - Send a text message\n"
                   "[2] - Simulation of a text message error\n"
                   "[3] - Send a file\n"
                   "[4] - Simulation of a file transfer error\n")

    if int(action) == 0:
        return 0

    elif int(action) == 1 or int(action) == 2:
        fragment_size = set_up_fragment_size()
        message = input("Enter a text message\n")
        file_size = len(message)
        file_name = "<text>"
        if int(action) == 1:
            defected = False
        elif int(action) == 2:
            defected = True
        packet_type = DAT

    elif int(action) == 3 or int(action) == 4:
        fragment_size = set_up_fragment_size()
        path_and_file_name = input("Enter the file name (enter the full path):\n")
        file_name = os.path.basename(path_and_file_name)
        file_size = os.path.getsize(path_and_file_name)

        with open(path_and_file_name, "rb") as file:
            while True:
                byte = file.read(1)
                if not byte:
                    break
                byte_array += byte
        file.close()

        if int(action) == 3:
            defected = False
        elif int(action) == 4:
            defected = True
        packet_type = DAT

    fragment_count = calculate_fragment_count(file_size, fragment_size)
    header = create_custom_header(file_size, int(fragment_count), int(fragment_size), INF)
    temp = header + file_name.encode(encoding='utf-8')
    crc = zlib.crc32(temp)
    fragment_to_send = header + crc.to_bytes(4, 'big') + file_name.encode(encoding='utf-8')

    sent_packet = decode_data(fragment_to_send)

    # sending the informational message to the server
    try:
        sock.sendto(fragment_to_send, (server_ip, int(server_port)))
        if SHOW_EACH_FRAGMENT_INFO:
            print("[ ] The information message has been sent to the server")
            if SHOW_ADDITIONAL_FRAGMENT_INFO:
                print(sent_packet, "\n")
    except socket.error as e:
        quit("[x] The information message was NOT sent to the server\n" + str(e))

    # waiting for the ACK
    try:
        response_to_fragment, addr = sock.recvfrom(LARGEST_POSSIBLE_TRANSMISSION_SIZE)
    except socket.error as e:
        quit("[x] ACK was not received for the information message from the server\n" + str(e))

    received_packet = decode_data(response_to_fragment)

    # comparing sent packet with received packet
    if received_packet['sequence_number'] == sent_packet['sequence_number'] \
            and received_packet['fragment_count'] == sent_packet['fragment_count'] \
            and received_packet['fragment_size'] == sent_packet['fragment_size'] \
            and received_packet['data'] == sent_packet['data'] \
            and received_packet['packet_type'] == ACK:

        if SHOW_EACH_FRAGMENT_INFO:
            print("[√] ACK was received for the information message from the server")
            if SHOW_ADDITIONAL_FRAGMENT_INFO:
                print(received_packet, "\n")

        successfully_sent_fragments = 0
        while successfully_sent_fragments < int(fragment_count):

            data_length = calculate_data_length(successfully_sent_fragments, file_size, fragment_size)

            header = create_custom_header(successfully_sent_fragments + 1, int(fragment_count), int(data_length),
                                          packet_type)

            if file_name == "<text>":
                fragment_data = bytes(
                    message[successfully_sent_fragments * int(fragment_size):(successfully_sent_fragments * int(
                        fragment_size)) + int(fragment_size)], 'utf-8')

            else:
                fragment_data = bytes(
                    byte_array[successfully_sent_fragments * int(fragment_size):(successfully_sent_fragments * int(
                        fragment_size)) + int(fragment_size)])

            if defected:
                temp = header + fragment_data.swapcase()
                defected = False
            else:
                temp = header + fragment_data

            crc = zlib.crc32(temp)
            fragment_to_send = header + crc.to_bytes(4, 'big') + fragment_data
            sent_decoded_fragment = decode_data(fragment_to_send)

            # sending the packet
            try:
                sock.sendto(fragment_to_send, (server_ip, int(server_port)))
                if SHOW_EACH_FRAGMENT_INFO:
                    print("[ ] Packet no. %d | %d bytes has been sent" % (
                        sent_decoded_fragment['sequence_number'], sent_decoded_fragment['fragment_size'] + CUSTOM_HEADER_SIZE))
                    if SHOW_ADDITIONAL_FRAGMENT_INFO:
                        print(sent_decoded_fragment, "\n")
            except socket.error as e:
                quit("[x] Failed to send Packet no. %d | %d bytes\n" % (
                    sent_decoded_fragment['sequence_number'], sent_decoded_fragment['fragment_size'] + CUSTOM_HEADER_SIZE) + str(e))

            # waiting for the response (ACK or NACK)
            try:
                response_to_fragment, addr = sock.recvfrom(LARGEST_POSSIBLE_TRANSMISSION_SIZE)
            except socket.error as e:
                quit("[x] ACK was NOT received for the Packet no. %d\n" % (sent_decoded_fragment['sequence_number']) + str(e))

            decoded_response_to_fragment = decode_data(response_to_fragment)

            # response to the sent fragment was ACK
            if decoded_response_to_fragment['sequence_number'] == sent_decoded_fragment['sequence_number'] \
                    and decoded_response_to_fragment['fragment_count'] == sent_decoded_fragment['fragment_count'] \
                    and decoded_response_to_fragment['fragment_size'] == sent_decoded_fragment['fragment_size'] \
                    and decoded_response_to_fragment['packet_type'] == ACK:
                if SHOW_EACH_FRAGMENT_INFO:
                    print("[√] ACK for the Packet no. %d was received" % (decoded_response_to_fragment['sequence_number']))
                    if SHOW_ADDITIONAL_FRAGMENT_INFO:
                        print(decoded_response_to_fragment, "\n")

                successfully_sent_fragments += 1

            # response to the sent fragment was NACK
            elif decoded_response_to_fragment['sequence_number'] == sent_decoded_fragment['sequence_number'] \
                    and decoded_response_to_fragment['fragment_count'] == sent_decoded_fragment['fragment_count'] \
                    and decoded_response_to_fragment['fragment_size'] == sent_decoded_fragment['fragment_size'] \
                    and decoded_response_to_fragment['packet_type'] == NACK:
                if SHOW_EACH_FRAGMENT_INFO:
                    print("[!] NACK for the Packet no. %d was received" % (decoded_response_to_fragment['sequence_number']))
                    if SHOW_ADDITIONAL_FRAGMENT_INFO:
                        print(decoded_response_to_fragment, "\n")

            if successfully_sent_fragments == int(fragment_count):
                if file_name == "<text>":
                    print("\n[√] The message '%s' has been sent successfully\n" % message)

                else:
                    print("\n[√] The file '%s' has been sent successfully\n" % file_name)

    else:
        quit("Validation error\n")

    return 1


if __name__ == '__main__':

    while True:
        choice = input("Choose from the options:\n"
                       "[1] - Server\n"
                       "[2] - Client\n")

        if int(choice) == 1:
            set_up_server()
        elif int(choice) == 2:
            set_up_client()
