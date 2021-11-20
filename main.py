import os
import socket
import heapq
import zlib
import threading

terminate_event = threading.Event()

MAX_DATA_SIZE = 1432
CUSTOM_HEADER_SIZE = 13

# SWITCHES
SHOW_EACH_FRAGMENT_INFO = True
SHOW_ADDITIONAL_FRAGMENT_INFO = True

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
    while int(fragment_size) < 1 or int(fragment_size) > MAX_DATA_SIZE - CUSTOM_HEADER_SIZE:
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
        quit("Cannot create folder " + str(e))
    print("The files will be saved in the directory %s\n" % path)
    return path


def keep_alive_client(server_ip, server_port, sock):
    while not terminate_event.is_set():
        event_timer = terminate_event.wait(10)
        if not event_timer:
            kpa_header = create_custom_header(0, 0, 0, KPA)
            crc = 0
            kpa_data = 0
            kpa_message = kpa_header + crc.to_bytes(4, 'big') + kpa_data.to_bytes(1, 'big')
            kpa_message_decoded = decode_data(kpa_message)
            sock.sendto(kpa_message, (server_ip, int(server_port)))
            if SHOW_EACH_FRAGMENT_INFO:
                print("")
                print("[ ] Keep Alive message has been sent")
                if SHOW_ADDITIONAL_FRAGMENT_INFO:
                    print(kpa_message_decoded)
            try:
                data, addr = sock.recvfrom(MAX_DATA_SIZE)
                decoded_data = decode_data(data)
                if SHOW_EACH_FRAGMENT_INFO:
                    print("[√] ACK was received for the Keep Alive message")
                    if SHOW_ADDITIONAL_FRAGMENT_INFO:
                        print(decoded_data)
            except socket.timeout:
                print("Time out, socket is closing")
                terminate_event.set()
                sock.close()


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
            return


def server(server_ip, server_port, sock, path):
    received_message = []
    heapq.heapify(received_message)
    final_message = ""

    choice2 = input("Server has set IP address %s.\n"
                    "Choose from the options:\n"
                    "[0] Sign out\n"
                    "[1] Listen on port %s\n" % (server_ip, server_port))

    if int(choice2) == 0:
        return 0

    print(">>> The server is waiting to receive data <<<")

    while True:
        try:
            data, addr = sock.recvfrom(MAX_DATA_SIZE)
            received_data = decode_data(data)
        except socket.error as e:
            print("")
            print("[x] No packet was received from the client. The connection " + str(e) + "\n")
            return 0

        # sending ACK for the informational message
        if received_data['packet_type'] == INF:
            if SHOW_EACH_FRAGMENT_INFO:
                print("[ ] The information message was received from the client")
                if SHOW_ADDITIONAL_FRAGMENT_INFO:
                    print(received_data)

            type_of_message = str(received_data['data'], 'utf-8')
            fragment_count = received_data['fragment_count']

            # create the ACK for the INF packet
            ack_header = create_custom_header(received_data['sequence_number'], received_data['fragment_count'],
                                              received_data['fragment_size'], ACK)
            crc = 0
            ack_to_inf_packet = ack_header + crc.to_bytes(4, 'big') + received_data['data']
            decoded_ack_to_inf_packet = decode_data(ack_to_inf_packet)

            # sending the ACK for the INF packet
            try:
                sock.sendto(ack_to_inf_packet, (addr[0], addr[1]))
                if SHOW_EACH_FRAGMENT_INFO:
                    print("[√] ACK has been sent to the client for the information message")
                    if SHOW_ADDITIONAL_FRAGMENT_INFO:
                        print(decoded_ack_to_inf_packet)
            except socket.error as e:
                print("[x] Failed to send ACK to the client for the information message " + str(e))
                return 0

            print("[i] The server expects a %lu byte message from the client, divided into %d packets. The message is "
                  "fragmented by %lu bytes. A total of %lu bytes will be transferred.\n "
                  % (received_data['sequence_number'], fragment_count, received_data['fragment_size'],
                     (fragment_count * int(CUSTOM_HEADER_SIZE)) + received_data['sequence_number']))

            buffer = 0
            while buffer < fragment_count:

                data, addr = sock.recvfrom(MAX_DATA_SIZE)
                received_fragment = decode_data(data)
                data_without_crc = data[:9] + data[13:]
                if received_fragment['packet_type'] == DAT:

                    # crc is correct
                    if received_fragment['crc'] == zlib.crc32(data_without_crc):

                        if SHOW_EACH_FRAGMENT_INFO:
                            print("[ ] Packet no. %d | %lu bytes received" % (
                                received_fragment['sequence_number'],
                                received_fragment['fragment_size'] + CUSTOM_HEADER_SIZE))
                            if SHOW_ADDITIONAL_FRAGMENT_INFO:
                                print(received_fragment)

                        heapq.heappush(received_message,
                                       (received_fragment['sequence_number'], received_fragment['data']))

                        if type_of_message == "<text>":
                            final_message += heapq.heappop(received_message)[1].decode('utf-8')

                        # sending ACK for the fragment
                        fr_ack_header = create_custom_header(received_fragment['sequence_number'],
                                                             received_fragment['fragment_count'],
                                                             received_fragment['fragment_size'], ACK)
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
                                    print(sent_decoded_fr_ack_message)
                            buffer += 1
                        except socket.error as e:
                            print("[x] Failed to send ACK for Packet no. %d " % (
                                sent_decoded_fr_ack_message['sequence_number']) + str(e))
                            return 0

                    # crc is NOT correct
                    elif received_fragment['crc'] != zlib.crc32(data_without_crc):
                        if SHOW_EACH_FRAGMENT_INFO:
                            print("[!] Packet no. %d | %lu bytes received >>> INVALID CRC <<<" % (
                                (received_fragment['sequence_number']),
                                received_fragment['fragment_size'] + CUSTOM_HEADER_SIZE))
                            if SHOW_ADDITIONAL_FRAGMENT_INFO:
                                print(received_fragment)

                        # sending NACK for the fragment
                        fr_nack_header = create_custom_header(received_fragment['sequence_number'],
                                                              received_fragment['fragment_count'],
                                                              received_fragment['fragment_size'], NACK)

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
                                    print(sent_decoded_fr_nack_message)
                        except socket.error as e:
                            print("[x] Failed to send NACK for Packet no. %d " % (
                                fr_nack_message['sequence_number']) + str(e))
                            return 0

            if type_of_message == "<text>":
                print("")
                print("[i] Received message from %s: '%s'" % (addr[0], final_message))

            else:
                with open(os.path.join(path, type_of_message), 'wb') as file:
                    while received_message:
                        file.write(heapq.heappop(received_message)[1])

                print("")
                print("[i] Received file from %s: '%s' has been saved under directory %s" % (
                    addr[0], type_of_message, path))

            sock.settimeout(20)
            final_message = ""

        # sending ACK for the Keep Alive message
        if received_data['packet_type'] == KPA:
            if SHOW_EACH_FRAGMENT_INFO:
                print("")
                print("[ ] Keep Alive message was received")
                if SHOW_ADDITIONAL_FRAGMENT_INFO:
                    print(received_data)
            kpa_ack_header = create_custom_header(0, 0, 0, ACK)
            crc = 0
            kpa_data = 0
            kpa_ack_message = kpa_ack_header + crc.to_bytes(4, 'big') + kpa_data.to_bytes(1, 'big')
            sent_decoded_kpa_ack = decode_data(kpa_ack_message)

            try:
                sock.sendto(kpa_ack_message, (addr[0], addr[1]))
                if SHOW_EACH_FRAGMENT_INFO:
                    print("[√] ACK has been sent for the Keep Alive message")
                    if SHOW_ADDITIONAL_FRAGMENT_INFO:
                        print(sent_decoded_kpa_ack)

            except socket.error as e:
                print("[x] Failed to send ACK for the Keep Alive message " + str(e))
                return 0


def set_up_client():
    print(">>> CLIENT <<<\n")
    server_ip = input("[1] Enter the IP address of the server:\n")
    server_port = input("[2] Enter the port:\n")

    # creating the socket
    sock = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)

    while True:
        buffer = client(server_ip, server_port, sock)
        if buffer == 0:
            terminate_event.set()
            sock.close()
            return
        if buffer == 1:
            print("[i] Starting Keep Alive in the background\n")
            terminate_event.clear()
            keep_alive_thread = threading.Thread(target=keep_alive_client, args=(server_ip, server_port, sock))
            keep_alive_thread.start()


def client(server_ip, server_port, sock):
    fragment_size = 0
    message = ""
    file_size = 0
    file_name = ""
    defected = False
    packet_type = 0
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

    # calculate fragment count
    fragment_count = calculate_fragment_count(file_size, fragment_size)

    terminate_event.set()

    # creating the INF packet
    header = create_custom_header(file_size, int(fragment_count), int(fragment_size), INF)
    temp = header + file_name.encode(encoding='utf-8')
    crc = zlib.crc32(temp)
    inf_packet = header + crc.to_bytes(4, 'big') + file_name.encode(encoding='utf-8')
    decoded_inf_packet = decode_data(inf_packet)

    # sending the INF packet
    try:
        sock.sendto(inf_packet, (server_ip, int(server_port)))
        if SHOW_EACH_FRAGMENT_INFO:
            print("[ ] The information message has been sent to the server")
            if SHOW_ADDITIONAL_FRAGMENT_INFO:
                print(decoded_inf_packet)
    except socket.error as e:
        print("[x] The information message was NOT sent to the server " + str(e))
        return 0

    # waiting for response
    try:
        response_to_inf_packet, addr = sock.recvfrom(MAX_DATA_SIZE)
    except socket.error as e:
        print("[x] ACK was not received for the information message from the server " + str(e))
        return 0

    decoded_inf_response = decode_data(response_to_inf_packet)

    # comparing INF packet with the response
    if decoded_inf_response['sequence_number'] == decoded_inf_packet['sequence_number'] \
            and decoded_inf_response['fragment_count'] == decoded_inf_packet['fragment_count'] \
            and decoded_inf_response['fragment_size'] == decoded_inf_packet['fragment_size'] \
            and decoded_inf_response['data'] == decoded_inf_packet['data'] \
            and decoded_inf_response['packet_type'] == ACK:

        if SHOW_EACH_FRAGMENT_INFO:
            print("[√] ACK was received for the information message from the server")
            if SHOW_ADDITIONAL_FRAGMENT_INFO:
                print(decoded_inf_response)

        buffer = 0
        while buffer < int(fragment_count):

            data_length = calculate_data_length(buffer, file_size, fragment_size)

            header = create_custom_header(buffer + 1, int(fragment_count), int(data_length), packet_type)

            if file_name == "<text>":
                fragment_data = bytes(
                    message[buffer * int(fragment_size):(buffer * int(fragment_size)) + int(fragment_size)], 'utf-8')

            else:
                fragment_data = bytes(
                    byte_array[buffer * int(fragment_size):(buffer * int(fragment_size)) + int(fragment_size)])

            if defected:
                temp = header + fragment_data.join([b'defected'])
                defected = False
            else:
                temp = header + fragment_data

            crc = zlib.crc32(temp)
            dat_fragment = header + crc.to_bytes(4, 'big') + fragment_data
            decoded_dat_fragment = decode_data(dat_fragment)

            # sending the DAT fragment
            try:
                sock.sendto(dat_fragment, (server_ip, int(server_port)))
                if SHOW_EACH_FRAGMENT_INFO:
                    print("[ ] Packet no. %d | %d bytes has been sent" % (
                        decoded_dat_fragment['sequence_number'],
                        decoded_dat_fragment['fragment_size'] + CUSTOM_HEADER_SIZE))
                    if SHOW_ADDITIONAL_FRAGMENT_INFO:
                        print(decoded_dat_fragment)
            except socket.error as e:
                print("[x] Failed to send Packet no. %d | %d bytes " % (
                    decoded_dat_fragment['sequence_number'],
                    decoded_dat_fragment['fragment_size'] + CUSTOM_HEADER_SIZE) + str(e))
                return 0

            # waiting for the response (ACK or NACK)
            response_to_dat_fragment, addr = sock.recvfrom(MAX_DATA_SIZE)
            decoded_response_to_dat_fragment = decode_data(response_to_dat_fragment)

            # response to the sent fragment was ACK
            if decoded_response_to_dat_fragment['sequence_number'] == decoded_dat_fragment['sequence_number'] \
                    and decoded_response_to_dat_fragment['fragment_count'] == decoded_dat_fragment['fragment_count'] \
                    and decoded_response_to_dat_fragment['fragment_size'] == decoded_dat_fragment['fragment_size'] \
                    and decoded_response_to_dat_fragment['packet_type'] == ACK:
                if SHOW_EACH_FRAGMENT_INFO:
                    print("[√] ACK for the Packet no. %d was received" % (
                        decoded_response_to_dat_fragment['sequence_number']))
                    if SHOW_ADDITIONAL_FRAGMENT_INFO:
                        print(decoded_response_to_dat_fragment)

                buffer += 1

            # response to the sent fragment was NACK
            elif decoded_response_to_dat_fragment['sequence_number'] == decoded_dat_fragment['sequence_number'] \
                    and decoded_response_to_dat_fragment['fragment_count'] == decoded_dat_fragment['fragment_count'] \
                    and decoded_response_to_dat_fragment['fragment_size'] == decoded_dat_fragment['fragment_size'] \
                    and decoded_response_to_dat_fragment['packet_type'] == NACK:
                if SHOW_EACH_FRAGMENT_INFO:
                    print("[!] NACK for the Packet no. %d was received" % (
                        decoded_response_to_dat_fragment['sequence_number']))
                    if SHOW_ADDITIONAL_FRAGMENT_INFO:
                        print(decoded_response_to_dat_fragment)

            if buffer == int(fragment_count):
                if file_name == "<text>":
                    print("")
                    print("[√] The message '%s' has been sent successfully\n" % message)

                else:
                    print("")
                    print("[√] The file '%s' has been sent successfully\n" % file_name)

    else:
        print("[!] Something went terribly wrong.\n")
        return 0

    return 1


if __name__ == '__main__':
    terminate_event.set()

    while True:
        choice = input("Choose from the options:\n"
                       "[1] - Server\n"
                       "[2] - Client\n")

        if int(choice) == 1:
            set_up_server()
        elif int(choice) == 2:
            set_up_client()
