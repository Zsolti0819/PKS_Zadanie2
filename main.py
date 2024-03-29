import ipaddress
import math
import os
import socket
import threading
import zlib

# SWITCHES
SHOW_ATTRIBUTES = True
SHOW_RAW_DATA = False
CLIENT_SHOW_KPAs_AND_FINs = False

# EVENTS
client_terminate_KPAs = threading.Event()
server_FIN = threading.Event()

# SIZES
MAX_DATA_SIZE_IN_BYTES = 1458
CUSTOM_HEADER_SIZE_IN_BYTES = 13
TIMEOUT_IN_SECONDS = 20
KPA_SENDING_FREQUENCY_IN_SECONDS = 5
DAMAGE_EVERY_NTH_PACKET = 1

# PACKET TYPES
INF = 0
ACK = 1
NACK = 2
DAT = 3
KPA = 4
FIN = 5

# BUFFERS
server_first_start = True
client_first_start = True
client_logout = False
client_logout_done = False


def validate_ip_address(address):
    try:
        ipaddress.ip_address(address)
        return True
    except ValueError:
        return False


def input_IP():
    while True:
        server_ip = input("Enter the IP address of the server:\n")
        if validate_ip_address(server_ip):
            break
        else:
            print("Please enter a valid IP address.")
            continue
    return server_ip


def input_port():
    server_port = 0
    while True:
        try:
            server_port = int(input("Enter the port:\n"))
            break
        except ValueError:
            print("Please enter numbers only.")
            continue
    return server_port


def create_directory():
    path = ""
    mode = 0o777
    while True:
        try:
            path = input("Enter the name of the folder where you want to save the files:\n")
            os.makedirs(name=path, mode=mode, exist_ok=True)
            print("The files will be saved in the directory %s" % path)
            break
        except OSError as e:
            print("Cannot create folder " + str(e))
            continue

    return path


def set_fragment_size():
    while True:
        try:
            fragment_size = int(input("Enter the size of the fragments. 13 bytes will be automatically added to the value.\n"))
            while int(fragment_size) < 1 or int(fragment_size) > MAX_DATA_SIZE_IN_BYTES - CUSTOM_HEADER_SIZE_IN_BYTES:
                try:
                    fragment_size = int(input("You have entered an invalid size. Please enter a size between 1 - %d.\n" % (MAX_DATA_SIZE_IN_BYTES - CUSTOM_HEADER_SIZE_IN_BYTES)))
                except ValueError:
                    print("Please enter numbers only.")

            return fragment_size
        except ValueError:
            print("Please enter numbers only.")


def calculate_fragment_count(file_size, fragment_size):
    if int(file_size) > int(fragment_size):
        fragment_count = int(file_size) / int(fragment_size)
    else:
        fragment_count = 1

    return math.ceil(fragment_count)


def calculate_data_length(buffer, file_size, fragment_size):
    if int(fragment_size) * (buffer + 1) < file_size:
        data_length = fragment_size
    else:
        data_length = int(fragment_size) - ((int(fragment_size) * (buffer + 1)) - file_size)

    if data_length < 0:
        data_length = 0

    return data_length


def create_custom_header(sequence_number, fragment_count, fragment_size, packet_type):
    sn = sequence_number.to_bytes(3, 'big')
    fc = fragment_count.to_bytes(3, 'big')
    fs = fragment_size.to_bytes(2, 'big')
    pt = packet_type.to_bytes(1, 'big')
    return sn + fc + fs + pt


def has_the_same_header_except_flag(sent_packet, received_packet, flag):
    if received_packet['sequence_number'] == sent_packet['sequence_number'] and \
            received_packet['fragment_count'] == sent_packet['fragment_count'] and\
            received_packet['fragment_size'] == sent_packet['fragment_size'] and\
            received_packet['packet_type'] == flag:
        return True
    return False


def decode_data(data):
    decoded_data = {'sequence_number': int.from_bytes(data[0:3], 'big'),
                    'fragment_count': int.from_bytes(data[3:6], 'big'),
                    'fragment_size': int.from_bytes(data[6:8], 'big'),
                    'packet_type': int.from_bytes(data[8:9], 'big'),
                    'crc': int.from_bytes(data[9:13], 'big'),
                    'data': data[13:], }
    return decoded_data


def packet_format(packet):
    packet_type = ""
    if packet['packet_type'] == INF:
        packet_type = "INF"
    if packet['packet_type'] == ACK:
        packet_type = "ACK"
    if packet['packet_type'] == NACK:
        packet_type = "NACK"
    if packet['packet_type'] == DAT:
        packet_type = "DAT"
    if packet['packet_type'] == KPA:
        packet_type = "KPA"
    if packet['packet_type'] == FIN:
        packet_type = "FIN"

    if SHOW_RAW_DATA:
        packet_formatted = "sequence_number %d | fragment_count %d | fragment_size %d bytes | %s | CRC %d | data %s" % (packet['sequence_number'], packet['fragment_count'], packet['fragment_size'], packet_type, packet['crc'], packet['data'])
    else:
        packet_formatted = "sequence_number %d | fragment_count %d | fragment_size %d bytes | %s | CRC %d" % (packet['sequence_number'], packet['fragment_count'], packet['fragment_size'], packet_type, packet['crc'])

    return packet_formatted


def server_logout():
    while True:
        try:
            user_input = int(input())
            if int(user_input) == 0:
                print("Logging out...")
                server_FIN.set()
                break
            else:
                print("Please enter 0 to close the socket.")
        except ValueError:
            print("Please enter 0 to close the socket.")


def configure_server():
    print(">>> SERVER <<<\n")
    global server_first_start

    server_ip = input_IP()
    server_port = input_port()

    # creating the socket
    sock = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)

    # bind IP address
    try:
        sock.bind((server_ip, int(server_port)))
    except OSError:
        print("Server is currently logged in.")
        return

    path = create_directory()

    server_input_thread = threading.Thread(target=server_logout)

    while True:
        buffer = server(sock, path, server_input_thread)
        if buffer == 0:
            if server_input_thread.is_alive():
                server_input_thread.join()
            server_FIN.clear()
            server_first_start = True
            return


def server(sock, path, server_input_thread):
    global server_first_start

    while True:

        if server_first_start:
            action = input("Choose from the options:\n"
                           "(0) - Log out\n"
                           "(1) - Start the server (Wait for the first message)\n")
            if int(action) == 0:
                return 0
            else:
                server_first_start = False
                server_input_thread.start()
                print(">>> Server is running <<<")

        # receive INF, KPA or FIN
        try:
            data, addr = sock.recvfrom(MAX_DATA_SIZE_IN_BYTES)
            received_data = decode_data(data)

            if received_data['packet_type'] == INF:

                received_message = bytearray()
                received_file_name = bytearray()
                received_fragments = 0
                list_of_bad_fragments = []
                bad_fragments = 0

                if SHOW_ATTRIBUTES:
                    print("RECEIVED: [✓]", packet_format(received_data))

                type_of_message = str(received_data['data'], 'utf-8')
                fragment_count = received_data['fragment_count']
                additional_packets = received_data['sequence_number']

                # create the ACK for the INF packet
                header = create_custom_header(received_data['sequence_number'], received_data['fragment_count'],
                                              received_data['fragment_size'], ACK)
                crc = 0
                packet_encoded = header + crc.to_bytes(4, 'big') + received_data['data']
                packet_decoded = decode_data(packet_encoded)

                # sending the ACK for the INF packet
                try:
                    sock.sendto(packet_encoded, (addr[0], addr[1]))
                    if SHOW_ATTRIBUTES:
                        print("SENT    : [>]", packet_format(packet_decoded))

                    # receiving fragments
                    buffer = 0
                    while buffer < fragment_count:
                        try:
                            data, addr = sock.recvfrom(MAX_DATA_SIZE_IN_BYTES)
                            received_fragment = decode_data(data)
                            data_without_crc = data[:9] + data[13:]

                            if received_fragment['packet_type'] == DAT and received_fragment['sequence_number'] == buffer + 1:
                                received_fragments += 1

                                # crc is valid
                                if received_fragment['crc'] == zlib.crc32(data_without_crc):

                                    if SHOW_ATTRIBUTES:
                                        print("RECEIVED: [✓]", packet_format(received_fragment))

                                    if buffer < additional_packets:
                                        received_file_name += received_fragment['data']
                                    else:
                                        received_message += received_fragment['data']

                                    # creating ACK for the fragment
                                    header = create_custom_header(received_fragment['sequence_number'], received_fragment['fragment_count'], received_fragment['fragment_size'], ACK)
                                    crc = 0
                                    packet_encoded = header + crc.to_bytes(4, 'big')
                                    packet_decoded = decode_data(packet_encoded)

                                    try:
                                        sock.sendto(packet_encoded, (addr[0], addr[1]))
                                        if SHOW_ATTRIBUTES:
                                            print("SENT    : [>]", packet_format(packet_decoded))
                                        buffer += 1

                                    except socket.error as e:
                                        print("[✗] Failed to send ACK for Packet no. %d " % (packet_decoded['sequence_number']) + str(e))
                                        return 0

                                # crc is NOT valid
                                elif received_fragment['crc'] != zlib.crc32(data_without_crc):

                                    list_of_bad_fragments.insert(bad_fragments, received_fragment['sequence_number'])
                                    bad_fragments += 1

                                    print(">>> PACKET %d HAS INVALID CRC <<<" % received_fragment['sequence_number'])
                                    if SHOW_ATTRIBUTES:
                                        print("RECEIVED: [!]", packet_format(received_fragment))

                                    # sending NACK for the fragment
                                    header = create_custom_header(received_fragment['sequence_number'], received_fragment['fragment_count'], received_fragment['fragment_size'], NACK)
                                    crc = 0
                                    packet_encoded = header + crc.to_bytes(4, 'big')
                                    packet_decoded = decode_data(packet_encoded)

                                    try:
                                        sock.sendto(packet_encoded, (addr[0], addr[1]))
                                        if SHOW_ATTRIBUTES:
                                            print("SENT    : [>]", packet_format(packet_decoded))

                                    except socket.error as e:
                                        print("[✗] Failed to send NACK for Packet no. %d " % (packet_encoded['sequence_number']) + str(e))
                                        return 0

                            # the client did not receive the ACK or NACK for the fragment
                            else:

                                # crc is valid
                                if received_fragment['crc'] == zlib.crc32(data_without_crc):

                                    if SHOW_ATTRIBUTES:
                                        print("RECEIVED: [✓]", packet_format(received_fragment))

                                    # creating ACK for the fragment
                                    header = create_custom_header(received_fragment['sequence_number'],
                                                                  received_fragment['fragment_count'],
                                                                  received_fragment['fragment_size'], ACK)
                                    crc = 0
                                    packet_encoded = header + crc.to_bytes(4, 'big')
                                    packet_decoded = decode_data(packet_encoded)

                                    try:
                                        sock.sendto(packet_encoded, (addr[0], addr[1]))
                                        if SHOW_ATTRIBUTES:
                                            print("SENT    : [>]", packet_format(packet_decoded))

                                    except socket.error as e:
                                        print("[✗] Failed to send ACK for Packet no. %d " % (packet_decoded['sequence_number']) + str(e))
                                        return 0

                                # crc is NOT valid
                                elif received_fragment['crc'] != zlib.crc32(data_without_crc):

                                    list_of_bad_fragments.insert(bad_fragments, received_fragment['sequence_number'])
                                    bad_fragments += 1

                                    print(">>> PACKET %d HAS INVALID CRC <<<" % received_fragment['sequence_number'])
                                    if SHOW_ATTRIBUTES:
                                        print("RECEIVED: [!]", packet_format(received_fragment))

                                    # sending NACK for the fragment
                                    header = create_custom_header(received_fragment['sequence_number'],
                                                                  received_fragment['fragment_count'],
                                                                  received_fragment['fragment_size'], NACK)
                                    crc = 0
                                    packet_encoded = header + crc.to_bytes(4, 'big')
                                    packet_decoded = decode_data(packet_encoded)

                                    try:
                                        sock.sendto(packet_encoded, (addr[0], addr[1]))
                                        if SHOW_ATTRIBUTES:
                                            print("SENT    : [>]", packet_format(packet_decoded))

                                    except socket.error as e:
                                        print("[✗] Failed to send NACK for Packet no. %d " % (packet_encoded['sequence_number']) + str(e))
                                        return 0

                        except socket.error as e:
                            print("[✗] Packet no. %d was NOT received\n" % int(buffer + 1), str(e))
                            continue

                    # text message
                    if type_of_message == "T":
                        print(">>> Received message from %s: '%s' <<<" % (addr[0], received_message.decode('utf-8')))

                    # file
                    elif type_of_message == "F":
                        with open(os.path.join(path, received_file_name.decode('utf-8')), 'wb') as file:
                            file.write(received_message)
                        print(">>> Received file from %s: '%s' has been saved under directory %s <<<" % (addr[0], received_file_name.decode('utf-8'), path))
                        print(path+"\\"+received_file_name.decode('utf-8'))

                    server_print_summary(bad_fragments, list_of_bad_fragments, received_fragments)

                    received_message.clear()
                    received_file_name.clear()
                    sock.settimeout(TIMEOUT_IN_SECONDS)
                    return 1

                except socket.error as e:
                    print("[✗] Failed to send ACK to the client for the information message.\n" + str(e))
                    return 0

            if received_data['packet_type'] == KPA:
                if SHOW_ATTRIBUTES:
                    print("RECEIVED: [✓]", packet_format(received_data))
                if server_FIN.is_set():
                    header = create_custom_header(0, 0, CUSTOM_HEADER_SIZE_IN_BYTES, FIN)
                else:
                    header = create_custom_header(0, 0, CUSTOM_HEADER_SIZE_IN_BYTES, ACK)
                crc = 0
                packet_encoded = header + crc.to_bytes(4, 'big')
                packet_decoded = decode_data(packet_encoded)

                try:
                    sock.sendto(packet_encoded, (addr[0], addr[1]))
                    if server_FIN.is_set():
                        if SHOW_ATTRIBUTES:
                            print("SENT    : [>]", packet_format(packet_decoded))
                        sock.close()
                        return 0
                    else:
                        if SHOW_ATTRIBUTES:
                            print("SENT    : [>]", packet_format(packet_decoded))
                        return 1

                except socket.error as e:
                    print("[✗] Failed to send response for the Keep Alive message.\n" + str(e))
                    return 0

            if received_data['packet_type'] == FIN:
                if SHOW_ATTRIBUTES:
                    print("RECEIVED: [✓]", packet_format(received_data))
                print(
                    ">>> FIN message was received from the client. Please log out to close the socket <<<\n(0) - Log out")
                return 0

        except socket.timeout:
            print("[x] No packets were received from the client. The connection timed out.")
            return 0
        except socket.error as e:
            print("[✗] No packets were received from the client.\n" + str(e))
            return 0


def client_keep_alive(server_ip, server_port, sock):
    global client_logout_done
    while not client_terminate_KPAs.is_set():
        event_timer = client_terminate_KPAs.wait(KPA_SENDING_FREQUENCY_IN_SECONDS)
        if not event_timer:
            if not client_logout:
                header = create_custom_header(0, 0, CUSTOM_HEADER_SIZE_IN_BYTES, KPA)
            else:
                header = create_custom_header(0, 0, CUSTOM_HEADER_SIZE_IN_BYTES, FIN)
            crc = 0
            message = header + crc.to_bytes(4, 'big')
            message_decoded = decode_data(message)
            try:
                sock.sendto(message, (server_ip, int(server_port)))
                if CLIENT_SHOW_KPAs_AND_FINs:
                    if SHOW_ATTRIBUTES:
                        print("SENT    : [>]", packet_format(message_decoded))
                if client_logout:
                    client_logout_done = True
                    return
                try:
                    data, addr = sock.recvfrom(MAX_DATA_SIZE_IN_BYTES)
                    decoded_data = decode_data(data)
                    if decoded_data['packet_type'] == ACK:
                        if CLIENT_SHOW_KPAs_AND_FINs:
                            if SHOW_ATTRIBUTES:
                                print("RECEIVED: [✓]", packet_format(decoded_data))
                    elif decoded_data['packet_type'] == FIN:
                        if SHOW_ATTRIBUTES:
                            print("RECEIVED: [✓]", packet_format(decoded_data))
                        client_terminate_KPAs.set()
                        print(
                            ">>> FIN message was received from the server. Please log out to close the socket <<<\n(0) - Log out")
                        client_logout_done = True
                        return
                except socket.error as e:
                    print("[✗] ACK was NOT received for the Keep Alive message. Closing the socket.\n" + str(e))
                    client_terminate_KPAs.set()
                    sock.close()

            except socket.error as e:
                print("[✗] Failed to send Keep alive message. Closing the socket.\n" + str(e))
                client_terminate_KPAs.set()
                sock.close()


def configure_client():
    print(">>> CLIENT <<<\n")
    server_ip = input_IP()
    server_port = input_port()
    global client_logout
    global client_first_start

    # creating the socket
    sock = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)

    while True:
        buffer = client(server_ip, server_port, sock)
        if buffer == 0:
            client_logout = False
            client_first_start = True
            sock.close()
            return
        if buffer == 1:
            client_terminate_KPAs.clear()
            keep_alive_thread = threading.Thread(target=client_keep_alive, args=(server_ip, server_port, sock))
            keep_alive_thread.start()


def client(server_ip, server_port, sock):
    global client_logout
    global client_logout_done
    global client_first_start
    message = ""
    file_name = ""
    file_size = 0
    inf_data = ""
    damaged = False
    packet_type = 0
    byte_array = bytearray()
    additional_size = 0
    additional_packets = 0

    while True:
        try:
            action = int(input("Choose from the options:\n"
                               "(0) - Log out\n"
                               "(1) - Send a text message\n"
                               "(2) - Simulation of a text message error\n"
                               "(3) - Send a file\n"
                               "(4) - Simulation of a file transfer error\n"))

            if int(action) == 0:
                print("Logging out...")
                if client_first_start:
                    return 0
                client_logout = True
                while True:
                    if client_logout_done:
                        break
                client_logout_done = False
                return 0

            elif int(action) == 1 or int(action) == 2:
                fragment_size = set_fragment_size()
                message = input("Enter a text message\n")
                file_size = len(message)
                inf_data = "T"
                if int(action) == 1:
                    damaged = False
                elif int(action) == 2:
                    damaged = True
                packet_type = DAT

            elif int(action) == 3 or int(action) == 4:
                fragment_size = set_fragment_size()
                while True:
                    try:
                        inf_data = "F"
                        path_and_file_name = input("Enter the file name (enter the full path):\n")
                        file_name = os.path.basename(path_and_file_name)
                        additional_size = len(file_name)
                        additional_packets = calculate_fragment_count(additional_size, fragment_size)
                        file_size = os.path.getsize(path_and_file_name)
                        with open(path_and_file_name, "rb") as file:
                            while True:
                                byte = file.read(1)
                                if not byte:
                                    break
                                byte_array += byte
                        file.close()
                        print(">>> File %s will be sent to the client. <<<" % path_and_file_name)
                        if int(action) == 3:
                            damaged = False
                        elif int(action) == 4:
                            damaged = True
                        packet_type = DAT

                        break
                    except FileNotFoundError:
                        print("Please enter the file's absolute path correctly.")
                        continue
                    except OSError:
                        print("Please enter the file's absolute path correctly.")
                        continue

            else:
                print("Please enter a number from the list.")
                continue

            # client did not log out without sending a message
            client_first_start = False

            # just before we send a new INF packet, we stop sending KPAs
            client_terminate_KPAs.set()

            # calculate fragment count
            fragment_count = calculate_fragment_count(file_size, fragment_size) + additional_packets

            # creating the INF packet
            header = create_custom_header(int(additional_packets), int(fragment_count), int(fragment_size) + CUSTOM_HEADER_SIZE_IN_BYTES, INF)
            temp = header + inf_data.encode(encoding='utf-8')
            crc = zlib.crc32(temp)
            packet_encoded_sent = header + crc.to_bytes(4, 'big') + inf_data.encode(encoding='utf-8')
            packet_decoded_sent = decode_data(packet_encoded_sent)

            # sending the INF packet
            try:
                sock.sendto(packet_encoded_sent, (server_ip, int(server_port)))
                sock.settimeout(TIMEOUT_IN_SECONDS)
                if SHOW_ATTRIBUTES:
                    print("SENT    : [>]", packet_format(packet_decoded_sent))

                # receiving response for the INF packet
                try:
                    data, addr = sock.recvfrom(MAX_DATA_SIZE_IN_BYTES)
                    packet_decoded_recv = decode_data(data)

                    # the response was ACK and the received frame had the same content
                    if has_the_same_header_except_flag(packet_decoded_sent, packet_decoded_recv, ACK) and packet_decoded_sent['data'] == packet_decoded_recv['data']:
                        if SHOW_ATTRIBUTES:
                            print("RECEIVED: [✓]", packet_format(packet_decoded_recv))

                        # sending the packets fragment_count times
                        buffer = 0
                        damaged_sent = False
                        while buffer < int(fragment_count):

                            if buffer < int(additional_packets):
                                data_length = calculate_data_length(buffer, additional_size, fragment_size)
                                header = create_custom_header(buffer + 1, int(fragment_count), int(data_length) + CUSTOM_HEADER_SIZE_IN_BYTES, packet_type)
                                fragment_data = bytes(file_name[buffer * int(fragment_size):(buffer * int(fragment_size)) + int(fragment_size)], 'utf-8')

                            else:
                                data_length = calculate_data_length((buffer - int(additional_packets)), file_size, fragment_size)
                                header = create_custom_header(buffer + 1, int(fragment_count), int(data_length) + CUSTOM_HEADER_SIZE_IN_BYTES, packet_type)

                                if inf_data == "T":
                                    fragment_data = bytes(message[(buffer - int(additional_packets)) * int(fragment_size):((buffer - int(additional_packets)) * int(fragment_size)) + int(fragment_size)], 'utf-8')

                                else:
                                    fragment_data = bytes(byte_array[(buffer - int(additional_packets)) * int(fragment_size):((buffer - int(additional_packets)) * int(fragment_size)) + int(fragment_size)])

                            temp = header + fragment_data
                            crc = zlib.crc32(temp)
                            if damaged:
                                if (buffer + 1) % DAMAGE_EVERY_NTH_PACKET == 0 and damaged_sent is False:
                                    fragment_data = fragment_data[1:]
                                    damaged_sent = True
                                else:
                                    damaged_sent = False
                            packet_encoded_sent = header + crc.to_bytes(4, 'big') + fragment_data
                            packet_decoded_sent = decode_data(packet_encoded_sent)

                            # sending the DAT fragment
                            try:
                                sock.sendto(packet_encoded_sent, (server_ip, int(server_port)))
                                if SHOW_ATTRIBUTES:
                                    print("SENT    : [>]", packet_format(packet_decoded_sent))

                                # receiving response for the DAT fragment
                                try:
                                    packet_encoded_recv, addr = sock.recvfrom(MAX_DATA_SIZE_IN_BYTES)
                                    packet_decoded_recv = decode_data(packet_encoded_recv)

                                    # response to the sent fragment was ACK
                                    if has_the_same_header_except_flag(packet_decoded_sent, packet_decoded_recv, ACK):
                                        if SHOW_ATTRIBUTES:
                                            print("RECEIVED: [✓]", packet_format(packet_decoded_recv))
                                        buffer += 1

                                    # response to the sent fragment was NACK
                                    elif has_the_same_header_except_flag(packet_decoded_sent, packet_decoded_recv, NACK):
                                        if SHOW_ATTRIBUTES:
                                            print("RECEIVED: [!]", packet_format(packet_decoded_recv))
                                        if (buffer + 1) % DAMAGE_EVERY_NTH_PACKET == 0:
                                            damaged_sent = True

                                    # all fragments were transferred successfully
                                    if buffer == int(fragment_count):
                                        if inf_data == "T":
                                            print(">>> The message '%s' has been sent successfully <<<" % message)

                                        else:
                                            print(">>> The file '%s' has been sent successfully <<<" % file_name)

                                # if receiving the response for the DAT fragment failed somehow
                                except socket.error as e:
                                    print("[✗] No response was received for the Packet %d -" % int(buffer + 1), str(e))
                                    print("Retransmitting...")
                                    sock.sendto(packet_encoded_sent, (server_ip, int(server_port)))
                                    continue

                            # if sending the DAT fragment failed somehow
                            except socket.error as e:
                                print("[✗] Failed to send Packet no. %d\n" % (packet_decoded_sent['sequence_number']) + str(e))
                                return 0

                    # if the response was something different than what we expected
                    else:
                        print("[!] Something went terribly wrong.")
                        return 0

                    return 1

                # if receiving response for the INF packet failed somehow
                except socket.error as e:
                    print("[✗] Response was not received for the information message from the server\n" + str(e))
                    return 0

            # if sending the INF packet failed somehow
            except socket.error as e:
                print("[✗] The information message was NOT sent to the server\n" + str(e))
                return 0

        except ValueError:
            print("Please enter numbers only.")


def server_print_summary(bad_fragments, list_of_bad_fragments, received_fragments):
    print(">>> Summary <<<")
    print("Number of received fragments: %d + 1 (INF message)" % received_fragments)

    print("Number of bad fragments: %d" % bad_fragments)
    converted_bad_fragment_list = [str(element) for element in list_of_bad_fragments]
    joined_bad_fragment_string = ", ".join(converted_bad_fragment_list)
    print("Bad fragments: %s" % joined_bad_fragment_string)


if __name__ == '__main__':
    client_terminate_KPAs.set()

    while True:
        try:
            choice = int(input("Choose from the options:\n"
                               "(0) - Quit application\n"
                               "(1) - Log in as server\n"
                               "(2) - Log in as client\n"))

            if int(choice) == 0:
                quit()
            elif int(choice) == 1:
                configure_server()
            elif int(choice) == 2:
                configure_client()

        except ValueError:
            print("Please enter numbers only.")
