import os
import socket
import heapq
import zlib
import threading
import ipaddress

stop_sending_KPAs = threading.Event()
stop_receiving_KPAs = threading.Event()

MAX_DATA_SIZE = 1432
CUSTOM_HEADER_SIZE = 13

# SWITCHES
SHOW_EACH_FRAGMENT = True
SHOW_ADDITIONAL_FRAGMENT_INFO = True
DEBUG_MODE = False

# PACKET TYPES
INF = 0
ACK = 1
NACK = 2
DAT = 3
KPA = 4


def validate_ip_address(address):
    try:
        ipaddress.ip_address(address)
        return True
    except ValueError:
        return False


def input_port():
    server_port = 0
    while True:
        try:
            server_port = int(input("[2] Enter the port:\n"))
            break
        except ValueError:
            print("Please enter numbers only.")
            continue
    return server_port


def input_IP():
    while True:
        server_ip = input("[1] Enter the IP address of the server:\n")
        if validate_ip_address(server_ip):
            break
        else:
            print("Please enter a valid IP address.")
            continue
    return server_ip


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


def set_fragment_size():
    while True:
        try:
            fragment_size = int(input("Enter the size of the fragments:\n"))
            while int(fragment_size) < 1 or int(fragment_size) > MAX_DATA_SIZE - CUSTOM_HEADER_SIZE:

                try:
                    fragment_size = int(input(
                        "[!] You have entered an invalid size. The max fragment size is 1419. Please enter the "
                        "fragment size again:\n"))
                except ValueError:
                    print("Please enter numbers only.")

            return fragment_size
        except ValueError:
            print("Please enter numbers only.")


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
    print("The files will be saved in the directory %s" % path)
    return path


def client_keep_alive(server_ip, server_port, sock):
    while not stop_sending_KPAs.is_set():
        event_timer = stop_sending_KPAs.wait(10)
        if not event_timer:
            kpa_header = create_custom_header(0, 0, 0, KPA)
            crc = 0
            kpa_message = kpa_header + crc.to_bytes(4, 'big')
            kpa_message_decoded = decode_data(kpa_message)
            try:
                sock.sendto(kpa_message, (server_ip, int(server_port)))
                if SHOW_EACH_FRAGMENT:
                    print("[ ] Keep Alive message has been sent")
                    if SHOW_ADDITIONAL_FRAGMENT_INFO:
                        print(kpa_message_decoded)
                sock.settimeout(20)
                try:
                    data, addr = sock.recvfrom(MAX_DATA_SIZE)
                    decoded_data = decode_data(data)
                    if SHOW_EACH_FRAGMENT:
                        print("[√] ACK was received for the Keep Alive message")
                        if SHOW_ADDITIONAL_FRAGMENT_INFO:
                            print(decoded_data)
                except socket.error as e:
                    if DEBUG_MODE:
                        print("[x] ACK was NOT received for the Keep Alive message. Closing the socket.\n" + str(e))
                    else:
                        print("[x] ACK was NOT received for the Keep Alive message. Closing the socket.\n")
                    stop_sending_KPAs.set()
                    sock.close()

            except socket.error as e:
                if DEBUG_MODE:
                    print("[x] Failed to send Keep alive message. Closing the socket.\n" + str(e))
                else:
                    print("[x] Failed to send Keep alive message. Closing the socket.\n")
                stop_sending_KPAs.set()
                sock.close()


def server_logout(sock):
    while True:
        try:
            user_input = int(input())
            if int(user_input) == 0:
                print("Logging out...")
                stop_receiving_KPAs.set()
                sock.close()
                break
            else:
                print("Please enter 0 to log out.")
        except ValueError:
            print("Please enter 0 to log out.")


def configure_server():
    print(">>> SERVER <<<\n")

    server_ip = input_IP()
    server_port = input_port()

    path = create_directory()

    # creating the socket
    sock = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)

    # bind IP address
    sock.bind((server_ip, int(server_port)))

    server_input_thread = threading.Thread(target=server_logout, args=(sock,))
    server_input_thread.start()

    while True:
        buffer = server(sock, path, stop_receiving_KPAs)
        if buffer == 0:
            stop_receiving_KPAs.clear()
            server_input_thread.join()
            return


def server(sock, path, event):
    received_message = []
    heapq.heapify(received_message)
    final_message = ""

    while True:

        print("\n>>> The server is live and ready to receive data <<<\n"
              "[0] - Log out (Will close the socket)")

        try:
            data, addr = sock.recvfrom(MAX_DATA_SIZE)
            received_data = decode_data(data)

            # sending ACK for the informational message
            if received_data['packet_type'] == INF:
                if SHOW_EACH_FRAGMENT:
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
                    if SHOW_EACH_FRAGMENT:
                        print("[√] ACK has been sent to the client for the information message")
                        if SHOW_ADDITIONAL_FRAGMENT_INFO:
                            print(decoded_ack_to_inf_packet)
                except socket.error as e:
                    if DEBUG_MODE:
                        print(
                            "[x] Failed to send ACK to the client for the information message. Closing the socket.\n" + str(
                                e))
                    else:
                        print("[x] Failed to send ACK to the client for the information message. Closing the socket.\n")
                    return 0

                print("[i] The server expects a %lu byte message from the client, divided into %d packets. The message "
                      "is fragmented by %lu bytes. A total of %lu bytes will be transferred."
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

                            if SHOW_EACH_FRAGMENT:
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
                            fr_ack_message = fr_ack_header + crc.to_bytes(4, 'big')
                            sent_decoded_fr_ack_message = decode_data(fr_ack_message)

                            try:
                                sock.sendto(fr_ack_message, (addr[0], addr[1]))
                                if SHOW_EACH_FRAGMENT:
                                    print("[√] ACK for Packet no. %d has been sent" % (
                                        sent_decoded_fr_ack_message['sequence_number']))
                                    if SHOW_ADDITIONAL_FRAGMENT_INFO:
                                        print(sent_decoded_fr_ack_message)
                                buffer += 1
                            except socket.error as e:
                                if DEBUG_MODE:
                                    print("[x] Failed to send ACK for Packet no. %d " % (
                                    sent_decoded_fr_ack_message['sequence_number']) + str(e))
                                else:
                                    print("[x] Failed to send ACK for Packet no. %d " % (
                                    sent_decoded_fr_ack_message['sequence_number']))
                                return 0

                        # crc is NOT correct
                        elif received_fragment['crc'] != zlib.crc32(data_without_crc):
                            if SHOW_EACH_FRAGMENT:
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
                            fr_nack_message = fr_nack_header + crc.to_bytes(4, 'big')
                            sent_decoded_fr_nack_message = decode_data(fr_nack_message)
                            try:
                                sock.sendto(fr_nack_message, (addr[0], addr[1]))
                                if SHOW_EACH_FRAGMENT:
                                    print("[√] NACK for Packet no. %d has been sent" % (
                                        sent_decoded_fr_nack_message['sequence_number']))
                                    if SHOW_ADDITIONAL_FRAGMENT_INFO:
                                        print(sent_decoded_fr_nack_message)
                            except socket.error as e:
                                if DEBUG_MODE:
                                    print("[x] Failed to send NACK for Packet no. %d " % (
                                    fr_nack_message['sequence_number']) + str(e))
                                else:
                                    print("[x] Failed to send NACK for Packet no. %d " % (
                                    fr_nack_message['sequence_number']))
                                return 0

                if type_of_message == "<text>":
                    print("[i] Received message from %s: '%s'" % (addr[0], final_message))

                else:
                    with open(os.path.join(path, type_of_message), 'wb') as file:
                        while received_message:
                            file.write(heapq.heappop(received_message)[1])

                    print("[i] Received file from %s: '%s' has been saved under directory %s" % (
                        addr[0], type_of_message, path))

                sock.settimeout(20)
                final_message = ""
                return 1

            # sending ACK for the Keep Alive message
            if received_data['packet_type'] == KPA:
                if SHOW_EACH_FRAGMENT:
                    print("[ ] Keep Alive message was received")
                    if SHOW_ADDITIONAL_FRAGMENT_INFO:
                        print(received_data)
                kpa_ack_header = create_custom_header(0, 0, 0, ACK)
                crc = 0
                kpa_ack_message = kpa_ack_header + crc.to_bytes(4, 'big')
                sent_decoded_kpa_ack = decode_data(kpa_ack_message)

                try:
                    sock.sendto(kpa_ack_message, (addr[0], addr[1]))
                    if SHOW_EACH_FRAGMENT:
                        print("[√] ACK has been sent for the Keep Alive message")
                        if SHOW_ADDITIONAL_FRAGMENT_INFO:
                            print(sent_decoded_kpa_ack)
                    return 1

                except socket.error as e:
                    if DEBUG_MODE:
                        print("[x] Failed to send ACK for the Keep Alive message. Closing the socket.\n" + str(e))
                    else:
                        print("[x] Failed to send ACK for the Keep Alive message. Closing the socket.\n")
                    return 0

        except socket.error as e:
            if DEBUG_MODE:
                print("[x] No packets were received from the client. Closing the socket.\n" + str(e))
            else:
                print("[x] No packets were received from the client. The connection timed out. Press 0 to log out")
            return 0


def configure_client():
    print(">>> CLIENT <<<\n")

    server_ip = input_IP()
    server_port = input_port()

    # creating the socket
    sock = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)

    while True:
        buffer = client(server_ip, server_port, sock)
        if buffer == 0:
            stop_sending_KPAs.set()
            sock.close()
            return
        if buffer == 1:
            print("[i] Starting Keep Alive in the background")
            stop_sending_KPAs.clear()
            keep_alive_thread = threading.Thread(target=client_keep_alive, args=(server_ip, server_port, sock))
            keep_alive_thread.start()


def client(server_ip, server_port, sock):
    fragment_size = 0
    message = ""
    file_size = 0
    file_name = ""
    defected = False
    packet_type = 0
    byte_array = bytearray()

    try:
        action = int(input("\nChoose from the options:\n"
                           "[0] - Sign out\n"
                           "[1] - Send a text message\n"
                           "[2] - Simulation of a text message error\n"
                           "[3] - Send a file\n"
                           "[4] - Simulation of a file transfer error\n"))

        if int(action) == 0:
            return 0

        elif int(action) == 1 or int(action) == 2:
            fragment_size = set_fragment_size()
            message = input("Enter a text message\n")
            file_size = len(message)
            file_name = "<text>"
            if int(action) == 1:
                defected = False
            elif int(action) == 2:
                defected = True
            packet_type = DAT

        elif int(action) == 3 or int(action) == 4:
            fragment_size = set_fragment_size()
            while True:
                try:
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

                    break
                except FileNotFoundError:
                    print("Please enter the file's absolute path correctly.")
                    continue
                except OSError:
                    print("Please enter the file's absolute path correctly.")
                    continue

        # calculate fragment count
        fragment_count = calculate_fragment_count(file_size, fragment_size)

        stop_sending_KPAs.set()

        # creating the INF packet
        header = create_custom_header(file_size, int(fragment_count), int(fragment_size), INF)
        temp = header + file_name.encode(encoding='utf-8')
        crc = zlib.crc32(temp)
        inf_packet = header + crc.to_bytes(4, 'big') + file_name.encode(encoding='utf-8')
        decoded_inf_packet = decode_data(inf_packet)

        # sending the INF packet
        try:
            sock.sendto(inf_packet, (server_ip, int(server_port)))
            if SHOW_EACH_FRAGMENT:
                print("[ ] The information message has been sent to the server")
                if SHOW_ADDITIONAL_FRAGMENT_INFO:
                    print(decoded_inf_packet)

            # receiving response for the INF packet
            try:
                response_to_inf_packet, addr = sock.recvfrom(MAX_DATA_SIZE)
                decoded_inf_response = decode_data(response_to_inf_packet)

                # the response was ACK and the received frame had the same content
                if decoded_inf_response['sequence_number'] == decoded_inf_packet['sequence_number'] and \
                        decoded_inf_response['fragment_count'] == decoded_inf_packet['fragment_count'] and \
                        decoded_inf_response['fragment_size'] == decoded_inf_packet['fragment_size'] and \
                        decoded_inf_response['data'] == decoded_inf_packet['data'] and \
                        decoded_inf_response['packet_type'] == ACK:

                    if SHOW_EACH_FRAGMENT:
                        print("[√] ACK was received for the information message from the server")
                        if SHOW_ADDITIONAL_FRAGMENT_INFO:
                            print(decoded_inf_response)

                    # sending the packets fragment_count times
                    buffer = 0
                    while buffer < int(fragment_count):

                        data_length = calculate_data_length(buffer, file_size, fragment_size)

                        header = create_custom_header(buffer + 1, int(fragment_count), int(data_length), packet_type)

                        if file_name == "<text>":
                            fragment_data = bytes(
                                message[buffer * int(fragment_size):(buffer * int(fragment_size)) + int(fragment_size)],
                                'utf-8')

                        else:
                            fragment_data = bytes(
                                byte_array[
                                buffer * int(fragment_size):(buffer * int(fragment_size)) + int(fragment_size)])

                        if defected:
                            defected_data = 69
                            defected_data_bytes = defected_data.to_bytes(1, 'big')
                            temp = header + fragment_data + defected_data_bytes
                            defected = False
                        else:
                            temp = header + fragment_data

                        crc = zlib.crc32(temp)
                        dat_fragment = header + crc.to_bytes(4, 'big') + fragment_data
                        decoded_dat_fragment = decode_data(dat_fragment)

                        # sending the DAT fragment
                        try:
                            sock.sendto(dat_fragment, (server_ip, int(server_port)))
                            if SHOW_EACH_FRAGMENT:
                                print("[ ] Packet no. %d | %d bytes has been sent" % (
                                    decoded_dat_fragment['sequence_number'],
                                    decoded_dat_fragment['fragment_size'] + CUSTOM_HEADER_SIZE))
                                if SHOW_ADDITIONAL_FRAGMENT_INFO:
                                    print(decoded_dat_fragment)

                            # receiving response for the DAT fragment
                            try:
                                response_to_dat_fragment, addr = sock.recvfrom(MAX_DATA_SIZE)
                                decoded_response_to_dat_fragment = decode_data(response_to_dat_fragment)

                                # response to the sent fragment was ACK
                                if decoded_response_to_dat_fragment['sequence_number'] == decoded_dat_fragment[
                                    'sequence_number'] \
                                        and decoded_response_to_dat_fragment['fragment_count'] == decoded_dat_fragment[
                                    'fragment_count'] \
                                        and decoded_response_to_dat_fragment['fragment_size'] == decoded_dat_fragment[
                                    'fragment_size'] \
                                        and decoded_response_to_dat_fragment['packet_type'] == ACK:
                                    if SHOW_EACH_FRAGMENT:
                                        print("[√] ACK for the Packet no. %d was received" % (
                                            decoded_response_to_dat_fragment['sequence_number']))
                                        if SHOW_ADDITIONAL_FRAGMENT_INFO:
                                            print(decoded_response_to_dat_fragment)

                                    # successfully transferred fragments
                                    buffer += 1

                                # response to the sent fragment was NACK
                                elif decoded_response_to_dat_fragment['sequence_number'] == decoded_dat_fragment[
                                    'sequence_number'] \
                                        and decoded_response_to_dat_fragment['fragment_count'] == decoded_dat_fragment[
                                    'fragment_count'] \
                                        and decoded_response_to_dat_fragment['fragment_size'] == decoded_dat_fragment[
                                    'fragment_size'] \
                                        and decoded_response_to_dat_fragment['packet_type'] == NACK:
                                    if SHOW_EACH_FRAGMENT:
                                        print("[!] NACK for the Packet no. %d was received" % (
                                            decoded_response_to_dat_fragment['sequence_number']))
                                        if SHOW_ADDITIONAL_FRAGMENT_INFO:
                                            print(decoded_response_to_dat_fragment)

                                # all fragments were transferred successfully
                                if buffer == int(fragment_count):
                                    if file_name == "<text>":
                                        print("[√] The message '%s' has been sent successfully" % message)

                                    else:
                                        print("[√] The file '%s' has been sent successfully" % file_name)

                            # if receiving the response for the DAT fragment failed somehow
                            except socket.error as e:
                                if DEBUG_MODE:
                                    print("No response was received for the Packet\n" + str(e))
                                else:
                                    print("No response was received for the Packet\n")
                                return 0

                        # if sending the DAT fragment failed somehow
                        except socket.error as e:
                            if DEBUG_MODE:
                                print("[x] Failed to send Packet no. %d | %d bytes\n" % (
                                decoded_dat_fragment['sequence_number'],
                                decoded_dat_fragment['fragment_size'] + CUSTOM_HEADER_SIZE) + str(e))
                            else:
                                print("[x] Failed to send Packet no. %d | %d bytes\n" % (
                                decoded_dat_fragment['sequence_number'],
                                decoded_dat_fragment['fragment_size'] + CUSTOM_HEADER_SIZE))
                            return 0

                # if the response was something different than what we expected
                else:
                    print("[!] Something went terribly wrong.")
                    return 0

                return 1

            # if receiving response for the INF packet failed somehow
            except socket.error as e:
                if DEBUG_MODE:
                    print("[x] Response was not received for the information message from the server\n" + str(e))
                else:
                    print("[x] Response was not received for the information message from the server\n")
                return 0

        # if sending the INF packet failed somehow
        except socket.error as e:
            if DEBUG_MODE:
                print("[x] The information message was NOT sent to the server\n" + str(e))
            else:
                print("[x] The information message was NOT sent to the server\n")
            return 0

    except ValueError:
        print("Please enter numbers only.")


if __name__ == '__main__':
    stop_sending_KPAs.set()

    while True:
        try:
            choice = int(input("\nChoose from the options:\n"
                               "[0] - Quit application\n"
                               "[1] - Log in as server\n"
                               "[2] - Log in as client\n"))

            if int(choice) == 0:
                quit()
            elif int(choice) == 1:
                configure_server()
            elif int(choice) == 2:
                configure_client()

        except ValueError:
            print("Please enter numbers only.")
