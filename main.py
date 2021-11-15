import os
import socket
import heapq

INIT = 0
ACK = 1
NACK = 2
DAT = 3


CUSTOM_HEADER_SIZE = 11
SHOW_EACH_FRAGMENT_INFO = True


def create_custom_header(sequence_number, fragment_count, fragment_size, packet_type):
    sn = sequence_number.to_bytes(3, 'big')
    fc = fragment_count.to_bytes(3, 'big')
    fs = fragment_size.to_bytes(2, 'big')
    pt = packet_type.to_bytes(1, 'big')
    return sn + fc + fs + pt


def crc16(data: bytes):
    """
    CRC-16-CCITT Algorithm
    """
    poly = 0x8408
    data = bytearray(data)
    crc = 0xFFFF
    for b in data:
        cur_byte = 0xFF & b
        for _ in range(0, 8):
            if (crc & 0x0001) ^ (cur_byte & 0x0001):
                crc = (crc >> 1) ^ poly
            else:
                crc >>= 1
            cur_byte >>= 1
    crc = (~crc & 0xFFFF)
    crc = (crc << 8) | ((crc >> 8) & 0xFF)

    return crc & 0xFFFF


def decode_data(data):
    parsed_data = {'sequence_number': int.from_bytes(data[0:3], 'big'),
                   'fragment_count': int.from_bytes(data[3:6], 'big'),
                   'fragment_size': int.from_bytes(data[6:8], 'big'),
                   'packet_type': int.from_bytes(data[8:9], 'big'),
                   'crc': int.from_bytes(data[9:11], 'big'),
                   'data': data[11:],}
    return parsed_data


def set_up_fragment_size():
    fragment_size = input("Zadajte velkost fragmentov:\n")
    while int(fragment_size) < 1 or int(fragment_size) > 32767 - 11:
        fragment_size = input("[!] Zadali ste neplatnu velkost. "
                              "Zadajte velkost fragmentov este raz:\n")
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
    directory = input("[3] Zadajte meno priecinku, kam chcete ulozit subory\n")
    parent_directory = "C:\\Users\\destr\\PycharmProjects\\PKS_Zadanie2"
    path = os.path.join(parent_directory, directory)
    mode = 0o777
    try:
        os.makedirs(name=path, mode=mode, exist_ok=True)
    except OSError as e:
        quit("Nie je mozne vytvorit priecinok\n" + str(e))
    print("Subory budu ulozene v adresary %s\n" % path)
    return path


def set_up_server():
    print(">>> SERVER <<<\n")
    server_ip = input("[1] Zadajte IP adresu servera:\n")
    server_port = input("[2] Zadajte port servera:\n")
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

    choice2 = input("Server ma nastavenu IP adresu %s a port %s.\n"
                    "Zvolte z moznosti:\n"
                    "[0] Odhlasit sa\n"
                    "[1] Prijat pakety\n" % (server_ip, server_port))

    if int(choice2) == 0:
        return 0

    print("[√] >>> Server caka na prijimanie udajov <<<")

    # receiving the initial message
    try:
        data, addr = sock.recvfrom(32767)
        decoded_data = decode_data(data)
    except socket.error as e:
        quit("[x] Inicializacna sprava NEBOLA prijata od klienta\n" + str(e))

    type_of_message = str(decoded_data['data'], 'utf-8')
    fragment_count = decoded_data['fragment_count']

    # sending ACK for the initial message
    if decoded_data['packet_type'] == INIT:
        if SHOW_EACH_FRAGMENT_INFO:
            print("[ ] Inicializacna sprava bola prijata od klienta")
            print(decoded_data, "\n")

        ack_header = create_custom_header(decoded_data['sequence_number'], decoded_data['fragment_count'],
                                          decoded_data['fragment_size'], ACK)
        temp = ack_header + decoded_data['data']
        crc = crc16(temp)
        ack_message = ack_header + crc.to_bytes(2, 'big') + decoded_data['data']
        sent_decoded_ack = decode_data(ack_message)

        try:
            sock.sendto(ack_message, (addr[0], addr[1]))
            if SHOW_EACH_FRAGMENT_INFO:
                print("[√] ACK bol odoslany pre inicializacnu spravu klientovi")
                print(sent_decoded_ack, "\n")
        except socket.error as e:
            quit("[x] ACK NEBOL odoslany pre inicializacnu spravu klientovi\n" + str(e))

    successfully_received_fragments = 0
    while successfully_received_fragments < fragment_count:
        try:
            data, addr = sock.recvfrom(32767)

            decoded_data = decode_data(data)
            data_without_crc = data[:9] + data[11:]
            if decoded_data['packet_type'] == DAT:

                # crc is correct
                if decoded_data['crc'] == crc16(data_without_crc):

                    if SHOW_EACH_FRAGMENT_INFO:
                        print("[ ] Packet c. %d | %lu byteov bol prijaty" % (
                            decoded_data['sequence_number'], decoded_data['fragment_size']))
                        print(decoded_data, "\n")

                    heapq.heappush(received_message, (decoded_data['sequence_number'], decoded_data['data']))

                    if type_of_message == "<text>":
                        final_message += heapq.heappop(received_message)[1].decode('utf-8')

                    # sending ACK for the fragment
                    fr_ack_header = create_custom_header(decoded_data['sequence_number'], decoded_data['fragment_count'],
                                                         decoded_data['fragment_size'], ACK)
                    temp = fr_ack_header + decoded_data['data']
                    crc = 0
                    ack_data = 0
                    fr_ack_message = fr_ack_header + crc.to_bytes(2, 'big') + ack_data.to_bytes(1, 'big')
                    sent_decoded_fr_ack_message = decode_data(fr_ack_message)

                    try:
                        sock.sendto(fr_ack_message, (addr[0], addr[1]))
                        if SHOW_EACH_FRAGMENT_INFO:
                            print("[√] ACK pre Packet c. %d bol odoslany" % (sent_decoded_fr_ack_message['sequence_number']))
                            print(sent_decoded_fr_ack_message, "\n")
                        successfully_received_fragments += 1
                    except socket.error as e:
                        quit("[x] ACK pre Packet c. %d NEBOL odoslany\n" % (sent_decoded_fr_ack_message['sequence_number']) + str(
                            e))

                # crc is NOT correct
                elif decoded_data['crc'] != crc16(data_without_crc):
                    if SHOW_EACH_FRAGMENT_INFO:
                        print("[!] Packet c. %d | %lu byteov bol prijaty >>> CHYBA PRI CRC KONTROLE <<<" % (
                            (decoded_data['sequence_number']), decoded_data['fragment_size']))
                        print(decoded_data, "\n")

                    # sending NACK for the fragment
                    fr_nack_header = create_custom_header(decoded_data['sequence_number'], decoded_data['fragment_count'],
                                                          decoded_data['fragment_size'], NACK)
                    temp = fr_nack_header + decoded_data['data']
                    crc = 0
                    nack_data = 0
                    fr_nack_message = fr_nack_header + crc.to_bytes(2, 'big') + nack_data.to_bytes(1, 'big')
                    sent_decoded_fr_nack_message = decode_data(fr_nack_message)
                    try:
                        sock.sendto(fr_nack_message, (addr[0], addr[1]))
                        if SHOW_EACH_FRAGMENT_INFO:
                            print("[√] NACK pre Packet c. %d bol odoslany" % (
                                sent_decoded_fr_nack_message['sequence_number']))
                            print(sent_decoded_fr_nack_message, "\n")
                    except socket.error as e:
                        quit(
                            "[x] NACK pre Packet c. %d NEBOL odoslany\n" % (
                                fr_nack_message['sequence_number']) + str(e))

        except socket.error as e:
            quit("[x] Packet c. %d byteov NEBOL prijaty.\n" % (decoded_data['sequence_number']) + str(e))

    if type_of_message == "<text>":
        print("\n[i] Prijata sprava od %s: '%s'\n" % (addr[0], final_message))

    else:
        with open(os.path.join(path, type_of_message), 'wb') as file:
            while received_message:
                file.write(heapq.heappop(received_message)[1])
        print("\n[i] Prijaty subor od %s: '%s' bol ulozeny pod adresarom %s\n" % (addr[0], type_of_message, path))


def set_up_client():
    print(">>> KLIENT <<<\n")
    server_ip = input("[1] Zadajte IP adresu servera:\n")
    server_port = input("[2] Zadajte port servera:\n")

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

    action = input("Zvolte z moznosti:\n"
                   "[0] - Odhlasit sa\n"
                   "[1] - Poslat textovu spravu\n"
                   "[2] - Simulacia chyby v textovej sprave\n"
                   "[3] - Poslat subor\n"
                   "[4] - Simulacia chyby pri poslani suboru\n")

    if int(action) == 0:
        return 0

    elif int(action) == 1 or int(action) == 2:
        fragment_size = set_up_fragment_size()
        message = input("Zadajte textovu spravu\n")
        file_size = len(message)
        # print(file_size)
        file_name = "<text>"
        if int(action) == 1:
            defected = False
        elif int(action) == 2:
            defected = True
        packet_type = DAT

    elif int(action) == 3 or int(action) == 4:
        fragment_size = set_up_fragment_size()
        path_and_file_name = input("Zadajte meno suboru:\n")
        file_name = os.path.basename(path_and_file_name)
        file_size = os.path.getsize(path_and_file_name)
        # print(file_size)

        with open(path_and_file_name, "rb") as file:
            while True:
                byte = file.read(1)
                if not byte:
                    break
                byte_array += byte
        file.close()

        # print(byte_array)

        if int(action) == 3:
            defected = False
        elif int(action) == 4:
            defected = True
        packet_type = DAT

    fragment_count = calculate_fragment_count(file_size, fragment_size)
    header = create_custom_header(file_size, int(fragment_count), int(fragment_size), INIT)
    temp = header + file_name.encode(encoding='utf-8')
    crc = crc16(temp)
    fragment_to_send = header + crc.to_bytes(2, 'big') + file_name.encode(encoding='utf-8')

    sent_packet = decode_data(fragment_to_send)

    # sending the initial message to the server
    try:
        sock.sendto(fragment_to_send, (server_ip, int(server_port)))
        if SHOW_EACH_FRAGMENT_INFO:
            print("[ ] Inicializacna sprava bola odoslana serverovi")
            print(sent_packet, "\n")
    except socket.error as e:
        quit("[x] Inicializacna sprava nebola odoslana serverovi\n" + str(e))

    # waiting for the ACK
    try:
        response_to_fragment, addr = sock.recvfrom(32767)
    except socket.error as e:
        quit("[x] ACK nebol prijaty pre inicializacnu spravu od servera\n" + str(e))

    received_packet = decode_data(response_to_fragment)

    # comparing sent packet with received packet
    if received_packet['sequence_number'] == sent_packet['sequence_number'] \
            and received_packet['fragment_count'] == sent_packet['fragment_count'] \
            and received_packet['fragment_size'] == sent_packet['fragment_size'] \
            and received_packet['data'] == sent_packet['data'] \
            and received_packet['packet_type'] == ACK:

        if SHOW_EACH_FRAGMENT_INFO:
            print("[√] ACK bol prijaty pre inicializacnu spravu od servera")
            print(received_packet, "\n")

        successfully_sent_fragments = 0
        while successfully_sent_fragments < int(fragment_count):

            data_length = calculate_data_length(successfully_sent_fragments, file_size, fragment_size)

            header = create_custom_header(successfully_sent_fragments + 1, int(fragment_count), int(data_length), packet_type)

            if file_name == "<text>":
                fragment_data = bytes(
                    message[successfully_sent_fragments * int(fragment_size):(successfully_sent_fragments * int(
                        fragment_size)) + int(fragment_size)], 'utf-8')

            else:
                fragment_data = bytes(
                    byte_array[successfully_sent_fragments * int(fragment_size):(successfully_sent_fragments * int(
                        fragment_size)) + int(fragment_size)])

            temp = header + fragment_data

            if defected:
                crc = crc16(temp) + 1
                defected = False
            else:
                crc = crc16(temp)

            fragment_to_send = header + crc.to_bytes(2, 'big') + fragment_data
            sent_decoded_fragment = decode_data(fragment_to_send)

            # sending the packet
            try:
                sock.sendto(fragment_to_send, (server_ip, int(server_port)))
                if SHOW_EACH_FRAGMENT_INFO:
                    print("[ ] Packet c. %d | %d byteov bol odoslany" % (
                        sent_decoded_fragment['sequence_number'], sent_decoded_fragment['fragment_size']))
                    print(sent_decoded_fragment, "\n")
            except socket.error as e:
                quit("[x] Packet c. %d | %d byteov nebol odoslany\n" % (
                    sent_decoded_fragment['sequence_number'], sent_decoded_fragment['fragment_size']) + str(e))

            # waiting for the response (ACK or NACK)
            try:
                response_to_fragment, addr = sock.recvfrom(32767)
            except socket.error as e:
                quit("[x] ACK pre Packet c. %d NEBOL prijaty\n" % (sent_decoded_fragment['sequence_number']) + str(e))

            decoded_response_to_fragment = decode_data(response_to_fragment)

            # response to the sent fragment was ACK
            if decoded_response_to_fragment['sequence_number'] == sent_decoded_fragment['sequence_number'] \
                    and decoded_response_to_fragment['fragment_count'] == sent_decoded_fragment['fragment_count'] \
                    and decoded_response_to_fragment['fragment_size'] == sent_decoded_fragment['fragment_size'] \
                    and decoded_response_to_fragment['packet_type'] == ACK:
                if SHOW_EACH_FRAGMENT_INFO:
                    print("[√] ACK pre Packet c. %d bol prijaty" % (decoded_response_to_fragment['sequence_number']))
                    print(decoded_response_to_fragment, "\n")

                successfully_sent_fragments += 1

            # response to the sent fragment was NACK
            elif decoded_response_to_fragment['sequence_number'] == sent_decoded_fragment['sequence_number'] \
                    and decoded_response_to_fragment['fragment_count'] == sent_decoded_fragment['fragment_count'] \
                    and decoded_response_to_fragment['fragment_size'] == sent_decoded_fragment['fragment_size'] \
                    and decoded_response_to_fragment['packet_type'] == NACK:
                if SHOW_EACH_FRAGMENT_INFO:
                    print("[!] NACK pre Packet c. %d bol prijaty" % (decoded_response_to_fragment['sequence_number']))
                    print(decoded_response_to_fragment, "\n")

            if successfully_sent_fragments == int(fragment_count):
                if file_name == "<text>":
                    print("\n[√] Sprava '%s' bola uspesne odoslana\n" % message)

                else:
                    print("\n[√] Subor '%s' bol uspesne odoslany\n" % file_name)

    else:
        quit("Chyba pri overeni\n")

    return 1


if __name__ == '__main__':

    while True:
        choice = input("Zvolte z nasledujucich moznosti:\n"
                       "[1] - Server\n"
                       "[2] - Klient\n")

        if int(choice) == 1:
            set_up_server()
        elif int(choice) == 2:
            set_up_client()
