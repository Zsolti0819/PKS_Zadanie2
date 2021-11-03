import os
import socket
import heapq

INIT = 0
ACK = 1
DAT = 2
RERQ = 3
DEBUG_MODE = False


def create_header(sequence_number, fragment_count, fragment_size, packet_type):
    sn = sequence_number.to_bytes(3, 'big')
    fc = fragment_count.to_bytes(3, 'big')
    fs = fragment_size.to_bytes(2, 'big')
    pt = packet_type.to_bytes(1, 'big')
    return sn + fc + fs + pt


def crc16(data: bytes):
    '''
    CRC-16-CCITT Algorithm
    '''
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
    parsed_data = {'crc': int.from_bytes(data[0:2], 'big'),
                   'sequence_number': int.from_bytes(data[2:5], 'big'),
                   'fragment_count': int.from_bytes(data[5:8], 'big'),
                   'fragment_size': int.from_bytes(data[8:10], 'big'),
                   'packet_type': int.from_bytes(data[10:11], 'big'),
                   'data': data[11:]}
    return parsed_data


def set_up_fragment_size():
    fragment_size = input("Zadajte velkost fragmentov:\n")
    while int(fragment_size) < 1 or int(fragment_size) > 1013:
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

    print("[√] >>> Server caka na prijimanie udajov <<<\n")

    # receiving the initial message
    try:
        data, addr = sock.recvfrom(2048)
        decoded_data = decode_data(data)
    except socket.error as e:
        quit("[x] Inicializacna sprava NEBOLA prijata od klienta\n" + str(e))

    type_of_message = str(decoded_data['data'], 'utf-8')
    fragment_count = decoded_data['fragment_count']

    # sending ACK for the initial message
    if decoded_data['packet_type'] == INIT:
        print("[ ] Inicializacna sprava bola prijata od klienta")
        if DEBUG_MODE:
            print("received:", decoded_data)

        ack_header = create_header(decoded_data['sequence_number'], decoded_data['fragment_count'],
                                   decoded_data['fragment_size'], ACK)
        ack_header_and_data = ack_header + decoded_data['data']
        crc = crc16(ack_header_and_data)
        ack_message = crc.to_bytes(2, 'big') + ack_header_and_data

        try:
            sock.sendto(ack_message, (addr[0], addr[1]))
            print("[√] ACK bol odoslany pre inicializacnu spravu klientovi")
        except socket.error as e:
            quit("[x] ACK NEBOL odoslany pre inicializacnu spravu klientovi\n" + str(e))

    successfully_received_fragments = 0
    while successfully_received_fragments < fragment_count:
        try:
            data, addr = sock.recvfrom(2048)
            decoded_data = decode_data(data)
            if decoded_data['packet_type'] == DAT:

                # crc is correct
                if decoded_data['crc'] == crc16(data[2:]):

                    print("[ ] Packet c. %d | %lu byteov bol prijaty" % (
                        decoded_data['sequence_number'], decoded_data['fragment_size']))

                    heapq.heappush(received_message, (decoded_data['sequence_number'], decoded_data['data']))

                    if type_of_message == "<text>":
                        final_message += heapq.heappop(received_message)[1].decode('utf-8')
                    # else:
                    #     with open(os.path.join(path, type_of_message), 'wb') as fp:
                    #         fp.write(heapq.heappop(received_message)[1])

                    if DEBUG_MODE:
                        print("received:", decoded_data)

                    # sending ACK for the fragment
                    ack_header = create_header(decoded_data['sequence_number'], decoded_data['fragment_count'],
                                               decoded_data['fragment_size'], ACK)
                    ack_header_and_data = ack_header + decoded_data['data']
                    crc = crc16(ack_header_and_data)
                    ack_message = crc.to_bytes(2, 'big') + ack_header_and_data

                    try:
                        sock.sendto(ack_message, (addr[0], addr[1]))
                        print("[√] ACK pre Packet c. %d bol odoslany" % (decoded_data['sequence_number']))
                        successfully_received_fragments += 1
                    except socket.error as e:
                        quit("[x] ACK pre Packet c. %d NEBOL odoslany\n" % (decoded_data['sequence_number']) + str(
                            e))

                # crc is NOT correct
                elif decoded_data['crc'] != crc16(data[2:]):
                    print("[!] Packet c. %d | %lu byteov bol prijaty >>> CHYBA PRI CRC KONTROLE <<<" % (
                        (decoded_data['sequence_number']), decoded_data['fragment_size']))

                    # sending RERQ for the fragment
                    rerq_header = create_header(decoded_data['sequence_number'], decoded_data['fragment_count'],
                                                decoded_data['fragment_size'], RERQ)
                    rerq_header_and_data = rerq_header + decoded_data['data']
                    crc = crc16(rerq_header_and_data)
                    rerq_message = crc.to_bytes(2, 'big') + rerq_header_and_data
                    try:
                        sock.sendto(rerq_message, (addr[0], addr[1]))
                        print("[√] RERQ pre Packet c. %d bol odoslany" % (
                            decoded_data['sequence_number']))
                    except socket.error as e:
                        quit(
                            "[x] RERQ pre Packet c. %d NEBOL odoslany\n" % (
                                decoded_data['sequence_number']) + str(e))

        except socket.error as e:
            quit("[x] Packet c. %d byteov NEBOL prijaty.\n" % (decoded_data['sequence_number']) + str(e))

    if type_of_message == "<text>":
        print("\n[i] Prijata sprava od %s: %s\n" % (addr[0], final_message))

    else:
        print("\n[i] Prijaty subor od %s: %s bol ulozeny pod adresarom %s\n" % (addr[0], type_of_message, path))
        with open(os.path.join(path, type_of_message), 'wb') as file:
            while received_message:
                file.write(heapq.heappop(received_message)[1])


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
    header = create_header(file_size, int(fragment_count), int(fragment_size), INIT)
    packet_and_data = header + file_name.encode(encoding='utf-8')
    crc = crc16(packet_and_data)
    fragment_to_send = crc.to_bytes(2, 'big') + packet_and_data

    # sending the initial message to the server
    try:
        sock.sendto(fragment_to_send, (server_ip, int(server_port)))
        print("[ ] Inicializacna sprava bola odoslana serverovi")
    except socket.error as e:
        quit("[x] Inicializacna sprava nebola odoslana serverovi\n" + str(e))

    # waiting for the ACK
    try:
        response_to_fragment, addr = sock.recvfrom(2048)
    except socket.error as e:
        quit("[x] ACK nebol prijaty pre inicializacnu spravu od servera\n" + str(e))

    sent_packet = decode_data(fragment_to_send)
    received_packet = decode_data(response_to_fragment)

    # comparing sent packet with received packet
    if received_packet['sequence_number'] == sent_packet['sequence_number'] \
            and received_packet['fragment_count'] == sent_packet['fragment_count'] \
            and received_packet['fragment_size'] == sent_packet['fragment_size'] \
            and received_packet['data'] == sent_packet['data'] \
            and received_packet['packet_type'] == ACK:

        print("[√] ACK bol prijaty pre inicializacnu spravu od servera")

        if DEBUG_MODE:
            print("sent:", sent_packet)
            print("received:", received_packet)

        successfully_sent_fragments = 0
        while successfully_sent_fragments < int(fragment_count):

            data_length = calculate_data_length(successfully_sent_fragments, file_size, fragment_size)

            header = create_header(successfully_sent_fragments + 1, int(fragment_count), int(data_length), packet_type)

            if file_name == "<text>":
                fragment_data = bytes(
                    message[successfully_sent_fragments * int(fragment_size):(successfully_sent_fragments * int(fragment_size)) + int(fragment_size)], 'utf-8')

            else:
                fragment_data = bytes(
                    byte_array[successfully_sent_fragments * int(fragment_size):(successfully_sent_fragments * int(fragment_size)) + int(fragment_size)])

            header_and_fragment_data = header + fragment_data

            if defected:
                crc = crc16(header_and_fragment_data) + 1
                defected = False
            else:
                crc = crc16(header_and_fragment_data)

            fragment_to_send = crc.to_bytes(2, 'big') + header_and_fragment_data
            sent_decoded_fragment = decode_data(fragment_to_send)

            # sending the packet
            try:
                sock.sendto(fragment_to_send, (server_ip, int(server_port)))
                print("[ ] Packet c. %d | %d byteov bol odoslany" % (
                    sent_decoded_fragment['sequence_number'], sent_decoded_fragment['fragment_size']))
            except socket.error as e:
                quit("[x] Packet c. %d | %d byteov nebol odoslany\n" % (
                    sent_decoded_fragment['sequence_number'], sent_decoded_fragment['fragment_size']) + str(e))

            # waiting for the response (ACK or RERQ)
            try:
                response_to_fragment, addr = sock.recvfrom(1024)
            except socket.error as e:
                quit("[x] ACK pre Packet c. %d NEBOL prijaty\n" % (sent_decoded_fragment['sequence_number']) + str(e))

            decoded_response_to_fragment = decode_data(response_to_fragment)

            # response to the sent fragment was ACK
            if decoded_response_to_fragment['sequence_number'] == sent_decoded_fragment['sequence_number'] \
                    and decoded_response_to_fragment['fragment_count'] == sent_decoded_fragment['fragment_count'] \
                    and decoded_response_to_fragment['fragment_size'] == sent_decoded_fragment['fragment_size'] \
                    and decoded_response_to_fragment['data'] == sent_decoded_fragment['data'] \
                    and decoded_response_to_fragment['packet_type'] == ACK:
                print("[√] ACK pre Packet c. %d bol prijaty" % (decoded_response_to_fragment['sequence_number']))
                if DEBUG_MODE:
                    print("sent:", sent_decoded_fragment)
                    print("received:", decoded_response_to_fragment)

                successfully_sent_fragments += 1

            # response to the sent fragment was RERQ
            elif decoded_response_to_fragment['sequence_number'] == sent_decoded_fragment['sequence_number'] \
                    and decoded_response_to_fragment['fragment_count'] == sent_decoded_fragment['fragment_count'] \
                    and decoded_response_to_fragment['fragment_size'] == sent_decoded_fragment['fragment_size'] \
                    and decoded_response_to_fragment['data'] == sent_decoded_fragment['data'] \
                    and decoded_response_to_fragment['packet_type'] == RERQ:
                print("[!] RERQ pre Packet c. %d bol prijaty" % (decoded_response_to_fragment['sequence_number']))
                if DEBUG_MODE:
                    print("sent:", sent_decoded_fragment)
                    print("received:", decoded_response_to_fragment)

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
