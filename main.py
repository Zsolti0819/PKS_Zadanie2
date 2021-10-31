import socket
import os

INIT = 0
ACK = 1
DAT = 2
DEBUG_MODE = False


def create_header(sequence_number, fragment_count, fragment_size, packet_type):
    sn = sequence_number.to_bytes(3, 'big')
    fc = fragment_count.to_bytes(3, 'big')
    fs = fragment_size.to_bytes(2, 'big')
    pt = packet_type.to_bytes(1, 'big')
    return sn + fc + fs + pt


def calculate_fragment_count(file_size, fragment_size):
    fragment_count = 1
    if int(file_size) > int(fragment_size):
        fragment_count = int(file_size) / int(fragment_size)
        if int(file_size) % int(fragment_size) != 0:
            fragment_count += 1

    return fragment_count


def create_directory():
    directory = input("[2] Zadajte meno priecinku, kam chcete ulozit subory\n")
    parent_directory = "C:\\Users\\destr\\PycharmProjects\\PKS_Zadanie2"
    path = os.path.join(parent_directory, directory)
    mode = 0o777
    try:
        os.makedirs(name=path, mode=mode, exist_ok=True)
    except OSError as e:
        quit("Nie je mozne vytvorit priecinok\n" + str(e))
    print("Subory budu ulozene v adresary %s\n" % path)


def decode_data(data):
    parsed_data = {'crc': int.from_bytes(data[0:2], 'big'),
                   'sequence_number': int.from_bytes(data[2:5], 'big'),
                   'fragment_count': int.from_bytes(data[5:8], 'big'),
                   'fragment_size': int.from_bytes(data[8:10], 'big'),
                   'packet_type': int.from_bytes(data[10:11], 'big'),
                   'data': data[11:]}
    return parsed_data


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


def server():
    print("-------------------------------------------------------------\n")
    print(">>> SERVER <<<\n")
    print("-------------------------------------------------------------\n")

    port = input("[1] Zadajte cislo portu servera:\n")
    print("-------------------------------------------------------------\n")

    # creating the socket
    sock = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)

    # bind any IP address
    sock.bind(("127.0.0.1", int(port)))

    create_directory()

    data = ""
    parsed_data = ""
    addr = ""
    type_of_message = ""
    fragment_count = 0

    print("[√] >>> Server caka na prijimanie udajov <<<\n")
    while True:

        # receiving the informational message
        try:
            data, addr = sock.recvfrom(1024)
            print("[ ] Informacna sprava bola prijata od klienta\n")
            parsed_data = decode_data(data)
            if DEBUG_MODE:
                print(parsed_data)
        except socket.error as e:
            quit("[x] Informacna sprava NEBOLA prijata od klienta\n" + str(e))

        type_of_message = str(parsed_data['data'], 'utf-8')
        fragment_count = parsed_data['fragment_count']
        crc = parsed_data['crc']

        # sending ACK for the informational message
        if parsed_data['packet_type'] == INIT:

            ack_packet = create_header(parsed_data['sequence_number'] + 1, 0, 0, ACK)
            ack_packet_and_data = ack_packet + parsed_data['data']
            crc = crc16(ack_packet_and_data)
            ack_message = crc.to_bytes(2, 'big') + ack_packet_and_data
            try:
                sock.sendto(ack_message, (addr[0], addr[1]))
                print("[√] ACK bol odoslany pre informacnu spravu klientovi\n")
            except socket.error as e:
                quit("[x] ACK NEBOL odoslany pre informacnu spravu klientovi\n" + str(e))

            buffer = 0
            while buffer < fragment_count:
                try:
                    data, addr = sock.recvfrom(1024)
                    parsed_data = decode_data(data)
                    print("[ ] Packet c. %d | %lu byteov bol prijaty\n" % ((buffer + 1), parsed_data['fragment_size']))
                    if DEBUG_MODE:
                        print(parsed_data)
                except socket.error as e:
                    quit("[x] Packet c. %d byteov NEBOL prijaty.\n" % (buffer + 1) + str(e))

                if parsed_data['crc'] != crc16(data[2:]):
                    buffer -= 1
                    print("[x] >>> CHYBA PRI CRC KONTROLE <<<\n")
                    print("-------------------------------------------------------------\n")
                    try:
                        sock.sendto(ack_message, (addr[0], addr[1]))
                        print("[√] ACK pre Packet c. %d bol odoslany !!! CHYBA PRI CRC !!! \n" % (buffer + 1))
                    except socket.error as e:
                        quit("[x] ACK pre Packet c. %d NEBOL odoslany !!! CHYBA PRI CRC !!! \n" % (buffer + 1) + str(e))

                elif parsed_data['crc'] == crc16(data[2:]):
                    try:
                        sock.sendto(ack_message, (addr[0], addr[1]))
                        print("[√] ACK pre Packet c. %d bol odoslany\n" % (buffer + 1))
                        buffer += 1
                    except socket.error as e:
                        quit("[x] ACK pre Packet c. %d NEBOL odoslany\n" % (buffer + 1) + str(e))


def client():
    print("-------------------------------------------------------------\n")
    print(">>> KLIENT <<<\n")
    print("-------------------------------------------------------------\n")
    ip = input("[1] Zadajte IP adresu servera:\n")
    print("-------------------------------------------------------------\n")
    port = input("[2] Zadajte cislo portu servera:\n")
    print("-------------------------------------------------------------\n")
    fragment_size = input("[3] Zadajte velkost fragmentov:\n")
    print("-------------------------------------------------------------\n")

    while int(fragment_size) < 1 or int(fragment_size) > 1456:
        fragment_size = input("[!] Zadali ste neplatnu velkost. "
                              "Velkost fragmentu musi byt vacsie ako 0. "
                              "Zadajte velkost fragmentov este raz:\n")
        print("-------------------------------------------------------------\n")

    file_size = 0
    file_name = ""
    init_ack = ""
    message = ""
    packet_type = ""

    while True:
        action = input("Zvolte z moznosti:\n"
                       "[0] - Ukoncit spojenie\n"
                       "[1] - Poslat textovu spravu\n"
                       "[2] - Simulacia chyby v textovej sprave\n"
                       "[3] - Poslat subor\n"
                       "[4] - Simulacia chyby pri poslani suboru\n")
        print("-------------------------------------------------------------\n")

        sock = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)

        if int(action) == 0:
            file_size = 0
            file_name = "DISCONNECT"
            defected = False
            packet_type = 4
            print("-------------------------------------------------------------\n")

        elif int(action) == 1 or int(action) == 2:
            message = input()
            file_size = len(message)
            # print(file_size)
            file_name = "text"
            if int(action) == 1:
                defected = False
            elif int(action) == 2:
                defected = True
            packet_type = DAT

        fragment_count = calculate_fragment_count(file_size, fragment_size)
        header = create_header(file_size, int(fragment_count), int(fragment_size), INIT)
        packet_and_data = header + file_name.encode(encoding='utf-8')
        crc = crc16(packet_and_data)
        message_to_send = crc.to_bytes(2, 'big') + packet_and_data

        # sending the informational message to the server
        try:
            sock.sendto(message_to_send, (ip, int(port)))
            print("[ ] Informacna sprava bola odoslana serverovi\n")
        except socket.error as e:
            quit("[x] Informacna sprava nebola odoslana serverovi\n" + str(e))

        # waiting for the ACK
        try:
            init_ack, addr = sock.recvfrom(1024)
            print("[√] ACK bol prijaty pre informacnu spravu od servera\n")
        except socket.error as e:
            quit("[x] ACK nebol prijaty pre informacnu spravu od servera\n" + str(e))

        # comparing file_name with inf_ack
        received_data = decode_data(init_ack)
        if file_name == str(received_data['data'], 'utf-8'):

            buffer = 0
            while buffer < int(fragment_count):
                if int(fragment_size) * (buffer + 1) < file_size:
                    data_length = fragment_size
                else:
                    data_length = int(fragment_size) - ((int(fragment_size) * (buffer + 1)) - file_size)

                header = create_header(buffer + 1, int(fragment_count), int(data_length), packet_type)
                fragment_data = bytes(
                    message[buffer * int(fragment_size):(buffer * int(fragment_size)) + int(fragment_size)],
                    'utf-8')
                header_and_fragment_data = header + fragment_data
                crc = crc16(header_and_fragment_data)
                message_to_send = crc.to_bytes(2, 'big') + header_and_fragment_data

                # sending the packet
                try:
                    sock.sendto(message_to_send, (ip, int(port)))
                    print("[ ] Packet c. %d | %d byteov bol odoslany\n" % ((buffer + 1), int(data_length)))
                except socket.error as e:
                    quit("[x] Packet c. %d | %d byteov nebol odoslany\n" % ((buffer + 1), int(data_length)) + str(e))

                # waiting for the ACK
                try:
                    init_ack, addr = sock.recvfrom(1024)
                    print("[√] ACK pre Packet c. %d bol prijaty\n" % (buffer + 1))
                    buffer += 1
                except socket.error as e:
                    quit("[x] ACK pre Packet c. %d NEBOL prijaty\n" % (buffer + 1) + str(e))



        else:
            quit("Chyba pri overeni\n")


if __name__ == '__main__':

    choice = input("Zvolte z nasledujucich moznosti:\n"
                   "[0] - Koniec aplikacie\n"
                   "[1] - Server\n"
                   "[2] - Klient\n")

    if int(choice) == 1:
        server()
    elif int(choice) == 2:
        client()
    else:
        quit()
