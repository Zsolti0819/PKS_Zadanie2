import os
import socket

INIT = 0
ACK = 1
DAT = 2
RERQ = 3
DEBUG_MODE = True


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


def calculate_data_length(buffer, file_size, fragment_size):
    if int(fragment_size) * (buffer + 1) < file_size:
        data_length = fragment_size
    else:
        data_length = int(fragment_size) - ((int(fragment_size) * (buffer + 1)) - file_size)
    return data_length


def create_directory():
    directory = input("[2] Zadajte meno priecinku, kam chcete ulozit subory\n")
    parent_directory = "C:\\Users\\destr\\PycharmProjects\\PKS_Zadanie2"
    path = os.path.join(parent_directory, directory)
    mode = 0o777
    try:
        os.makedirs(name=path, mode=mode, exist_ok=True)
    except OSError as e:
        quit("Nie je mozne vytvorit priecinok" + str(e))
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
    print(">>> SERVER <<<\n")
    port = input("[1] Zadajte cislo portu servera:\n")

    # creating the socket
    sock = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)

    # bind IP address
    sock.bind(("127.0.0.1", int(port)))

    create_directory()
    decoded_data = ""
    addr = ""

    print("[√] >>> Server caka na prijimanie udajov <<<\n")
    while True:

        # receiving the initial message
        try:
            data, addr = sock.recvfrom(2048)
            decoded_data = decode_data(data)
        except socket.error as e:
            quit("[x] Inicializacna sprava NEBOLA prijata od klienta" + str(e))

        type_of_message = str(decoded_data['data'], 'utf-8')
        fragment_count = decoded_data['fragment_count']

        # sending ACK for the initial message
        if decoded_data['packet_type'] == INIT:
            print("[ ] Inicializacna sprava bola prijata od klienta")
            if DEBUG_MODE:
                print("received:", decoded_data)

            ack_header = create_header(decoded_data['sequence_number'], decoded_data['fragment_count'], decoded_data['fragment_size'], ACK)
            ack_header_and_data = ack_header + decoded_data['data']
            crc = crc16(ack_header_and_data)
            ack_message = crc.to_bytes(2, 'big') + ack_header_and_data

            try:
                sock.sendto(ack_message, (addr[0], addr[1]))
                print("[√] ACK bol odoslany pre inicializacnu spravu klientovi")
            except socket.error as e:
                quit("[x] ACK NEBOL odoslany pre inicializacnu spravu klientovi" + str(e))

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
                            quit("[x] ACK pre Packet c. %d NEBOL odoslany" % (decoded_data['sequence_number']) + str(
                                e))

                    # crc is NOT correct
                    elif decoded_data['crc'] != crc16(data[2:]):
                        successfully_received_fragments -= 1
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
                            print("[√] RERQ pre Packet c. %d bol odoslany !!! CHYBA PRI CRC !!! " % (decoded_data['sequence_number']))
                        except socket.error as e:
                            quit(
                                "[x] RERQ pre Packet c. %d NEBOL odoslany !!! CHYBA PRI CRC !!! " % (
                                            successfully_received_fragments + 1) + str(e))

            except socket.error as e:
                quit("[x] Packet c. %d byteov NEBOL prijaty." % (decoded_data['sequence_number']) + str(e))

            if type_of_message == "text":
                print(str(decoded_data['data'], 'utf-8'))

            elif type_of_message == "file":
                print("FILE, TO DO")



def client():
    print(">>> KLIENT <<<\n")
    ip = input("[1] Zadajte IP adresu servera:\n")
    port = input("[2] Zadajte cislo portu servera:\n")
    fragment_size = input("[3] Zadajte velkost fragmentov:\n")

    while int(fragment_size) < 1 or int(fragment_size) > 1456:
        fragment_size = input("[!] Zadali ste neplatnu velkost. "
                              "Velkost fragmentu musi byt vacsie ako 0. "
                              "Zadajte velkost fragmentov este raz:\n")

    file_size = 0
    file_name = ""
    response_to_fragment = ""
    message = ""
    packet_type = ""
    defected = ""

    while True:
        action = input("Zvolte z moznosti:\n"
                       "[0] - Ukoncit spojenie\n"
                       "[1] - Poslat textovu spravu\n"
                       "[2] - Simulacia chyby v textovej sprave\n"
                       "[3] - Poslat subor\n"
                       "[4] - Simulacia chyby pri poslani suboru\n")

        sock = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)

        if int(action) == 0:
            file_size = 0
            file_name = "DISCONNECT"
            defected = False
            packet_type = 4

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
        fragment_to_send = crc.to_bytes(2, 'big') + packet_and_data

        # sending the initial message to the server
        try:
            sock.sendto(fragment_to_send, (ip, int(port)))
            print("[ ] Inicializacna sprava bola odoslana serverovi")
        except socket.error as e:
            quit("[x] Inicializacna sprava nebola odoslana serverovi" + str(e))

        # waiting for the ACK
        try:
            response_to_fragment, addr = sock.recvfrom(2048)
        except socket.error as e:
            quit("[x] ACK nebol prijaty pre informacnu spravu od servera" + str(e))

        # comparing file_name with inf_ack
        sent_data = decode_data(fragment_to_send)
        received_data = decode_data(response_to_fragment)
        if received_data['sequence_number'] == sent_data['sequence_number'] \
                and received_data['fragment_count'] == sent_data['fragment_count'] \
                and received_data['fragment_size'] == sent_data['fragment_size'] \
                and received_data['data'] == sent_data['data'] \
                and received_data['packet_type'] == ACK:

            if DEBUG_MODE:
                print("sent:", sent_data)
                print("received:", received_data)

            buffer = 0
            while buffer < int(fragment_count):

                data_length = calculate_data_length(buffer, file_size, fragment_size)

                header = create_header(buffer + 1, int(fragment_count), int(data_length), packet_type)
                fragment_data = bytes(message[buffer * int(fragment_size):(buffer * int(fragment_size)) + int(fragment_size)], 'utf-8')
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
                    sock.sendto(fragment_to_send, (ip, int(port)))
                    print("[ ] Packet c. %d | %d byteov bol odoslany" % (sent_decoded_fragment['sequence_number'], sent_decoded_fragment['fragment_size']))
                except socket.error as e:
                    quit("[x] Packet c. %d | %d byteov nebol odoslany" % (sent_decoded_fragment['sequence_number'], sent_decoded_fragment['fragment_size']) + str(e))

                # waiting for the response (ACK or RERQ)
                try:
                    response_to_fragment, addr = sock.recvfrom(1024)
                except socket.error as e:
                    quit("[x] ACK pre Packet c. %d NEBOL prijaty" % (sent_decoded_fragment['sequence_number']) + str(e))

                decoded_response_to_fragment = decode_data(response_to_fragment)
                if decoded_response_to_fragment['sequence_number'] == sent_decoded_fragment['sequence_number'] \
                        and decoded_response_to_fragment['fragment_count'] == sent_decoded_fragment['fragment_count'] \
                        and decoded_response_to_fragment['fragment_size'] == sent_decoded_fragment['fragment_size'] \
                        and decoded_response_to_fragment['data'] == sent_decoded_fragment['data'] \
                        and decoded_response_to_fragment['packet_type'] == ACK:
                    print("[√] ACK pre Packet c. %d bol prijaty" % (decoded_response_to_fragment['sequence_number']))
                    if DEBUG_MODE:
                        print("sent:", sent_decoded_fragment)
                        print("received:", decoded_response_to_fragment)

                    buffer += 1

                elif decoded_response_to_fragment['sequence_number'] == sent_decoded_fragment['sequence_number'] \
                        and decoded_response_to_fragment['fragment_count'] == sent_decoded_fragment['fragment_count'] \
                        and decoded_response_to_fragment['fragment_size'] == sent_decoded_fragment['fragment_size'] \
                        and decoded_response_to_fragment['data'] == sent_decoded_fragment['data'] \
                        and decoded_response_to_fragment['packet_type'] == RERQ:
                    print("[!] RERQ pre Packet c. %d bol prijaty" % (decoded_response_to_fragment['sequence_number']))
                    if DEBUG_MODE:
                        print("sent:", sent_decoded_fragment)
                        print("received:", decoded_response_to_fragment)



        else:
            quit("Chyba pri overeni")


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
