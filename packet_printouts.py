from main import DEBUG_MODE, SHOW_ATTRIBUTES, SHOW_RAW_DATA, INF, ACK, NACK, DAT, KPA, FIN


# SERVER


def print_server_expects(fragment_count, received_data):
    print(">>> The next %d are containing the file name. Together  %d packets will be received after the information message. The message is fragmented by %d bytes. <<<" % (received_data['sequence_number'], fragment_count, received_data['fragment_size']))


def print_server_inf_recv_success(received_data):
    if SHOW_ATTRIBUTES:
        print("RECEIVED: [✓]", packet_format(received_data))


def print_server_packet_recv_fail(e):
    if DEBUG_MODE:
        print("[✗] No packets were received from the client.\n" + str(e))


def print_server_inf_ack_send_success(inf_ack_packet_decoded):
    if SHOW_ATTRIBUTES:
        print("SENT    : [>]", packet_format(inf_ack_packet_decoded))


def print_server_inf_ack_send_fail(e):
    if DEBUG_MODE:
        print("[✗] Failed to send ACK to the client for the information message.\n" + str(e))
    else:
        print("[✗] Failed to send ACK to the client for the information message.")


def print_server_dat_recv_success(received_fragment):
    if SHOW_ATTRIBUTES:
        print("RECEIVED: [✓]", packet_format(received_fragment))


def print_server_dat_recv_fail(buffer, e):
    if DEBUG_MODE:
        print("[✗] Packet no. %d was NOT received\n" % int(buffer + 1), str(e))
    else:
        print("[✗] Packet no. %d was NOT received" % int(buffer + 1))


def print_server_dat_recv_success_crc_error(received_fragment):
    if SHOW_ATTRIBUTES:
        print("RECEIVED: [!]", packet_format(received_fragment))


def print_server_dat_ack_send_success(packet_decoded):
    if SHOW_ATTRIBUTES:
        print("SENT    : [>]", packet_format(packet_decoded))


def print_server_dat_ack_send_fail(e, packet_decoded):
    if DEBUG_MODE:
        print("[✗] Failed to send ACK for Packet no. %d " % (packet_decoded['sequence_number']) + str(e))
    else:
        print("[✗] Failed to send ACK for Packet no. %d " % (packet_decoded['sequence_number']))


def print_server_dat_nack_send_success(packet_decoded):
    if SHOW_ATTRIBUTES:
        print("SENT    : [>]", packet_format(packet_decoded))


def print_server_dat_nack_send_fail(e, packet_encoded):
    if DEBUG_MODE:
        print("[✗] Failed to send NACK for Packet no. %d " % (
            packet_encoded['sequence_number']) + str(e))
    else:
        print("[✗] Failed to send NACK for Packet no. %d " % (
            packet_encoded['sequence_number']))


def print_server_kpa_recv_success(received_data):
    if SHOW_ATTRIBUTES:
        print("RECEIVED: [✓]", packet_format(received_data))


def print_server_fin_recv_success(received_data):
    if SHOW_ATTRIBUTES:
        print("RECEIVED: [✓]", packet_format(received_data))


def print_server_timeout():
    print("[x] No packets were received from the client. The connection timed out.")


def print_server_kpa_ack_send_success(packet_decoded):
    if SHOW_ATTRIBUTES:
        print("SENT    : [>]", packet_format(packet_decoded))


def print_server_kpa_fin_send_success(packet_decoded):
    if SHOW_ATTRIBUTES:
        print("SENT    : [>]", packet_format(packet_decoded))


def print_server_kpa_response_send_fail(e):
    if DEBUG_MODE:
        print("[✗] Failed to send response for the Keep Alive message.\n" + str(e))
    else:
        print("[✗] Failed to send response for the Keep Alive message.")


# CLIENT


def print_client_inf_send_success(packet_decoded):
    if SHOW_ATTRIBUTES:
        print("SENT    : [>]", packet_format(packet_decoded))


def print_client_inf_send_fail(e):
    if DEBUG_MODE:
        print("[✗] The information message was NOT sent to the server\n" + str(e))
    else:
        print("[✗] The information message was NOT sent to the server")


def print_client_inf_ack_recv_success(packet_decoded_recv):
    if SHOW_ATTRIBUTES:
        print("RECEIVED: [✓]", packet_format(packet_decoded_recv))


def print_client_inf_response_recv_fail(e):
    if DEBUG_MODE:
        print("[✗] Response was not received for the information message from the server\n" + str(e))
    else:
        print("[✗] Response was not received for the information message from the server")


def print_client_dat_send_success(packet_decoded):
    if SHOW_ATTRIBUTES:
        print("SENT    : [>]", packet_format(packet_decoded))


def print_client_dat_send_fail(e, packet_decoded):
    if DEBUG_MODE:
        print("[✗] Failed to send Packet no. %d\n" % (packet_decoded['sequence_number'] + str(e)))
    else:
        print("[✗] Failed to send Packet no. %d " % (packet_decoded['sequence_number']))


def print_client_dat_ack_recv_success(packet_decoded_recv):
    if SHOW_ATTRIBUTES:
        print("RECEIVED: [✓]", packet_format(packet_decoded_recv))


def print_client_dat_nack_recv_success(packet_decoded_recv):
    if SHOW_ATTRIBUTES:
        print("RECEIVED: [!]", packet_format(packet_decoded_recv))


def print_client_dat_response_recv_fail(buffer, e):
    if DEBUG_MODE:
        print("[✗] No response was received for the Packet %d\n" % int(buffer + 1), str(e))
    else:
        print("[✗] No response was received for the Packet %d" % int(buffer + 1))


def print_client_kpa_send_success(kpa_message_decoded):
    if SHOW_ATTRIBUTES:
        print("SENT    : [>]", packet_format(kpa_message_decoded))


def print_client_kpa_send_fail(e):
    if DEBUG_MODE:
        print("[✗] Failed to send Keep alive message. Closing the socket.\n" + str(e))
    else:
        print("[✗] Failed to send Keep alive message. Closing the socket.")


def print_client_kpa_ack_recv_success(decoded_data):
    if SHOW_ATTRIBUTES:
        print("RECEIVED: [✓]", packet_format(decoded_data))


def print_client_kpa_fin_recv_success(decoded_data):
    if SHOW_ATTRIBUTES:
        print("RECEIVED: [✓]", packet_format(decoded_data))


def print_client_kpa_response_recv_fail(e):
    if DEBUG_MODE:
        print("[✗] ACK was NOT received for the Keep Alive message. Closing the socket.\n" + str(e))
    else:
        print("[✗] ACK was NOT received for the Keep Alive message. Closing the socket.")


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
