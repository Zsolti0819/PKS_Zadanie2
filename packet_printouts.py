from main import DEBUG_MODE, SHOW_EACH_FRAGMENT, SHOW_ALL_ATTRIBUTES, CUSTOM_HEADER_SIZE_IN_BYTES, INF, ACK, NACK, DAT, KPA, FIN


# SERVER


def print_server_expects(fragment_count, received_data):
    print("The next %d are containing the file name. Together  %d packets will be received after the information message. The message is fragmented by %d bytes." % (received_data['sequence_number'], fragment_count, received_data['fragment_size']))


def print_server_inf_recv_success(received_data):
    if SHOW_EACH_FRAGMENT:
        print("[ ] The information message was received from the client")
    if SHOW_ALL_ATTRIBUTES:
        print("RECV:", packet_format(received_data))


def print_server_packet_recv_fail(e):
    if DEBUG_MODE:
        print("[x] No packets were received from the client.\n" + str(e))


def print_server_inf_ack_send_success(inf_ack_packet_decoded):
    if SHOW_EACH_FRAGMENT:
        print("[√] ACK has been sent to the client for the information message")
    if SHOW_ALL_ATTRIBUTES:
        print("SENT:", packet_format(inf_ack_packet_decoded))


def print_server_inf_ack_send_fail(e):
    if DEBUG_MODE:
        print("[x] Failed to send ACK to the client for the information message.\n" + str(e))
    else:
        print("[x] Failed to send ACK to the client for the information message.")


def print_server_dat_recv_success(received_fragment):
    if SHOW_EACH_FRAGMENT:
        print("[ ] Packet no. %d (%d bytes) was received" % (
            received_fragment['sequence_number'], received_fragment['fragment_size'] + CUSTOM_HEADER_SIZE_IN_BYTES))
    if SHOW_ALL_ATTRIBUTES:
        print("RECV:", packet_format(received_fragment))


def print_server_dat_recv_fail(buffer, e):
    if DEBUG_MODE:
        print("[x] Packet no. %d was NOT received\n" % int(buffer + 1), str(e))
    else:
        print("[x] Packet no. %d was NOT received" % int(buffer + 1))


def print_server_dat_recv_success_crc_error(received_fragment):
    if SHOW_EACH_FRAGMENT:
        print("[!] Packet no. %d (%d bytes) was received >>> INVALID CRC <<<" % (
            (received_fragment['sequence_number']), received_fragment['fragment_size'] + CUSTOM_HEADER_SIZE_IN_BYTES))
    if SHOW_ALL_ATTRIBUTES:
        print("RECV:", packet_format(received_fragment))


def print_server_dat_ack_send_success(packet_decoded):
    if SHOW_EACH_FRAGMENT:
        print("[√] ACK for Packet no. %d has been sent" % (packet_decoded['sequence_number']))
    if SHOW_ALL_ATTRIBUTES:
        print("SENT:", packet_format(packet_decoded))


def print_server_dat_ack_send_fail(e, packet_decoded):
    if DEBUG_MODE:
        print("[x] Failed to send ACK for Packet no. %d " % (packet_decoded['sequence_number']) + str(e))
    else:
        print("[x] Failed to send ACK for Packet no. %d " % (packet_decoded['sequence_number']))


def print_server_dat_nack_send_success(packet_decoded):
    if SHOW_EACH_FRAGMENT:
        print("[√] NACK for Packet no. %d has been sent" % (
            packet_decoded['sequence_number']))
    if SHOW_ALL_ATTRIBUTES:
        print("SENT:", packet_format(packet_decoded))


def print_server_dat_nack_send_fail(e, packet_encoded):
    if DEBUG_MODE:
        print("[x] Failed to send NACK for Packet no. %d " % (
            packet_encoded['sequence_number']) + str(e))
    else:
        print("[x] Failed to send NACK for Packet no. %d " % (
            packet_encoded['sequence_number']))


def print_server_kpa_recv_success(received_data):
    if SHOW_EACH_FRAGMENT:
        print("[ ] Keep Alive message was received")
    if SHOW_ALL_ATTRIBUTES:
        print("RECV:", packet_format(received_data))

def print_server_fin_recv_success(received_data):
    if SHOW_EACH_FRAGMENT:
        print("[ ] Fin message was received")
    if SHOW_ALL_ATTRIBUTES:
        print("RECV:", packet_format(received_data))


def print_server_timeout():
    print("[x] No packets were received from the client. The connection timed out.")


def print_server_kpa_ack_send_success(packet_decoded):
    if SHOW_EACH_FRAGMENT:
        print("[√] ACK has been sent for the Keep Alive message")
    if SHOW_ALL_ATTRIBUTES:
        print("SENT:", packet_format(packet_decoded))


def print_server_kpa_fin_send_success(packet_decoded):
    if SHOW_EACH_FRAGMENT:
        print("[√] FIN has been sent for the Keep Alive message")
    if SHOW_ALL_ATTRIBUTES:
        print("SENT:", packet_format(packet_decoded))


def print_server_kpa_response_send_fail(e):
    if DEBUG_MODE:
        print("[x] Failed to send response for the Keep Alive message.\n" + str(e))
    else:
        print("[x] Failed to send response for the Keep Alive message.")


# CLIENT


def print_client_inf_send_success(packet_decoded):
    if SHOW_EACH_FRAGMENT:
        print("[ ] The information message has been sent to the server")
    if SHOW_ALL_ATTRIBUTES:
        print("SENT:", packet_format(packet_decoded))


def print_client_inf_send_fail(e):
    if DEBUG_MODE:
        print("[x] The information message was NOT sent to the server\n" + str(e))
    else:
        print("[x] The information message was NOT sent to the server")


def print_client_inf_ack_recv_success(packet_decoded_recv):
    if SHOW_EACH_FRAGMENT:
        print("[√] ACK was received for the information message from the server")
    if SHOW_ALL_ATTRIBUTES:
        print("RECV:", packet_format(packet_decoded_recv))


def print_client_inf_response_recv_fail(e):
    if DEBUG_MODE:
        print("[x] Response was not received for the information message from the server\n" + str(e))
    else:
        print("[x] Response was not received for the information message from the server")


def print_client_dat_send_success(packet_decoded):
    if SHOW_EACH_FRAGMENT:
        print("[ ] Packet no. %d (%d bytes) has been sent" % (
            packet_decoded['sequence_number'],
            packet_decoded['fragment_size'] + CUSTOM_HEADER_SIZE_IN_BYTES))
    if SHOW_ALL_ATTRIBUTES:
        print("SENT:", packet_format(packet_decoded))


def print_client_dat_send_fail(e, packet_decoded):
    if DEBUG_MODE:
        print("[x] Failed to send Packet no. %d (%d bytes)\n" % (
            packet_decoded['sequence_number'],
            packet_decoded['fragment_size'] + CUSTOM_HEADER_SIZE_IN_BYTES) + str(e))
    else:
        print("[x] Failed to send Packet no. %d (%d bytes)" % (
            packet_decoded['sequence_number'],
            packet_decoded['fragment_size'] + CUSTOM_HEADER_SIZE_IN_BYTES))


def print_client_dat_ack_recv_success(packet_decoded_recv):
    if SHOW_EACH_FRAGMENT:
        print("[√] ACK for the Packet no. %d was received" % (
            packet_decoded_recv['sequence_number']))
    if SHOW_ALL_ATTRIBUTES:
        print("RECV:", packet_format(packet_decoded_recv))


def print_client_dat_nack_recv_success(packet_decoded_recv):
    if SHOW_EACH_FRAGMENT:
        print("[!] NACK for the Packet no. %d was received" % (
            packet_decoded_recv['sequence_number']))
    if SHOW_ALL_ATTRIBUTES:
        print("RECV:", packet_format(packet_decoded_recv))


def print_client_dat_response_recv_fail(buffer, e):
    if DEBUG_MODE:
        print("No response was received for the Packet %d\n" % int(buffer + 1), str(e))
    else:
        print("No response was received for the Packet %d" % int(buffer + 1))


def print_client_kpa_send_success(kpa_message_decoded):
    if SHOW_EACH_FRAGMENT:
        print("[ ] Keep Alive message has been sent")
    if SHOW_ALL_ATTRIBUTES:
        print("SENT:", packet_format(kpa_message_decoded))


def print_client_kpa_send_fail(e):
    if DEBUG_MODE:
        print("[x] Failed to send Keep alive message. Closing the socket.\n" + str(e))
    else:
        print("[x] Failed to send Keep alive message. Closing the socket.")


def print_client_kpa_ack_recv_success(decoded_data):
    if SHOW_EACH_FRAGMENT:
        print("[√] ACK was received for the Keep Alive message")
    if SHOW_ALL_ATTRIBUTES:
        print("RECV:", packet_format(decoded_data))


def print_client_kpa_fin_recv_success(decoded_data):
    if SHOW_EACH_FRAGMENT:
        print("[√] FIN was received for the Keep Alive message")
    if SHOW_ALL_ATTRIBUTES:
        print("RECV:", packet_format(decoded_data))


def print_client_kpa_response_recv_fail(e):
    if DEBUG_MODE:
        print("[x] ACK was NOT received for the Keep Alive message. Closing the socket.\n" + str(e))
    else:
        print("[x] ACK was NOT received for the Keep Alive message. Closing the socket.")


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

    packet_formatted = "Sequence Number %d | Fragment Count %d | Fragment Size %d bytes | %s | CRC %d | Data %s" % (
        packet['sequence_number'], packet['fragment_count'], packet['fragment_size'], packet_type, packet['crc'],
        packet['data'])

    return packet_formatted
