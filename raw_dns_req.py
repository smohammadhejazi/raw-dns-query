import binascii
import socket
from collections import OrderedDict


def send_udp_message(message, address, port):
    """
    Send UDP message to server,
    message should be hexadecimal
    :param message: Hex message to send
    :param address: Address to send to
    :param port: Address port to send to
    :return: Server response
    """
    message = message.replace(" ", "").replace("\n", "")
    server_address = (address, port)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.sendto(binascii.unhexlify(message), server_address)
        data, _ = s.recvfrom(4096)

    return binascii.hexlify(data).decode("utf-8")


def build_message(type="A", address="", recursion = 1):
    """
    Build dns query message with one question
    :param type: Record type
    :param address: QNAME
    :return: hex message
    """
    # HEADER SECTION
    ID = 4369  # ID = 0x1111                            (16 bit)
    QR = 0  # Query/Response                            (01 bit)
    OPCODE = 0  # Query opcode - For query only         (04 bit)
    AA = 0  # Authoritative answer - For response only  (01 bit)
    TC = 0  # Truncation                                (01 bit)
    RD = recursion  # Recursion                         (01 bit)
    RA = 0  # Recursion available - For response only   (01 bit)
    Z = 0  # Reversed                                   (03 bit)
    RCODE = 0  # Response opcode - For response only    (04 bit)

    query_params = str(QR)
    query_params += str(OPCODE).zfill(4)
    query_params += str(AA) + str(TC) + str(RD) + str(RA)
    query_params += str(Z).zfill(3)
    query_params += str(RCODE).zfill(4)

    QDCOUNT = 1  # Number of questions           4bit
    ANCOUNT = 0  # Number of resource records    4bit
    NSCOUNT = 0  # Number of authority records   4bit
    ARCOUNT = 0  # Number of additional records  4bit

    message = "{:04x}".format(ID)
    message += "{:04x}".format(int(query_params, 2))
    message += "{:04x}".format(QDCOUNT)
    message += "{:04x}".format(ANCOUNT)
    message += "{:04x}".format(NSCOUNT)
    message += "{:04x}".format(ARCOUNT)

    # QUESTION SECTION
    # QNAME
    QNAME = ""
    addr_parts = address.split(".")
    for part in addr_parts:
        addr_len = "{:02x}".format(len(part))
        addr_part = binascii.hexlify(part.encode())
        QNAME += addr_len
        QNAME += addr_part.decode()

    QNAME += "00"  # Terminating bit for QNAME
    message += QNAME

    # Request type
    QTYPE = get_type(type)
    message += QTYPE

    # Class type
    QCLASS = 1
    message += "{:04x}".format(QCLASS)

    return message


def decode_message(message):
    """
    Decode dns hex message
    :param message: Hex message
    :return: Human readable decoded dns message
    """
    # HEADER SECTION
    decoded_message = []
    servers = []
    answers = []

    ID = message[0:4]
    query_params = message[4:8]
    QDCOUNT = int(message[8:12], 16)
    ANCOUNT = int(message[12:16], 16)
    NSCOUNT = int(message[16:20], 16)
    ARCOUNT = int(message[20:24], 16)

    params = "{:b}".format(int(query_params, 16)).zfill(16)
    QPARAMS = OrderedDict([
        ("QR", params[0:1]),
        ("OPCODE", params[1:5]),
        ("AA", params[5:6]),
        ("TC", params[6:7]),
        ("RD", params[7:8]),
        ("RA", params[8:9]),
        ("Z", params[9:12]),
        ("RCODE", params[12:16])
    ])

    QUESTION_SECTION_STARTS = 24
    question_parts, _ = parse_address_parts(message, QUESTION_SECTION_STARTS)

    QNAME = ".".join(map(lambda p: binascii.unhexlify(p).decode(), question_parts))

    QTYPE_STARTS = QUESTION_SECTION_STARTS + (len("".join(question_parts))) + (len(question_parts) * 2) + 2
    QCLASS_STARTS = QTYPE_STARTS + 4

    QTYPE = message[QTYPE_STARTS:QCLASS_STARTS]
    QCLASS = message[QCLASS_STARTS:QCLASS_STARTS + 4]

    decoded_message.append("\n# HEADER")
    decoded_message.append("ID: " + ID)
    decoded_message.append("QUERYPARAMS: ")
    for qp in QPARAMS:
        decoded_message.append(" - " + qp + ": " + QPARAMS[qp])
    decoded_message.append("QDCOUNT: " + str(QDCOUNT))
    decoded_message.append("ANCOUNT: " + str(ANCOUNT))
    decoded_message.append("NSCOUNT: " + str(NSCOUNT))
    decoded_message.append("ARCOUNT: " + str(ARCOUNT))

    # QUESTION SECTION
    decoded_message.append("\n# QUESTION SECTION")
    decoded_message.append("QNAME: " + QNAME)
    decoded_message.append("QTYPE: " + QTYPE + " (\"" + get_type(int(QTYPE, 16)) + "\")")
    decoded_message.append("QCLASS: " + QCLASS)

    # ANSWER SECTION
    ANSWER_SECTION_STARTS = QCLASS_STARTS + 4

    NUM_ANSWERS = ANCOUNT + NSCOUNT + ARCOUNT
    answers_number = ANCOUNT
    if NUM_ANSWERS > 0:
        decoded_message.append("\n# ANSWER SECTION")

        for ANSWER_COUNT in range(NUM_ANSWERS):
            if ANSWER_SECTION_STARTS < len(message):
                ANAME, temp = parse_address_parts(message, ANSWER_SECTION_STARTS)
                ATYPE = message[temp:temp + 4]
                ACLASS = message[temp + 4:temp + 8]
                TTL = int(message[temp + 8:temp + 16], 16)
                RDLENGTH = int(message[temp + 16:temp + 20], 16)
                RDDATA = message[temp + 20:temp + 20 + (RDLENGTH * 2)]

                # 0001 = A Record
                # if ATYPE == "0001":
                # octets = [RDDATA[i:i + 2] for i in range(0, len(RDDATA), 2)]
                # RDDATA_decoded = ".".join(list(map(lambda x: str(int(x, 16)), octets)))
                if ATYPE == get_type("A"):
                    RDDATA_decoded = parse_ipv4(RDDATA)
                    if answers_number > 0:
                        answers_number -= 1
                        answers.append(RDDATA_decoded)
                elif ATYPE == get_type("AAAA"):
                    RDDATA_decoded = parse_ipv6(RDDATA)
                elif ATYPE == get_type("NS"):
                    RDDATA_decoded, _ = parse_address_parts(message, temp + 20)
                    RDDATA_decoded = ".".join(map(lambda p: binascii.unhexlify(p).decode(), RDDATA_decoded))
                    servers.append(RDDATA_decoded)
                else:
                    RDDATA_decoded = RDDATA

                ANSWER_SECTION_STARTS = temp + 20 + (RDLENGTH * 2)

            try:
                ATYPE
            except NameError:
                None
            else:
                decoded_message.append("# ANSWER " + str(ANSWER_COUNT + 1) + "")
                decoded_message.append("ANAME: " + ".".join(map(lambda p: binascii.unhexlify(p).decode(), ANAME)))
                decoded_message.append("ATYPE: " + ATYPE + " (\"" + get_type(int(ATYPE, 16)) + "\")")
                decoded_message.append("ACLASS: " + ACLASS)
                decoded_message.append("TTL: " + str(TTL))
                decoded_message.append("RDLENGTH: " + str(RDLENGTH))
                decoded_message.append("RDDATA: " + RDDATA)
                decoded_message.append("RDDATA decoded (result): " + RDDATA_decoded + "\n")

    if ANCOUNT > 0 or QPARAMS["QR"] == "0" or QPARAMS["RD"] == "1":
        return "\n".join(decoded_message), answers, "A"
    else:
        return "\n".join(decoded_message), servers, "S"


def get_type(type):
    types = [
        "ERROR",
        "A",
        "NS",
        "MD",
        "MF",
        "CNAME",
        "SOA",
        "MB",
        "MG",
        "MR",
        "NULL",
        "WKS",
        "PTS",
        "HINFO",
        "MINFO",
        "MX",
        "TXT"
    ]

    if type == "AAAA":
        return "{:04x}".format(28)
    elif type == 28:
        return "AAAA"
    elif isinstance(type, int) and type > 16:
        return "Unknown"

    return "{:04x}".format(types.index(type)) if isinstance(type, str) else types[type]


def parse_ipv4(hex_address):
    return socket.inet_ntop(socket.AF_INET, binascii.unhexlify(hex_address))


def parse_ipv6(hex_address):
    return socket.inet_ntop(socket.AF_INET6, binascii.unhexlify(hex_address))


def parse_address_parts(message, start):
    parts = []

    while True:
        part_start = start + 2
        identifier = message[start:part_start]
        binary = "".join(map(lambda p: str(bin(int(p, 16))[2:]).zfill(4), identifier))
        if binary[0:2] == "11":
            pointer_parts, _ = parse_address_parts(message, int(message[part_start:part_start + 2], 16) * 2)
            for i in pointer_parts:
                parts.append(i)
            return parts, part_start + 2

        part_len = int(identifier, 16)
        if part_len == 0:
            return parts, part_start
        part_end = part_start + (part_len * 2)
        parts.append(message[part_start:part_end])
        start = part_end
