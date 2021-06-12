from raw_dns_req import *
import sys
import csv


def query_recursive(name_address, dns_server):
    request = build_message("A", name_address, 1)
    request_encoded, _, _ = decode_message(request)
    response = send_udp_message(request, dns_server, 53)
    decoded_response, message_list, mode = decode_message(response)
    if len(message_list) > 0:
        return message_list
    else:
        return []


def writeCSV(dns_server):
    try:
        csvFile = open("./address.csv", 'r')
    except FileNotFoundError:
        print("File not found")
        exit(1)

    csvReader = csv.reader(csvFile)
    lines = list(csvReader)
    for i in range(1, len(lines)):
        if len(lines[i]) > 1:
            continue
        result = query_recursive(lines[i][0], dns_server)
        if len(result) > 0:
            for r in result:
                lines[i].append(r)
    csvFile.close()
    with open("./address.csv", 'w', newline='') as csvFile:
        csvWriter = csv.writer(csvFile)
        csvWriter.writerows(lines)


if __name__ == "__main__":
    if len(sys.argv) == 1:
        print("Error: Enter name address")
    elif len(sys.argv) == 2:
        print("Error: Enter DNS server address")
    elif len(sys.argv) == 3:
        if sys.argv[1] == "csv":
            writeCSV(sys.argv[2])
            print("Success.")
            exit(0)
        print("Error: Enter recursion mode")
    else:
        name_address = sys.argv[1]
        dns_server = sys.argv[2]
        recursion = sys.argv[3]

        if not isinstance(name_address, str) and not \
                isinstance(dns_server, str) and not \
                (recursion == "0" or recursion == "1"):
            print("Error: Invalid inputs")
            exit(1)

        if recursion == "0":
            request = build_message("A", name_address, 0)
            request_encoded, _, _ = decode_message(request)
            print("Request message:\n" + request_encoded)

            print("\n*****\n")

            response = send_udp_message(request, dns_server, 53)
            decoded_response, message_list, mode = decode_message(response)
            print("Response message: \n" + decoded_response)

            if mode == "S":
                while len(message_list) > 0:
                    request = build_message("A", name_address, 0)
                    request_encoded, _, _ = decode_message(request)
                    print("--------------")
                    print("Sending new request to: \n" + str(message_list[0]))
                    print("Request message:\n" + request_encoded)
                    response = send_udp_message(request, message_list[0], 53)
                    decoded_response, message_list, mode = decode_message(response)
                    if mode == "A":
                        print("\n*****\n")
                        print("Final response message: \n" + decoded_response)
                        print("Resolved IP List: " + str(message_list))
                        exit(0)
                    print("\n*****\n")
                    print("Response message: \n" + decoded_response)
                print("**Couldn't resolve address**")
            else:
                if len(message_list) > 0:
                    print("Response message: \n" + decoded_response)
                else:
                    print("**Couldn't resolve address**")

        else:
            request = build_message("A", name_address, 1)
            request_encoded, _, _ = decode_message(request)
            print("Request message:\n" + request_encoded)

            print("\n*****\n")

            response = send_udp_message(request, dns_server, 53)
            decoded_response, message_list, mode = decode_message(response)

            if len(message_list) > 0:
                print("Response message: \n" + decoded_response)
                print("Resolved IP List: " + str(message_list))
            else:
                print("Response message: \n" + decoded_response)
                print("**Couldn't resolve address**")
