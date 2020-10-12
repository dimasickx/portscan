import argparse
import random
import struct
import socket
import sys
import threading
from type_protocol import Protocols


def parse_arg(args):
    parser = argparse.ArgumentParser()
    parser.add_argument('-t', dest='tcp', help='адресс для tcp протокола', type=str)
    parser.add_argument('-u', dest='udp', help='адресс для udp протокола', type=str)
    parser.add_argument('-p', dest='ports', help='список портов для сканирования', type=int, nargs='+', required=True)
    answer = parser.parse_args(args[1:])
    return answer


def tcp_scan(ip, port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(1)
        try:
            sock.connect((ip, port))
        except socket.error:
            sock.close()
            return
        else:
            for p in Protocols.tcp:
                try:
                    sock.sendall(p)
                    data = sock.recv(1024)
                    protocol = Protocols.get_protocol(data)
                    if protocol is not None:
                        print(f'TCP {port} {protocol}')
                        break
                    else:
                        print(f'TCP {port}')
                        break
                except Exception:
                    continue
            sock.close()


def udp_scan(ip, port):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(1)
        try:
            pack = build_packet()
            sock.sendto(bytes(pack), (ip, port))
            sock.recvfrom(1024)
            sock.close()
        except socket.timeout:
            pass
        except socket.error:
            return

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(1)
        try:
            sock.connect((ip, port))
        except socket.error:
            sock.close()
            return
        else:
            for p in Protocols.udp:
                try:
                    sock.sendall(p)
                    data = sock.recv(1024)
                    protocol = Protocols.get_protocol(data)
                    if protocol is not None:
                        print(f'UDP {port} {protocol}')
                        break
                    else:
                        print(f'UDP {port}')
                        break
                except Exception:
                    continue
            sock.close()


def main():
    arguments = parse_arg(sys.argv)
    threads = []
    ports = [x for x in range(int(arguments.ports[0]), int(arguments.ports[1] + 1))] if len(arguments.ports) > 1 \
        else [int(arguments.ports[0])]
    if arguments.tcp and arguments.udp:
        for port in ports:
            threads.append(threading.Thread(target=tcp_scan, args=(arguments.tcp, port)))
            threads.append(threading.Thread(target=udp_scan, args=(arguments.udp, port)))
    elif arguments.udp:
        for port in ports:
            threads.append(threading.Thread(target=udp_scan, args=(arguments.udp, port)))
    elif arguments.tcp:
        for port in ports:
            threads.append(threading.Thread(target=tcp_scan, args=(arguments.tcp, port)))

    for t in threads:
        t.start()

    for t in threads:
        t.join()


def build_packet():
    randint = random.randint(0, 65535)
    packet = struct.pack(">H", randint)  # Query Ids (Just 1 for now)
    packet += struct.pack(">H", 0x0100)  # Flags
    packet += struct.pack(">H", 1)  # Questions
    packet += struct.pack(">H", 0)  # Answers
    packet += struct.pack(">H", 0)  # Authorities
    packet += struct.pack(">H", 0)  # Additional
    url = 'www.google.com'
    split_url = url.split(".")
    for part in split_url:
        packet += struct.pack("B", len(part))
        for s in part:
            packet += struct.pack('c', s.encode())
    packet += struct.pack("B", 0)  # End of String
    packet += struct.pack(">H", 1)  # Query Type
    packet += struct.pack(">H", 1)  # Query Class
    return packet


if __name__ == '__main__':
    main()
