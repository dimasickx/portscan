import binascii
import re


dns_message = binascii.unhexlify("AA AA 01 00 00 01 00 00 00 00 00 00 07 "
                                 "65 78 61 6d 70 6c 65 03 63 6f 6d 00 00 01 00 01".replace(' ', ''))


class Protocols:
    tcp = [b"USER toster\r\n", b"GET HTTP/1.1\r\nHost: government.ru\r\n\r\n", b"EHLO toster.com\r\n", b"A001 LOGIN toster\r\n", dns_message]  # pop3, http, smtp, imap, dns
    udp = [dns_message, b'something']

    @staticmethod
    def get_protocol(data):
        pattern_pop3 = rb'(\+OK)|(\-ERR)'
        pattern_imap = rb'(\* OK)'
        if data.startswith(b"HTTP"):
            return "HTTP"
        elif data.startswith(binascii.unhexlify("AAAA")):
            return "DNS"
        elif re.match(rb'\d{3}', data):
            return 'SMTP'
        elif re.match(pattern_pop3, data):
            return 'POP3'
        elif re.match(pattern_imap, data):
            return 'IMAP'
        else:
            return None
