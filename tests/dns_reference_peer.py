#!/usr/bin/env python3
"""Independent stdlib DNS wire peer on one inherited Unix socket; public test data only."""
import base64
import ipaddress
from pathlib import Path
import socket
import ssl
import struct
import sys
import time
import urllib.parse


def name(value):
    if value == '.':
        return b'\0'
    return b''.join(bytes([len(label)]) + label.encode('ascii') for label in value.split('.')) + b'\0'


def record(owner, kind, value, ttl=120):
    return owner + struct.pack('!HHIH', kind, 1, ttl, len(value)) + value


def answer(query, variant, fault):
    transaction, flags, count = struct.unpack('!HHH', query[:6])
    assert flags & ~0x0030 == 0x0100 and count == 1
    at, labels = 12, []
    while query[at]:
        length = query[at]
        assert 1 <= length <= 63
        labels.append(query[at + 1:at + 1 + length].decode('ascii'))
        at += 1 + length
    at += 1
    kind, klass = struct.unpack('!HH', query[at:at + 4])
    assert klass == 1
    host = '.'.join(labels) or '.'
    question = query[12:at + 4]
    additional = b''
    arcount = struct.unpack('!H', query[10:12])[0]
    if arcount:
        assert arcount == 1 and query[at + 4:at + 7] == b'\0\0\x29'
        assert len(query) == at + 15 and query[-2:] == b'\0\0'
        additional = b'\0\0\x29\x04\xd0' + query[-6:-2] + b'\0\0'
    else:
        assert at + 4 == len(query)
    if fault == 'question-mismatch':
        question = name('other.fixture.test') + struct.pack('!HH', kind, 1)
    response_flags, records, authority = 0x8180 | (flags & 0x0010), [], []
    owner = b'\xc0\x0c'
    if fault.startswith('truncated'):
        response_flags |= 0x0200
    elif fault == 'servfail':
        response_flags |= 2
    elif fault == 'negative':
        response_flags |= 3
        soa = name('ns.fixture.test') + name('hostmaster.fixture.test') + struct.pack('!IIIII', 1, 60, 60, 60, 30)
        authority.append(record(name('fixture.test'), 6, soa, 60))
    elif fault == 'pointer-loop':
        records.append(record(owner, 5, bytes([0xc0, len(query) + 12])))
    elif fault == 'alias-loop':
        records.append(record(owner, 5, name(host)))
    elif kind == 5:
        records.append(record(owner, 5, name('target.fixture.test')))
    elif kind in (1, 28):
        ip = ipaddress.ip_address('2001:db8::10' if kind == 28 else '192.0.2.' + str(variant))
        if host in ('alias.fixture.test', 'follow.fixture.test'):
            records.append(record(owner, 5, name('target.fixture.test')))
            if host == 'alias.fixture.test':
                records.append(record(name('target.fixture.test'), kind, ip.packed))
            records.append(record(name('unrelated.fixture.test'), kind, ipaddress.ip_address('2001:db8::99' if kind == 28 else '203.0.113.99').packed))
        else:
            records.append(record(owner, kind, ip.packed, 0 if fault == 'zero-ttl' else 120))
    elif kind == 15:
        records.append(record(owner, kind, struct.pack('!H', 10) + name('mail.fixture.test')))
    elif kind == 16:
        records.append(record(owner, kind, b'\x05hello\x05world'))
    elif kind in (2, 12):
        records.append(record(owner, kind, name('ns.fixture.test')))
    elif kind == 65280:
        records.append(record(owner, kind, b'\x00\xff\xc0\x0c\x01'))
    if fault == 'bad-address-length':
        records = [record(owner, 1, b'\x01\x02\x03')]
    packet = struct.pack('!HHHHHH', transaction, response_flags, 1, len(records), len(authority), int(bool(additional))) + question + b''.join(records + authority) + additional
    return packet


def exact(conn, length):
    result = b''
    while len(result) < length:
        part = conn.recv(length - len(result))
        if not part:
            raise EOFError()
        result += part
    return result


def main():
    fd, variant, transport, fault = int(sys.argv[1]), int(sys.argv[2]), sys.argv[3], sys.argv[4]
    conn = socket.socket(fileno=fd)
    conn.settimeout(4)
    try:
        if transport in ('tls', 'https'):
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.set_alpn_protocols(['http/1.1'])
            certificates = Path(__file__).parent / 'fixtures/vmess'
            ctx.load_cert_chain(certificates / 'server.pem', certificates / 'server-key.pem')
            conn = ctx.wrap_socket(conn, server_side=True)
        if transport == 'relay':
            request = b''
            while not request.endswith(b'\r\n\r\n'):
                request += exact(conn, 1)
            assert request.startswith(b'GET /verify HTTP/1.1\r\n')
            conn.sendall(b'HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n')
            return
        if transport == 'https':
            request = b''
            while not request.endswith(b'\r\n\r\n'):
                assert len(request) < 16384
                request += exact(conn, 1)
            line = request.decode().split('\r\n', 1)[0]
            query = urllib.parse.parse_qs(urllib.parse.urlsplit(line.split(' ')[1]).query)['dns'][0]
            query = base64.urlsafe_b64decode(query + '=' * (-len(query) % 4))
        elif transport == 'udp':
            query = conn.recv(65535)
        else:
            query = exact(conn, struct.unpack('!H', exact(conn, 2))[0])
        if fault == 'timeout':
            time.sleep(1.5)
            return
        response = answer(query, variant or 10, fault)
        if fault == 'id-mismatch':
            conn.send(bytes([response[0] ^ 1]) + response[1:])
        if transport == 'https':
            mime = b'application/json' if fault == 'bad-content-type' else b'application/dns-message'
            age = b'Age: 30\r\n' if fault == 'http-age' else b''
            conn.sendall(b'HTTP/1.1 200 OK\r\nContent-Type: ' + mime + b'\r\nContent-Length: ' + str(len(response)).encode() + b'\r\n' + age + b'Connection: close\r\n\r\n' + response)
        elif transport == 'udp':
            conn.send(response)
        else:
            framed = struct.pack('!H', len(response)) + response
            for byte in framed:
                conn.sendall(bytes([byte]))
    except (ssl.SSLError, EOFError, BrokenPipeError, ConnectionResetError):
        # Certificate refusal / cancellation are expected negative cases.
        pass
    finally:
        conn.close()


if __name__ == '__main__':
    main()
