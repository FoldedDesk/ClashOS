#!/usr/bin/env python3
"""Independent Trojan server using hashlib/OpenSSL over one inherited Unix socket.
Only public fixture credentials are used; no production configuration is read.
"""
import hashlib
import os
from pathlib import Path
import socket
import ssl
import sys
import time

from vmess_reference_peer import Wire

PASSWORD = 'pässword-测试'
PAYLOAD = bytes((i * 17 + 3) % 256 for i in range(50000))
RESPONSE = b'trojan-response:' + PAYLOAD[::-1]


class TrojanWire(Wire):
    def exact(self, size):
        if not self.ws:
            return self.raw_exact(size)
        while len(self.buffer) < size:
            opcode, data = self.read_frame()
            if opcode == 10:
                assert data == b'trojan-ping'
                continue
            if opcode == 8:
                raise EOFError('Client WebSocket closed')
            assert opcode == 2
            self.buffer += data
        result, self.buffer = self.buffer[:size], self.buffer[size:]
        return result


def address(host, port):
    try:
        result = b'\x01' + socket.inet_pton(socket.AF_INET, host)
    except OSError:
        try:
            result = b'\x04' + socket.inet_pton(socket.AF_INET6, host)
        except OSError:
            encoded = host.encode()
            result = b'\x03' + bytes([len(encoded)]) + encoded
    return result + port.to_bytes(2, 'big')


def read_address(wire):
    kind = wire.exact(1)
    if kind == b'\x01':
        host = socket.inet_ntop(socket.AF_INET, wire.exact(4))
    elif kind == b'\x04':
        host = socket.inet_ntop(socket.AF_INET6, wire.exact(16))
    else:
        assert kind == b'\x03', 'Unknown Trojan address type'
        length = wire.exact(1)[0]
        assert length > 0
        host = wire.exact(length).decode()
    port = int.from_bytes(wire.exact(2), 'big')
    assert port > 0
    return host, port


def read_header(wire, host='target.test', port=443, udp=False, password=PASSWORD):
    assert wire.exact(56) == hashlib.sha224(password.encode()).hexdigest().encode()
    assert wire.exact(2) == b'\r\n'
    assert wire.exact(1) == (b'\x03' if udp else b'\x01')
    assert read_address(wire) == (host, port)
    assert wire.exact(2) == b'\r\n'


def context():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.set_alpn_protocols(['h2', 'http/1.1'])
    fixtures = Path(__file__).parent / 'fixtures/vmess'
    ctx.load_cert_chain(fixtures / 'server.pem', fixtures / 'server-key.pem')
    return ctx


def udp_frame(host, port, payload):
    return address(host, port) + len(payload).to_bytes(2, 'big') + b'\r\n' + payload


def send_fragmented(wire, data):
    if wire.ws:
        wire.frame(data[:37], opcode=2, final=False)
        wire.frame(b'trojan-ping', opcode=9)
        wire.frame(data[37:], opcode=0)
    else:
        for start, end in [(0, 1), (1, 3), (3, 19), (19, len(data))]:
            if end > start:
                wire.send(data[start:end])
                time.sleep(.002)


def datagrams(wire, fault):
    for index in range(4 if fault == 'udp' else 1):
        assert read_address(wire) == ('target.test', 443)
        size = int.from_bytes(wire.exact(2), 'big')
        assert wire.exact(2) == b'\r\n'
        body = wire.exact(size)
        expected = [b'packet-0', b'', b'P' * 4096,
                    bytes(i % 256 for i in range(65507 - 3 - len(address('target.test', 443))))][index]
        assert body == expected, 'Trojan UDP lost a packet boundary or payload'
        if fault == 'udp':
            source = ['8.8.8.8', '2001:db8::1', 'answer.test', '8.8.8.8'][index]
            payload = b'udp-response:' + body[::-1] if index < 3 else bytes(i % 256 for i in range(65497))
            send_fragmented(wire, udp_frame(source, 53 + index, payload))
            continue
        good = udp_frame('8.8.8.8', 53, b'good')
        if fault == 'udp-oversize':
            wire.send(udp_frame('8.8.8.8', 53, b'X' * 65535))
            wire.send(good)
        elif fault == 'udp-atyp':
            wire.send(b'\x02')
        elif fault == 'udp-domain-empty':
            wire.send(b'\x03\x00')
        elif fault == 'udp-domain-nul':
            wire.send(b'\x03\x02a\x00\x00\x35')
        elif fault == 'udp-port':
            wire.send(address('8.8.8.8', 0))
        elif fault == 'udp-crlf':
            wire.send(good[:9] + b'\n\r' + good[11:])
        elif fault == 'udp-short-address':
            wire.send(b'\x04\x01\x02')
        elif fault == 'udp-short-payload':
            wire.send(address('8.8.8.8', 53) + b'\x00\x20\r\nshort')
        else:
            raise AssertionError('Unknown UDP fault')


def main():
    fd, scenario, kind, fault = int(sys.argv[1]), int(sys.argv[2]), sys.argv[3], sys.argv[4]
    conn = socket.socket(fileno=fd)
    conn.settimeout(6)
    ctx = context()
    names = []
    ctx.sni_callback = lambda connection, name, selected: names.append(name)
    try:
        conn = ctx.wrap_socket(conn, server_side=True)
    except ssl.SSLError:
        if fault not in ('tls-reject-ca', 'tls-reject-host'):
            raise
        return
    assert names == ['vmess.test'] or fault == 'tls-reject-host'
    assert conn.selected_alpn_protocol() == ('h2' if scenario == 1 and kind == 'tls' else 'http/1.1')
    wire = TrojanWire(conn)
    if kind == 'ws-tls':
        wire.upgrade(fault == 'ws-accept', path='/trojan?test=1')
        if fault == 'ws-accept':
            conn.close()
            return
        # A control frame split across TLS records must not block client payload forwarding.
        conn.sendall(b'\x89')
        time.sleep(.01)
        conn.sendall(b'\x0btrojan-ping')
    if fault == 'bad-password':
        read_header(wire, password='wrong-secret')
        assert wire.exact(len(PAYLOAD)) == PAYLOAD
        conn.close()
        return
    host = 'target.test'
    # Scenario 2 and 3 exercise literal destinations independently of the C++ encoder.
    if scenario == 2:
        host = '192.0.2.9'
    elif scenario == 3:
        host = '2001:db8::9'
    udp = fault.startswith('udp')
    read_header(wire, host, udp=udp)
    if udp:
        datagrams(wire, fault)
    else:
        assert wire.exact(len(PAYLOAD)) == PAYLOAD
        if fault == 'tls-corrupt':
            os.write(conn.fileno(), b'\x17\x03\x03\x00\x20' + b'X' * 32)
            conn.close()
            return
        send_fragmented(wire, RESPONSE)
    if wire.ws:
        wire.frame(b'', opcode=8)
        conn.close()
    else:
        try:
            conn.unwrap().close()
        except (ssl.SSLError, OSError):
            conn.close()


if __name__ == '__main__':
    main()
