#!/usr/bin/env python3
"""Hosts forwarding reference: Python cryptography/OpenSSL and inherited sockets.

Only fixed public credentials and destinations are used. The peer independently
decodes the actual SS/VMess/Trojan request, including TLS and WebSocket variants.
"""
import os
import socket
import sys
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from generate_ss_aead_vectors import master_key, subkey
from ss_reference_peer import exact
from trojan_reference_peer import TrojanWire, address, context, read_address, read_header, udp_frame
from vmess_reference_peer import PAYLOAD, Wire, decode_header, read_request, response_packet

RESPONSE = b'hosts-response'


class SsWire:
    def __init__(self, conn):
        self.conn, self.buffer, self.counter = conn, b'', 0
        self.master = master_key(32)
        self.reader = AESGCM(subkey(self.master, exact(conn, 32)))

    def exact(self, size):
        while len(self.buffer) < size:
            length = self.reader.decrypt(self.counter.to_bytes(12, 'little'), exact(self.conn, 18), None)
            self.counter += 1
            count = int.from_bytes(length, 'big')
            assert 0 < count <= 0x3fff
            self.buffer += self.reader.decrypt(self.counter.to_bytes(12, 'little'), exact(self.conn, count + 16), None)
            self.counter += 1
        result, self.buffer = self.buffer[:size], self.buffer[size:]
        return result

    def send(self, payload):
        salt = os.urandom(32)
        writer = AESGCM(subkey(self.master, salt))
        self.conn.sendall(salt + writer.encrypt(bytes(12), len(payload).to_bytes(2, 'big'), None)
                          + writer.encrypt((1).to_bytes(12, 'little'), payload, None))


class BytesWire:
    def __init__(self, data):
        self.buffer = data

    def exact(self, size):
        assert len(self.buffer) >= size
        result, self.buffer = self.buffer[:size], self.buffer[size:]
        return result


def main():
    fd, scenario, kind, mode = int(sys.argv[1]), int(sys.argv[2]), sys.argv[3], sys.argv[4]
    host = ['192.0.2.9', '2001:db8::9', 'target.test', '203.0.113.10'][scenario]
    conn = socket.socket(fileno=fd)
    conn.settimeout(8)
    udp = mode.startswith('udp')
    maximum = 65507 - 32 - 16 - len(address(host, 443))
    body = bytes(i % 256 for i in range(maximum)) if mode == 'udp-max' else b'packet-0'
    if kind == 'ss' and udp:
        packet = conn.recv(65536)
        assert len(packet) <= 65507
        wire = BytesWire(AESGCM(subkey(master_key(32), packet[:32])).decrypt(bytes(12), packet[32:], None))
        assert read_address(wire) == (host, 443), 'SS UDP ignored the configured hosts destination'
        assert wire.buffer == body
        salt = os.urandom(32)
        conn.send(salt + AESGCM(subkey(master_key(32), salt)).encrypt(bytes(12), address(host, 443) + RESPONSE, None))
        return
    if 'tls' in kind:
        ctx = context()
        ctx.set_alpn_protocols(['http/1.1'])
        names = []
        ctx.sni_callback = lambda connection, name, selected: names.append(name)
        conn = ctx.wrap_socket(conn, server_side=True)
        assert names == ['vmess.test'], 'The destination override must preserve proxy TLS SNI'
    wire = SsWire(conn) if kind == 'ss' else TrojanWire(conn) if kind.startswith('trojan') else Wire(conn)
    if 'ws' in kind:
        wire.upgrade(path='/trojan?test=1' if kind.startswith('trojan') else '/vmess?test=1')
    command = None
    if kind == 'ss':
        assert read_address(wire) == (host, 443), 'SS TCP ignored the configured hosts destination'
    elif kind.startswith('trojan'):
        read_header(wire, host=host, udp=udp)
    else:
        command = decode_header(wire, 0, target_host=host)
        assert command[37] == (2 if udp else 1)
    if udp:
        if command is not None:
            assert read_request(wire, command, 1) == [body]
            wire.send(response_packet(command, 0, '', [RESPONSE]))
        else:
            assert read_address(wire) == (host, 443), 'Trojan UDP packet differs from its mapped header'
            size = int.from_bytes(wire.exact(2), 'big')
            assert wire.exact(2) == b'\r\n' and wire.exact(size) == body
            wire.send(udp_frame(host, 443, RESPONSE))
    elif mode == 'http':
        request = b''
        while not request.endswith(b'\r\n\r\n'):
            request += wire.exact(1)
        assert request.startswith(b'GET /test HTTP/1.1\r\n')
        assert b'\r\nHost: source.fixture.test:443\r\n' in request
        wire.send(b'HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n')
    else:
        request = read_request(wire, command) if command is not None else wire.exact(len(PAYLOAD))
        assert request == PAYLOAD
        wire.send(response_packet(command, 0, '', [RESPONSE, b''])) if command is not None else wire.send(RESPONSE)
    conn.close()


if __name__ == '__main__':
    main()
