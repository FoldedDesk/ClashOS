#!/usr/bin/env python3
"""Queue an independently authenticated reply, then close before a late upload.

Inherited Unix sockets, public credentials and fixed binary data only. The peer
must exit before the production relay starts, making the write failure certain.
"""
import os
import socket
import sys
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from generate_ss_aead_vectors import master_key, subkey
from ss_reference_peer import exact
from trojan_reference_peer import context, read_address, read_header as trojan_header
from vless_reference_peer import read_header as vless_header
from forward_reference_peer import read_forward_header
from vmess_reference_peer import Wire, PAYLOAD, decode_header, read_request, response_packet

RESPONSE = bytes((i * 23 + 11) % 256 for i in range(50000))


class ShadowsocksWire:
    def __init__(self, conn, method):
        self.conn, self.buffer, self.counter = conn, b'', 0
        self.size = 16 if method == 'aes-128-gcm' else 32
        self.algorithm = ChaCha20Poly1305 if method == 'chacha20-ietf-poly1305' else AESGCM
        self.master = master_key(self.size)
        self.reader = self.algorithm(subkey(self.master, exact(conn, self.size)))

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

    def response(self, corrupt):
        salt = os.urandom(self.size)
        writer = self.algorithm(subkey(self.master, salt))
        packet, counter = bytearray(salt), 0
        for start in range(0, len(RESPONSE), 4093):
            body = RESPONSE[start:start + 4093]
            packet.extend(writer.encrypt(counter.to_bytes(12, 'little'), len(body).to_bytes(2, 'big'), None))
            counter += 1
            packet.extend(writer.encrypt(counter.to_bytes(12, 'little'), body, None))
            counter += 1
        if corrupt:
            packet[self.size + 17] ^= 1
        self.conn.sendall(packet)


def main():
    conn = socket.socket(fileno=int(sys.argv[1]))
    conn.settimeout(6)
    conn.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 262144)
    protocol, transport = sys.argv[3].split(':', 1)
    corrupt = sys.argv[4] == 'corrupt'
    if 'tls' in transport:
        ctx = context()
        names = []
        ctx.sni_callback = lambda connection, name, selected: names.append(name)
        conn = ctx.wrap_socket(conn, server_side=True)
        assert names == ['vmess.test']
    wire = ShadowsocksWire(conn, transport) if protocol == 'ss' else Wire(conn)
    if 'ws' in transport:
        wire.upgrade(path='/' + protocol + '?test=1')
    command = None
    if protocol == 'ss':
        assert read_address(wire) == ('192.0.2.9', 443)
    elif protocol == 'trojan':
        trojan_header(wire, host='192.0.2.9')
    elif protocol == 'vless':
        vless_header(wire, host='192.0.2.9')
    elif protocol == 'vmess':
        command = decode_header(wire, 0, target_host='192.0.2.9')
    elif protocol in ('http', 'socks5'):
        assert read_forward_header(wire, protocol, host='192.0.2.9')
    else:
        assert protocol == 'direct'
    request = read_request(wire, command, byte_limit=len(PAYLOAD)) if command is not None else wire.exact(len(PAYLOAD))
    assert request == PAYLOAD, 'The initial application payload or proxy authentication changed'
    if protocol == 'ss':
        wire.response(corrupt)
    elif protocol == 'vmess':
        chunks = [RESPONSE[start:start + 1966] for start in range(0, len(RESPONSE), 1966)] + [b'']
        wire.send(response_packet(command, 0, 'auth' if corrupt else '', chunks))
    elif protocol == 'vless':
        wire.send((b'\x01\0' if corrupt else b'\0\0') + RESPONSE)
    elif corrupt:
        assert 'tls' in transport
        # A deliberately unauthenticated TLS application record. Never fall
        # back to forwarding this raw transport after the upload has failed.
        os.write(conn.fileno(), b'\x17\x03\x03\x00\x20' + b'X' * 32)
    else:
        for start in range(0, len(RESPONSE), 4093):
            wire.send(RESPONSE[start:start + 4093])
    conn.close()


if __name__ == '__main__':
    main()
