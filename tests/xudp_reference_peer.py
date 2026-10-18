#!/usr/bin/env python3
"""Independent XUDP stream peer over Python/OpenSSL VMess/VLESS test transports."""
import hashlib
import json
from pathlib import Path
import socket
import ssl
import struct
import sys

from generate_xudp_vectors import address, frame
from trojan_reference_peer import context
from vmess_reference_peer import ID, Wire, Mask, body_aead, decode_header, response_packet


class Channel:
    def __init__(self, wire, command=None, alter=0):
        self.wire, self.command, self.alter = wire, command, alter
        self.buffer, self.header = b'', False
        self.read_counter, self.write_counter = 0, 0
        if command:
            digest = hashlib.md5 if alter else hashlib.sha256
            self.read_iv, key = command[1:17], command[17:33]
            self.options, security = command[34], command[35] & 15
            self.read_mask, self.read_cipher = Mask(self.read_iv), body_aead(key, security)
            self.write_iv = digest(self.read_iv).digest()[:16]
            self.write_mask = Mask(self.write_iv)
            self.write_cipher = body_aead(digest(key).digest()[:16], security)

    def exact(self, size):
        if not self.command or not self.options & 1:
            return self.wire.exact(size)
        while len(self.buffer) < size:
            encoded = int.from_bytes(self.wire.exact(2), 'big')
            padding = self.read_mask.next() % 64 if self.options & 8 else 0
            length = encoded ^ self.read_mask.next() if self.options & 4 else encoded
            assert length <= 2048
            data = self.wire.exact(length)
            if padding:
                data = data[:-padding]
            if self.read_cipher:
                data = self.read_cipher.decrypt(self.read_counter.to_bytes(2, 'big') + self.read_iv[2:12], data, None)
            self.read_counter += 1
            if not data:
                raise EOFError('VMess ended inside an XUDP frame')
            self.buffer += data
        value, self.buffer = self.buffer[:size], self.buffer[size:]
        return value

    def send(self, data, corrupt=False, fragment=True):
        if not self.header:
            self.wire.send(response_packet(self.command, self.alter, '', []) if self.command else b'\0\0')
            self.header = True
        if not self.command or not self.options & 1:
            self.wire.send(data)
            return
        # Deliberately split mux metadata and lengths over authenticated VMess
        # records instead of preserving sender write/packet boundaries.
        offset = 0
        sizes = [1, 2, 3, 7, 19] + [1337] * (len(data) // 1337 + 1) if fragment else [len(data)]
        for length in sizes:
            body = data[offset:offset + length]
            if not body:
                break
            offset += len(body)
            padding = self.write_mask.next() % 64 if self.options & 8 else 0
            packet = self.write_cipher.encrypt(self.write_counter.to_bytes(2, 'big') + self.write_iv[2:12], body, None) if self.write_cipher else body
            if corrupt:
                packet = packet[:-1] + bytes([packet[-1] ^ 1])
            length = len(packet) + padding
            if self.options & 4:
                length ^= self.write_mask.next()
            self.wire.send(struct.pack('>H', length) + packet + b'P' * padding)
            self.write_counter += 1
            if corrupt:
                return  # The client must close after this invalid record.
        assert offset == len(data)


def packet(channel, first):
    length = int.from_bytes(channel.exact(2), 'big')
    assert 4 <= length <= 4096
    data = channel.exact(length)
    session, status, options = struct.unpack('>HBB', data[:4])
    assert session == 0 and status == (1 if first else 2) and options == 1 and data[4] == 2
    port, kind = struct.unpack('>HB', data[5:8])
    offset = 8
    if kind in (1, 3):
        size = 4 if kind == 1 else 16
        host = socket.inet_ntop(socket.AF_INET if kind == 1 else socket.AF_INET6, data[offset:offset + size])
        offset += size
    else:
        assert kind == 2
        size = data[offset]
        host = data[offset + 1:offset + 1 + size].decode('ascii')
        offset += 1 + size
    identity = data[offset:]
    assert len(identity) in ((0, 8) if first else (0,))
    payload = channel.exact(int.from_bytes(channel.exact(2), 'big'))
    return host, port, identity, payload


def main():
    fd, scenario, transport, fault = int(sys.argv[1]), int(sys.argv[2]), sys.argv[3], sys.argv[4]
    marker = None
    if '|' in fault:
        fault, marker = fault.split('|', 1)
    conn = socket.socket(fileno=fd)
    conn.settimeout(6)
    if 'tls' in transport:
        try:
            conn = context().wrap_socket(conn, server_side=True)
        except ssl.SSLError:
            if fault not in ('tls-reject-ca', 'tls-reject-host'):
                raise
            return
    wire = Wire(conn)
    if 'ws' in transport:
        wire.upgrade(path='/xudp?test=1')
    if scenario == 0:
        assert wire.exact(19) == b'\0' + ID + b'\0\3', 'VLESS XUDP must use address-free Mux command'
        channel = Channel(wire)
    else:
        alter = 64 if scenario == 5 else 0
        command = decode_header(wire, alter, mux=True, fresh_legacy=True)
        assert (command[35] & 15) == {1: 3, 2: 4, 3: 5, 4: 5, 5: 3}[scenario]
        channel = Channel(wire, command, alter)
    if fault == 'record':
        host, port, identity, body = packet(channel, True)
        assert host in ('target.test', 'second.test') and port == 443 and body == b'identity-probe'
        assert len(identity) == 8 and any(identity)
        Path(marker).write_text(json.dumps({'identity': identity.hex()}))
        channel.send(frame(2, body, host, port))
    elif fault == 'duplex':
        assert packet(channel, True)[3] == b'packet-0'
        first = frame(2, b'packet-0', '192.0.2.80', 5400)
        channel.send(first[:3])
        Path(marker).write_text('ready')
        assert packet(channel, False)[3] == b'P' * 8192
        channel.send(first[3:] + frame(2, b'P' * 8192, '2001:db8::9', 5401))
    else:
        bodies = [b'packet-0', b'', bytes((i * 17 + 3) % 256 for i in range(1400)), b'P' * 8192, bytes(i % 256 for i in range(65485))]
        for index, expected in enumerate(bodies):
            host, port, identity, body = packet(channel, index == 0)
            assert host == 'target.test' and port == 443 and body == expected
            if fault in ('bad-session', 'bad-network', 'tag'):
                response = bytearray(frame(2, b'never-deliver', '192.0.2.80', 5400))
                if fault == 'bad-session':
                    response[3] = 1
                elif fault == 'bad-network':
                    response[6] = 1
                # Send exactly the invalid record. A correctly rejecting client
                # may close immediately; no later test writes are required.
                channel.send(bytes(response), corrupt=fault == 'tag', fragment=False)
                break
            source = [('192.0.2.80', 5400), ('reply.test', 5401), ('2001:db8::9', 5402), (None, 0), ('2001:db8::9', 5404)][index]
            response = frame(2, body[::-1], *source)
            # Keepalive with its own discard-only body must never become UDP data.
            channel.send(struct.pack('>H H B B H', 4, 0, 4, 1, 4) + b'DROP' + response)
    if wire.ws and fault not in ('bad-session', 'bad-network', 'tag'):
        wire.frame(b'', opcode=8)
    conn.close()


if __name__ == '__main__':
    main()
