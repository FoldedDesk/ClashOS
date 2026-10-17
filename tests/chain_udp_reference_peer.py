#!/usr/bin/env python3
"""Independent SS carrier with SS/SOCKS/direct UDP exits; inherited sockets only."""
import os
import socket
import sys
import time
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from generate_ss_aead_vectors import master_key, subkey
from trojan_reference_peer import address
from forward_reference_peer import read_forward_header
from vmess_reference_peer import Wire
from vless_reference_peer import read_header as read_vless_header


def split_address(data):
    size = 7 if data[0] == 1 else 19 if data[0] == 4 else 4 + data[1]
    assert len(data) >= size
    return data[:size], data[size:]


def main():
    conn = socket.socket(fileno=int(sys.argv[1]))
    conn.settimeout(8)
    kind = sys.argv[3]
    streamed = kind.startswith('vless+')
    if streamed:
        kind = kind[6:]
    if kind == 'control':
        assert read_forward_header(Wire(conn), 'socks5', udp=True, bound='192.0.2.1')
        assert not conn.recv(1), 'UDP control must remain alive until client releases flow'
        conn.close()
        return
    outer_key = master_key(32)
    outer_target = address('target.test', 443) if kind == 'direct' else address('192.0.2.1', 18096) if kind == 'socks5' else address('inner.chain.test', 443)
    child_size = 16 if kind == 'aes-128-gcm' else 32
    child_algorithm = ChaCha20Poly1305 if kind == 'chacha20-ietf-poly1305' else AESGCM
    child_key = master_key(child_size)
    child_overhead = 0 if kind == 'direct' else 3 + len(address('target.test', 443)) if kind == 'socks5' else child_size + 16 + len(address('target.test', 443))
    maximum = 65507 - (0 if streamed else 48 + len(outer_target)) - child_overhead
    seen = set()
    wire = Wire(conn)
    response_header = False
    if streamed:
        read_vless_header(wire, 'inner.chain.test', udp=True)

    def receive():
        return wire.exact(int.from_bytes(wire.exact(2), 'big')) if streamed else conn.recv(65536)

    def carrier_send(packet):
        nonlocal response_header
        if streamed:
            prefix = b'' if response_header else b'\0\0'
            response_header = True
            wire.send(prefix + len(packet).to_bytes(2, 'big') + packet)
        else:
            conn.send(packet)

    def send(body, source, port):
        if kind == 'direct':
            inner = body
            outer_source = address(source, port)
        elif kind == 'socks5':
            inner = b'\0\0\0' + address(source, port) + body
            outer_source = outer_target
        else:
            salt = os.urandom(child_size)
            inner = salt + child_algorithm(subkey(child_key, salt)).encrypt(bytes(12), address(source, port) + body, None)
            outer_source = outer_target
        salt = os.urandom(32)
        packet = inner if streamed else salt + AESGCM(subkey(outer_key, salt)).encrypt(bytes(12), outer_source + inner, None)
        assert len(packet) <= 65507
        carrier_send(packet)

    for index in range(4):
        packet = receive()
        assert len(packet) <= 65507 and packet[:32] not in seen
        seen.add(packet[:32])
        plain = outer_target + packet if streamed else AESGCM(subkey(outer_key, packet[:32])).decrypt(bytes(12), packet[32:], None)
        destination, inner = split_address(plain)
        assert destination == outer_target, 'Carrier must reach the exit server, never the website directly'
        if kind == 'socks5':
            assert inner[:3] == b'\0\0\0'
            destination, body = split_address(inner[3:])
            assert destination == address('target.test', 443)
        elif kind == 'direct':
            body = inner
        else:
            decoded = child_algorithm(subkey(child_key, inner[:child_size])).decrypt(bytes(12), inner[child_size:], None)
            destination, body = split_address(decoded)
            assert destination == address('target.test', 443)
        expected = [b'packet-0', b'', b'P' * 4096, bytes(i % 256 for i in range(maximum))][index]
        assert body == expected, 'Nested UDP limit, address or datagram boundary changed'
        source = ['8.8.8.8', '2001:db8::1', 'answer.test', '8.8.8.8'][index]
        response = b'' if index == 1 else body if index == 3 else b'udp-response:' + body[::-1]
        if index == 0:
            carrier_send(packet)  # Reflections and damaged authentication never reach the client.
            carrier_send(packet[:-1] + bytes([packet[-1] ^ 1]))
        send(response, source, 53 + index)
    for body in [b'A', b'', b'B']:
        send(body, '8.8.4.4', 53)
    deadline = time.monotonic() + 8
    while not Path(sys.argv[4]).exists() and time.monotonic() < deadline:
        time.sleep(.002)
    assert Path(sys.argv[4]).exists(), 'Client did not verify/cancel the live UDP chain'
    conn.close()


if __name__ == '__main__':
    main()
