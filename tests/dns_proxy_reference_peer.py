#!/usr/bin/env python3
"""Independent SS/VMess/Trojan UDP DNS peer. No arbitrary forwarding or credentials."""
import os
from pathlib import Path
import socket
import ssl
import sys
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from generate_ss_aead_vectors import master_key, subkey
from dns_reference_peer import answer


def main():
    fd, alter, transport, fault = int(sys.argv[1]), int(sys.argv[2]), sys.argv[3], sys.argv[4]
    conn = socket.socket(fileno=fd)
    conn.settimeout(5)
    if transport.startswith('ss-'):
        method = transport[3:]
        size = 16 if method == 'aes-128-gcm' else 32
        algorithm = ChaCha20Poly1305 if method == 'chacha20-ietf-poly1305' else AESGCM
        master = master_key(size)
        packet = conn.recv(65535)
        salt = packet[:size]
        plain = algorithm(subkey(master, salt)).decrypt(bytes(12), packet[size:], None)
        target = b'\x01\xc0\x00\x02\x35\x00\x35'
        assert plain.startswith(target)
        response = answer(plain[len(target):], 10, '')
        output_salt = os.urandom(size)
        output = output_salt + algorithm(subkey(master, output_salt)).encrypt(bytes(12), target + response, None)
        conn.send(output[:-1] + bytes([output[-1] ^ 1]))
        conn.send(output)
    elif transport.startswith('vmess-'):
        from vmess_reference_peer import Wire, decode_header, read_request, response_packet
        kind = transport[6:]
        if 'tls' in kind:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            files = Path(__file__).parent / 'fixtures/vmess'
            ctx.load_cert_chain(files / 'server.pem', files / 'server-key.pem')
            conn = ctx.wrap_socket(conn, server_side=True)
        wire = Wire(conn)
        if 'ws' in kind:
            wire.upgrade(False)
        command = decode_header(wire, alter, '192.0.2.53', 53)
        assert command[37] == 2
        packets = read_request(wire, command, datagram_count=1)
        assert len(packets) == 1
        response = response_packet(command, alter, '', [answer(packets[0], 10, ''), b''])
        wire.frame(response, 2) if wire.ws else conn.sendall(response)
    else:
        from trojan_reference_peer import context, TrojanWire, read_header, read_address, udp_frame
        conn = context().wrap_socket(conn, server_side=True)
        wire = TrojanWire(conn)
        if transport == 'trojan-ws-tls':
            wire.upgrade(False, path='/trojan?test=1')
        read_header(wire, '192.0.2.53', 53, udp=True)
        assert read_address(wire) == ('192.0.2.53', 53)
        size = int.from_bytes(wire.exact(2), 'big')
        assert wire.exact(2) == b'\r\n'
        response = udp_frame('192.0.2.53', 53, answer(wire.exact(size), 10, ''))
        wire.send(response)
    conn.close()


if __name__ == '__main__':
    main()
