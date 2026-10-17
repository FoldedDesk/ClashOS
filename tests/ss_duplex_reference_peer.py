#!/usr/bin/env python3
"""Independent AEAD peer: a partial reply must not block later client data."""
import os
import socket
import sys
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from generate_ss_aead_vectors import master_key, subkey
from ss_reference_peer import exact, TARGET


def main():
    fd, method, scenario = int(sys.argv[1]), sys.argv[3], sys.argv[4]
    phase, marker = scenario.split('|', 1)
    server_first = phase.startswith('server-first-')
    phase = phase.removeprefix('server-first-')
    conn = socket.socket(fileno=fd)
    conn.settimeout(5)
    size = 16 if method == 'aes-128-gcm' else 32
    algorithm = ChaCha20Poly1305 if method == 'chacha20-ietf-poly1305' else AESGCM
    master = master_key(size)
    reader = algorithm(subkey(master, exact(conn, size)))
    read_nonce = 0

    def chunk():
        nonlocal read_nonce
        count = int.from_bytes(reader.decrypt(read_nonce.to_bytes(12, 'little'), exact(conn, 18), None), 'big')
        read_nonce += 1
        assert 0 < count <= 0x3fff
        result = reader.decrypt(read_nonce.to_bytes(12, 'little'), exact(conn, count + 16), None)
        read_nonce += 1
        return result

    pending = bytearray()

    def plain_exact(count):
        while len(pending) < count:
            pending.extend(chunk())
        result = bytes(pending[:count])
        del pending[:count]
        return result

    assert plain_exact(len(TARGET)) == TARGET
    if not server_first:
        assert plain_exact(5) == b'first'
    salt = os.urandom(size)
    writer = algorithm(subkey(master, salt))
    write_nonce = 0

    def frame(body):
        nonlocal write_nonce
        packet = writer.encrypt(write_nonce.to_bytes(12, 'little'), len(body).to_bytes(2, 'big'), None)
        write_nonce += 1
        packet += writer.encrypt(write_nonce.to_bytes(12, 'little'), body, None)
        write_nonce += 1
        return packet

    prefix = frame(b'head') if phase.startswith('second-') else b''.join(frame(b'') for _ in range(65)) if phase == 'empty-run' else b''
    offset = size + len(prefix)
    packet = salt + prefix + frame(b'done')
    split = {'salt': 1, 'salt-end': size, 'length': offset + 1,
             'length-tag': offset + 17, 'payload-start': offset + 18,
             'payload': offset + 19, 'payload-tag': offset + 37,
             'second-length': offset + 1, 'second-payload': offset + 19,
             'empty-run': offset + 1}[phase]
    conn.sendall(packet[:split])
    Path(marker).write_text('partial SS reply sent\n')
    if server_first:
        assert plain_exact(5) == b'first'
    assert plain_exact(4) == b'tail', 'A partial Shadowsocks reply blocked later client data'
    assert not pending
    assert conn.recv(1) == b'', 'Client half-close must preserve the response direction'
    conn.sendall(packet[split:])
    conn.close()


if __name__ == '__main__':
    main()
