#!/usr/bin/env python3
"""Independent SS TCP/UDP server: Python cryptography/OpenSSL and inherited Unix sockets only."""
import errno
import os
import socket
import sys
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from generate_ss_aead_vectors import master_key, subkey

PAYLOAD = bytes((i * 17 + 3) % 256 for i in range(50000))
RESPONSE = b"ss-response:" + PAYLOAD[::-1]
TARGET = b"\x03\x0btarget.test\x01\xbb"

def exact(conn, size):
    data = b""
    while len(data) < size:
        part = conn.recv(size - len(data))
        if not part:
            raise EOFError("truncated SS input")
        data += part
    return data

def main():
    fd, method, mode = int(sys.argv[1]), sys.argv[3], sys.argv[4]
    conn = socket.socket(fileno=fd)
    conn.settimeout(8)
    size = 16 if method == "aes-128-gcm" else 32
    algorithm = ChaCha20Poly1305 if method == "chacha20-ietf-poly1305" else AESGCM
    master = master_key(size)
    if mode == "udp":
        salts = set()
        for round in range(3):
            packet = conn.recv(65536)
            salt = packet[:size]
            assert len(packet) <= 65507 and salt not in salts
            salts.add(salt)
            plain = algorithm(subkey(master, salt)).decrypt(bytes(12), packet[size:], None)
            expected = (b"packet-0", b"", bytes(i % 256 for i in range(65507 - size - 16 - len(TARGET))))[round]
            assert plain == TARGET + expected, "SS UDP payload, key length, salt or nonce differs"
            body = b"udp-response:" + expected[::-1] if round < 2 else b"max-accepted"
            response_salt = os.urandom(size)
            address = b"\x01\x08\x08\x08\x08\x01\xbb"
            response = response_salt + algorithm(subkey(master, response_salt)).encrypt(bytes(12), address + body, None)
            if round == 0:
                conn.send(packet)  # Reflection of an authenticated client packet must be filtered.
                conn.send(response[:-1] + bytes([response[-1] ^ 1]))
            conn.send(response)
            if round == 0:
                conn.send(response)  # A valid duplicate must not appear as a second reply.
        conn.close()
        return
    client_salt = exact(conn, size)
    reader = algorithm(subkey(master, client_salt))
    nonce = 0
    chunks = []
    while True:
        first = conn.recv(1)
        if not first:
            break
        length = reader.decrypt(nonce.to_bytes(12, "little"), first + exact(conn, 17), None)
        nonce += 1
        count = int.from_bytes(length, "big")
        assert 0 < count <= 0x3fff
        chunks.append(reader.decrypt(nonce.to_bytes(12, "little"), exact(conn, count + 16), None))
        nonce += 1
    assert chunks[0] == TARGET and b"".join(chunks[1:]) == PAYLOAD
    assert nonce >= 10 and nonce % 2 == 0, "Client must split the 50 kB payload into bounded SS chunks"
    salt = bytes(range(128, 128 + size))
    writer = algorithm(subkey(master, salt))
    if mode == "tcp-short-salt":
        packet = salt[:size // 2]
    elif mode == "tcp-length-tag":
        frame = writer.encrypt(bytes(12), b"\x00\x01", None)
        packet = salt + frame[:-1] + bytes([frame[-1] ^ 1])
    elif mode == "tcp-payload-tag":
        frame = writer.encrypt(bytes(12), b"\x00\x01", None) + writer.encrypt((1).to_bytes(12, "little"), b"x", None)
        packet = salt + frame[:-1] + bytes([frame[-1] ^ 1])
    else:
        packet, nonce = salt, 0
        for i in range(0, len(RESPONSE), 0x3fff):
            part = RESPONSE[i:i + 0x3fff]
            packet += writer.encrypt(nonce.to_bytes(12, "little"), len(part).to_bytes(2, "big"), None)
            nonce += 1
            packet += writer.encrypt(nonce.to_bytes(12, "little"), part, None)
            nonce += 1
    try:
        for i in range(0, len(packet), 97):
            conn.sendall(packet[i:i + 97])
    except OSError as error:
        if mode == "tcp" or error.errno not in (errno.EPIPE, errno.ECONNRESET, errno.ENOTCONN):
            raise
    conn.close()

if __name__ == "__main__":
    main()
