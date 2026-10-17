#!/usr/bin/env python3
"""Independent entry proxy relaying decrypted bytes to an independent exit peer.

Only inherited Unix sockets and fixed public test credentials are used.
The two relay directions keep separate framing/nonces; neither waits for EOF
before forwarding. Plain HTTP/SOCKS and SS AEAD entries are supported here.
"""
import base64
import errno
import os
import socket
import sys
import threading
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from generate_ss_aead_vectors import master_key, subkey
from ss_reference_peer import exact


def headers(conn):
    result = b''
    while not result.endswith(b'\r\n\r\n'):
        result += exact(conn, 1)
        assert len(result) <= 65536
    return result


def address(read):
    kind = read(1)[0]
    if kind == 3:
        host = read(read(1)[0]).decode()
    else:
        host = socket.inet_ntop(socket.AF_INET if kind == 1 else socket.AF_INET6, read(4 if kind == 1 else 16))
    return host, int.from_bytes(read(2), 'big')


def shutdown(conn, direction):
    try:
        conn.shutdown(direction)
    except OSError as error:
        if error.errno not in (errno.ENOTCONN, errno.EPIPE, errno.EINVAL):
            raise


def main():
    conn = socket.socket(fileno=int(sys.argv[1]))
    kind = sys.argv[3]
    downstream = socket.socket(fileno=int(sys.argv[4]))
    conn.settimeout(10)
    downstream.settimeout(10)
    receive = lambda: conn.recv(16384)
    transmit = conn.sendall
    if kind == 'http':
        message = headers(conn)
        assert message.startswith(b'CONNECT inner.chain.test:443 HTTP/1.1\r\n')
        expected = base64.b64encode('fixture用户:p@ss:word测试'.encode())
        assert b'Proxy-Authorization: Basic ' + expected + b'\r\n' in message
        conn.sendall(b'HTTP/1.1 200 Connection Established\r\n\r\n')
    elif kind == 'socks5':
        assert exact(conn, 3) == b'\x05\x01\x02'
        conn.sendall(b'\x05\x02')
        assert exact(conn, 1) == b'\x01'
        assert exact(conn, exact(conn, 1)[0]) == 'fixture用户'.encode()
        assert exact(conn, exact(conn, 1)[0]) == 'p@ss:word测试'.encode()
        conn.sendall(b'\x01\x00')
        assert exact(conn, 3) == b'\x05\x01\x00'
        assert address(lambda n: exact(conn, n)) == ('inner.chain.test', 443)
        conn.sendall(b'\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x01')
    elif kind == 'ss':
        master = master_key(32)
        incoming = AESGCM(subkey(master, exact(conn, 32)))
        outgoing_salt = os.urandom(32)
        outgoing = AESGCM(subkey(master, outgoing_salt))
        read_nonce = write_nonce = 0
        sent_salt = False
        pending = bytearray()

        def chunk():
            nonlocal read_nonce
            head = conn.recv(1)
            if not head:
                return b''
            count = int.from_bytes(incoming.decrypt(read_nonce.to_bytes(12, 'little'), head + exact(conn, 17), None), 'big')
            read_nonce += 1
            assert 0 < count <= 0x3fff
            body = incoming.decrypt(read_nonce.to_bytes(12, 'little'), exact(conn, count + 16), None)
            read_nonce += 1
            return body

        def plain_exact(count):
            while len(pending) < count:
                value = chunk()
                if not value:
                    raise EOFError('truncated entry target')
                pending.extend(value)
            result = bytes(pending[:count])
            del pending[:count]
            return result

        assert address(plain_exact) == ('inner.chain.test', 443)

        def receive():
            if pending:
                result = bytes(pending)
                pending.clear()
                return result
            return chunk()

        def transmit(data):
            nonlocal write_nonce, sent_salt
            packet = b'' if sent_salt else outgoing_salt
            sent_salt = True
            for offset in range(0, len(data), 0x3fff):
                body = data[offset:offset + 0x3fff]
                packet += outgoing.encrypt(write_nonce.to_bytes(12, 'little'), len(body).to_bytes(2, 'big'), None)
                write_nonce += 1
                packet += outgoing.encrypt(write_nonce.to_bytes(12, 'little'), body, None)
                write_nonce += 1
            conn.sendall(packet)
    else:
        raise AssertionError('unsupported entry fixture')
    failures = []

    def upload():
        try:
            while True:
                data = receive()
                if not data:
                    shutdown(downstream, socket.SHUT_WR)
                    return
                downstream.sendall(data)
        except Exception as error:
            # A completed exit may close while a TLS client sends close_notify.
            # Protocol validation remains in the separate destination process.
            if not isinstance(error, OSError) or error.errno not in (errno.EPIPE, errno.ECONNRESET, errno.ENOTCONN):
                failures.append(error)
            shutdown(downstream, socket.SHUT_RDWR)

    thread = threading.Thread(target=upload)
    thread.start()
    try:
        while True:
            data = downstream.recv(16384)
            if not data:
                shutdown(conn, socket.SHUT_WR)
                break
            transmit(data)
    finally:
        thread.join(timeout=11)
        assert not thread.is_alive() and not failures
        conn.close()
        downstream.close()


if __name__ == '__main__':
    main()
