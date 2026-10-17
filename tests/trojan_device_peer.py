#!/usr/bin/env python3
"""Loopback-only Trojan TLS/WS fixture for an emulator reached through HDC rport.

This server only returns a fixed HTTP 204 for trojan.device.test:80. It cannot
forward arbitrary traffic and uses the repository's public test certificate.
"""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import socket
import ssl
import threading
import time

PASSWORD = b'device-public-fixture'


class Stream:
    def __init__(self, conn):
        self.conn, self.websocket, self.buffer = conn, False, b''

    def raw(self, length):
        data = b''
        while len(data) < length:
            part = self.conn.recv(length - len(data))
            if not part:
                raise EOFError()
            data += part
        return data

    def exact(self, length):
        if not self.websocket:
            return self.raw(length)
        while len(self.buffer) < length:
            first, second = self.raw(2)
            assert first & 0x80 and not first & 0x70 and second & 0x80
            size = second & 127
            if size in (126, 127):
                size = int.from_bytes(self.raw(2 if size == 126 else 8), 'big')
            assert size <= 65536
            mask, encrypted = self.raw(4), self.raw(size)
            payload = bytes(byte ^ mask[i % 4] for i, byte in enumerate(encrypted))
            if first & 15 == 10:
                continue
            assert first & 15 == 2
            self.buffer += payload
        result, self.buffer = self.buffer[:length], self.buffer[length:]
        return result

    def send(self, payload, opcode=2):
        prefix = b''
        if self.websocket:
            prefix = bytes([0x80 | opcode, len(payload)]) if len(payload) < 126 else bytes([0x80 | opcode, 126]) + len(payload).to_bytes(2, 'big')
        self.conn.sendall(prefix + payload)

    def upgrade(self):
        # Peek the first plaintext byte to distinguish HTTP Upgrade from Trojan authentication.
        first = self.raw(1)
        if first != b'G':
            self.buffer = first
            return False
        request = first
        while not request.endswith(b'\r\n\r\n'):
            assert len(request) < 16384
            request += self.raw(1)
        lines = request.decode().split('\r\n')
        assert lines[0] == 'GET /trojan-device HTTP/1.1'
        headers = dict(line.split(': ', 1) for line in lines[1:] if ': ' in line)
        accept = base64.b64encode(hashlib.sha1((headers['Sec-WebSocket-Key'] + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11').encode()).digest())
        self.conn.sendall(b'HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ' + accept + b'\r\n\r\n')
        self.websocket = True
        self.send(b'device-ping', opcode=9)
        return True


def serve(conn, context):
    conn.settimeout(8)
    try:
        conn = context.wrap_socket(conn, server_side=True)
        stream = Stream(conn)
        ws = stream.upgrade()
        # The first authentication byte was consumed while checking for WebSocket.
        digest = stream.exact(56) if ws else stream.buffer + stream.raw(55)
        assert digest == hashlib.sha224(PASSWORD).hexdigest().encode()
        assert stream.exact(3) == b'\r\n\x01'
        assert stream.exact(1) == b'\x03'
        length = stream.exact(1)[0]
        assert stream.exact(length) == b'trojan.device.test'
        assert stream.exact(4) == b'\x00\x50\r\n'
        request = b''
        while not request.endswith(b'\r\n\r\n'):
            assert len(request) < 16384
            request += stream.exact(1)
        assert request.startswith(b'GET /verify HTTP/1.1\r\n')
        stream.send(b'HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n')
        if ws:
            stream.send(b'', opcode=8)
        print(json.dumps({'event': 'verified-request', 'transport': 'ws-tls' if ws else 'tls', 'status': 204}), flush=True)
    except ssl.SSLError:
        print(json.dumps({'event': 'tls-closed'}), flush=True)
    except (EOFError, OSError):
        print(json.dumps({'event': 'peer-closed'}), flush=True)
    finally:
        conn.close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--ready-file', required=True, type=Path)
    parser.add_argument('--lifetime', type=int, default=300)
    args = parser.parse_args()
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.set_alpn_protocols(['http/1.1'])
    fixtures = Path(__file__).parent / 'fixtures/vmess'
    context.load_cert_chain(fixtures / 'server.pem', fixtures / 'server-key.pem')
    with socket.socket() as listener:
        listener.bind(('127.0.0.1', 0))
        listener.listen(8)
        listener.settimeout(.5)
        metadata = {'port': listener.getsockname()[1], 'pid': os.getpid()}
        args.ready_file.write_text(json.dumps(metadata))
        print(json.dumps({'event': 'ready', **metadata}), flush=True)
        until = time.monotonic() + min(max(args.lifetime, 1), 600)
        while time.monotonic() < until:
            try:
                conn, _ = listener.accept()
            except socket.timeout:
                continue
            threading.Thread(target=serve, args=(conn, context), daemon=True).start()


if __name__ == '__main__':
    main()
