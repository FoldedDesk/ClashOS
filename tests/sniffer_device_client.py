#!/usr/bin/env python3
"""Independent HTTP/SOCKS -> TLS client for the emulator sniffer fixture.

The requested IP is deliberately unreachable. A matching sniffer config must
route/rewrite vmess.test to the HDC-reversed fixed endpoint for TLS to succeed.
"""
import argparse
import json
from pathlib import Path
import socket
import ssl


def exact(conn, size):
    data = b''
    while len(data) < size:
        part = conn.recv(size - len(data))
        if not part:
            raise EOFError('Proxy closed its handshake')
        data += part
    return data


def headers(conn):
    data = b''
    while not data.endswith(b'\r\n\r\n'):
        assert len(data) < 16384
        data += exact(conn, 1)
    return data


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('kind', choices=['http-tls', 'socks-tls', 'http-host', 'socks-http'])
    parser.add_argument('--proxy-port', type=int, required=True)
    parser.add_argument('--target-port', type=int, required=True)
    args = parser.parse_args()
    tls = args.kind.endswith('tls')
    host = 'vmess.test' if tls else 'sniff.fixture.test'
    with socket.create_connection(('127.0.0.1', args.proxy_port), timeout=8) as raw:
        conn = raw
        if args.kind.startswith('socks'):
            conn.sendall(b'\x05\x01\x00')
            assert exact(conn, 2) == b'\x05\x00'
            conn.sendall(b'\x05\x01\x00\x01' + socket.inet_aton('203.0.113.10') + args.target_port.to_bytes(2, 'big'))
            assert exact(conn, 10)[1] == 0
        elif tls:
            conn.sendall(f'CONNECT 203.0.113.10:{args.target_port} HTTP/1.1\r\nHost: 203.0.113.10\r\n\r\n'.encode())
            assert headers(conn).startswith(b'HTTP/1.1 200 ')
        if tls:
            # The public legacy fixture has no Authority Key Identifier. Require
            # CA-chain, expiry and hostname validation without the newer strict
            # extension policy enabled by Python 3.13's create_default_context.
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.load_verify_locations(cafile=str(Path(__file__).parent / 'fixtures/vmess/ca.pem'))
            context.set_alpn_protocols(['http/1.1'])
            conn = context.wrap_socket(raw, server_hostname=host)
        try:
            target = f'http://203.0.113.10:{args.target_port}/probe' if args.kind == 'http-host' else '/probe'
            conn.sendall(f'GET {target} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n'.encode())
            assert headers(conn).startswith(b'HTTP/1.1 204 ')
            print(json.dumps({'kind': args.kind, 'status': 204, 'tlsCertificateVerified': tls, 'originalIP': '203.0.113.10'}))
        finally:
            if tls:
                conn.close()


if __name__ == '__main__':
    main()
