#!/usr/bin/env python3
"""Loopback-only fixed HTTP/TLS endpoints for an HDC-rport sniffer check.

Uses the public vmess.test fixture certificate. Never forwards traffic.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import socket
import ssl
import threading
import time


def serve(listener, context, stop, udp=False):
    def request(conn):
        try:
            conn.settimeout(8)
            if context:
                conn = context.wrap_socket(conn, server_side=True)
            if udp:
                def exact(size):
                    result = b''
                    while len(result) < size:
                        data = conn.recv(size - len(result))
                        if not data:
                            raise EOFError()
                        result += data
                    return result
                address = b'\x03\x12sniff.fixture.test' + (18091).to_bytes(2, 'big')
                # The domain is 18 bytes; require the sniffed destination both
                # in the association header and every independently framed packet.
                assert exact(56) == hashlib.sha224(b'public-sniffer-device').hexdigest().encode()
                assert exact(3) == b'\r\n\x03'
                assert exact(len(address)) == address and exact(2) == b'\r\n'
                vectors = json.loads((Path(__file__).parent / 'fixtures/sniffer/vectors.json').read_text())
                allowed = {bytes.fromhex(vectors[key]) for key in ['quic_v1', 'quic_v2', 'quic_fragment_head', 'quic_fragment_tail']}
                allowed.add(bytes.fromhex(vectors['quic_fragment_head'] + vectors['quic_fragment_tail']))
                for _ in range(32):
                    assert exact(len(address)) == address
                    size = int.from_bytes(exact(2), 'big')
                    assert size <= 16384 and exact(2) == b'\r\n'
                    payload = exact(size)
                    assert payload in allowed
                    conn.sendall(address + size.to_bytes(2, 'big') + b'\r\n' + payload)
                    print(json.dumps({'event': 'QUIC-echo', 'bytes': size, 'destination': 'sniff.fixture.test:18091'}), flush=True)
                return
            data = b''
            while b'\r\n\r\n' not in data and len(data) < 16384:
                chunk = conn.recv(4096)
                if not chunk:
                    return
                data += chunk
            assert data.startswith(b'GET /probe HTTP/1.1\r\n')
            host = b'vmess.test' if context else b'sniff.fixture.test'
            assert b'\r\nHost: ' + host + b'\r\n' in data
            conn.sendall(b'HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n')
            print(json.dumps({'event': 'verified', 'transport': 'TLS' if context else 'HTTP', 'status': 204}), flush=True)
        except EOFError:
            pass
        except (OSError, AssertionError):
            print(json.dumps({'event': 'peer-closed-or-invalid'}), flush=True)
        finally:
            conn.close()

    while not stop.is_set():
        try:
            conn, _ = listener.accept()
        except socket.timeout:
            continue
        threading.Thread(target=request, args=(conn,), daemon=True).start()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--ready-file', required=True, type=Path)
    parser.add_argument('--tls-port', type=int, default=18089)
    parser.add_argument('--http-port', type=int, default=18090)
    parser.add_argument('--udp-tls-port', type=int, default=18092)
    parser.add_argument('--lifetime', type=int, default=600)
    args = parser.parse_args()
    fixtures = Path(__file__).parent / 'fixtures/vmess'
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(fixtures / 'server.pem', fixtures / 'server-key.pem')
    context.set_alpn_protocols(['http/1.1'])

    def sni(conn, name, ctx):
        if name != 'vmess.test':
            return ssl.ALERT_DESCRIPTION_UNRECOGNIZED_NAME
    context.sni_callback = sni
    listeners = []
    stop = threading.Event()
    try:
        for port, ctx, udp in [(args.tls_port, context, False), (args.http_port, None, False), (args.udp_tls_port, context, True)]:
            listener = socket.socket()
            listeners.append(listener)
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind(('127.0.0.1', port))
            listener.listen(8)
            listener.settimeout(.25)
            threading.Thread(target=serve, args=(listener, ctx, stop, udp), daemon=True).start()
        metadata = {'pid': os.getpid(), 'tlsPort': listeners[0].getsockname()[1], 'httpPort': listeners[1].getsockname()[1], 'udpTlsPort': listeners[2].getsockname()[1]}
        args.ready_file.write_text(json.dumps(metadata))
        print(json.dumps({'event': 'ready', **metadata}), flush=True)
        time.sleep(min(max(args.lifetime, 1), 1800))
    finally:
        stop.set()
        for listener in listeners:
            listener.close()


if __name__ == '__main__':
    main()
