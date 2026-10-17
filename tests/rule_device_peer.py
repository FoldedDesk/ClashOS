#!/usr/bin/env python3
"""Loopback HTTP/MRS fixture with a fixed 204 endpoint and file-controlled updates."""
import argparse
import hashlib
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import os
from pathlib import Path
import time


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--ready-file', required=True, type=Path)
    parser.add_argument('--mode-file', required=True, type=Path)
    parser.add_argument('--stop-file', required=True, type=Path)
    parser.add_argument('--mrs', required=True, type=Path)
    parser.add_argument('--lifetime', type=int, default=600)
    args = parser.parse_args()
    data = args.mrs.read_bytes()

    class Handler(BaseHTTPRequestHandler):
        protocol_version = 'HTTP/1.1'

        def setup(self):
            super().setup()
            self.connection.settimeout(3)

        def do_GET(self):
            self.close_connection = True
            if self.path == '/verify':
                self.send_response(204)
                self.send_header('Content-Length', '0')
                self.send_header('Connection', 'close')
                self.end_headers()
                return
            if self.path != '/google.mrs':
                self.send_error(404)
                return
            mode = args.mode_file.read_text().strip() if args.mode_file.exists() else 'valid'
            body = b'invalid MRS update' if mode == 'broken' else data
            self.send_response(200)
            self.send_header('Content-Type', 'application/octet-stream')
            self.send_header('Content-Length', str(len(body)))
            self.send_header('Connection', 'close')
            self.end_headers()
            self.wfile.write(body)
            print(json.dumps({'event': 'rule-resource', 'mode': mode, 'bytes': len(body)}), flush=True)

        def log_message(self, *_):
            pass

    with HTTPServer(('127.0.0.1', 0), Handler) as server:
        server.timeout = .2
        metadata = {'port': server.server_port, 'pid': os.getpid(), 'mrsSha256': hashlib.sha256(data).hexdigest()}
        args.ready_file.write_text(json.dumps(metadata))
        print(json.dumps({'event': 'ready', **metadata}), flush=True)
        deadline = time.monotonic() + min(max(args.lifetime, 1), 600)
        while time.monotonic() < deadline and not args.stop_file.exists():
            server.handle_request()
    print(json.dumps({'event': 'stopped'}), flush=True)


if __name__ == '__main__':
    main()
