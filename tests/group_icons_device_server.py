#!/usr/bin/env python3
"""Loopback fixed image fixtures for HDC reverse port 18095; no file browsing."""
import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import threading
import time
from urllib.parse import urlsplit

PNG = (Path(__file__).parent / 'fixtures/icons/quadrants.png').read_bytes()
SVG = b'<svg xmlns="http://www.w3.org/2000/svg" width="64" height="64"><rect width="64" height="64" fill="#3478f6"/><path d="M8 32L28 52L56 10" stroke="white" stroke-width="8" fill="none"/></svg>'


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        path = urlsplit(self.path).path
        if path == '/quadrants.png':
            content, mime = PNG, 'image/png'
        elif path == '/check.svg':
            content, mime = SVG, 'image/svg+xml'
        else:
            self.send_error(404)
            print(json.dumps({'event': 'missing-icon'}), flush=True)
            return
        self.send_response(200)
        self.send_header('Content-Type', mime)
        self.send_header('Content-Length', str(len(content)))
        self.end_headers()
        self.wfile.write(content)
        print(json.dumps({'event': 'served-icon', 'path': path}), flush=True)

    def log_message(self, *args):
        pass


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--ready-file', type=Path, required=True)
    parser.add_argument('--port', type=int, default=18095)
    parser.add_argument('--lifetime', type=int, default=1200)
    args = parser.parse_args()
    with ThreadingHTTPServer(('127.0.0.1', args.port), Handler) as server:
        metadata = {'port': server.server_port, 'pid': os.getpid()}
        args.ready_file.write_text(json.dumps(metadata))
        print(json.dumps({'event': 'ready', **metadata}), flush=True)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        time.sleep(min(max(args.lifetime, 1), 1800))
        server.shutdown()


if __name__ == '__main__':
    main()
