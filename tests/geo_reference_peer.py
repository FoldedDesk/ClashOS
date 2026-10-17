#!/usr/bin/env python3
"""Independent HTTP resource server on an inherited socket; no public network listener."""
from pathlib import Path
import socket
import sys
import time

conn = socket.socket(fileno=int(sys.argv[1]))
conn.settimeout(4)
try:
    request = b''
    while b'\r\n\r\n' not in request:
        part = conn.recv(4096)
        if not part:
            raise EOFError()
        request += part
    assert request.startswith(b'GET /') and b'HTTP/1.1\r\n' in request
    if sys.argv[4] == 'timeout':
        time.sleep(1.5)
    else:
        body = Path(sys.argv[4]).read_bytes()
        conn.sendall(b'HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: ' + str(len(body)).encode() + b'\r\nConnection: close\r\n\r\n' + body)
except (BrokenPipeError, ConnectionResetError, EOFError):
    pass
finally:
    conn.close()
