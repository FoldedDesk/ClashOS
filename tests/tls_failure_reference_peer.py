#!/usr/bin/env python3
"""Independent OpenSSL handshake controls; inherited Unix sockets only."""
import socket
import ssl
import sys
from ss_reference_peer import exact
from trojan_reference_peer import context

conn = socket.socket(fileno=int(sys.argv[1]))
conn.settimeout(5)
mode = sys.argv[3]
if mode in ('valid', 'untrusted', 'wronghost'):
    try:
        conn = context().wrap_socket(conn, server_side=True)
    except ssl.SSLError:
        assert mode != 'valid'
    else:
        assert mode == 'valid', 'Client accepted a bad certificate'
        assert exact(conn, 4) == b'done'
        conn.sendall(b'ok')
else:
    header = exact(conn, 5)
    assert header[0] == 22
    exact(conn, int.from_bytes(header[3:], 'big'))
    if mode == 'alert':
        conn.sendall(b'\x15\x03\x03\x00\x02\x02\x28')
    elif mode == 'invalid':
        conn.sendall(b'HTTP/1.1 503 Not TLS\r\n\r\n')
    elif mode == 'timeout':
        assert not conn.recv(1), 'Timed-out client must release its descriptor'
    else:
        assert mode == 'eof'
conn.close()
