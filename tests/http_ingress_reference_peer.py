#!/usr/bin/env python3
"""Independent HTTP origin for ingress checks, using public data and inherited FDs."""
import hashlib
import base64
import http.client
import select
import socket
import sys
import time
from pathlib import Path


BODY = b'data\x00xyz'
CHUNKS = b'4;ext="a,b"\r\ndata\r\n4\r\n\x00xyz\r\n0\r\nX-Trailer: ok\r\n\r\n'


def exact(stream, size):
    output = b''
    while len(output) < size:
        part = stream.read(size - len(output))
        assert part, 'Truncated public fixture payload'
        output += part
    return output


def main():
    channel = socket.socket(fileno=int(sys.argv[1]))
    channel.settimeout(5)
    number, mode, fault = int(sys.argv[2]), sys.argv[3], sys.argv[4]
    if mode == 'unread-early':
        if fault == 'invalid':
            channel.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\nprivate-response')
        elif fault != 'empty':
            framing = b'Transfer-Encoding: chunked\r\n' if fault == 'chunked' else b'Content-Length: 8\r\n' if fault == 'length' else b''
            body = b'8\r\ndenied!!\r\n0\r\n\r\n' if fault == 'chunked' else b'denied!!'
            channel.sendall(b'HTTP/1.1 413 Payload Too Large\r\n' + framing + b'Connection: close\r\n\r\n' + body)
        channel.close()
        return
    stream = channel.makefile('rb', buffering=0)
    line = stream.readline(65537)
    headers = http.client.parse_headers(stream)
    assert headers.get('Proxy-Authorization') is None, 'Proxy credentials reached the origin'
    assert headers.get('Proxy-Connection') is None, 'Proxy hop header reached the origin'
    if mode in ('pipeline', 'body', 'head'):
        if mode == 'body':
            assert line == b'POST /1 HTTP/1.1\r\n'
            expected = BODY if number == 0 else CHUNKS
            assert exact(stream, len(expected)) == expected, 'Upload framing/payload changed'
        elif mode == 'head':
            assert line == b'HEAD /1 HTTP/1.1\r\n'
        else:
            assert line == f'GET /{number} HTTP/1.1\r\n'.encode(), 'Request was not routed as an origin-form message'
        assert headers['Host'] == f'origin{1 if mode in ("body", "head") else number}.fixture.test', 'Absolute target and origin Host disagree'
        # A second pipelined proxy request belongs to a separate origin and may
        # never be appended as this request's unframed payload.
        ready, _, _ = select.select([channel], [], [], .1)
        assert not ready or not channel.recv(8192, socket.MSG_PEEK), 'Next request or credentials leaked into this origin'
        body = f'origin-{1 if mode == "body" else number}'.encode()
        channel.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: ' + str(999 if mode == 'head' else len(body)).encode() + b'\r\nConnection: close\r\n\r\n' + (b'' if mode == 'head' else body))
    elif mode == 'upgrade':
        assert line == b'GET /socket HTTP/1.1\r\n'
        assert 'upgrade' in [token.strip().lower() for token in headers['Connection'].split(',')], 'Connection Upgrade was removed'
        assert headers['Upgrade'].lower() == 'websocket'
        assert headers.get('X-Hop') is None, 'Connection-nominated header reached origin'
        accept = base64.b64encode(hashlib.sha1((headers['Sec-WebSocket-Key'] + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11').encode()).digest())
        channel.sendall(b'HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: ' + accept + b'\r\n\r\n\x81\x05hello')
        assert exact(stream, 8) == b'\x81\x82\x01\x02\x03\x04ik', 'Optimistic masked frame was lost'
        channel.sendall(b'\x88\x02\x03\xe8')
    elif mode == 'expect':
        assert line == b'POST /upload HTTP/1.1\r\n' and headers['Expect'].lower() == '100-continue'
        channel.sendall(b'HTTP/1.1 103 Early Hints\r\nLink: </style>; rel=preload\r\n\r\nHTTP/1.1 100 Continue\r\n\r\n')
        assert exact(stream, int(headers['Content-Length'])) == BODY
        channel.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 8\r\n\r\nuploaded')
    elif mode == 'early-final':
        framing, marker = fault.split('|', 1)
        assert line == b'POST /upload HTTP/1.1\r\n' and headers['Expect'].lower() == '100-continue'
        header = b'Transfer-Encoding: chunked\r\n' if framing == 'chunked' else b'Content-Length: 8\r\n' if framing == 'length' else b''
        channel.sendall(b'HTTP/1.1 413 Payload Too Large\r\n' + header + b'Connection: close\r\n\r\n')
        deadline = time.monotonic() + 5
        while not Path(marker).exists() and time.monotonic() < deadline:
            time.sleep(.001)
        assert Path(marker).exists(), 'Client did not observe the early final response'
        try:
            channel.sendall(b'8\r\ndenied!!\r\n0\r\n\r\n' if framing == 'chunked' else b'denied!!')
        except (BrokenPipeError, ConnectionResetError):
            pass  # The pre-fix proxy closes before the independent response body.
    elif mode == 'response':
        assert line.startswith(b'GET /verify HTTP/1.')
        if fault == 'canonical-host':
            assert headers['Host'] == ('[2001:db8::1]:8080' if number == 6 else 'origin.fixture.test:8080')
            assert headers['Authorization'] == 'Bearer public-origin'
            assert headers.get('X-Hop') is None
        responses = {
            'chunked': b'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: 999\r\nConnection: X-Hop\r\nX-Hop: remove\r\n\r\n' + CHUNKS,
            'equal-length': b'HTTP/1.1 200 OK\r\nContent-Length: 8, 8\r\nContent-Length: 8\r\n\r\n' + BODY,
            'bad-length': b'HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Length: 8\r\n\r\n' + BODY,
            'truncated-length': b'HTTP/1.1 200 OK\r\nContent-Length: 99\r\n\r\nshort',
            'eof': b'HTTP/1.1 200 OK\r\nX-Result: public\r\n\r\n' + BODY,
            'bad-status': b'HTTP/1.1 20x Bad\r\nContent-Length: 0\r\n\r\n',
            'bad-te': b'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked, gzip\r\n\r\n',
            'bad-upgrade': b'HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\nprivate-response',
            'too-many-interim': b'HTTP/1.1 103 Early Hints\r\n\r\n' * 17,
            'bad-chunk': b'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n+4\r\ndata\r\n0\r\n\r\n',
            'bad-trailer': b'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\nProxy-Authorization: private-response\r\n\r\n',
            'canonical-host': b'HTTP/1.1 200 OK\r\nContent-Length: 8\r\n\r\n' + BODY,
            'http10': b'HTTP/1.0 200 OK\r\nContent-Length: 8\r\n\r\n' + BODY,
            'http10-chunked': b'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nTrailer: X-Trailer\r\n\r\n' + CHUNKS,
        }
        response = responses[fault]
        try:
            for at in range(0, len(response), number or len(response)):
                channel.sendall(response[at:at+(number or len(response))])
                if number == 1: time.sleep(.0001)
        except (BrokenPipeError, ConnectionResetError):
            assert fault.startswith('bad-') or fault == 'too-many-interim'
    elif mode == 'invalid-body':
        assert line.startswith(b'POST /upload HTTP/1.1')
        tail = b''
        while True:
            part = stream.read(8192)
            if not part: break
            tail += part
        assert b'Proxy-Authorization' not in tail and b'origin2' not in tail, 'Malformed body leaked protected next-request data'
    else:
        raise AssertionError('Unknown public peer case')
    stream.close()
    channel.close()


if __name__ == '__main__':
    main()
