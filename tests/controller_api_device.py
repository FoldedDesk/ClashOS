#!/usr/bin/env python3
"""Independent stdlib HTTP/RFC 6455 client for a forwarded device controller.

Read-only by default. --fixture permits selection only in the fixed public test
group below; it never imports, exports, or edits the user's configuration files.
"""
import argparse
import base64
import hashlib
import json
import socket
import struct
import time
from pathlib import Path
from urllib.parse import quote

GROUP = 'API+fixture /选择'
DIRECT = '直连😀'
REJECT = '拒绝+ /?%'
checks = 0


def check(condition, message):
    global checks
    if not condition:
        raise AssertionError(message)
    checks += 1


class Wire:
    def __init__(self, address):
        self.sock = socket.create_connection(address, timeout=5)
        self.sock.settimeout(5)
        self.pending = bytearray()

    def close(self):
        self.sock.close()

    def exact(self, size):
        while len(self.pending) < size:
            data = self.sock.recv(max(4096, size - len(self.pending)))
            if not data:
                raise EOFError('Device controller closed its stream')
            self.pending.extend(data)
        value = bytes(self.pending[:size])
        del self.pending[:size]
        return value

    def until(self, delimiter):
        while delimiter not in self.pending:
            data = self.sock.recv(4096)
            if not data:
                raise EOFError('Device response ended before its delimiter')
            self.pending.extend(data)
            check(len(self.pending) <= 1024 * 1024, 'Unexpected oversized response')
        end = self.pending.index(delimiter) + len(delimiter)
        value = bytes(self.pending[:end])
        del self.pending[:end]
        return value

    def headers(self):
        lines = self.until(b'\r\n\r\n').decode('latin1').split('\r\n')
        headers = {}
        for line in lines[1:]:
            if ':' in line:
                name, value = line.split(':', 1)
                headers[name.lower()] = value.strip()
        return int(lines[0].split()[1]), headers

    def frame(self):
        first, second = self.exact(2)
        check(first & 0xf0 == 0x80 and second & 0x80 == 0,
              'Server frame must be final, unmasked and have no extension bits')
        length = second
        if length == 126:
            length = struct.unpack('!H', self.exact(2))[0]
        elif length == 127:
            length = struct.unpack('!Q', self.exact(8))[0]
        check(length <= 1024 * 1024, 'Unexpected oversized WebSocket message')
        return first & 15, self.exact(length)


def masked(opcode, payload=b''):
    check(len(payload) <= 125, 'Test control frame is too long')
    mask = b'\x11\x22\x33\x44'
    return bytes((0x80 | opcode, 0x80 | len(payload))) + mask + bytes(
        value ^ mask[index % 4] for index, value in enumerate(payload))


def request(address, method, path, body=None):
    data = b'' if body is None else json.dumps(body, ensure_ascii=True).encode()
    client = Wire(address)
    try:
        client.sock.sendall((f'{method} {path} HTTP/1.1\r\nHost: localhost\r\n'
                            f'Content-Length: {len(data)}\r\nConnection: close\r\n\r\n').encode() + data)
        status, headers = client.headers()
        payload = client.exact(int(headers.get('content-length', '0')))
        return status, json.loads(payload) if payload else None
    finally:
        client.close()


def subscribe(address, websocket=False, early=b''):
    client = Wire(address)
    key = base64.b64encode(b'ClashOS-test-key').decode()
    headers = 'GET /traffic HTTP/1.1\r\nHost: localhost\r\n'
    if websocket:
        headers += ('Upgrade: websocket\r\nConnection: keep-alive, Upgrade\r\n'
                    f'Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n')
    try:
        client.sock.sendall(headers.encode() + b'\r\n' + early)
        status, returned = client.headers()
        if websocket:
            expected = base64.b64encode(hashlib.sha1(
                (key + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11').encode()).digest()).decode()
            check(status == 101 and returned.get('sec-websocket-accept') == expected,
                  'Device WebSocket handshake failed independent SHA1 check')
        else:
            check(status == 200 and returned.get('content-type') == 'application/json'
                  and 'content-length' not in returned, 'HTTP NDJSON subscription failed')
        return client
    except BaseException:
        client.close()
        raise


def sample(client, websocket=False):
    if websocket:
        opcode, data = client.frame()
        check(opcode == 1, 'Expected a traffic text message')
    else:
        data = client.until(b'\n')
    value = json.loads(data)
    check(set(value) == {'up', 'down', 'upTotal', 'downTotal'} and
          all(type(number) is int and number >= 0 for number in value.values()),
          'Traffic fields must contain actual nonnegative integer rates and totals')
    return value


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--controller', default='127.0.0.1:19090')
    parser.add_argument('--proxy', default='127.0.0.1:17890')
    parser.add_argument('--fixture', action='store_true')
    parser.add_argument('--output', type=Path, required=True)
    options = parser.parse_args()
    address = lambda value: (value.rsplit(':', 1)[0], int(value.rsplit(':', 1)[1]))
    controller, proxy = address(options.controller), address(options.proxy)
    status, version = request(controller, 'GET', '/version')
    check(status == 200, 'Device controller unavailable')
    status, listed = request(controller, 'GET', '/proxies')
    check(status == 200, 'Proxy list failed')
    proxies = listed['proxies']
    names = ['DIRECT', 'REJECT'] + [name for name in proxies if any(ord(c) > 127 for c in name)][:4]
    for name in names:
        status, detail = request(controller, 'GET', '/proxies/' + quote(name, safe=''))
        check(status == 200 and detail['name'] == name and detail['type'] == proxies[name]['type'],
              'Encoded proxy detail disagrees with the list')
        check(not any(key in detail for key in ('password', 'uuid', 'server', 'cipher')),
              'Controller exposed node credentials')
    check(request(controller, 'GET', '/proxies/missing-public-fixture')[0] == 404,
          'Unknown proxy must return HTTP 404')
    check(request(controller, 'GET', '/proxies/%GG')[0] == 400,
          'Malformed proxy encoding must return HTTP 400')
    for line in ('GET /traffic HTTP/2.0', 'GET /traffic HTTP/1.1 extra'):
        bad = Wire(controller)
        try:
            bad.sock.sendall((line + '\r\nHost: localhost\r\n\r\n').encode())
            check(bad.headers()[0] == 400, 'Malformed request line was accepted')
        finally:
            bad.close()
    bad = Wire(controller)
    try:
        bad.sock.sendall(b'GET /traffic HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\n'
                        b'Connection: Upgrade\r\nSec-WebSocket-Version: 12\r\n\r\n')
        status, headers = bad.headers()
        check(status == 426 and headers.get('sec-websocket-version') == '13',
              'Unsupported WS version must advertise version 13')
    finally:
        bad.close()
    bad = subscribe(controller, True, b'\x89\x00')
    try:
        check(bad.frame() == (8, b'\x03\xea'), 'Unmasked control frame must close with 1002')
    finally:
        bad.close()

    if options.fixture:
        check(GROUP in proxies and proxies[GROUP]['all'] == [DIRECT, REJECT],
              'Fixed public fixture is absent; refusing to change any selection')
        route = '/proxies/' + quote(GROUP, safe='')
        check(request(controller, 'PUT', route, {'name': REJECT})[0] == 204,
              'Escaped Unicode proxy selection failed')
        check(request(controller, 'GET', route)[1]['now'] == REJECT,
              'Group detail did not reflect successful selection')
        check(request(proxy, 'GET', 'http://127.0.0.1:9090/version')[0] == 403,
              'Actual HTTP proxy did not enforce selected REJECT')
        check(request(controller, 'PUT', route, {'name': DIRECT})[0] == 204,
              'Direct fixture selection failed')
        check(request(controller, 'PUT', route, {'other': REJECT})[0] == 400 and
              request(controller, 'GET', route)[1]['now'] == DIRECT,
              'Malformed selection changed runtime state')
        check(request(proxy, 'GET', 'http://127.0.0.1:9090/version')[0] == 200,
              'Actual HTTP proxy did not forward selected DIRECT')

    print('Proxy details and HTTP status checks passed.', flush=True)
    traffic_evidence = []
    http = subscribe(controller)
    ws = subscribe(controller, True, masked(9, b'p\x00ng'))
    try:
        check(ws.frame() == (10, b'p\x00ng'), 'Early masked ping was lost')
        before_http, before_ws = sample(http), sample(ws, True)
        if options.fixture:
            for _ in range(20):
                check(request(proxy, 'GET', 'http://127.0.0.1:9090/proxies')[0] == 200,
                      'Public proxy traffic generation failed')
            for client, websocket, before in ((http, False, before_http), (ws, True, before_ws)):
                saw_rate = False
                for _ in range(4):
                    value = sample(client, websocket)
                    saw_rate |= value['up'] > 0 and value['down'] > 0
                    if value['upTotal'] > before['upTotal'] and value['downTotal'] > before['downTotal'] and saw_rate:
                        break
                check(saw_rate and value['upTotal'] > before['upTotal'] and value['downTotal'] > before['downTotal'],
                      'Traffic stream did not follow actual proxy bytes')
                traffic_evidence.append({'protocol': 'websocket' if websocket else 'http',
                                         'before': before, 'after': value})
        fragment = masked(9, b'partial-control')
        ws.sock.sendall(fragment[:1])
        sample(ws, True)
        ws.sock.sendall(fragment[1:])
        # A scheduled text tick can precede the pong; no frame bytes may be lost.
        for _ in range(3):
            frame = ws.frame()
            if frame[0] == 10:
                break
        check(frame == (10, b'partial-control'), 'Partial ping did not resume')
        close = struct.pack('!H', 1000) + '再见'.encode()
        ws.sock.sendall(masked(8, close))
        for _ in range(3):
            frame = ws.frame()
            if frame[0] == 8:
                break
        check(frame == (8, close), 'WebSocket close was not acknowledged')
    finally:
        http.close()
        ws.close()
    print('HTTP/WS streams, traffic counters and frame handling passed.', flush=True)
    time.sleep(0.1)
    clients = []
    try:
        for _ in range(16):
            clients.append(subscribe(controller))
        check(request(controller, 'GET', '/traffic')[0] == 429,
              'Device subscriber limit was not enforced')
        check(request(controller, 'GET', '/version')[0] == 200,
              'Traffic subscriptions blocked ordinary control requests')
    finally:
        for client in clients:
            client.close()
    time.sleep(0.1)
    reusable = subscribe(controller)
    reusable.close()
    record = {'version': version['version'], 'assertions': checks,
              'transport': 'Independent Python stdlib HTTP and RFC 6455 client over HDC forwarding',
              'fixtureSelectionAndRealForwarding': options.fixture,
              'proxyDetails': True, 'encodedNames': True, 'missing404': True, 'invalidPath400': True,
              'invalidRequestLine400': True, 'unsupportedWsVersion426': True, 'unmaskedFrame1002': True,
              'httpNdjson': True, 'websocketHandshake': True, 'coalescedPing': True,
              'partialPingKeepsTicks': True, 'closeHandshake': True,
              'actualTrafficCounters': options.fixture, 'subscriberLimit16': True,
              'normalApiUnderLoad': True, 'closedSlotsReusable': True,
              'trafficEvidence': traffic_evidence}
    options.output.write_text(json.dumps(record, ensure_ascii=False, indent=2) + '\n')
    print(f'Device controller checks passed: {checks}', flush=True)


if __name__ == '__main__':
    main()
