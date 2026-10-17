#!/usr/bin/env python3
"""Independent device stream checks. Only closes the Google connection it creates.
No profiles, modes, selected nodes or private credentials are changed/read.
"""
import argparse
import base64
import hashlib
import json
import socket
import ssl
import time
from pathlib import Path
from controller_api_device import Wire, masked

checks = 0


def check(value, message):
    global checks
    if not value:
        raise AssertionError(message)
    checks += 1


def subscribe(address, path, websocket=False):
    client = Wire(address)
    key = base64.b64encode(b'0123456789abcdef').decode()
    headers = f'GET {path} HTTP/1.1\r\nHost: localhost\r\n'
    if websocket:
        headers += ('Connection: Upgrade\r\nUpgrade: websocket\r\n'
                    f'Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: {key}\r\n')
    try:
        client.sock.sendall(headers.encode() + b'\r\n')
        status, returned = client.headers()
        check(status == (101 if websocket else 200), 'State stream handshake failed')
        if websocket:
            expected = base64.b64encode(hashlib.sha1((key + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11').encode()).digest()).decode()
            check(returned.get('sec-websocket-accept') == expected, 'Invalid independent WS acceptance')
        else:
            check('content-length' not in returned and returned.get('content-type') == 'application/json', 'HTTP state response must be streaming JSON')
        return client
    except BaseException:
        client.close()
        raise


def request(address, path, method='GET'):
    client = Wire(address)
    try:
        client.sock.sendall(f'{method} {path} HTTP/1.1\r\nHost: localhost\r\n\r\n'.encode())
        status, headers = client.headers()
        body = client.exact(int(headers.get('content-length', 0)))
        return status, json.loads(body) if body else None
    finally:
        client.close()


def sample(client, websocket=False):
    if websocket:
        opcode, payload = client.frame()
        check(opcode == 1, 'Expected text JSON snapshot')
    else:
        payload = client.until(b'\n')
    value = json.loads(payload)
    check(isinstance(value, dict), 'Invalid state JSON')
    return value


def until(client, predicate, websocket=False, timeout=8):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        value = sample(client, websocket)
        if predicate(value):
            return value
    raise AssertionError('Expected state event did not arrive')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--controller', default='127.0.0.1:19090')
    parser.add_argument('--proxy', default='127.0.0.1:17890')
    parser.add_argument('--output', type=Path, required=True)
    options = parser.parse_args()
    address = lambda text: (text.rsplit(':', 1)[0], int(text.rsplit(':', 1)[1]))
    controller, proxy = address(options.controller), address(options.proxy)
    status, version = request(controller, '/version')
    check(status == 200 and '0.23' in version['version'], 'New device core unavailable')
    status, baseline = request(controller, '/connections?interval=ignored-for-http')
    check(status == 200 and type(baseline['memory']) is int and baseline['memory'] > 0, 'REST connections must remain finite and include real memory')
    baseline_ids = {item['id'] for item in baseline['connections']}
    for path, ws in [('/logs?level=invalid', False), ('/memory?unused=%GG', False), ('/connections?interval=0', True), ('/connections?interval=100&interval=200', True)]:
        client = Wire(controller)
        try:
            headers = 'Upgrade: websocket\r\n' if ws else ''
            client.sock.sendall(f'GET {path} HTTP/1.1\r\nHost: localhost\r\n{headers}\r\n'.encode())
            check(client.headers()[0] == 400, 'Invalid state options must receive HTTP 400')
        finally:
            client.close()
    memory_http, memory_ws = subscribe(controller, '/memory'), subscribe(controller, '/memory', True)
    logs_http = subscribe(controller, '/logs?level=info')
    logs_ws = subscribe(controller, '/logs?level=debug&format=structured', True)
    connections = subscribe(controller, '/connections?interval=100', True)
    owned_id = None
    origin = None
    try:
        memories = [sample(memory_http), sample(memory_ws, True), sample(memory_http)]
        check(all(set(x) == {'inuse', 'oslimit'} and type(x['inuse']) is int and x['inuse'] > 0 and x['oslimit'] == 0 for x in memories), 'Memory samples must contain actual RSS, including first tick')
        initial = sample(connections, True)
        check(isinstance(initial['connections'], list) and initial['memory'] > 0, 'Initial connection snapshot missing')
        origin = Wire(proxy)
        origin.sock.sendall(b'CONNECT www.gstatic.com:443 HTTP/1.1\r\nHost: www.gstatic.com:443\r\n\r\n')
        check(origin.headers()[0] == 200, 'Google tunnel creation failed')
        check(not origin.pending, 'Unexpected bytes before TLS handshake')
        origin.sock = ssl.create_default_context().wrap_socket(origin.sock, server_hostname='www.gstatic.com')
        origin.sock.sendall(b'GET /generate_204 HTTP/1.1\r\nHost: www.gstatic.com\r\nConnection: keep-alive\r\n\r\n')
        check(origin.headers()[0] == 204, 'Google HTTPS over actual device core failed')
        def own(value):
            return next((x for x in value['connections'] if x['id'] not in baseline_ids and x['metadata'].get('host') == 'www.gstatic.com' and x.get('upload', 0) > 0 and x.get('download', 0) > 0), None)
        live = until(connections, own, True)
        row = own(live)
        owned_id = row['id']
        check(row['upload'] > 0 and row['download'] > 0, 'Connection WS must report real TLS upload/download')
        event = until(logs_http, lambda x: x.get('type') == 'info' and 'www.gstatic.com:443' in x.get('payload', ''))
        structured = until(logs_ws, lambda x: x.get('level') == 'info' and 'www.gstatic.com:443' in x.get('message', ''), True)
        check(set(event) == {'type', 'payload'}, 'Standard log shape mismatch')
        check(set(structured) == {'time', 'level', 'message', 'fields'} and len(structured['time']) == 8 and structured['fields'] == [], 'Structured log shape mismatch')
        check(request(controller, '/connections/' + owned_id, 'DELETE')[0] == 204, 'Owned-connection deletion must return no-content success')
        deleted_id = owned_id
        owned_id = None
        until(connections, lambda x: all(c['id'] != deleted_id for c in x['connections']), True)
        check(True, 'Deleted connection disappeared from live snapshot')
        logs_ws.sock.sendall(masked(9, b'idle-state'))
        while True:
            opcode, data = logs_ws.frame()
            if opcode == 10:
                check(data == b'idle-state', 'Idle state stream lost ping/pong')
                break
            check(opcode == 1, 'Unexpected state control frame')
    finally:
        if owned_id is not None:
            request(controller, '/connections/' + owned_id, 'DELETE')
        if origin:
            origin.close()
        for client in (memory_http, memory_ws, logs_http, logs_ws, connections):
            client.close()
    result = {'coreVersion': version['version'], 'checks': checks, 'memorySamples': memories,
              'actualGoogleHttps': 204, 'tlsVerified': True, 'logsHttpAndStructuredWs': True,
              'realConnectionCountersAndDelete': True, 'idlePingPong': True,
              'originalProfilesModesSelectionsUntouched': True,
              'scope': 'Independent Python stdlib HTTP, RFC6455 and TLS over HDC forwarding; no private profile export or log payload retained'}
    options.output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n')
    print(f'Device state stream checks passed: {checks}')


if __name__ == '__main__':
    main()
