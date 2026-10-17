#!/usr/bin/env python3
"""Device auth checks using fixed PUBLIC test keys set through the actual app UI.
No user key is discovered, read from disk or printed by this script.
"""
import argparse
import base64
import hashlib
import json
import struct
import time
from pathlib import Path
from urllib.parse import quote
from controller_api_device import Wire

TOKENS = {'A': 'clashos-device-auth-A', 'B': 'clashos-device-auth-B'}
checks = 0


def check(condition, message):
    global checks
    if not condition:
        raise AssertionError(message)
    checks += 1


def request(address, path, token=None, method='GET', body=None):
    data = b'' if body is None else json.dumps(body).encode()
    headers = '' if token is None else 'Authorization: Bearer ' + token + '\r\n'
    client = Wire(address)
    try:
        client.sock.sendall((f'{method} {path} HTTP/1.1\r\nHost: localhost\r\n'
                            f'{headers}Content-Length: {len(data)}\r\n\r\n').encode() + data)
        status, returned = client.headers()
        value = client.exact(int(returned.get('content-length', '0')))
        return status, json.loads(value) if value else None
    finally:
        client.close()


def subscribe(address, token, websocket=False):
    client = Wire(address)
    key = base64.b64encode(b'0123456789abcdef').decode()
    path = '/traffic?token=' + quote(token, safe='') if websocket else '/traffic'
    headers = f'GET {path} HTTP/1.1\r\nHost: localhost\r\n'
    if websocket:
        headers += ('Upgrade: websocket\r\nConnection: Upgrade\r\n'
                    f'Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n')
    else:
        headers += 'Authorization: Bearer ' + token + '\r\n'
    try:
        client.sock.sendall(headers.encode() + b'\r\n')
        status, returned = client.headers()
        if websocket:
            expected = base64.b64encode(hashlib.sha1(
                (key + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11').encode()).digest()).decode()
            check(status == 101 and returned.get('sec-websocket-accept') == expected,
                  'Authenticated WebSocket handshake failed')
        else:
            check(status == 200, 'Authenticated HTTP stream failed')
        return client
    except BaseException:
        client.close()
        raise


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('phase', choices=['A', 'B', 'disabled', 'rotate', 'disable'])
    parser.add_argument('--controller', default='127.0.0.1:19090')
    parser.add_argument('--output', type=Path, required=True)
    options = parser.parse_args()
    host, port = options.controller.rsplit(':', 1)
    address = host, int(port)
    record = {'phase': options.phase, 'fixture': 'Fixed public test credentials; user credentials are never read'}
    if options.phase in ('rotate', 'disable'):
        old = TOKENS['A' if options.phase == 'rotate' else 'B']
        new = TOKENS['B'] if options.phase == 'rotate' else None
        http, ws = subscribe(address, old), subscribe(address, old, True)
        try:
            print('READY: authenticated HTTP and WebSocket subscribers are live', flush=True)
            until = time.monotonic() + 45
            while time.monotonic() < until:
                opcode, payload = ws.frame()
                if opcode == 8:
                    check(payload == struct.pack('!H', 1008), 'Revoked WebSocket needs policy close 1008')
                    break
                check(opcode == 1, 'Unexpected traffic frame during credential update')
            else:
                raise AssertionError('Old WebSocket did not close after credential update')
            while http.sock.recv(4096):
                pass
            check(True, 'Old HTTP subscription ended')
            check(request(address, '/version', new)[0] == 200, 'Updated credential must authorize new requests')
            if new is not None:
                check(request(address, '/version', old)[0] == 401, 'Revoked credential must fail on new requests')
            record.update(oldHttpClosed=True, oldWebsocketClose1008=True, newAccessWorks=True,
                          oldKeyRejected=new is not None)
        finally:
            http.close()
            ws.close()
    elif options.phase == 'disabled':
        for path in ('/version', '/configs', '/proxies', '/clashos/ports'):
            check(request(address, path)[0] == 200, 'Default unauthenticated access was not restored')
        record['defaultAccessRestored'] = True
    else:
        token = TOKENS[options.phase]
        for path in ('/version', '/configs', '/proxies', '/connections', '/rules', '/clashos/ports'):
            status, denied = request(address, path)
            check(status == 401 and denied == {'error': 'Unauthorized'}, 'Missing keys must receive a generic 401')
            status, allowed = request(address, path, token)
            check(status == 200, 'Correct bearer credential must authorize each ordinary API')
            serialized = json.dumps(allowed)
            check(all(key not in serialized for key in TOKENS.values()), 'Credential leaked in controller metadata')
        check(request(address, '/version', 'wrong-public-token')[0] == 401, 'Wrong credentials were accepted')
        check(request(address, '/version?token=' + quote(token, safe=''))[0] == 401,
              'Query credential must not authorize ordinary HTTP')
        before = request(address, '/configs', token)[1]
        target = 'Direct' if before['mode'] != 'Direct' else 'Rule'
        check(request(address, '/configs', method='PATCH', body={'mode': target})[0] == 401,
              'Unauthorized config mutation was accepted')
        check(request(address, '/configs', token)[1]['mode'] == before['mode'], 'Rejected mutation changed active mode')
        http, ws = subscribe(address, token), subscribe(address, token, True)
        try:
            sample = json.loads(http.until(b'\n'))
            opcode, payload = ws.frame()
            check(opcode == 1 and set(json.loads(payload)) == set(sample) == {'up', 'down', 'upTotal', 'downTotal'},
                  'Authorized traffic streams failed')
        finally:
            http.close()
            ws.close()
        record.update(bearerApis=True, missing401=True, wrong401=True, noMetadataLeak=True,
                      httpQueryRejected=True, deniedMutationPreservesMode=True,
                      authenticatedHttpTraffic=True, websocketQueryToken=True,
                      currentMode=before['mode'])
    record['checks'] = checks
    options.output.write_text(json.dumps(record, ensure_ascii=False, indent=2) + '\n')
    print(f'Device authentication checks passed: {checks}', flush=True)


if __name__ == '__main__':
    main()
