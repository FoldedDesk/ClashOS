#!/usr/bin/env python3
"""Independent HTTP CONNECT/SOCKS5 fixtures using Python/OpenSSL and inherited sockets.

Only public credentials and payloads; no real proxy server or user profile is read.
"""
import base64
import os
import socket
import ssl
import sys
import time
from pathlib import Path

from vmess_reference_peer import Wire
from trojan_reference_peer import context, read_address, address

USER = 'fixture用户'
PASSWORD = 'p@ss:word测试'
PAYLOAD = bytes((i * 19 + 7) % 256 for i in range(50000))
RESPONSE = b'forward-response:' + PAYLOAD[::-1]


def read_forward_header(wire, protocol, host='target.test', port=443, auth=True,
                        fault='', udp=False, bound='192.0.2.1', user=USER, password=PASSWORD):
    if protocol == 'http':
        head = b''
        while not head.endswith(b'\r\n\r\n'):
            assert len(head) < 32768
            head += wire.exact(1)
        lines = head.decode().split('\r\n')
        authority = ('[' + host + ']' if ':' in host else host) + ':' + str(port)
        assert lines[0] == 'CONNECT ' + authority + ' HTTP/1.1'
        fields = dict(line.split(': ', 1) for line in lines[1:] if ': ' in line)
        assert fields['Host'] == authority and fields['X-Test'] == ('updated-peer' if fault == 'provider-headers' else 'native-peer')
        expected = 'Basic ' + base64.b64encode((user + ':' + password).encode()).decode()
        assert fields.get('Proxy-Authorization') == (expected if auth else None)
        if fault == 'auth-fail':
            wire.send(b'HTTP/1.1 407 public-secret\r\nContent-Length: 13\r\n\r\npublic-secret')
            return False
        if fault == 'status':
            wire.send(b'HTTP/1.1 403 Denied\r\n\r\n')
            return False
        if fault == 'bad-status':
            wire.send(b'HTTP/1.1 200X bad\r\n\r\n')
            return False
        if fault == 'short-header':
            wire.send(b'HTTP/1.1 200 OK\r\n')
            return False
        if fault == 'oversize-header':
            wire.send(b'HTTP/1.1 200 OK\r\nX-Padding: ' + b'P' * 65536 + b'\r\n\r\n')
            return False
        if fault == 'many-interim':
            wire.send(b'HTTP/1.1 100 Continue\r\n\r\n' * 8)
            return False
        prefix = b'HTTP/1.1 103 Early Hints\r\nLink: public\r\n\r\nHTTP/1.1 100 Continue\r\n\r\n' if fault == 'interim' else b''
        header = b'HTTP/1.0 201 Tunnel\r\nContent-Length: 999\r\nTransfer-Encoding: chunked\r\n\r\n' if fault == 'success-201' else b'HTTP/1.1 200 Connection established\r\n\r\n'
        wire.send(prefix + header + (b'greeting' if fault in ('server-first', 'remote-half-close') else b''))
        return True
    method = b'\x02' if auth else b'\0'
    assert wire.exact(3) == b'\x05\x01' + method
    if fault == 'method':
        wire.send(b'\x05' + (b'\0' if auth else b'\x02'))
        return False
    if fault == 'version':
        wire.send(b'\x04' + method)
        return False
    wire.send(b'\x05' + method)
    if auth:
        assert wire.exact(1) == b'\x01'
        assert wire.exact(wire.exact(1)[0]) == user.encode()
        assert wire.exact(wire.exact(1)[0]) == password.encode()
        wire.send(b'\x02\0' if fault == 'auth-version' else b'\x01\x01' if fault == 'auth-fail' else b'\x01\0')
        if fault in ('auth-fail', 'auth-version'):
            return False
    assert wire.exact(3) == (b'\x05\x03\0' if udp else b'\x05\x01\0')
    if udp:
        assert wire.exact(7) == b'\x01\0\0\0\0\0\0'
    else:
        assert read_address(wire) == (host, port)
    if fault in ('reply-version', 'reply-status', 'reply-reserved', 'reply-atyp', 'reply-short', 'reply-domain-empty'):
        replies = {'reply-version': b'\x04\0\0\x01', 'reply-status': b'\x05\x05\0\x01',
                   'reply-reserved': b'\x05\0\x01\x01', 'reply-atyp': b'\x05\0\0\x02',
                   'reply-short': b'\x05\0\0\x04\0', 'reply-domain-empty': b'\x05\0\0\x03\0'}
        wire.send(replies[fault])
        return False
    packet = b'\x05\0\0' + address(bound, 0 if fault == 'udp-port-zero' else 18096 if udp else 0)
    wire.send(packet + (b'greeting' if fault in ('server-first', 'remote-half-close') else b''))
    return fault != 'udp-port-zero'


def datagrams(wire, peer, fault, host, marker=None):
    peer.settimeout(6)
    for i in range(4):
        packet = peer.recv(65536)
        expected_body = [b'packet-0', b'', b'P' * 4096, bytes(i % 256 for i in range(65489))][i]
        assert packet == b'\0\0\0' + address(host, 443) + expected_body
        source = ['8.8.8.8', '2001:db8::1', 'answer.test', '8.8.8.8'][i]
        body = b'' if i == 1 else expected_body if i == 3 else b'udp-response:' + expected_body[::-1]
        good = b'\0\0\0' + address(source, 53 + i) + body
        if i == 0:
            for bad in (b'\0\x01\0' + good[3:], b'\0\0\x01' + good[3:], b'\0\0\0\x03\0', b'\0\0\0\x02'):
                peer.send(bad)
        peer.send(good)
    # Control TCP/TLS must outlive all exchanges and the client must release it.
    if fault == 'udp-control-close':
        # Close only after the test client confirms delivery of the last reply.
        # A reply racing TCP EOF may correctly be dropped by an RFC 1928 client.
        deadline = time.monotonic() + 6
        while not Path(marker).exists() and time.monotonic() < deadline:
            time.sleep(.002)
        assert Path(marker).exists(), 'Client did not acknowledge final UDP response'
        if isinstance(wire.conn, ssl.SSLSocket):
            try:
                wire.conn.unwrap().close()
            except (ssl.SSLError, OSError):
                pass
        else:
            wire.conn.shutdown(socket.SHUT_RDWR)
            wire.conn.close()
        try:
            peer.send(b'\0\0\0' + address('8.8.8.8', 53) + b'late')
        except OSError:
            pass
        return
    try:
        assert not wire.conn.recv(1), 'SOCKS UDP control channel received application data'
    except (ssl.SSLError, ConnectionResetError):
        pass


def main():
    fd, scenario, kind, fault = int(sys.argv[1]), int(sys.argv[2]), sys.argv[3], sys.argv[4]
    extra, marker = None, None
    if '|' in fault:
        pieces = fault.split('|')
        fault, descriptors = pieces[:2]
        marker = pieces[2] if len(pieces) > 2 else None
        server_fd, client_fd = map(int, descriptors.split(':'))
        extra = socket.socket(fileno=server_fd)
        os.close(client_fd)
    conn = socket.socket(fileno=fd)
    conn.settimeout(6)
    if kind.endswith('tls'):
        names = []
        ctx = context()
        ctx.sni_callback = lambda connection, name, selected: names.append(name)
        try:
            conn = ctx.wrap_socket(conn, server_side=True)
        except ssl.SSLError:
            if fault not in ('tls-reject-ca', 'tls-reject-host'):
                raise
            return
        assert names == ['vmess.test']
    wire = Wire(conn)
    host = '192.0.2.9' if scenario in (2, 4) else '2001:db8::9' if scenario == 3 else 'target.test'
    protocol = kind.split('-')[0]
    bound = ['192.0.2.1', '0.0.0.0', 'relay.test', '2001:db8::9'][scenario % 4] if extra else ['192.0.2.1', 'answer.test', '2001:db8::9'][scenario % 3]
    user, password = ('U' * 255, 'P' * 255) if scenario == 5 else (USER, PASSWORD)
    if fault in ('provider-user', 'provider-headers'):
        user = 'updated-user'
    if not read_forward_header(wire, protocol, host, 80 if fault == 'plain-http' else 443,
                               auth=scenario != 1, fault=fault, udp=extra is not None,
                               bound=bound, user=user, password=password):
        conn.close()
        return
    if extra:
        datagrams(wire, extra, fault, host, marker)
        extra.close()
        conn.close()
        return
    if fault == 'remote-half-close':
        assert kind.endswith('tcp')
        conn.shutdown(socket.SHUT_WR)
    if fault == 'plain-http':
        request = b''
        while not request.endswith(b'\r\n\r\n'):
            request += wire.exact(1)
            assert len(request) < 16384
        assert request.startswith(b'GET /verify HTTP/1.1\r\n')
        assert b'Host: target.test' in request and b'Authorization: Bearer public-origin' in request
        assert b'Proxy-Authorization' not in request and b'Proxy-Connection' not in request
        wire.send(b'HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n')
    else:
        assert wire.exact(len(PAYLOAD)) == PAYLOAD
        if fault == 'tls-corrupt':
            os.write(conn.fileno(), b'\x17\x03\x03\x00\x20' + b'X' * 32)
            conn.close()
            return
        if fault != 'remote-half-close':
            for start in range(0, len(RESPONSE), 17000):
                wire.send(RESPONSE[start:start + 17000])
                time.sleep(.001)
    if isinstance(conn, ssl.SSLSocket):
        try:
            conn.unwrap().close()
        except (ssl.SSLError, OSError):
            conn.close()
    else:
        conn.close()


if __name__ == '__main__':
    main()
