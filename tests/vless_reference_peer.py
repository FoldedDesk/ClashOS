#!/usr/bin/env python3
"""Independent VLESS v0 fixture, using Python/OpenSSL and public test credentials.

One inherited Unix socket; no user profiles, external listeners or network targets.
Request/UDP codecs are deliberately independent of the production C++ implementation.
"""
import os
from pathlib import Path
import socket
import ssl
import sys
import time
import uuid

from vmess_reference_peer import Wire
from trojan_reference_peer import context

UUID = '11111111-2222-4333-8444-555555555555'
PAYLOAD = bytes((i * 17 + 3) % 256 for i in range(50000))
RESPONSE = b'vless-response:' + PAYLOAD[::-1]


def read_header(wire, host='target.test', port=443, udp=False):
    assert wire.exact(1) == b'\0', 'VLESS wire version'
    assert wire.exact(16) == uuid.UUID(UUID).bytes, 'VLESS UUID bytes'
    assert wire.exact(1) == b'\0', 'Standard VLESS must not request Vision'
    assert wire.exact(1) == (b'\x02' if udp else b'\x01'), 'VLESS command'
    assert int.from_bytes(wire.exact(2), 'big') == port
    kind = wire.exact(1)
    if kind == b'\x01':
        destination = socket.inet_ntop(socket.AF_INET, wire.exact(4))
    elif kind == b'\x03':
        destination = socket.inet_ntop(socket.AF_INET6, wire.exact(16))
    else:
        assert kind == b'\x02', 'VLESS address type differs from SOCKS'
        length = wire.exact(1)[0]
        assert length > 0
        destination = wire.exact(length).decode()
    assert destination == host, 'VLESS destination changed'


def send_fragmented(wire, data):
    # Split response headers and UDP lengths across independent transport records.
    for start, end in [(0, 1), (1, 2), (2, 3), (3, 19), (19, len(data))]:
        if end > start:
            wire.send(data[start:end])
            time.sleep(.001)


def datagrams(wire, fault):
    count = 4 if fault == 'udp' else 1
    for index in range(count):
        size = int.from_bytes(wire.exact(2), 'big')
        body = wire.exact(size)
        expected = [b'packet-0', b'', b'P' * 4096,
                    bytes(i % 256 for i in range(65507 - 3 - 15))][index]
        assert body == expected, 'UDP length framing or payload changed'
        header = b'\0\0' if index == 0 else b''
        if fault == 'udp-short-length':
            wire.send(header + b'\0')
        elif fault == 'udp-short-payload':
            wire.send(header + b'\0\x20short')
        elif fault == 'udp-oversize':
            wire.send(header + b'\xff\xff' + b'X' * 65535 + b'\0\x04good')
        else:
            response = b'udp-response:' + body[::-1] if index < 3 else body
            send_fragmented(wire, header + len(response).to_bytes(2, 'big') + response)
    if fault == 'udp':
        # Coalesced packets and an actual empty reply are three distinct datagrams.
        wire.send(b'\0\x01A\0\0\0\x01B')


def main():
    fd, scenario, kind, fault = int(sys.argv[1]), int(sys.argv[2]), sys.argv[3], sys.argv[4]
    marker = None
    if '|' in fault:
        fault, marker = fault.split('|', 1)
    conn = socket.socket(fileno=fd)
    conn.settimeout(6)
    if 'tls' in kind:
        ctx = context()
        names = []
        ctx.sni_callback = lambda connection, name, selected: names.append(name)
        try:
            conn = ctx.wrap_socket(conn, server_side=True)
        except ssl.SSLError:
            if fault not in ('tls-reject-ca', 'tls-reject-host'):
                raise
            return
        assert names == ['vmess.test']
        assert conn.selected_alpn_protocol() == ('h2' if scenario == 1 and kind == 'tls' else 'http/1.1')
    wire = Wire(conn)
    if 'ws' in kind:
        wire.upgrade(fault == 'ws-accept', path='/vless?test=1')
        if fault == 'ws-accept':
            return
    host = '192.0.2.9' if scenario in (2, 4) else '2001:db8::9' if scenario == 3 else 'target.test'
    read_header(wire, host, udp=fault.startswith('udp'))
    if fault == 'remote-half-close':
        assert kind == 'tcp'
        wire.send(b'\0\0greeting')
        conn.shutdown(socket.SHUT_WR)
        assert wire.exact(len(PAYLOAD)) == PAYLOAD
        conn.close()
        return
    if fault.startswith('udp'):
        datagrams(wire, fault)
    else:
        response_header = b'\0\0'
        if fault in ('addons', 'duplex-addons'):
            response_header = b'\0\x05\x12\x03abc'  # protobuf field 2 (optional seed)
        elif fault == 'addons-max':
            response_header = b'\0\xff\x12\xfc\x01' + b'S' * 252
        if fault.startswith('duplex-'):
            assert wire.exact(16) == PAYLOAD[:16]
            cut = 1 if fault == 'duplex-version' else 2 if fault == 'duplex-addons' else 3
            if fault == 'duplex-payload':
                response_header += b'v'
            wire.send(response_header[:cut])
            Path(marker).write_text('ready')
            assert wire.exact(len(PAYLOAD) - 16) == PAYLOAD[16:]
            wire.send(response_header[cut:] + (RESPONSE[1:] if fault == 'duplex-payload' else RESPONSE))
        elif fault == 'server-first':
            wire.send(response_header + b'greeting')
            assert wire.exact(len(PAYLOAD)) == PAYLOAD
            wire.send(RESPONSE)
        else:
            assert wire.exact(len(PAYLOAD)) == PAYLOAD
            if fault == 'version':
                wire.send(b'\x01\0never-expose')
            elif fault == 'short-header':
                wire.send(b'\0')
            elif fault == 'short-addons':
                wire.send(b'\0\x05\x12\x03a')
            elif fault == 'invalid-addons':
                wire.send(b'\0\x01\x0a')
            elif fault == 'vision-response':
                wire.send(b'\0\x08\x0a\x06visionnever-expose')
            elif fault == 'tls-corrupt':
                os.write(conn.fileno(), b'\x17\x03\x03\x00\x20' + b'X' * 32)
                conn.close()
                return
            else:
                send_fragmented(wire, response_header + RESPONSE)
    if wire.ws:
        wire.frame(b'', opcode=8)
        conn.close()
    elif isinstance(conn, ssl.SSLSocket):
        try:
            conn.unwrap().close()
        except (ssl.SSLError, OSError):
            conn.close()
    else:
        conn.shutdown(socket.SHUT_WR)
        conn.close()


if __name__ == '__main__':
    main()
