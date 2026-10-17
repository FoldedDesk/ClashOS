#!/usr/bin/env python3
"""Independent SIP022/023 peer: Rust BLAKE3 + PyCryptodome, inherited sockets.

Public synthetic keys only. No production framing helpers or app configuration.
"""
import json
import os
from pathlib import Path
import socket
import sys
import time
from blake3 import blake3
from Crypto.Cipher import AES, ChaCha20_Poly1305

PAYLOAD = bytes((i * 17 + 3) % 256 for i in range(70000))


def keys(method, identities):
    size = 16 if 'aes-128' in method else 32
    return [bytes((i + 31 * layer) % 256 for i in range(size)) for layer in range(identities + 1)]


def derive(key, salt, identity=False):
    return blake3(key + salt, derive_key_context='shadowsocks 2022 ' + ('identity' if identity else 'session') + ' subkey').digest(len(key))


def seal(method, key, nonce, body):
    c = ChaCha20_Poly1305.new(key=key, nonce=nonce) if 'chacha' in method else AES.new(key, AES.MODE_GCM, nonce=nonce)
    cipher, tag = c.encrypt_and_digest(body)
    return cipher + tag


def open_packet(method, key, nonce, packet):
    c = ChaCha20_Poly1305.new(key=key, nonce=nonce) if 'chacha' in method else AES.new(key, AES.MODE_GCM, nonce=nonce)
    return c.decrypt_and_verify(packet[:-16], packet[-16:])


def address(data, offset=0):
    kind = data[offset]
    length = 7 if kind == 1 else 19 if kind == 4 else 4 + data[offset + 1]
    assert kind in (1, 3, 4) and len(data) >= offset + length
    assert int.from_bytes(data[offset + length - 2:offset + length], 'big') == 443
    return data[offset:offset + length], length


def exact(conn, count):
    out = b''
    while len(out) < count:
        data = conn.recv(count - len(out))
        if not data:
            raise EOFError('truncated public peer request')
        out += data
    return out


def frame(method, key, counter, plain):
    return seal(method, key, counter.to_bytes(12, 'little'), plain)


def reply(method, psk, request_salt, chunks, fault=''):
    salt = bytes(range(128, 128 + len(psk)))
    key = derive(psk, salt)
    stamp = int(time.time()) + (60 if fault == 'future' else -60 if fault == 'stale' else 0)
    fixed = bytes([0 if fault == 'type' else 1]) + stamp.to_bytes(8, 'big')
    fixed += (bytes(len(request_salt)) if fault == 'request-salt' else request_salt) + len(chunks[0]).to_bytes(2, 'big')
    wire = salt + frame(method, key, 0, fixed) + frame(method, key, 1, chunks[0])
    for i, chunk in enumerate(chunks[1:], 1):
        wire += frame(method, key, 2 * i, len(chunk).to_bytes(2, 'big')) + frame(method, key, 2 * i + 1, chunk)
    if fault == 'header-tag':
        wire = bytearray(wire); wire[len(salt) + len(fixed) + 15] ^= 1; wire = bytes(wire)
    elif fault == 'payload-tag':
        wire = wire[:-1] + bytes([wire[-1] ^ 1])
    elif fault == 'short-header':
        wire = wire[:len(salt) + 1]
    elif fault == 'short-payload':
        wire = wire[:-1]
    return wire


def tcp(conn, method, psks, fault, marker):
    salt = exact(conn, len(psks[-1]))
    for current, following in zip(psks, psks[1:]):
        identity = AES.new(derive(current, salt, True), AES.MODE_ECB).decrypt(exact(conn, 16))
        assert identity == blake3(following).digest(16), 'SIP023 identity hash/subkey'
    key = derive(psks[-1], salt)
    fixed = open_packet(method, key, bytes(12), exact(conn, 11 + 16))
    assert fixed[0] == 0 and abs(int.from_bytes(fixed[1:9], 'big') - int(time.time())) <= 30
    variable = open_packet(method, key, (1).to_bytes(12, 'little'), exact(conn, int.from_bytes(fixed[9:], 'big') + 16))
    destination, length = address(variable)
    assert destination == b'\x03\x0btarget.test\x01\xbb'
    padding = int.from_bytes(variable[length:length + 2], 'big')
    assert 1 <= padding <= 900 and length + 2 + padding == len(variable), 'No-payload handshake requires nonzero padding'
    counter = 2
    pending = b''

    def receive(count):
        nonlocal counter, pending
        payload = pending
        while len(payload) < count:
            length = open_packet(method, key, counter.to_bytes(12, 'little'), exact(conn, 18))
            assert len(length) == 2
            counter += 1
            size = int.from_bytes(length, 'big')
            payload += open_packet(method, key, counter.to_bytes(12, 'little'), exact(conn, size + 16))
            counter += 1
        pending = payload[count:]
        return payload[:count]

    if fault.startswith('duplex-'):
        if fault != 'duplex-server-first':
            assert receive(5) == b'first'
        wire = reply(method, psks[-1], salt, [b'done'])
        size = len(salt)
        cut = {'duplex-salt': 1, 'duplex-header': size + 5,
               'duplex-payload': 2 * size + 28, 'duplex-server-first': size + 3}[fault]
        conn.sendall(wire[:cut]); Path(marker).write_text('ready')
        if fault == 'duplex-server-first':
            assert receive(5) == b'first'
        assert receive(4) == b'tail'
        assert conn.recv(1) == b''
        conn.sendall(wire[cut:])
        return
    if fault == 'server-first':
        conn.sendall(reply(method, psks[-1], salt, [b'greeting']))
        assert receive(len(PAYLOAD)) == PAYLOAD
        return
    assert receive(len(PAYLOAD)) == PAYLOAD
    assert conn.recv(1) == b''
    response = b'ss2022-response:' + PAYLOAD[::-1]
    wire = reply(method, psks[-1], salt, [response[:65535], response[65535:]], fault)
    try:
        for start, end in [(0, 1), (1, len(salt) + 3), (len(salt) + 3, len(wire))]:
            conn.sendall(wire[start:end])
    except BrokenPipeError:
        if fault not in ('type', 'stale', 'future', 'request-salt', 'header-tag', 'payload-tag', 'short-header', 'short-payload'):
            raise


class Ss2022Tunnel:
    """A generic independent server stream for the OpenSSL HTTPS reference."""
    def __init__(self, wire, method, identities, target):
        self.wire, self.method = wire, method
        psks = keys(method, identities)
        salt = wire.exact(len(psks[-1]))
        for current, following in zip(psks, psks[1:]):
            assert AES.new(derive(current, salt, True), AES.MODE_ECB).decrypt(wire.exact(16)) == blake3(following).digest(16)
        self.reader = derive(psks[-1], salt)
        fixed = open_packet(method, self.reader, bytes(12), wire.exact(27))
        assert fixed[0] == 0 and abs(int.from_bytes(fixed[1:9], 'big') - int(time.time())) <= 30
        variable = open_packet(method, self.reader, (1).to_bytes(12, 'little'), wire.exact(int.from_bytes(fixed[9:], 'big') + 16))
        destination, length = address(variable)
        expected = bytes([3, len(target)]) + target.encode() + b'\x01\xbb'
        assert destination == expected
        padding = int.from_bytes(variable[length:length + 2], 'big')
        assert padding > 0 and length + 2 + padding == len(variable)
        self.request_salt, self.salt = salt, os.urandom(len(salt))
        self.writer = derive(psks[-1], self.salt)
        self.read_count, self.send_count = 2, 0

    def receive(self):
        length = open_packet(self.method, self.reader, self.read_count.to_bytes(12, 'little'), self.wire.exact(18))
        self.read_count += 1
        data = open_packet(self.method, self.reader, self.read_count.to_bytes(12, 'little'), self.wire.exact(int.from_bytes(length, 'big') + 16))
        self.read_count += 1
        return data

    def send(self, data):
        for offset in range(0, len(data), 1500):
            part = data[offset:offset + 1500]
            if self.send_count == 0:
                fixed = b'\x01' + int(time.time()).to_bytes(8, 'big') + self.request_salt + len(part).to_bytes(2, 'big')
                packet = self.salt + frame(self.method, self.writer, 0, fixed)
            else:
                packet = frame(self.method, self.writer, self.send_count, len(part).to_bytes(2, 'big'))
            self.send_count += 1
            packet += frame(self.method, self.writer, self.send_count, part)
            self.send_count += 1
            self.wire.send(packet)


def udp_decode(method, psks, wire):
    if 'chacha' in method:
        body = open_packet(method, psks[-1], wire[:24], wire[24:])
        separate, body = body[:16], body[16:]
    else:
        separate = AES.new(psks[0], AES.MODE_ECB).decrypt(wire[:16])
        offset = 16
        for current, following in zip(psks, psks[1:]):
            identity = AES.new(current, AES.MODE_ECB).decrypt(wire[offset:offset + 16])
            assert bytes(a ^ b for a, b in zip(identity, separate)) == blake3(following).digest(16)
            offset += 16
        body = open_packet(method, derive(psks[-1], separate[:8]), separate[4:], wire[offset:])
    assert body[0] == 0 and abs(int.from_bytes(body[1:9], 'big') - int(time.time())) <= 30
    offset = 11 + int.from_bytes(body[9:11], 'big')
    destination, size = address(body, offset)
    return separate[:8], int.from_bytes(separate[8:], 'big'), destination, body[offset + size:]


def udp_reply(method, psk, client, packet_id, destination, payload, fault='', server=b'SERVER01'):
    separate = server + packet_id.to_bytes(8, 'big')
    timestamp = int(time.time()) - (60 if fault == 'stale' else 0)
    body = bytes([0 if fault == 'type' else 1]) + timestamp.to_bytes(8, 'big')
    body += (b'INVALID!' if fault == 'session' else client) + (65535 if fault == 'padding' else 0).to_bytes(2, 'big')
    body += destination + payload
    if 'chacha' in method:
        nonce = os.urandom(24)
        wire = nonce + seal(method, psk, nonce, separate + body)
    else:
        wire = AES.new(psk, AES.MODE_ECB).encrypt(separate) + seal(method, derive(psk, server), separate[4:], body)
    if fault == 'tag':
        wire = wire[:-1] + bytes([wire[-1] ^ 1])
    return wire


def udp(conn, method, psks):
    client_id = None
    for i in range(4):
        raw = conn.recv(65536)
        client, packet_id, destination, payload = udp_decode(method, psks, raw)
        assert packet_id == i and (client_id is None or client == client_id)
        client_id = client
        expected = [b'packet-0', b'', b'P' * 4096, b'L' * (65507 - (67 if 'chacha' in method else 43 + 16 * (len(psks) - 1)) - len(destination))][i]
        assert payload == expected
        if i == 0:
            for fault in ['tag', 'type', 'stale', 'session', 'padding']:
                conn.send(udp_reply(method, psks[-1], client, 0, destination, b'invalid', fault))
        # A server reply has an additional 8-byte client-session field.
        response = payload[:-8] if i == 3 else b'udp-response:' + payload[::-1]
        wire = udp_reply(method, psks[-1], client, i + 2, destination, response)
        conn.send(wire)
        if i == 0:
            conn.send(wire)  # replay must not become a second application packet
    for packet_id, value in [(1, b'late'), (0, b'old'), (2000, b'ahead'), (1, b'outside')]:
        conn.send(udp_reply(method, psks[-1], client_id, packet_id, destination, value))
    conn.send(udp_reply(method, psks[-1], client_id, 2001, destination, b''))
    conn.send(udp_reply(method, psks[-1], client_id, 0, destination, b'restart', server=b'SERVER02'))
    conn.send(udp_reply(method, psks[-1], client_id, 2002, destination, b'retained'))
    for i in range(31):
        conn.send(udp_reply(method, psks[-1], client_id, 0, destination, ('new-' + str(i)).encode(), server=('N%07d' % i).encode()))
    conn.send(udp_reply(method, psks[-1], client_id, 2003, destination, b'existing'))


def main():
    fd, identities, method, fault = int(sys.argv[1]), int(sys.argv[2]), sys.argv[3], sys.argv[4]
    fault, _, marker = fault.partition('|')
    conn = socket.socket(fileno=fd); conn.settimeout(6)
    psks = keys(method, identities)
    if fault == 'vectors':
        salt = bytes(range(len(psks[-1])))
        data = {'key': psks[-1].hex(), 'salt': salt.hex(), 'wire': reply(method, psks[-1], salt, [b'head', b'tail']).hex()}
        Path(marker).write_text('\n'.join(data.values()) + '\n')
    elif fault == 'udp':
        udp(conn, method, psks)
    else:
        tcp(conn, method, psks, fault, marker)
    conn.close()


def crypto_vectors():
    result = []
    for method in ['2022-blake3-aes-128-gcm', '2022-blake3-aes-256-gcm', '2022-blake3-chacha20-poly1305']:
        size = 16 if 'aes-128' in method else 32
        key, salt, nonce = bytes(range(size)), bytes(range(128, 128 + size)), bytes(range(24))
        plain = b'public SS2022 crypto vector'
        result.append({'method': method, 'key': key.hex(), 'salt': salt.hex(), 'subkey': derive(key, salt).hex(),
                       'identity': derive(key, salt, True).hex(), 'hash': blake3(key).digest(16).hex(), 'plain': plain.hex(),
                       'sealed': seal(method, derive(key, salt), bytes(12), plain).hex(), 'nonce': nonce.hex(),
                       'udp': seal(method, key, nonce, plain).hex() if 'chacha' in method else '',
                       'block': AES.new(key, AES.MODE_ECB).encrypt(bytes(16)).hex() if 'chacha' not in method else ''})
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    if sys.argv[1:] == ['--crypto-vectors']:
        crypto_vectors()
    else:
        main()
