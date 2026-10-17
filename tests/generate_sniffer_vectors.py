#!/usr/bin/env python3
"""Deterministic public TLS/QUIC vectors using Python cryptography, not core code.

QUIC Initial protection: RFC 9001 sections 5.1/5.4, RFC 9369 section 3.
The ClientHello is intentionally a passive-parser fixture, not a full TLS client.
"""
import hashlib
import hmac
import json
import struct
from pathlib import Path
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand


def u16(value):
    return struct.pack('!H', value)


def varint(value):
    size = 1 if value < 64 else 2 if value < 16384 else 4 if value < 1073741824 else 8
    return (value | ({1: 0, 2: 1, 4: 2, 8: 3}[size] << (size * 8 - 2))).to_bytes(size, 'big')


def hello(host):
    name = host.encode('ascii')
    names = b'\0' + u16(len(name)) + name
    sni = u16(len(names)) + names
    extensions = b'\0\0' + u16(len(sni)) + sni + b'\0+' + u16(3) + b'\2\3\4'
    body = b'\3\3' + bytes(range(32)) + b'\0' + u16(4) + b'\x13\1\x13\2' + b'\1\0' + u16(len(extensions)) + extensions
    return b'\1' + len(body).to_bytes(3, 'big') + body


def record(data):
    return b'\x16\3\1' + u16(len(data)) + data


def expand(secret, label, size):
    label = b'tls13 ' + label
    info = u16(size) + bytes([len(label)]) + label + b'\0'
    return HKDFExpand(algorithm=hashes.SHA256(), length=size, info=info).derive(secret)


def initial(data, version=1, offset=0, pn=0, pn_size=2, extra=b''):
    dcid = bytes.fromhex('8394c8f03e515708')
    salt = bytes.fromhex('38762cf7f55934b34d179ae6a4c80cadccbb7f0a' if version == 1 else '0dede3def700a6db819381be6e269dcbf9bd2ed9')
    extracted = hmac.new(salt, dcid, hashlib.sha256).digest()
    client = expand(extracted, b'client in', 32)
    prefix = b'quic ' if version == 1 else b'quicv2 '
    key = expand(client, prefix + b'key', 16)
    iv = expand(client, prefix + b'iv', 12)
    hp = expand(client, prefix + b'hp', 16)
    scid = bytes.fromhex('12345678')
    header = bytes([(0xc0 if version == 1 else 0xd0) | (pn_size - 1)]) + struct.pack('!I', version) + bytes([len(dcid)]) + dcid + bytes([len(scid)]) + scid + b'\0'
    plain = extra + b'\6' + varint(offset) + varint(len(data)) + data
    # Length has two encoded bytes for a 1200-byte Initial.
    body_size = 1200 - len(header) - 2
    plain += bytes(max(0, body_size - pn_size - 16 - len(plain)))
    packet_length = pn_size + len(plain) + 16
    header += varint(packet_length)
    pn_offset = len(header)
    packet_number = (pn & ((1 << (pn_size * 8)) - 1)).to_bytes(pn_size, 'big')
    aad = header + packet_number
    nonce = bytes(a ^ b for a, b in zip(iv, pn.to_bytes(12, 'big')))
    packet = bytearray(aad + AESGCM(key).encrypt(nonce, plain, aad))
    encryptor = Cipher(algorithms.AES(hp), modes.ECB()).encryptor()
    mask = encryptor.update(bytes(packet[pn_offset + 4:pn_offset + 20])) + encryptor.finalize()
    packet[0] ^= mask[0] & 15
    for i in range(pn_size):
        packet[pn_offset + i] ^= mask[i + 1]
    return bytes(packet)


if __name__ == '__main__':
    host = 'sniff.fixture.test'
    ch = hello(host)
    split = len(ch) - 13
    vectors = {
        'host': host,
        'client_hello': ch.hex(),
        'tls_record': record(ch).hex(),
        'tls_records_split': (record(ch[:19]) + record(ch[19:split]) + record(ch[split:])).hex(),
        'quic_v1': initial(ch).hex(),
        'quic_v2': initial(ch, 0x6b3343cf).hex(),
        'quic_fragment_head': initial(ch[:split], pn=0).hex(),
        'quic_fragment_tail': initial(ch[split:], offset=split, pn=1, extra=b'\2\0\0\0\0').hex(),
        'quic_conflicting_head': initial(bytes([ch[0] ^ 1]) + ch[1:split], pn=2).hex(),
        'quic_pn255': initial(ch[:split], pn=255, pn_size=1).hex(),
        'quic_pn256': initial(ch[split:], offset=split, pn=256, pn_size=1).hex(),
        'quic_oversized_offset': initial(ch, offset=65536).hex(),
    }
    output = Path(__file__).parent / 'fixtures/sniffer/vectors.json'
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(vectors, indent=2) + '\n')
    print(f'Wrote {len(vectors) - 1} public TLS/QUIC vectors')
