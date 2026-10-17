#!/usr/bin/env python3
"""Independently encode the public v2ray .dat protobuf schema; no app codec is imported."""
import ipaddress
from pathlib import Path

ROOT = Path(__file__).parent / 'fixtures/geodata'


def varint(value):
    result = bytearray()
    while value >= 128:
        result.append((value & 127) | 128)
        value >>= 7
    result.append(value)
    return bytes(result)


def field(number, value):
    if isinstance(value, int):
        return varint(number << 3) + varint(value)
    if isinstance(value, str):
        value = value.encode()
    return varint((number << 3) | 2) + varint(len(value)) + value


def cidr(value):
    network = ipaddress.ip_network(value)
    return field(1, network.network_address.packed) + field(2, network.prefixlen)


def ipset(code, values, inverse=False):
    return field(1, field(1, code) + b''.join(field(2, cidr(v)) for v in values) + field(3, int(inverse)))


def domain(kind, value, attrs=()):
    return field(2, field(1, kind) + field(2, value) + b''.join(field(3, field(1, a) + field(2, 1)) for a in attrs))


if __name__ == '__main__':
    ROOT.mkdir(exist_ok=True)
    ips = ipset('CN', ['192.0.2.0/24', '2001:db8:1::/48']) + ipset('JP', ['198.51.100.0/24']) + ipset('NOT-CN', ['192.0.2.0/24'], True)
    sites = field(1, field(1, 'FIXTURE') + domain(2, 'fixture.test', ['cn']) + domain(3, 'exact.example.invalid') + domain(0, 'keywordfixture') + domain(1, r'^srv[0-9]+\.regex\.invalid$'))
    sites += field(1, field(1, 'EMPTY'))
    (ROOT / 'geoip.dat').write_bytes(ips)
    (ROOT / 'geosite.dat').write_bytes(sites)
    (ROOT / 'invalid-prefix.dat').write_bytes(field(1, field(1, 'CN') + field(2, field(1, b'\xc0\x00\x02\x00') + field(2, 33))))
    (ROOT / 'duplicate.dat').write_bytes(ips + ipset('CN', ['203.0.113.0/24']))
    (ROOT / 'truncated.dat').write_bytes(ips[:-1])
    (ROOT / 'varint-overflow.dat').write_bytes(b'\x80' * 10 + b'\x02')
    (ROOT / 'unknown-field.dat').write_bytes(ips + field(99, b'future field'))
    print('Generated public GeoData protobuf reference fixtures')
