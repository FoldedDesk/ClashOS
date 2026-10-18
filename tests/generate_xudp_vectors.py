#!/usr/bin/env python3
"""Public wire vectors from Xray's documented mux/XUDP layout, using stdlib only."""
import ipaddress
import json
from pathlib import Path
import struct


def address(host, port, socks=False):
    try:
        value = ipaddress.ip_address(host)
        kind = (1 if value.version == 4 else 4) if socks else (1 if value.version == 4 else 3)
        encoded = bytes([kind]) + value.packed
    except ValueError:
        domain = host.encode('ascii')
        encoded = bytes([3 if socks else 2, len(domain)]) + domain
    return encoded + struct.pack('>H', port) if socks else struct.pack('>H', port) + encoded


def frame(status, payload, host=None, port=0, identity=b''):
    metadata = struct.pack('>HBB', 0, status, 1)
    if host is not None:
        metadata += b'\x02' + address(host, port) + identity
    return struct.pack('>H', len(metadata)) + metadata + struct.pack('>H', len(payload)) + payload


def main():
    result = []
    for host, port, source, source_port, payload in [
        ('192.0.2.1', 53, '198.51.100.4', 5300, bytes.fromhex('00017fff')),
        ('2001:db8::1234', 8443, '2001:db8::55', 9000, bytes.fromhex('ff000203')),
        ('public.example', 443, 'reply.example', 53, b'hello'),
    ]:
        identity = bytes(range(1, 9))
        result.append(dict(host=host, port=port, identity=identity.hex(), payload=payload.hex(),
                           new=frame(1, payload, host, port, identity).hex(),
                           keep=frame(2, payload, host, port).hex(),
                           response=frame(2, payload, source, source_port).hex(),
                           source=address(source, source_port, socks=True).hex(),
                           implicit=frame(2, payload).hex(),
                           fallback=address('original.example', port, socks=True).hex()))
    path = Path(__file__).parent / 'fixtures/xudp-wire.json'
    path.write_text(json.dumps(result, indent=2) + '\n')


if __name__ == '__main__':
    main()
