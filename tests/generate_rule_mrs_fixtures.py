#!/usr/bin/env python3
"""Independent MRS v1 encoder for public fixtures, using Python tries/ipaddress and host libzstd."""
from collections import deque
import ctypes
import ctypes.util
import ipaddress
import json
from pathlib import Path
import struct

ROOT = Path(__file__).parent / 'fixtures/rules'


def compress(data):
    library = ctypes.CDLL(ctypes.util.find_library('zstd') or '/opt/homebrew/lib/libzstd.dylib')
    library.ZSTD_compressBound.argtypes = [ctypes.c_size_t]
    library.ZSTD_compressBound.restype = ctypes.c_size_t
    library.ZSTD_compress.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int]
    library.ZSTD_compress.restype = ctypes.c_size_t
    capacity = library.ZSTD_compressBound(len(data))
    output = ctypes.create_string_buffer(capacity)
    length = library.ZSTD_compress(output, capacity, data, len(data), 3)
    assert length <= capacity
    return output.raw[:length]


def number(value):
    return struct.pack('!Q', value)


def bitmap(values):
    words = [0] * ((len(values) + 63) // 64)
    for index, value in enumerate(values):
        words[index // 64] |= value << (index % 64)
    return number(len(words)) + b''.join(map(number, words))


def domain_strategy(patterns):
    root = {'terminal': False, 'children': {}}
    for pattern in patterns:
        variants = [pattern]
        if pattern.startswith('+.'):
            variants.append(pattern[2:])
        elif pattern.startswith('.'):
            variants = ['+' + pattern]
        for value in variants:
            node = root
            for byte in value.lower()[::-1].encode():
                node = node['children'].setdefault(byte, {'terminal': False, 'children': {}})
            node['terminal'] = True
    queue = deque([root])
    leaves, unary, labels = [], [], bytearray()
    while queue:
        node = queue.popleft()
        leaves.append(int(node['terminal']))
        for label, child in sorted(node['children'].items()):
            labels.append(label)
            unary.append(0)
            queue.append(child)
        unary.append(1)
    return b'\1' + bitmap(leaves) + bitmap(unary) + number(len(labels)) + labels


def ip_strategy(prefixes):
    networks = [ipaddress.ip_network(value, strict=False) for value in prefixes]
    ranges = []
    for family in (4, 6):
        for network in ipaddress.collapse_addresses(n for n in networks if n.version == family):
            first, last = network.network_address, network.broadcast_address
            if family == 4:
                first = ipaddress.IPv6Address('::ffff:' + str(first))
                last = ipaddress.IPv6Address('::ffff:' + str(last))
            ranges.append(first.packed + last.packed)
    return b'\1' + number(len(ranges)) + b''.join(ranges)


def encode(behavior, count, strategy, extra=b''):
    return b'MRS\1' + bytes([behavior]) + number(count) + number(len(extra)) + extra + strategy


def write(name, data):
    (ROOT / (name + '.mrs')).write_bytes(compress(data))


def main():
    ROOT.mkdir(parents=True, exist_ok=True)
    domains = ['exact.test', '+.suffix.test', '.subonly.test', '*.single.test',
               'api.*.wild.test', '*.nested.*.test', '+.例子.测试', '*.例子.测试']
    networks = ['192.0.2.0/24', '192.0.2.0/25', '198.51.100.128/25', '2001:db8::/32', '2001:db9::/48']
    domain = encode(0, len(domains), domain_strategy(domains), b'future-extension')
    ip = encode(1, len(networks), ip_strategy(networks))
    write('domain', domain)
    write('ipcidr', ip)
    for name, raw in {
        'bad-magic': b'BAD\1' + domain[4:],
        'bad-behavior': domain[:4] + b'\x01' + domain[5:],
        'negative-count': domain[:5] + b'\xff' * 8 + domain[13:],
        'huge-extra': domain[:13] + number(2**63 - 1) + domain[21:],
        'truncated-strategy': domain[:-1],
        'trailing-data': domain + b'x',
        'huge-bitmap': encode(0, 1, b'\1' + number(2**63 - 1)),
        'bad-trie-topology': encode(0, 1, b'\1' + bitmap([0, 1]) + bitmap([1, 0, 1]) + number(1) + b'a'),
        'bad-trie-padding': encode(0, 1, b'\1' + bitmap([0, 1, 1]) + bitmap([0, 1, 1]) + number(1) + b'a'),
        'bad-trie-utf8': encode(0, 1, b'\1' + bitmap([0, 1]) + bitmap([0, 1, 1]) + number(1) + b'\xff'),
        'short-trie-utf8': encode(0, 1, b'\1' + bitmap([0, 1]) + bitmap([0, 1, 1]) + number(1) + b'\xe4'),
        'bad-ip-range': encode(1, 1, b'\1' + number(1) + ipaddress.IPv6Address('2001:db8::2').packed + ipaddress.IPv6Address('2001:db8::1').packed),
    }.items():
        write(name, raw)
    compressed = compress(domain)
    (ROOT / 'truncated-zstd.mrs').write_bytes(compressed[:-3])
    (ROOT / 'trailing-zstd.mrs').write_bytes(compressed + compress(domain))
    (ROOT / 'domain.yaml').write_text(json.dumps({'payload': domains}, ensure_ascii=False) + '\n')
    (ROOT / 'ipcidr.txt').write_text('# public IPv4/IPv6 fixtures\n' + '\n'.join(networks) + '\n')
    print('Generated independent MRS domain/IPCIDR fixtures and invalid wire cases')


if __name__ == '__main__':
    main()
