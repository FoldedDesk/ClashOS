#!/usr/bin/env python3
"""Independent VMess duplex peer: a partial reply must not stop client writes."""
import socket
import sys
from pathlib import Path
from trojan_reference_peer import context
from vmess_reference_peer import Wire, Mask, body_aead, decode_header, response_packet


def main():
    fd, alter, transport = int(sys.argv[1]), int(sys.argv[2]), sys.argv[3]
    phase, marker = sys.argv[4].split('|', 1)
    conn = socket.socket(fileno=fd)
    conn.settimeout(5)
    if 'tls' in transport:
        ctx = context()
        ctx.set_alpn_protocols(['http/1.1'])
        conn = ctx.wrap_socket(conn, server_side=True)
    wire = Wire(conn)
    if 'ws' in transport:
        wire.upgrade()
    command = decode_header(wire, alter, target_host='192.0.2.9')
    iv, key, options, security = command[1:17], command[17:33], command[34], command[35] & 15
    mask, cipher, counter = Mask(iv), body_aead(key, security), 0

    def chunk():
        nonlocal counter
        length = int.from_bytes(wire.exact(2), 'big')
        padding = mask.next() % 64 if options & 8 else 0
        if options & 4:
            length ^= mask.next()
        packet = wire.exact(length)
        if padding:
            packet = packet[:-padding]
        result = cipher.decrypt(counter.to_bytes(2, 'big') + iv[2:12], packet, None) if cipher else packet
        counter += 1
        return result

    assert chunk() == b'first'
    prefix = response_packet(command, alter, '', [])
    whole = response_packet(command, alter, '', [b'done', b''])
    assert whole.startswith(prefix)
    split = {'header': 1, 'header-body': 19, 'length': len(prefix) + 1,
             'payload': len(prefix) + 3}[phase]
    wire.send(whole[:split])
    Path(marker).write_text('partial reply sent\n')
    assert chunk() == b'tail', 'A partial VMess reply blocked later client data'
    assert chunk() == b''
    wire.send(whole[split:])
    conn.close()


if __name__ == '__main__':
    main()
