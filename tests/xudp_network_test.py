#!/usr/bin/env python3
"""Real SOCKS UDP and TCP interoperability with a pinned, independent Mihomo.

Ordinary loopback listeners are required (Linux CI). Credentials, certificates
and names below are public fixtures. No user's configuration is read or edited.
"""
import argparse
import json
from pathlib import Path
import shutil
import socket
import struct
import subprocess
import tempfile
import threading
import time
import urllib.parse
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
UUID = '11111111-2222-4333-8444-555555555555'
HTTP = urllib.request.build_opener(urllib.request.ProxyHandler({}))
USED_PORTS = set()


def api(port, path, data=None, method=None):
    request = urllib.request.Request(f'http://127.0.0.1:{port}{path}',
        data=None if data is None else json.dumps(data).encode(),
        headers={'Content-Type': 'application/json'},
        method=method or ('GET' if data is None else 'PUT'))
    with HTTP.open(request, timeout=8) as response:
        content = response.read()
        return json.loads(content) if content else {}


def free_port():
    while True:
        with socket.socket() as listener:
            listener.bind(('127.0.0.1', 0))
            port = listener.getsockname()[1]
            if port not in USED_PORTS:
                USED_PORTS.add(port)
                return port


def read_exact(stream, length):
    result = b''
    while len(result) < length:
        part = stream.recv(length - len(result))
        if not part:
            raise AssertionError('Unexpected EOF in actual SOCKS handshake')
        result += part
    return result


class Echo:
    def __init__(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind(('127.0.0.1', 0))
        self.socket.settimeout(.1)
        self.port = self.socket.getsockname()[1]
        self.stopped = threading.Event()
        self.packets = []
        self.thread = threading.Thread(target=self.run, daemon=True)
        self.thread.start()

    def run(self):
        while not self.stopped.is_set():
            try:
                payload, source = self.socket.recvfrom(65535)
                self.packets.append(payload)
                self.socket.sendto(payload[::-1], source)
            except socket.timeout:
                continue
            except OSError:
                break

    def close(self):
        self.stopped.set()
        self.thread.join(1)
        self.socket.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--native', type=Path, required=True)
    parser.add_argument('--mihomo', type=Path, required=True)
    args = parser.parse_args()
    native, mihomo = args.native.resolve(strict=True), args.mihomo.resolve(strict=True)
    checks = 0

    def check(condition, message):
        nonlocal checks
        if not condition:
            raise AssertionError(message)
        checks += 1

    def ready(process, port):
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            if process.poll() is not None:
                raise AssertionError('Owned process stopped before listener readiness')
            try:
                return api(port, '/version')
            except (OSError, ValueError):
                time.sleep(.05)
        raise AssertionError('Owned listener did not become ready')

    with tempfile.TemporaryDirectory(prefix='clashos-xudp-network-') as temporary:
        work = Path(temporary)
        processes, logs, echoes = [], [], []
        label = 'setup'
        try:
            for name in ('server.pem', 'server-key.pem'):
                shutil.copyfile(ROOT / 'tests/fixtures/vmess' / name, work / name)
            peer_api, peer_tls, controller, http_port, socks_port, dns_port = [free_port() for _ in range(6)]
            server = {'external-controller': f'127.0.0.1:{peer_api}',
                'external-controller-tls': f'127.0.0.1:{peer_tls}',
                'tls': {'certificate': 'server.pem', 'private-key': 'server-key.pem'},
                'mode': 'rule', 'log-level': 'warning', 'find-process-mode': 'off',
                'hosts': {'udp-fixture.test': '192.0.2.44'},
                'dns': {'enable': True, 'listen': f'127.0.0.1:{dns_port}',
                    'ipv6': False, 'use-hosts': True, 'use-system-hosts': False,
                    'nameserver': ['udp://127.0.0.1:1']},
                'listeners': [], 'rules': ['MATCH,DIRECT']}
            client = {'port': http_port, 'socks-port': socks_port, 'mode': 'rule',
                'hosts': {'vmess.test': '127.0.0.1', 'wrong.test': '127.0.0.1'},
                'dns': {'enable': False, 'use-hosts': True}, 'proxies': [],
                'proxy-groups': [{'name': 'XUDP public', 'type': 'select', 'proxies': []}],
                'rules': ['MATCH,XUDP public']}
            for transport in ('tcp', 'tls', 'ws', 'ws-tls'):
                for protocol, alter in (('vless', 0), ('vmess', 0), ('vmess', 64)):
                    port = free_port()
                    listener = {'name': f'{protocol}-{alter}-{transport}',
                        'type': protocol, 'listen': '127.0.0.1', 'port': port,
                        'users': [{'username': 'public', 'uuid': UUID}]}
                    if protocol == 'vmess':
                        listener['users'][0]['alterId'] = alter
                    elif 'tls' not in transport:
                        # The independent server requires explicit opt-in for
                        # plaintext VLESS. This fixture listens only on loopback.
                        listener['allow-insecure'] = True
                    if 'ws' in transport:
                        listener['ws-path'] = '/xudp-public'
                    if 'tls' in transport:
                        listener.update({'certificate': 'server.pem', 'private-key': 'server-key.pem'})
                    server['listeners'].append(listener)
                    ciphers = ['aes-128-gcm', 'chacha20-poly1305', 'none', 'zero'] if protocol == 'vmess' and not alter else ['aes-128-gcm']
                    for cipher in ciphers:
                        name = f'{protocol}-{alter}-{cipher}-{transport}'
                        node = {'name': name, 'type': protocol, 'server': '127.0.0.1',
                            'port': port, 'uuid': UUID, 'udp': True, 'packet-encoding': 'xudp',
                            'network': 'ws' if 'ws' in transport else 'tcp',
                            'tls': 'tls' in transport, 'servername': 'vmess.test'}
                        if protocol == 'vmess':
                            node.update({'cipher': cipher, 'alterId': alter})
                        if 'ws' in transport:
                            node['ws-opts'] = {'path': '/xudp-public', 'headers': {'Host': 'vmess.test'}}
                        client['proxies'].append(node)
                        client['proxy-groups'][0]['proxies'].append(name)
            for filename, content in (('server.yaml', server), ('client.yaml', client)):
                (work / filename).write_text(json.dumps(content))
            for command, name in (([str(mihomo), '-d', str(work), '-f', str(work / 'server.yaml')], 'mihomo'),
                ([str(native), 'serve', str(work / 'client.yaml'), str(controller), str(ROOT / 'tests/fixtures/vmess/ca.pem')], 'native')):
                log = (work / (name + '.log')).open('w+')
                logs.append(log)
                processes.append(subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=log, stderr=log))
            check(ready(processes[0], peer_api)['version'] == 'v1.19.32', 'Independent server release is pinned')
            version = ready(processes[1], controller)
            check('Core 0.45' in version['version'] and 'xudp' in version['features'], 'Production XUDP implementation must be running')
            for _ in range(2):
                echoes.append(Echo())
            group = '/proxies/' + urllib.parse.quote('XUDP public', safe='')
            for node in client['proxies']:
                label = node['name']
                api(controller, group, {'name': label})
                check(api(controller, group)['now'] == label, 'Group selection must apply')
                # packet-encoding changes UDP only. Real HTTP and SOCKS TCP must
                # still use the ordinary protocol command, including verified TLS.
                for route in ('http', 'socks'):
                    proxy = ['--proxy', f'http://127.0.0.1:{http_port}'] if route == 'http' else ['--socks5-hostname', f'127.0.0.1:{socks_port}']
                    result = subprocess.run(['curl', '--noproxy', '', '--silent', '--show-error', '--fail',
                        '--connect-timeout', '5', '--max-time', '10', '--cacert', str(ROOT / 'tests/fixtures/vmess/ca.pem'),
                        *proxy, f'https://vmess.test:{peer_tls}/version'], capture_output=True, text=True, timeout=15)
                    check(result.returncode == 0 and json.loads(result.stdout)['version'] == 'v1.19.32',
                        'Ordinary TCP and verified HTTPS must reach official server: ' + result.stderr)
                with socket.create_connection(('127.0.0.1', socks_port), timeout=8) as control, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
                    udp.bind(('127.0.0.1', 0)); udp.settimeout(8)
                    control.sendall(b'\x05\x01\x00')
                    check(read_exact(control, 2) == b'\x05\x00', 'SOCKS no-auth negotiation')
                    control.sendall(b'\x05\x03\x00\x01' + b'\x00' * 6)
                    association = read_exact(control, 10)
                    check(association[:4] == b'\x05\x00\x00\x01', 'SOCKS UDP association')
                    relay = ('127.0.0.1', int.from_bytes(association[-2:], 'big'))
                    for echo in echoes:
                        header = b'\x00\x00\x00\x01\x7f\x00\x00\x01' + struct.pack('!H', echo.port)
                        for length in (0, 8, 1400, 8192, 65507 - len(header)):
                            label = node['name'] + f' UDP {length} destination {echo.port}'
                            body = bytes(index % 256 for index in range(length))
                            before = len(echo.packets)
                            udp.sendto(header + body, relay)
                            reply, source = udp.recvfrom(65535)
                            check(source == relay, 'Reply must come from the real native relay')
                            check(reply == header + body[::-1], 'Actual reply source/body/boundaries must match independent UDP echo')
                            check(len(echo.packets) == before + 1 and echo.packets[-1] == body, 'Every datagram must reach the independent destination exactly once')
                query = urllib.parse.urlencode({'name': 'udp-fixture.test', 'type': 'A',
                    'server': f'udp://127.0.0.1:{dns_port}#XUDP public'}, quote_via=urllib.parse.quote)
                api(controller, '/clahsos/dns/cache', method='DELETE')
                answer = api(controller, '/dns/query?' + query)
                check(answer.get('Status') == 0 and not answer.get('cached') and
                    any(record.get('data') == '192.0.2.44' for record in answer.get('Answer', [])),
                    'Uncached internal UDP DNS must use the selected XUDP route')
                print('PASS official Mihomo XUDP/TCP/TLS/DNS: ' + node['name'], flush=True)
            print(f'PASS {checks} official Mihomo XUDP network assertions', flush=True)
        except Exception as error:
            message = f'After {checks} assertions ({label}): {error}'
            print('::error title=XUDP interoperability::' + message.replace('%', '%25').replace('\r', '%0D').replace('\n', '%0A'), flush=True)
            for log in logs:
                log.flush(); log.seek(0); print(log.read()[-6000:])
            raise
        finally:
            for echo in echoes:
                echo.close()
            for process in reversed(processes):
                if process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        process.kill(); process.wait(timeout=5)
            for log in logs:
                log.close()


if __name__ == '__main__':
    main()
