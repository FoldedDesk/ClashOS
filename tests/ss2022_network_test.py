#!/usr/bin/env python3
"""Actual loopback interoperability with a separately supplied official Mihomo.

Requires ordinary TCP/UDP listener permissions (e.g. the Linux CI runner).
Only the repository's public synthetic profile/certificates are used. Both
processes and all files belong to this invocation and are cleaned on exit.
"""
import argparse
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
import urllib.parse
import urllib.request

parser = argparse.ArgumentParser()
parser.add_argument('--native', type=Path, required=True)
parser.add_argument('--mihomo', type=Path, required=True)
args = parser.parse_args()
root = Path(__file__).resolve().parents[1]
native, mihomo = args.native.resolve(strict=True), args.mihomo.resolve(strict=True)
http = urllib.request.build_opener(urllib.request.ProxyHandler({}))
checks = 0


def api(port, path, data=None):
    request = urllib.request.Request('http://127.0.0.1:' + str(port) + path,
                                     data=None if data is None else json.dumps(data).encode(),
                                     headers={'Content-Type': 'application/json'},
                                     method='GET' if data is None else 'PUT')
    with http.open(request, timeout=8) as response:
        content = response.read()
        return json.loads(content) if content else {}


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


def check(condition, message):
    global checks
    if not condition:
        raise AssertionError(message)
    checks += 1


with tempfile.TemporaryDirectory(prefix='clashos-ss2022-network-') as temp:
    work = Path(temp)
    for name in ('server.pem', 'server-key.pem'):
        shutil.copyfile(root / 'tests/fixtures/vmess' / name, work / name)
    server = work / 'server.yaml'
    shutil.copyfile(root / 'tests/fixtures/ss2022/device-server.yaml', server)
    profile = work / 'client.yaml'
    client = json.loads((root / 'tests/fixtures/ss2022/device-client.yaml').read_text())
    client['hosts']['wrong.test'] = '127.0.0.1'
    profile.write_text(json.dumps(client))
    processes, logs = [], []
    try:
        for command, name in [([str(mihomo), '-d', str(work), '-f', str(server)], 'mihomo'),
                              ([str(native), 'serve', str(profile), '19090'], 'native')]:
            log = (work / (name + '.log')).open('w+')
            logs.append(log)
            processes.append(subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=log, stderr=log))
        peer_version, native_version = ready(processes[0], 19094), ready(processes[1], 19090)
        check(peer_version['version'] == 'v1.19.32', 'The independent server must be the pinned release')
        check('Core 0.43' in native_version['version'], 'The production SS2022 implementation must be running')
        group = urllib.parse.quote('SS2022 public', safe='')
        for node in client['proxies']:
            api(19090, '/proxies/' + group, {'name': node['name']})
            check(api(19090, '/proxies/' + group)['now'] == node['name'], 'Actual group selection must apply')
            for route in ('http', 'socks'):
                for tls in (False, True):
                    proxy = ['--proxy', 'http://127.0.0.1:18890'] if route == 'http' else ['--socks5-hostname', '127.0.0.1:18891']
                    target = 'https://vmess.test:19095/version' if tls else 'http://127.0.0.1:19094/version'
                    command = ['curl', '--noproxy', '', '--silent', '--show-error', '--fail', '--connect-timeout', '5', '--max-time', '10', *proxy]
                    if tls:
                        command += ['--cacert', str(root / 'tests/fixtures/vmess/ca.pem')]
                    result = subprocess.run(command + [target], check=True, capture_output=True, text=True, timeout=15)
                    check(json.loads(result.stdout)['version'] == 'v1.19.32', 'Real HTTP/SOCKS/verified-TLS response must come from the independent server')
            for fault in ('wrong-host', 'untrusted-ca'):
                target = 'https://' + ('wrong.test' if fault == 'wrong-host' else 'vmess.test') + ':19095/version'
                command = ['curl', '--noproxy', '', '--silent', '--show-error', '--proxy', 'http://127.0.0.1:18890', '--connect-timeout', '5', '--max-time', '10']
                if fault == 'wrong-host':
                    command += ['--cacert', str(root / 'tests/fixtures/vmess/ca.pem')]
                result = subprocess.run(command + [target], capture_output=True, text=True, timeout=15)
                check(result.returncode == 60, 'SS2022 forwarding must preserve target certificate/hostname rejection')
            query = urllib.parse.urlencode({'name': 'udp-fixture.test', 'type': 'A', 'server': 'udp://127.0.0.1:18553#SS2022 public'}, quote_via=urllib.parse.quote)
            answer = api(19090, '/dns/query?' + query)
            check(answer.get('Status') == 0 and not answer.get('cached') and any(record.get('data') == '192.0.2.44' for record in answer.get('Answer', [])),
                  'Actual SS2022 UDP DNS must reach the independent resolver without a cached or direct substitute')
            print('PASS actual Mihomo TCP/UDP/TLS: ' + node['cipher'], flush=True)
        print('PASS ' + str(checks) + ' official Mihomo SS2022 network assertions', flush=True)
    except Exception as error:
        # A public check annotation makes a network failure actionable even when
        # GitHub requires authentication to download the complete job log.
        message = ('After ' + str(checks) + ' assertions: ' + str(error)).replace('%', '%25').replace('\r', '%0D').replace('\n', '%0A')
        print('::error title=SS2022 interoperability::' + message, flush=True)
        for log in logs:
            log.flush(); log.seek(0)
            print(log.read()[-6000:])  # Public fixture processes only.
        raise
    finally:
        for process in reversed(processes):
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill(); process.wait(timeout=5)
        for log in logs:
            log.close()
