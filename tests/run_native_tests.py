#!/usr/bin/env python3
"""Build production protocol/configuration code with independent peer/vector regression tests."""
from pathlib import Path
import argparse, os, shutil, subprocess, tempfile
from native_test_env import find_cmake
parser = argparse.ArgumentParser()
parser.add_argument('--suite', choices=['connection-trace', 'http', 'tls', 'dialer', 'groups', 'all', 'api', 'configs', 'inbound', 'sniffer', 'rules', 'dns', 'hosts', 'vless', 'forward', 'providers', 'yaml', 'ss-duplex', 'ss2022', 'geo', 'ports', 'rule-edits', 'object-edits', 'share-links', 'merges', 'scripts', 'archive', 'network-backup', 'editor-providers'], default='all')
parser.add_argument('--build-dir', type=Path, help='Optional reusable CMake build directory')
parser.add_argument('--config', type=Path, help='Optional local configuration compatibility check; defaults to the public fixture')
options = parser.parse_args()
root = Path(__file__).resolve().parents[1]
config = options.config.resolve() if options.config else root / 'tests/fixtures/core/public.yaml'
if not config.is_file():
    raise SystemExit('Configuration fixture not found. Supply an existing file with --config.')
python_candidates = [os.environ.get('CLAHSOS_REFERENCE_PYTHON'), '/opt/anaconda3/bin/python', shutil.which('python3')]
for candidate in python_candidates:
    if candidate and Path(candidate).is_file() and subprocess.run([candidate, '-c', 'import cryptography'], capture_output=True).returncode == 0:
        os.environ['CLAHSOS_REFERENCE_PYTHON'] = candidate
        break
else:
    raise SystemExit('Set CLAHSOS_REFERENCE_PYTHON to Python with cryptography for the independent VMess peer.')
if options.suite in ('ss2022', 'all') and subprocess.run([os.environ['CLAHSOS_REFERENCE_PYTHON'], '-c', 'import blake3; from Crypto.Cipher import AES, ChaCha20_Poly1305'], capture_output=True).returncode:
    raise SystemExit('SS2022 reference tests require blake3==1.0.8 and pycryptodome in CLAHSOS_REFERENCE_PYTHON (or its PYTHONPATH).')
cmake = find_cmake()
def run(command, timeout=180):
    try:
        result = subprocess.run([str(p) for p in command], cwd=root, text=True, capture_output=True, timeout=timeout)
    except subprocess.TimeoutExpired as error:
        output = (error.stdout or b'') + (error.stderr or b'')
        print(output.decode(errors='replace')[-8000:])
        raise SystemExit(f'Native test command timed out after {timeout}s') from None
    if result.returncode:
        print((result.stdout + result.stderr)[-8000:])
        raise SystemExit(result.returncode)
    return result.stdout
def verify(work):
    work.mkdir(parents=True, exist_ok=True)
    run([cmake, '-S', root / 'tests/native', '-B', work, '-DCMAKE_BUILD_TYPE=Debug'])
    run([cmake, '--build', work, '-j', '6'])
    # Reuse compiled dependencies, never provider caches or other mutable fixtures.
    with tempfile.TemporaryDirectory(prefix='clashos-native-fixtures-') as fixtures:
        command = [work / 'native_tests', config, Path(fixtures)]
        if options.suite != 'all': command.append(options.suite)
        print(run(command, timeout=90), end='')
if options.build_dir:
    verify(options.build_dir.resolve())
else:
    with tempfile.TemporaryDirectory(prefix='clahsos-native-') as temporary:
        verify(Path(temporary))
