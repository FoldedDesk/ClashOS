#!/usr/bin/env python3
"""Run production TUN/lwIP against a raw-IP socketpair; no device or TCP listener required."""
from pathlib import Path
import shutil
import subprocess
import tempfile
import os
from native_test_env import find_cmake

root = Path(__file__).resolve().parents[1]
cmake = find_cmake()
def run(args, timeout=60):
    result = subprocess.run([str(a) for a in args], cwd=root, text=True, capture_output=True, timeout=timeout)
    if result.returncode:
        print((result.stdout + result.stderr)[-12000:])
        raise SystemExit(result.returncode)
    return result.stdout
with tempfile.TemporaryDirectory(prefix='clahsos-tun-') as directory:
    work = Path(directory)
    run([cmake, '-S', root / 'tests/tun', '-B', work, '-DCMAKE_BUILD_TYPE=Debug'])
    run([cmake, '--build', work, '-j', '6'], timeout=180)
    print(run([work / 'tun_tests'], timeout=20), end='')
