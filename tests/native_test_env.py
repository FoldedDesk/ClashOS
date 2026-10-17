"""Locate build tools without requiring one developer's SDK installation."""
import os
from pathlib import Path
import shutil


def find_cmake():
    explicit = os.environ.get('CMAKE_COMMAND')
    if explicit:
        resolved = shutil.which(explicit)
        if resolved:
            return resolved
        raise SystemExit('CMAKE_COMMAND must point to an executable CMake installation.')
    found = shutil.which('cmake')
    if found:
        return found
    sdk = os.environ.get('DEVECO_SDK_HOME')
    candidates = []
    if sdk:
        for relative in ('default/openharmony/native/build-tools/cmake/bin/cmake', 'openharmony/native/build-tools/cmake/bin/cmake', 'native/build-tools/cmake/bin/cmake'):
            candidates.append(Path(sdk) / relative)
    candidates.append(Path('/Applications/DevEco-Studio.app/Contents/sdk/default/openharmony/native/build-tools/cmake/bin/cmake'))
    for candidate in candidates:
        for tool in (candidate, candidate.with_suffix('.exe')):
            if tool.is_file() and os.access(tool, os.X_OK):
                return str(tool)
    raise SystemExit('Install CMake on PATH, or set CMAKE_COMMAND / DEVECO_SDK_HOME.')
