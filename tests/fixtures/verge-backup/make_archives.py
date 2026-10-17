"""Independent Python ZIP fixtures following upstream create_backup layout."""
from pathlib import Path
import argparse, zipfile, io

root = Path(__file__).resolve().parent
parser = argparse.ArgumentParser()
parser.add_argument('output', type=Path)
args = parser.parse_args()
args.output.mkdir(parents=True, exist_ok=True)

def populate(archive):
    archive.writestr('profiles/', b'')
    for path in sorted(root.rglob('*')):
        if path.is_file() and path.suffix in ('.yaml', '.js'):
            archive.writestr(path.relative_to(root).as_posix(), path.read_bytes())
    archive.writestr('profiles/public-remote.yaml', (root / 'profiles/public.yaml').read_bytes())

for label, method in [('stored', zipfile.ZIP_STORED), ('deflated', zipfile.ZIP_DEFLATED)]:
    with zipfile.ZipFile(args.output / ('public-verge-' + label + '.zip'), 'w', compression=method) as archive:
        populate(archive)

class NonSeekable(io.BytesIO):
    def seekable(self): return False
    def seek(self, *args): raise io.UnsupportedOperation()

stream = NonSeekable()
with zipfile.ZipFile(stream, 'w', compression=zipfile.ZIP_DEFLATED) as archive:
    populate(archive)
(args.output / 'public-verge-descriptor.zip').write_bytes(stream.getvalue())
print('Created independent stored, deflated and data-descriptor public ZIP fixtures.')
