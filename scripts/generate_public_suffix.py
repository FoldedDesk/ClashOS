"""Regenerate the pinned PSL table without network access or third-party packages."""
from pathlib import Path
import hashlib
import json

root = Path(__file__).resolve().parents[1]
directory = root / "entry/src/main/cpp/third_party/public_suffix_list"
source = (directory / "public_suffix_list.dat").read_bytes()
metadata = json.loads((directory / "UPSTREAM.json").read_text())
if hashlib.sha256(source).hexdigest() != metadata["sha256"]:
    raise SystemExit("PSL source does not match the pinned checksum")
rules = set()
for line in source.decode("utf-8").splitlines():
    if not line.strip() or line.startswith("//"):
        continue
    rule = line.strip().lower()
    rules.add(rule)
    # PSL labels are already normalized. Keep Unicode rules and their RFC 3492 A-label aliases.
    prefix = "!" if rule.startswith("!") else ""
    labels = rule[len(prefix):].split(".")
    rules.add(prefix + ".".join(
        label if label.isascii() else "xn--" + label.encode("punycode").decode("ascii")
        for label in labels
    ))
generated = "// Generated from the pinned MPL-2.0 Public Suffix List; see UPSTREAM.json.\n"
generated += "".join(json.dumps(rule, ensure_ascii=False) + ",\n" for rule in sorted(rules))
(directory / "rules.inc").write_text(generated, encoding="utf-8")
(root / "entry/src/main/resources/rawfile/public_suffix_list.dat").write_bytes(source)
print(f"Generated {len(rules)} suffix rules and A-label aliases")
