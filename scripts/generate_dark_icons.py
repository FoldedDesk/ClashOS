#!/usr/bin/env python3
"""Generate native MenuItem SVG variants while preserving transparent cutouts."""
from pathlib import Path
import re

root = Path(__file__).resolve().parents[1] / 'entry/src/main/resources'
target = root / 'dark/media'
target.mkdir(parents=True, exist_ok=True)
for source in (root / 'base/media').glob('verge_*.svg'):
    (target / source.name).write_text(re.sub(r'#[0-9a-fA-F]{6}', '#C3C3CE', source.read_text()))
