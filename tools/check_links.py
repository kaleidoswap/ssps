#!/usr/bin/env python3
"""Check that relative links in the current top-level documents resolve."""
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
broken = []
for doc in sorted(ROOT.glob('*.md')):
    for target in re.findall(r'\]\(([^)]+)\)', doc.read_text()):
        if '://' in target or target.startswith('#'):
            continue
        if not (doc.parent / target.split('#')[0]).exists():
            broken.append(f'{doc.name}: {target}')
print('\n'.join(broken) or 'links ok')
sys.exit(1 if broken else 0)
