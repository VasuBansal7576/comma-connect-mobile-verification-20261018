#!/usr/bin/env python3
"""Compose reviewed same-file native tests without changing the audio suite."""
import hashlib
import os
from pathlib import Path
import runpy

if os.environ.get('GITHUB_ACTIONS') != 'true':
    raise SystemExit('Hosted CI only')
root = Path(__file__).resolve().parents[1]
inputs = [
    ('ios/V15InstalledUITests.swift', 'd34a1b286cd1c87a92b6072bdc49035ab2ae19661f1a36466c47f68c6ec527bc'),
    ('ios/V15NativeContinuation.swift.inc', '8d3156743e13fbf83f4fe1975be9c7498f8a4ea6ce52223f598e73b17d8b60bc'),
    ('ios/V15URLContinuation.swift.inc', '9ac3abf9050a54ba03e57b1755dc420dbc23c26fa39905295ef50180fcb2758f'),
]
parts = []
for name, expected in inputs:
    data = (root / name).read_bytes()
    if hashlib.sha256(data).hexdigest() != expected:
        raise SystemExit('Reviewed native source identity changed: ' + name)
    parts.append(data)
(root / 'ios/V15NativeComposed.swift').write_bytes(b'\n'.join(parts))
runpy.run_path(str(root / 'scripts/generate_v15_project.py'), run_name='__main__')
project = root / 'CIProbeV15.xcodeproj/project.pbxproj'
source = project.read_text()
anchor = '"ios/V15InstalledUITests.swift"'
if source.count(anchor) != 1:
    raise SystemExit('Generated UI source anchor changed')
project.write_text(source.replace(anchor, '"ios/V15NativeComposed.swift"'))
