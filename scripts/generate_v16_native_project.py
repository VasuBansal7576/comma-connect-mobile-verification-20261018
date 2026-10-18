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
    ('ios/V16InstalledUITests.swift', '5e146b088d81374a818cc4889c6f1785e030250cee16e4bec805a9774a77ed08'),
    ('ios/V16NativeContinuation.swift.inc', '743de1a6e02698723fab403e5eb04be705cb70af43e1ad36cb142e762b4d06e3'),
    ('ios/V16URLContinuation.swift.inc', 'e61820baa3ac8ec39e7a8d7bb0c4ab4902f22b48a1c4206d68e66db203e57d82'),
]
parts = []
for name, expected in inputs:
    data = (root / name).read_bytes()
    if hashlib.sha256(data).hexdigest() != expected:
        raise SystemExit('Reviewed native source identity changed: ' + name)
    parts.append(data)
(root / 'ios/V16NativeComposed.swift').write_bytes(b'\n'.join(parts))
runpy.run_path(str(root / 'scripts/generate_v16_project.py'), run_name='__main__')
project = root / 'CIProbeV16.xcodeproj/project.pbxproj'
source = project.read_text()
anchor = '"ios/V16InstalledUITests.swift"'
if source.count(anchor) != 1:
    raise SystemExit('Generated UI source anchor changed')
project.write_text(source.replace(anchor, '"ios/V16NativeComposed.swift"'))
