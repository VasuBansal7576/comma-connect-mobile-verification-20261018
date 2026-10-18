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
    ('ios/V16InstalledUITests.swift', 'ffa10053bd5e7bcb5082a58257654eda82a5484daa410ce31843e8958dc65b40'),
    ('ios/V16NativeContinuation.swift.inc', '6172a311db1e531acbbdadb545feab5ea140343e70e767ca6057ff33476e6150'),
    ('ios/V16URLContinuation.swift.inc', '32605983487d99146e67a15ad08e758670f9bb6a49ec001af66fb92fdcb21ae4'),
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
