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
    ('ios/V16InstalledUITests.swift', 'cc62b041999930b2a9a67ce413e6559671ac4785dc0515a3c725eb848bd889a5'),
    ('ios/V16NativeContinuation.swift.inc', '3d82748cd12d5bb3144bff934bf24d6a2ae479df89285bd269e546b97349e6f4'),
    ('ios/V16URLContinuation.swift.inc', '78aa6a6216964b984005d8330bf2e2426588c61da111ccd256c6c6abd1672b5a'),
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
