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
    ('ios/V15InstalledUITests.swift', 'd8e0ec914a6349fb6fb98aabc2be72656ab4e1f00d1c09a9d2329443b956c9a7'),
    ('ios/V15NativeContinuation.swift.inc', '0cbe6b5d6e56e82969fc96aa8e2ae2c98f94db77475a2d9ebe4d541a009af8dc'),
    ('ios/V15URLContinuation.swift.inc', 'ab16aef353559b2b5c28769f22a5dd2352ae324e157fb44af0f403e994e4ceb6'),
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
