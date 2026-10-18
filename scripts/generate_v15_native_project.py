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
    ('ios/V15InstalledUITests.swift', '52d2145ba11f24e11d24945890ce8827d3b4f9fbecb5392c11eaf60fc97b6e71'),
    ('ios/V15NativeContinuation.swift.inc', '8d3156743e13fbf83f4fe1975be9c7498f8a4ea6ce52223f598e73b17d8b60bc'),
    ('ios/V15URLContinuation.swift.inc', '838679c4db9a501876eb9969f66c25b5e997f6c1bdc14fa5fa0418d448a71dd6'),
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
