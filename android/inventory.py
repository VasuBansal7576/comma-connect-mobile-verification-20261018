#!/usr/bin/env python3
"""Read-only existing-runner SDK facts. Never invokes any Android command or installer."""
import argparse
import hashlib
import json
import os
import platform
import re
import shutil
import stat
import xml.etree.ElementTree as ET
from pathlib import Path

MAX_XML = 4 * 1024 * 1024
ID = re.compile(r"[a-zA-Z0-9_.-]{1,100}\Z")
HASH = re.compile(r"[0-9a-f]{40}\Z")
PACKAGE = re.compile(r"[A-Za-z0-9_.;-]{1,250}\Z")

def bounded(path, limit):
    if path.is_symlink() or not path.is_file() or path.stat().st_size > limit:
        raise ValueError('UNSAFE_OR_OVERSIZE_FILE')
    return path.read_bytes()

def tag(element):
    return element.tag.rsplit('}', 1)[-1]

def license_hashes(root):
    records = {}
    directory = root / 'licenses'
    if not directory.is_dir() or directory.is_symlink():
        return records
    for path in sorted(directory.iterdir())[:64]:
        if not ID.fullmatch(path.name):
            continue
        try:
            text = bounded(path, 16384).decode('ascii')
            lines = text.splitlines()
            hashes = [line for line in lines if HASH.fullmatch(line)]
            records[path.name] = {'acceptedSHA1Lines': hashes,
                                  'otherNonemptyLines': sum(bool(x) and not HASH.fullmatch(x) for x in lines)}
        except (OSError, UnicodeError, ValueError):
            records[path.name] = {'refused': 'UNREADABLE_OR_INVALID_LICENSE_FILE'}
    return records

def package_record(path, root, accepted):
    data = bounded(path, MAX_XML)
    if b'<!DOCTYPE' in data.upper() or b'<!ENTITY' in data.upper():
        raise ValueError('XML_DTD_REFUSED')
    xml = ET.fromstring(data)
    packages = [x for x in xml.iter() if tag(x) == 'localPackage']
    if len(packages) != 1:
        raise ValueError('EXACTLY_ONE_LOCAL_PACKAGE_REQUIRED')
    package = packages[0]
    name = package.get('path', '')
    if not PACKAGE.fullmatch(name):
        raise ValueError('INVALID_PACKAGE_ID')
    revision = next((x for x in package if tag(x) == 'revision'), None)
    rev = {tag(x): x.text for x in revision} if revision is not None else {}
    refs = [x.get('ref', '') for x in package if tag(x) == 'uses-license']
    licenses = {x.get('id'): ''.join(x.itertext()) for x in xml.iter() if tag(x) == 'license'}
    evidence = []
    for ref in refs:
        if not ID.fullmatch(ref):
            raise ValueError('INVALID_LICENSE_ID')
        text = licenses.get(ref)
        digest = hashlib.sha1(text.encode('utf-8')).hexdigest() if text is not None else None
        evidence.append({'ref': ref, 'persistedXMLValueSHA1': digest,
                         'exactValueHashFoundInExistingLicenseFile': bool(digest and digest in accepted.get(ref, {}).get('acceptedSHA1Lines', []))})
    all_matched = bool(evidence) and all(x['exactValueHashFoundInExistingLicenseFile'] for x in evidence)
    parent = path.parent
    return {'package': name, 'revision': rev, 'relativePackageXML': str(path.relative_to(root)),
            'packageXMLSHA256': hashlib.sha256(data).hexdigest(), 'licenses': evidence,
            'technicalPersistedLicenseMatch': all_matched,
            'requiredImageFiles': {n: (parent / n).is_file() for n in ['system.img', 'ramdisk.img', 'userdata.img', 'kernel-ranchu']} if name.startswith('system-images;') else None}

def avd_records(directory):
    rows = []
    if not directory.is_dir() or directory.is_symlink():
        return rows
    for config in sorted(directory.glob('*.avd/config.ini'))[:64]:
        row = {'name': config.parent.name.removesuffix('.avd')}
        try:
            text = bounded(config, 65536).decode('utf-8')
            allowed = {'abi.type', 'tag.id', 'PlayStore.enabled', 'image.sysdir.1', 'hw.device.name'}
            fields = {}
            for line in text.splitlines():
                key, sep, value = line.partition('=')
                if sep and key.strip() in allowed:
                    value = value.strip()
                    if len(value) > 250 or any(ord(c) < 32 for c in value):
                        raise ValueError('INVALID_AVD_VALUE')
                    # Only relative package paths; do not expose arbitrary home paths.
                    if key.strip() == 'image.sysdir.1' and (value.startswith('/') or '..' in Path(value).parts):
                        value = 'ABSOLUTE_OR_PARENT_PATH_REDACTED'
                    fields[key.strip()] = value
            row['fields'] = fields
        except (OSError, UnicodeError, ValueError):
            row['refused'] = 'UNREADABLE_OR_INVALID_AVD_CONFIG'
        rows.append(row)
    return rows

def collect(root, avds, kvm=Path('/dev/kvm')):
    accepted = license_hashes(root)
    rows, errors = [], []
    # Explicit SDK subtree allowlist; no home/config/environment dumps or recursive image-data reading.
    for folder in ['cmdline-tools', 'platform-tools', 'emulator', 'platforms', 'system-images', 'build-tools']:
        parent = root / folder
        if parent.is_symlink() or not parent.is_dir():
            continue
        candidates = sorted(parent.rglob('package.xml'))
        if len(candidates) > 1024:
            errors.append({'subtree': folder, 'refused': 'PACKAGE_COUNT_LIMIT'})
            continue
        for path in candidates:
            if len(path.relative_to(root).parts) > 9 or any(p.is_symlink() for p in [path, *path.parents] if p != root.parent):
                errors.append({'subtree': folder, 'refused': 'UNSAFE_PACKAGE_PATH'})
                continue
            try:
                rows.append(package_record(path, root, accepted))
            except (OSError, ValueError, UnicodeError, ET.ParseError):
                errors.append({'subtree': folder, 'refused': 'PACKAGE_METADATA_INVALID'})
    images = [r for r in rows if re.fullmatch(r'system-images;android-[0-9]+;google_apis_playstore;x86_64', r['package'])]
    image_ready = [r for r in images if r['technicalPersistedLicenseMatch'] and all(r['requiredImageFiles'].values())]
    bins = {name: bool(shutil.which(name)) for name in ['pulseaudio', 'pactl', 'parec', 'ffmpeg', 'google-chrome', 'chromium', 'Xvfb', 'adb']}
    sdk_bins = {name: (root / rel).is_file() and os.access(root / rel, os.X_OK) for name, rel in {'emulator': 'emulator/emulator', 'adb': 'platform-tools/adb', 'sdkmanager': 'cmdline-tools/latest/bin/sdkmanager'}.items()}
    kvm_facts = {'exists': kvm.exists(), 'characterDevice': kvm.exists() and stat.S_ISCHR(kvm.stat().st_mode), 'readWriteAccess': os.access(kvm, os.R_OK | os.W_OK)}
    basic = platform.system() == 'Linux' and platform.machine() == 'x86_64' and sdk_bins['emulator'] and sdk_bins['adb'] and bool(image_ready) and all(kvm_facts.values()) and all(bins[n] for n in ['pulseaudio', 'pactl', 'parec', 'ffmpeg'])
    return {'schema': 'existing-ubuntu-android-readonly-inventory-v1', 'system': platform.system(), 'arch': platform.machine(),
            'runnerImage': {k: os.environ.get(k) for k in ['ImageOS', 'ImageVersion']},
            'sdkRootExists': root.is_dir(), 'packages': rows, 'metadataRefusals': errors,
            'existingLicenseFiles': accepted, 'existingAVDs': avd_records(avds),
            'sdkExecutables': sdk_bins, 'hostToolsPresent': bins, 'kvm': kvm_facts,
            'existingGooglePlayX86ImageCount': len(images), 'technicallyMatchedCompleteImageCount': len(image_ready),
            'basicExistingResourcesAppearPresent': bool(basic and not errors),
            'launchAuthorizedByThisReport': False, 'legalAcceptanceInferred': False,
            'emulatorLaunched': False, 'networkCalls': 0, 'softwareInstalled': False, 'licensesAcceptedOrWritten': False,
            'nextStep': 'OWNER_REVIEW_FACTS_ONLY_NO_AUTOMATIC_LAUNCH',
            'limits': ['Filesystem package/license evidence only; no SDK parser/boot/device Chrome/PWA/audio verification.',
                       'Exact SHA1 of persisted XML license value is compared only; missing text/hash or normalization mismatch refuses readiness.',
                       'Existing acceptance files are a technical SDK state, not proof of who accepted terms or authorization to make new agreements.',
                       'Missing prerequisites remain missing; no install, apt, sdkmanager, acceptance, permission change or emulator command is run.']}

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--sdk-root', type=Path, default=Path('/usr/local/lib/android/sdk'))
    parser.add_argument('--avd-dir', type=Path, default=Path.home() / '.android/avd')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    report = collect(args.sdk_root.resolve(), args.avd_dir)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'status': 'READ_ONLY_INVENTORY_COMPLETE', 'packageCount': len(report['packages']), 'existingGooglePlayX86ImageCount': report['existingGooglePlayX86ImageCount'], 'basicExistingResourcesAppearPresent': report['basicExistingResourcesAppearPresent'], 'launchAuthorized': False}))

if __name__ == '__main__':
    main()
