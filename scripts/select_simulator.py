#!/usr/bin/env python3
import json, os, pathlib, subprocess
if os.environ.get('GITHUB_ACTIONS')!='true':raise SystemExit('CI-only simulator boot')
devices=json.loads(subprocess.check_output(['xcrun','simctl','list','devices','available','--json']))['devices']
choices=[]
for runtime, rows in devices.items():
    if 'iOS-18-5' in runtime or 'iOS-18-6' in runtime:
        for row in rows:
            if row.get('isAvailable') and row['name'].startswith('iPhone'):
                choices.append((runtime,row))
if not choices:raise SystemExit('No preinstalled eligible iOS 18.5/18.6 simulator; no download/acceptance fallback')
runtime,row=sorted(choices,key=lambda c:(c[0],c[1]['name']),reverse=True)[0]
pathlib.Path('evidence/selected-simulator.json').write_text(json.dumps({'runtime':runtime,**row},indent=2)+'\n')
print(row['udid'])
