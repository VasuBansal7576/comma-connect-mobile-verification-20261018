#!/usr/bin/env python3
"""Owner-reviewed optional Linux-only capability probe. No SDK/AVD/browser/audio.
Not run here; one original child creates a late same-session descendant on TERM.
"""
import json,os,sys,tempfile,time
from pathlib import Path
import boot

def main():
    if sys.argv[1:]!=['--owned-linux-capability-probe'] or sys.platform!='linux':raise SystemExit('EXPLICIT_OWNED_LINUX_PROBE_REQUIRED')
    with tempfile.TemporaryDirectory()as directory:
        boot.OUT=Path(directory);boot.STATE={'children':[]};boot.TRACE=[];boot.CHILDREN=[]
        boot.enable_owned_subreaper()
        code='''import signal,subprocess,sys,time

def end(*args):
 subprocess.Popen([sys.executable,'-c','import time;time.sleep(12)'])
 raise SystemExit(0)
signal.signal(signal.SIGTERM,end)
print('READY',flush=True)
time.sleep(12)
'''
        try:
            proc=boot.own_process([sys.executable,'-c',code],'emulator')
            deadline=time.monotonic()+3
            while time.monotonic()<deadline:
                if b'READY' in (boot.OUT/'emulator-private.raw').read_bytes():break
                time.sleep(.02)
            else:raise RuntimeError('PROBE_CHILD_NOT_READY')
        finally:boot.cleanup()
        result={'schema':'owned-linux-late-descendant-subreaper-probe-v1','enabled':boot.STATE.get('ownedSubreaper',{}).get('verified')is True,'cleanupVerified':boot.STATE.get('ownedChildCleanupVerified')is True,'cleanup':boot.STATE.get('cleanup'),'children':boot.STATE.get('children'),'PWAOrAudioTest':False}
        print(json.dumps(result))
        return 0 if result['enabled']and result['cleanupVerified']and any(c.get('adoptedGroupMembers')for c in result['children'])else 2
if __name__=='__main__':raise SystemExit(main())
