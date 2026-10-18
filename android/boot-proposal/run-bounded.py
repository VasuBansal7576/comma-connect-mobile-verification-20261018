#!/usr/bin/env python3
"""Bound and retain only the selected SDK install or Ubuntu dependency step."""
import os
from pathlib import Path
import subprocess
import sys
import threading

MODE=sys.argv[1] if len(sys.argv)==2 else ''
OUT=Path('evidence/android-boot');OUT.mkdir(parents=True,exist_ok=True)
commands={
 'sdk':(['/usr/local/lib/android/sdk/cmdline-tools/latest/bin/sdkmanager','--channel=0','emulator','system-images;android-35;google_apis_playstore;x86_64'],480),
 'apt-update':(['sudo','-n','apt-get','update'],60),
 'apt-install':(['sudo','-n','env','DEBIAN_FRONTEND=noninteractive','apt-get','-y','--no-install-recommends','install','acl','pulseaudio','pulseaudio-utils','ffmpeg'],120),
}
if MODE not in commands:raise SystemExit('REFUSED_OPERATION')
# No SDK agreement input is ever supplied. apt -y confirms only this explicit Ubuntu FLOSS package operation.
args,seconds=commands[MODE]
p=subprocess.Popen(args,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,start_new_session=True)
kept=bytearray()
def drain():
 while True:
  b=p.stdout.read(4096)
  if not b:break
  kept.extend(b)
  if len(kept)>65536:del kept[:-65536]
t=threading.Thread(target=drain,daemon=True);t.start()
try:p.wait(timeout=seconds);code=p.returncode
except subprocess.TimeoutExpired:
 import signal
 os.killpg(p.pid,signal.SIGKILL);p.wait();code=124
finally:t.join(timeout=2);(OUT/(MODE+'.log')).write_bytes(bytes(kept))
raise SystemExit(code)
