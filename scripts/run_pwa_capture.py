#!/usr/bin/env python3
"""Capture only after installed UI/context test passes; no capture into the web page."""
import json, os, pathlib, select, subprocess, sys, time
if os.environ.get('GITHUB_ACTIONS')!='true' or os.environ.get('RUNNER_OS')!='macOS':raise SystemExit('Remote CI only')
out=pathlib.Path('evidence/installed-output');out.mkdir()
collector=subprocess.Popen(['./capture-system-audio','capture',str(out/'system.f32'),'60',str(out/'capture.json')],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
try:
    readable,_,_=select.select([collector.stdout],[],[],8)
    if not readable or collector.stdout.readline().strip()!='CAPTURE_STARTED':raise RuntimeError('Capture start timeout')
    start=time.monotonic()
    command=['xcodebuild','test-without-building','-project','CIProbe.xcodeproj','-scheme','CIProbe','-destination',f'platform=iOS Simulator,id={sys.argv[1]}','-derivedDataPath','DerivedData','-resultBundlePath','evidence/controls.xcresult','-only-testing:CIProbeUITests/InstallProbeUITests/testInstalledOutputControls','CODE_SIGNING_ALLOWED=NO']
    with (out/'ui-test.log').open('w') as log:
        result=subprocess.run(command,stdout=log,stderr=subprocess.STDOUT,timeout=75)
    elapsed=time.monotonic()-start
    stdout,stderr=collector.communicate(timeout=65)
    (out/'command.json').write_text(json.dumps({'uiReturnCode':result.returncode,'collectorReturnCode':collector.returncode,'uiElapsedSeconds':elapsed,'captureWindowSeconds':60,'collectorStderr':stderr,'captureAlignment':'UI-test receipts and PCM host timestamps; no inferred sample-accurate button alignment'},indent=2)+'\n')
    if result.returncode or collector.returncode or elapsed>60:raise RuntimeError('Controls failed or exceeded capture window')
    subprocess.run([sys.executable,'scripts/assess_pcm.py',str(out/'system.f32'),str(out/'capture.json'),str(out/'assessment.json')],check=True)
finally:
    if collector.poll() is None:
        collector.terminate()
        try:collector.wait(timeout=3)
        except subprocess.TimeoutExpired:collector.kill();collector.wait()
