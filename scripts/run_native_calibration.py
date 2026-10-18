#!/usr/bin/env python3
"""REMOTE CI ONLY. Caller must select a reviewed output route; never run on user's Mac."""
import array, json, math, os, pathlib, select, subprocess, sys, time, wave
if os.environ.get('GITHUB_ACTIONS') != 'true' or os.environ.get('RUNNER_OS') != 'macOS':
    raise SystemExit('Refusing audio rendering outside an ephemeral GitHub macOS job')
out=pathlib.Path(sys.argv[1]);out.mkdir(parents=True,exist_ok=True)
if (out/'system.f32').exists(): raise SystemExit('Evidence exists')
rate=48000;samples=array.array('h')
for i in range(rate*8):
    value=int(.2*32767*math.sin(2*math.pi*440*i/rate)) if i<3*rate or i>=5*rate else 0
    samples.extend([value,value])
if sys.byteorder!='little':samples.byteswap()
with wave.open(str(out/'tone-zero-tone.wav'),'wb') as f:
    f.setnchannels(2);f.setsampwidth(2);f.setframerate(rate);f.writeframes(samples.tobytes())
collector=subprocess.Popen(['./capture-system-audio','capture',str(out/'system.f32'),'12',str(out/'capture.json')],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
try:
    readable,_,_=select.select([collector.stdout],[],[],8)
    if not readable or collector.stdout.readline().strip()!='CAPTURE_STARTED':
        raise RuntimeError('Capture did not acknowledge start within 8s')
    start=time.monotonic()
    # A separate native process uses OS output. No WebAudio, microphone, or in-page graph.
    playback=subprocess.run(['/usr/bin/afplay',str(out/'tone-zero-tone.wav')],capture_output=True,text=True,timeout=15)
    stdout,stderr=collector.communicate(timeout=18)
    receipt={'schema':'ci-native-calibration-command-v1','nativePlayer':'/usr/bin/afplay',
             'sourcePhasesSeconds':[{'from':0,'to':3,'hz':440},{'from':3,'to':5,'hz':0},{'from':5,'to':8,'hz':440}],
             'elapsedAfterStartAckSeconds':time.monotonic()-start,'playerReturnCode':playback.returncode,
             'collectorReturnCode':collector.returncode,'collectorStderr':stderr,
             'outputMuteIntervention':False,'remoteOnly':True,'runId':os.environ.get('GITHUB_RUN_ID')}
    (out/'command.json').write_text(json.dumps(receipt,indent=2)+'\n')
    if playback.returncode or collector.returncode:raise RuntimeError('Native calibration command failed')
finally:
    if collector.poll() is None:
        collector.terminate()
        try:collector.wait(timeout=3)
        except subprocess.TimeoutExpired:collector.kill();collector.wait()
