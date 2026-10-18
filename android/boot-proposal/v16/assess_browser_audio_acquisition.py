"""Fixed post-cleanup offline chain; original numeric/short gates unchanged. No audio/UI."""
import argparse,hashlib,json,os,shutil,sys
from pathlib import Path
from owned_audio_command import run_owned
HERE=Path(__file__).resolve().parent
REPO=HERE.parents[2]
def main():
 if os.environ.get('GITHUB_ACTIONS')!='true'or os.environ.get('RUNNER_OS')!='Linux':raise SystemExit('Hosted Linux evidence assessment only')
 out=Path('evidence/android-boot/audio');boot=json.loads(Path('evidence/android-boot/receipt.json').read_text())
 if boot.get('acquisitionMode')!='browser' or boot.get('browserNativeContextObserved')is not True or boot.get('installedPWAStandaloneObserved')is True or not boot.get('audioRawAndCarrierAcquired')or boot.get('ownedChildCleanupVerified')is not True or boot.get('KVMACLChanged')is not False or boot.get('ownedADBServerCleanupExitCode')!=0:raise SystemExit('Actual original acquisition and owned cleanup required')
 num=HERE/'numeric';node=shutil.which('node')
 if not node:raise SystemExit('Existing Node required')
 commands=[
  [node,str(HERE/'scalarize_pulse_pcm.cjs'),str(out/'system.f32'),str(out/'native-summary.json'),str(num/'scalar-core-180.js'),str(out/'scalars.json')],
  [sys.executable,str(HERE/'assess_android_browser_pulse.py'),'--source',str(out/'source-frozen.json'),'--integrity',str(out/'integrity.json'),'--raw',str(out/'system.f32'),'--summary',str(out/'native-summary.json'),'--journal',str(out/'native-journal.jsonl'),'--scalars',str(out/'scalars.json'),'--native-validator',str(REPO/'audio/native-pulse/validate_native.py'),'--frozen-assessor',str(num/'assess-os-recording.py'),'--assets',str(num/'ACQUISITION.json'),'--out',str(out/'numeric-components')],
  [sys.executable,str(HERE/'audit_pulse_short.py'),'--raw',str(out/'system.f32'),'--source',str(out/'source-frozen.json'),'--components',str(out/'numeric-components/ASSESSMENT.json'),'--numeric',str(out/'numeric-components/FROZEN-NUMERIC-REPORT.json'),'--coverage',str(out/'numeric-components/NATIVE-SOURCE-COVERAGE.json'),'--joint',str(num/'joint_tones.py'),'--zero',str(num/'audit_pcm_zeros.py'),'--out',str(out/'short-audit')]]
 receipts=[]
 for i,cmd in enumerate(commands):
  r=run_owned(cmd,out/('post-'+str(i)+'.log'),180);receipts.append(r)
  if not r['ok']:break
 result={'schema':'actual-v16-android-browser-native-audio-assessment-chain-v1','acquisitionMode':'browser','allAssessmentCommandsComplete':len(receipts)==3 and all(r['ok']for r in receipts),'ownedCleanupVerified':True,'commands':receipts,'PWAVerified':False,'wholeBugFixedClaimed':False,'scope':'Actual hosted OS mix + source/nonce/component checks and additive raw short diagnostics. Root must inspect low-window/raw findings; no automatic universal gapless or hardware claim.'}
 (out/'POST-ASSESSMENT.json').write_text(json.dumps(result,indent=2)+'\n');return 0 if result['allAssessmentCommandsComplete']else 2
if __name__=='__main__':raise SystemExit(main())
