"""Fixed official SDK install after exact existing-license/stable guard. EOF stdin."""
import hashlib,importlib.util,json,os,pathlib,sys
HERE=pathlib.Path(__file__).resolve().parent
def main():
 if sys.argv[1:]:raise SystemExit('Fixed operation takes no arguments')
 if os.uname().sysname!='Linux'or os.environ.get('GITHUB_ACTIONS')!='true'or os.environ.get('RUNNER_OS')!='Linux'or os.environ.get('RUNNER_ARCH')!='X64':raise SystemExit('Owned hosted Linux X64 only')
 path=HERE.parent/'v16/owned_audio_command.py'
 if hashlib.sha256(path.read_bytes()).hexdigest()!='3ff20c919cb167716c41f2f9aaf6797aed9aa008cadc82398ef0e48be07d9c66':raise SystemExit('Exact existing owned command primitive required')
 spec=importlib.util.spec_from_file_location('api36_owned_sdk',path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
 guardpath=HERE/'guard.py';spec=importlib.util.spec_from_file_location('api36_exact_guard',guardpath);g=importlib.util.module_from_spec(spec);spec.loader.exec_module(g)
 receipt=json.loads(pathlib.Path('evidence/android-license-parser/receipt.json').read_text());expected=g.select(receipt);plan=json.loads(pathlib.Path('evidence/android-stable-setup/plan.json').read_text())
 if expected!=plan:raise SystemExit('Exact fresh parser-to-plan binding required')
 out=pathlib.Path('evidence/android-api36-install');out.mkdir(exist_ok=False)
 command=['/usr/local/lib/android/sdk/cmdline-tools/latest/bin/sdkmanager','--channel=0','emulator','system-images;android-36;google_apis_playstore;x86_64']
 result=m.run_owned(command,out/'sdk.log',480)
 result.update(schema='fixed-api36-official-install-v1',stdin='DEVNULL',licenseAcceptanceInvoked=False,package='system-images;android-36;google_apis_playstore;x86_64',selectedRevision=7)
 (out/'receipt.json').write_text(json.dumps(result,indent=2)+'\n');return 0 if result['ok']else 2
if __name__=='__main__':raise SystemExit(main())
