#!/usr/bin/env python3
"""Remote CI only; verify installed CLI help before bounded official attachment export."""
import hashlib,json,os,pathlib,subprocess,time

def main():
    if os.environ.get('GITHUB_ACTIONS')!='true' or os.environ.get('RUNNER_OS')!='macOS':raise SystemExit('Hosted macOS CI only')
    root=pathlib.Path('evidence');report={'scope':'Official installed xcresulttool attachments export; no AX payload rewriting','exports':[]};began=time.monotonic()
    try:
        # The installed tool's own help is authoritative. Never assume undocumented options.
        helpResult=subprocess.run(['xcrun','xcresulttool','export','attachments','--help'],capture_output=True,text=True,timeout=8)
        helpText=helpResult.stdout+'\n'+helpResult.stderr;(root/'xcresult-attachments-help.txt').write_text(helpText)
        supported=helpResult.returncode==0 and '--path' in helpText and '--output-path' in helpText
        report.update(installedHelpReturnCode=helpResult.returncode,installedHelpSHA256=hashlib.sha256(helpText.encode()).hexdigest(),supportedFlagsVerified=supported)
        if not supported:raise RuntimeError('Installed xcresulttool does not advertise reviewed export attachments flags; retain original xcresult unchanged')
        for name in ['v15-install','v15-output','v15-native-eof','v15-native-failure','v15-url']:
            bundle=root/(name+'.xcresult');target=root/(name+'-attachments')
            if not bundle.exists():report['exports'].append({'bundle':str(bundle),'skipped':'bundle absent'});continue
            if target.exists():raise RuntimeError('Refuse attachment overwrite')
            command=['xcrun','xcresulttool','export','attachments','--path',str(bundle),'--output-path',str(target)]
            item={'bundle':str(bundle),'command':command}
            try:
                result=subprocess.run(command,capture_output=True,text=True,timeout=20)
                item.update(returnCode=result.returncode,stdout=result.stdout[:16000],stderr=result.stderr[:16000])
                item['files']=[{'path':str(f.relative_to(root)),'bytes':f.stat().st_size,'sha256':hashlib.sha256(f.read_bytes()).hexdigest()}for f in sorted(target.rglob('*'))if f.is_file()]
                item['exportCompleted']=result.returncode==0 and bool(item['files'])
            except Exception as error:item.update(exportCompleted=False,error={'name':type(error).__name__,'message':str(error)})
            report['exports'].append(item)
    except Exception as error:report['error']={'name':type(error).__name__,'message':str(error)}
    finally:
        report['elapsedSeconds']=time.monotonic()-began;(root/'xcresult-attachment-export.json').write_text(json.dumps(report,indent=2)+'\n')
    # Always-upload remains possible; a partial export never certifies carrier transfer.
    if report.get('error')or any(x.get('exportCompleted')is False for x in report['exports']):raise SystemExit(2)
if __name__=='__main__':main()
