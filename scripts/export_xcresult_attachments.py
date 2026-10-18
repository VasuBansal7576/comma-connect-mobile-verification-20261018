#!/usr/bin/env python3
"""Fixed hosted-CI xcresult attachment exports; direct logs and owned group cleanup."""
import hashlib,json,os,pathlib,re,time
from bounded_official import _execute_owned

BUNDLES=('v15-install','v15-output','v15-native-eof','v15-native-failure','v15-url')
HELP_COMMAND=('/usr/bin/xcrun','xcresulttool','export','attachments','--help')
COMMAND_LIMIT=30
MAX_HELP_BYTES=2*1024*1024
MAX_FILES=5000
MAX_HASH_BYTES=512*1024*1024
HASH_SECONDS=12

def cleanup_verified(result):
    c=result.get('cleanup',{})
    return c.get('leaderReaped')is True and c.get('ownedGroupAbsent')is True

def command_clean(result):
    # A zero-exit leader whose surviving descendants needed killing may have left partial files.
    return result.get('ok')is True and cleanup_verified(result)and result['cleanup'].get('signals')==[]

def inventory(target,root,deadline):
    """Only actual regular files; no symlinks, unbounded reads, or invented metadata."""
    files=[];total=0;entries_seen=0;stack=[target]
    while stack:
        if time.monotonic()>deadline:raise TimeoutError('Attachment hashing deadline exceeded')
        directory=stack.pop()
        if directory.is_symlink():raise ValueError('Refuse symlink attachment directory')
        with os.scandir(directory)as entries:
            for entry in entries:
                entries_seen+=1
                if entries_seen>MAX_FILES*2:raise ValueError('Attachment traversal count bound exceeded')
                if time.monotonic()>deadline:raise TimeoutError('Attachment inventory deadline exceeded')
                if entry.is_symlink():raise ValueError('Refuse symlink attachment')
                if entry.is_dir(follow_symlinks=False):stack.append(pathlib.Path(entry.path));continue
                if not entry.is_file(follow_symlinks=False):raise ValueError('Refuse nonregular attachment')
                if len(files)>=MAX_FILES:raise ValueError('Attachment count bound exceeded')
                path=pathlib.Path(entry.path);sha=hashlib.sha256();count=0
                with path.open('rb')as f:
                    before=os.fstat(f.fileno())
                    while True:
                        if time.monotonic()>deadline:raise TimeoutError('Attachment hashing deadline exceeded')
                        chunk=f.read(1024*1024)
                        if not chunk:break
                        count+=len(chunk);total+=len(chunk)
                        if total>MAX_HASH_BYTES:raise ValueError('Attachment byte bound exceeded')
                        sha.update(chunk)
                    after=os.fstat(f.fileno())
                if (before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns)!=(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns)or count!=after.st_size:raise ValueError('Attachment changed during hash')
                files.append({'path':str(path.relative_to(root)),'bytes':count,'sha256':sha.hexdigest()})
    return sorted(files,key=lambda x:x['path'])

def export_all(root,execute=_execute_owned):
    began=time.monotonic();root=pathlib.Path(root)
    report={'schema':'bounded-xcresult-attachment-export-v2','scope':'Official installed xcresulttool attachments export; original bundles preserved; no AX payload rewriting','exports':[],'allPresentBundlesExportCompleted':False,'commandLimitSeconds':COMMAND_LIMIT,'perCommandCleanupAllowanceSeconds':6,'maxCommands':6,'usesPipes':False}
    try:
        if root.is_symlink()or not root.is_dir():raise ValueError('Existing nonsymlink evidence directory required')
        # Help is authoritative; only inspect output after verified group cleanup.
        help_log=root/'xcresult-attachments-help.txt'
        if help_log.exists()or help_log.is_symlink():raise ValueError('Refuse help log overwrite')
        help_result=execute(list(HELP_COMMAND),help_log,COMMAND_LIMIT)
        report['installedHelpCommandReceipt']=help_result
        if not cleanup_verified(help_result):raise RuntimeError('Help command cleanup unknown; do not read live log')
        if not help_log.is_file()or help_log.is_symlink()or help_log.stat().st_size>MAX_HELP_BYTES:raise ValueError('Help output missing or exceeds bound')
        help_bytes=help_log.read_bytes();help_text=help_bytes.decode('utf-8',errors='replace')
        supported=all(re.search(r'(?<![\w-])'+re.escape(flag)+r'(?![\w-])',help_text)for flag in ('--path','--output-path'))
        report.update(installedHelpSHA256=hashlib.sha256(help_bytes).hexdigest(),installedHelpBytes=len(help_bytes),supportedFlagsVerified=bool(supported and command_clean(help_result)))
        if not command_clean(help_result):raise RuntimeError('Installed help failed, timed out, or needed descendant termination')
        if not supported:raise RuntimeError('Installed help does not advertise both reviewed flags')
        for name in BUNDLES:
            bundle=root/(name+'.xcresult');target=root/(name+'-attachments');log=root/(name+'-attachments-export.log')
            if bundle.is_symlink():raise ValueError('Refuse symlink result bundle')
            if not bundle.exists():report['exports'].append({'bundle':str(bundle),'skipped':'bundle absent'});continue
            item={'bundle':str(bundle),'exportCompleted':False,'files':[]};report['exports'].append(item)
            try:
                if not bundle.is_dir():raise ValueError('Result bundle must be an existing directory')
                if target.exists()or target.is_symlink()or log.exists()or log.is_symlink():raise ValueError('Refuse attachment target/log overwrite')
                command=['/usr/bin/xcrun','xcresulttool','export','attachments','--path',str(bundle),'--output-path',str(target)]
                result=execute(command,log,COMMAND_LIMIT);item['commandReceipt']=result
                if not cleanup_verified(result):raise RuntimeError('Export cleanup unknown; do not hash potentially live files')
                if not command_clean(result):raise RuntimeError('Export failed, timed out, or needed descendant termination; partial output retained unchanged')
                if not target.is_dir()or target.is_symlink():raise ValueError('Export produced no regular target directory')
                # Shared hashing allowance excludes command time, which has separate caps.
                hash_began=time.monotonic();remaining=HASH_SECONDS-report.get('hashElapsedSeconds',0)
                if remaining<=0:raise TimeoutError('Total attachment hashing allowance exhausted')
                try:item['files']=inventory(target,root,hash_began+remaining)
                finally:report['hashElapsedSeconds']=report.get('hashElapsedSeconds',0)+time.monotonic()-hash_began
                item['exportCompleted']=bool(item['files'])
                if not item['exportCompleted']:item['error']={'name':'EmptyExport','message':'No original exported attachment files'}
            except Exception as error:item['error']={'name':type(error).__name__,'message':str(error)}
            if item.get('commandReceipt')and not cleanup_verified(item['commandReceipt']):break
        present=[x for x in report['exports']if 'skipped'not in x]
        report['allPresentBundlesExportCompleted']=bool(present)and all(x.get('exportCompleted')is True for x in present)
    except Exception as error:report['error']={'name':type(error).__name__,'message':str(error)}
    report['elapsedSeconds']=time.monotonic()-began
    return report

def main():
    if os.environ.get('GITHUB_ACTIONS')!='true'or os.environ.get('RUNNER_OS')!='macOS'or os.environ.get('RUNNER_ARCH')!='ARM64':raise SystemExit('Hosted macOS ARM64 CI only')
    root=pathlib.Path('evidence');receipt=root/'xcresult-attachment-export.json'
    if receipt.exists()or receipt.is_symlink():raise SystemExit('Refuse export receipt overwrite')
    report=export_all(root)
    if not root.is_dir()or root.is_symlink():raise SystemExit('No safe evidence directory for receipt')
    with receipt.open('x')as f:f.write(json.dumps(report,indent=2)+'\n')
    raise SystemExit(0 if report['allPresentBundlesExportCompleted']and not report.get('error')else 2)
if __name__=='__main__':main()
