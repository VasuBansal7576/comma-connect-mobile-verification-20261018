"""Private fixed caller primitive using the adjacent reviewed boot's exact ownership checks."""
import hashlib,importlib.util,json,os,signal,subprocess,time
from pathlib import Path
HERE=Path(__file__).resolve().parent
BOOT_OWNERSHIP_SHA='ad7cc88f35dba4320606997c0b70d25914babb7ca133ba41efe4f6e9d3549f97'
def owner_module():
 path=HERE/'boot.py'
 if hashlib.sha256(path.read_bytes()).hexdigest()!=BOOT_OWNERSHIP_SHA:raise ValueError('Exact sealed adjacent boot ownership primitive required')
 spec=importlib.util.spec_from_file_location('isolated_audio_command_owner',path);b=importlib.util.module_from_spec(spec);spec.loader.exec_module(b);return b

def run_owned(command,logpath,seconds):
 if os.uname().sysname!='Linux':raise ValueError('Owned Linux process primitive only')
 start=time.monotonic();logpath=Path(logpath);work=logpath.parent/('owned-'+logpath.stem)
 if logpath.exists()or work.exists():raise ValueError('Fresh isolated owned-command paths required')
 work.mkdir();b=owner_module();b.OUT=work # Never overwrite the original Android acquisition receipt.
 previous={sig:signal.getsignal(sig)for sig in [signal.SIGTERM,signal.SIGINT]}
 def interrupted(*_):raise InterruptedError('Owned audio command interrupted')
 for sig in previous:signal.signal(sig,interrupted)
 p=None;result={'command':command,'limitSeconds':seconds,'usesPipes':False,'timedOut':False,'cleanupVerified':False,'ownerSourceSHA256':BOOT_OWNERSHIP_SHA,'ownershipReceipt':str(work/'receipt.json')}
 try:
  b.enable_owned_subreaper();p=b.own_process(command,'bounded-command')
  row=b.STATE['children'][-1];snapshot=b.group_snapshot(p.pid)
  if snapshot['complete']and any(m['pid']==p.pid and m['startTicks']==row['startTicks']and m['sid']==p.pid and m['uid']==os.getuid()for m in snapshot['members']):row['ownedGroupProvenance']=snapshot;b.save()
  try:p.wait(timeout=max(.001,seconds-(time.monotonic()-start)))
  except subprocess.TimeoutExpired:result['timedOut']=True
 finally:
  b.cleanup() # Original startTicks/SID/UID/bound-descendant anchors; no pgid-only kill here.
  result.update(returnCode=p.returncode if p else None,cleanupVerified=b.STATE.get('ownedChildCleanupVerified')is True,cleanup=b.STATE.get('cleanup'),elapsedSeconds=time.monotonic()-start)
  source=work/'bounded-command.log'
  if source.exists():logpath.write_bytes(source.read_bytes())
  for sig,handler in previous.items():signal.signal(sig,handler)
 result['ok']=not result['timedOut']and result.get('returnCode')==0 and result['cleanupVerified'];return result
def dependency_main(argv):
 if argv!=['--install-deps-root']:raise SystemExit('Exact fixed root dependency operation only')
 if os.uname().sysname!='Linux' or os.environ.get('GITHUB_ACTIONS')!='true'or os.environ.get('RUNNER_OS')!='Linux'or os.environ.get('RUNNER_ARCH')!='X64':raise SystemExit('Hosted Linux only')
 # Apt's privileged descendants must have the same UID as their owning subreaper.
 # Imported run_owned remains unchanged for all normal runner-UID acquisition callers.
 if os.getuid()!=0 or os.geteuid()!=0:raise SystemExit('Dependency subreaper must start as root')
 out=Path('evidence/android-audio-deps');out.mkdir(exist_ok=False)
 command=['env','DEBIAN_FRONTEND=noninteractive','apt-get','-y','--no-install-recommends','install','gcc','pkg-config','libpulse-dev']
 r=run_owned(command,out/'install.log',120);r['dependencyOwnerUID']=os.getuid();r['dependencyMode']='FIXED_ROOT_APT_ONLY'
 (out/'receipt.json').write_text(json.dumps(r,indent=2)+'\n');return 0 if r['ok']else 2
if __name__=='__main__':
 import sys
 raise SystemExit(dependency_main(sys.argv[1:]))
