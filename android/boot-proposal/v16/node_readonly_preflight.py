"""Choose an existing capability-proved Node, without installing or adding flags."""
import hashlib,json,os,pathlib,re,shutil,sys
HERE=pathlib.Path(__file__).resolve().parent
SCRIPT="process.stdout.write(JSON.stringify({schema:'existing-node-websocket-capability-v1',node:process.versions.node,webSocketType:typeof WebSocket,execPath:process.execPath})+'\\n')"
class Refused(ValueError):pass
def candidates(toolcache,current):
 out=[]
 if current:
  f=pathlib.Path(current).resolve(strict=True)
  if not f.is_file()or not os.access(f,os.X_OK):raise Refused('CURRENT_NODE_NOT_EXECUTABLE')
  out.append(f)
 if toolcache:
  root=pathlib.Path(toolcache).resolve(strict=True);base=root/'node'
  if base.is_dir():
   rows=list(base.iterdir())
   if len(rows)>128:raise Refused('NODE_TOOLCACHE_INVENTORY_BOUND')
   versions=sorted([f for f in rows if f.is_dir()and re.fullmatch(r'\d+\.\d+\.\d+',f.name)],key=lambda f:tuple(map(int,f.name.split('.'))),reverse=True)[:4]
   for version in versions:
    f=version/'x64/bin/node'
    if not f.is_file():continue
    actual=f.resolve(strict=True)
    if base.resolve()not in actual.parents or not os.access(actual,os.X_OK):raise Refused('ACTUAL_TOOLCACHE_NODE_SCOPE_REQUIRED')
    if actual not in out:out.append(actual)
 return out
def validate(raw,binary,receipt):
 if receipt.get('ok')is not True or receipt.get('cleanupVerified')is not True:raise Refused('OWNED_NODE_PROBE_CLEANUP_REQUIRED')
 if not isinstance(raw,bytes)or len(raw)>8192:raise Refused('NODE_CAPABILITY_OUTPUT_BOUND')
 try:r=json.loads(raw)
 except (ValueError,UnicodeError):raise Refused('NODE_CAPABILITY_JSON_REQUIRED')
 if not isinstance(r,dict)or set(r)!={'schema','node','webSocketType','execPath'}or r['schema']!='existing-node-websocket-capability-v1'or not isinstance(r['node'],str)or not re.fullmatch(r'\d+\.\d+\.\d+',r['node'])or r['webSocketType']not in ['undefined','function']:raise Refused('NODE_CAPABILITY_SCHEMA_REQUIRED')
 if not isinstance(r['execPath'],str)or pathlib.Path(r['execPath']).resolve(strict=True)!=binary:raise Refused('ACTUAL_NODE_EXECUTABLE_IDENTITY_REQUIRED')
 return r
def main():
 if sys.argv[1:]:raise SystemExit('Fixed Node capability preflight takes no arguments')
 if os.uname().sysname!='Linux'or os.environ.get('GITHUB_ACTIONS')!='true'or os.environ.get('RUNNER_OS')!='Linux'or os.environ.get('RUNNER_ARCH')!='X64':raise SystemExit('Owned hosted Linux X64 only')
 from owned_audio_command import run_owned
 out=pathlib.Path('evidence/android-node-runtime');out.mkdir(parents=True,exist_ok=False)
 result={'schema':'fixed-existing-node-readonly-capability-selection-v1','installedSoftware':False,'runtimeFlagsAdded':False,'probes':[],'selected':None,'pass':False,'originalWebSocketUndefinedIsPossibleNotActualOldCause':True}
 try:
  files=candidates(os.environ.get('RUNNER_TOOL_CACHE'),shutil.which('node'))
  if not files:raise Refused('NO_EXISTING_NODE_BINARY')
  for i,f in enumerate(files):
   log=out/('probe-'+str(i)+'.log');r=run_owned([str(f),'-e',SCRIPT],log,5);v=validate(log.read_bytes()if log.is_file()else b'',f,r)
   row={'candidate':str(f),'nodeVersion':v['node'],'webSocketType':v['webSocketType'],'binarySHA256':hashlib.sha256(f.read_bytes()).hexdigest(),'ownedCommand':r};result['probes'].append(row)
   if v['webSocketType']=='function':result['selected']=row;break
  if not result['selected']:raise Refused('NO_EXISTING_NODE_WITH_GLOBAL_WEBSOCKET')
  channel=pathlib.Path(os.environ['GITHUB_PATH'])
  if not channel.is_file()or channel.is_symlink():raise Refused('EXISTING_RUNNER_GITHUB_PATH_CHANNEL_REQUIRED')
  # A capability-proved existing directory is selected for subsequent workflow steps.
  with channel.open('a')as stream:stream.write(str(pathlib.Path(result['selected']['candidate']).parent)+'\n')
  result['pass']=True
 except Exception as e:
  known={'CURRENT_NODE_NOT_EXECUTABLE','NODE_TOOLCACHE_INVENTORY_BOUND','ACTUAL_TOOLCACHE_NODE_SCOPE_REQUIRED','OWNED_NODE_PROBE_CLEANUP_REQUIRED','NODE_CAPABILITY_OUTPUT_BOUND','NODE_CAPABILITY_JSON_REQUIRED','NODE_CAPABILITY_SCHEMA_REQUIRED','ACTUAL_NODE_EXECUTABLE_IDENTITY_REQUIRED','NO_EXISTING_NODE_BINARY','NO_EXISTING_NODE_WITH_GLOBAL_WEBSOCKET','EXISTING_RUNNER_GITHUB_PATH_CHANNEL_REQUIRED'}
  result['failureCode']=str(e)if isinstance(e,Refused)and str(e)in known else 'NODE_PREFLIGHT_REFUSED'
 finally:(out/'receipt.json').write_text(json.dumps(result,indent=2)+'\n')
 print(json.dumps({'pass':result['pass'],'selectedNodeVersion':(result['selected']or{}).get('nodeVersion'),'failureCode':result.get('failureCode')}));return 0 if result['pass']else 2
if __name__=='__main__':raise SystemExit(main())
