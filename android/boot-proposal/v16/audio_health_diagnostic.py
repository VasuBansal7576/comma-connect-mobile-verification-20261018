"""One fixed read-only health acquisition after the original Prepare health refusal.
No source/native action, retry, activation, handler/property change or acceptance bypass.
"""
from pathlib import Path
import hashlib,json,math,shutil
import readonly_browser_audio_bridge_v16 as bridge
HERE=Path(__file__).resolve().parent
REASON='REFUSED: Healthy single product video required'
def need(ok,why):
 if not ok:raise ValueError(why)
def number(v):return type(v)in[int,float]and math.isfinite(v)
def validate(value):
 need(isinstance(value,dict)and value.get('schema')=='fixed-owned-video-health-v1'and number(value.get('atMs'))and value['atMs']>=0,'HEALTH_SCHEMA')
 count=value.get('videoCount');videos=value.get('videos');need(type(count)is int and 0<=count<=10000 and isinstance(videos,list)and len(videos)==min(count,2),'HEALTH_VIDEO_COUNT')
 for v in videos:
  need(isinstance(v,dict)and all(type(v.get(k))is bool for k in ['connected','hasError','ended','paused','muted','seeking']),'HEALTH_BOOLEAN_FIELDS')
  need(v.get('errorCode')is None or type(v['errorCode'])is int and 1<=v['errorCode']<=4,'HEALTH_ERROR_CODE')
  need(v['hasError']is(v['errorCode']is not None),'HEALTH_ERROR_CONSISTENCY')
  need(type(v.get('readyState'))is int and 0<=v['readyState']<=4 and type(v.get('networkState'))is int and 0<=v['networkState']<=3,'HEALTH_MEDIA_STATES')
  need(v.get('durationKind')in['finite','nan','infinite']and(v.get('duration')is None if v['durationKind']!='finite'else number(v.get('duration'))and v['duration']>=0),'HEALTH_DURATION')
  need((v.get('currentTime')is None or number(v['currentTime'])and v['currentTime']>=0)and number(v.get('volume'))and 0<=v['volume']<=1,'HEALTH_TIME_VOLUME')
  need(all(type(v.get(k))is int and 0<=v[k]<=65536 for k in ['videoWidth','videoHeight'])and v.get('currentSrcKind')in['blob','owned-https','empty','unrecognized'],'HEALTH_VIDEO_FIELDS')
  for name in ['buffered','seekable']:
   n=v.get(name+'Count');rs=v.get(name);need(type(n)is int and 0<=n<=10000 and isinstance(rs,list)and len(rs)==min(n,32),'HEALTH_RANGE_COUNT')
   need(all(isinstance(row,list)and len(row)==2 and all(number(x)for x in row)and 0<=row[0]<=row[1]for row in rs),'HEALTH_RANGE_FIELDS')
 text=value.get('quickLogText');n=value.get('quickLogUTF16Units');need(isinstance(text,str)and len(text)<=65536 and type(n)is int and n>=len(text)and type(value.get('quickLogTruncated'))is bool and value['quickLogTruncated']is(n>65536),'HEALTH_QUICK_LOG')
 return value

def capture(driver):
 b=driver.b
 need(driver.collector is None and driver.seq.ack is False and driver.seq.dispatched==['Pin actual playlist','Prepare playback']and driver.origin is not None,'EXACT_PRE_CAPTURE_PREPARE_REFUSAL_SCOPE')
 driver.check();data=[]
 def adb(args):
  driver.check();raw,_,cut=b.run([b.ADB]+args,'audio-health-adb',timeout=5,limit=1024*1024,retain_stdout=False)
  need(not cut,'HEALTH_ADB_TRUNCATED');return raw
 def evaluate(endpoint):
  driver.check();node=shutil.which('node');need(node is not None,'EXISTING_NODE_REQUIRED')
  raw,_,cut=b.run([node,str(HERE/'read_audio_health_v16.mjs'),endpoint],'audio-health-fixed-readonly',timeout=12,limit=512*1024,retain_stdout=False)
  need(not cut,'HEALTH_DOM_TRUNCATED');value=bridge.decode_json(raw,512*1024);need(isinstance(value,list)and len(value)==11,'HEALTH_FIXED11_FIELDS')
  data.append(validate(value[10]));return json.dumps(value[:10]).encode()
 target=driver.out/'prepare-health-diagnostic'
 receipt=bridge.observe_owned_pwa(adb,bridge.local_http_get,evaluate,target,owned_vm_guard=True,require_carrier=False,allow_closed_device=False)
 need(receipt.get('status')=='CURRENT_DOCUMENT_OBSERVATION_RETAINED_NO_CARRIER'and receipt.get('cleanupVerified')is True and len(data)==1,'HEALTH_CURRENT_DOCUMENT_OR_CLEANUP_UNVERIFIED')
 need(receipt['observation']['timeOrigin']==driver.origin,'HEALTH_DOCUMENT_CHANGED');driver.check()
 result={'schema':'prepare-health-diagnostic-v1','trigger':REASON,'originalHealthGuardChanged':False,'sourceWrites':0,'inputCommands':0,'currentDocument':receipt['observation'],'health':data[0],'bridgeCleanupVerified':True,'PWAVerified':False,'audioMeasured':False,'scope':'Current read-only state after original refusal, not an atomic snapshot of the earlier guard decision.'}
 (target/'health.json').write_text(json.dumps(result,indent=2,allow_nan=False)+'\n');return result
