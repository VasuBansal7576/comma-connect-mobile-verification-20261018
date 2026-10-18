"""iOS EOF-only derivative: actual original carrier remains mandatory."""
import base64,hashlib,json,math,re,zlib
from urllib.parse import parse_qsl
SOURCE='24debd4d28470b53f97d41bc46fdc44b060ae0c1bb16f33c331aa5896b5ba07b'
ENTRY='e7ab13f79d01a5784c7879f9a02a2f9b8a0078e3281dbb6cfda01d36a0467641'
class Refused(ValueError):pass
def need(ok,code):
 if not ok:raise Refused(code)

def number(v):need(type(v)in[int,float]and math.isfinite(v),'FINITE_NUMBER_REQUIRED');return v

def digest(v):return hashlib.sha256(v).hexdigest()

def unpack(raw,packed,frozen,time_origin):
 need(isinstance(raw,bytes)and 0<len(raw)<=16*1024*1024,'BOUNDED_CARRIER_REQUIRED')
 need(packed.startswith(f'Packed {len(raw)} UTF-8 carrier bytes; SHA-256 {digest(raw)};'),'PACKED_BYTE_HASH_MISMATCH')
 p=json.loads(raw);need(p['format']=='v13-gzip-export-carrier-v1'and p['encoding']=='gzip+base64','CARRIER_FORMAT')
 need(all(p['packing'].get(k)is True for k in ['trustedClick','roundTripVerified','originalCachedPayloadPreserved']),'NATIVE_TRUSTED_PACK_REQUIRED')
 need(all(p['packing'].get(k)is False for k in ['productStateModified','nativeMediaModified']),'PRODUCT_NATIVE_WRITES_FORBIDDEN')
 o=p['original'];need(o['candidateEntrySHA256']==ENTRY and o['candidateSourceTreeSHA256']==SOURCE and o['originalUIStatus']==frozen,'CURRENT_FROZEN_PINS_REQUIRED')
 n=o['utf8Bytes'];need(type(n)is int and 0<n<=64*1024*1024,'BOUNDED_ORIGINAL')
 z=base64.b64decode(p['compressed']['base64'],validate=True);need(len(z)==p['compressed']['gzipBytes']and digest(z)==p['compressed']['gzipSHA256'],'GZIP_HASH')
 dec=zlib.decompressobj(31);data=dec.decompress(z,n+1);need(len(data)==n and dec.eof and not dec.unused_data and not dec.unconsumed_tail and digest(data)==o['sha256'],'ORIGINAL_ROUNDTRIP')
 x=json.loads(data);state=x['state'];need(x['format']=='connect-candidate-observer-export-v1','EXPORT_FORMAT')
 need(x['candidate']['candidateEntrySHA256']==ENTRY and x['candidate']['candidateSourceTreeSHA256']==SOURCE,'CURRENT_CANDIDATE')
 need(state['config']['entrySHA256']==ENTRY and state['config']['candidateSourceTreeSHA256']==SOURCE,'CURRENT_OBSERVER')
 need(state['standaloneNavigator']is True and state['standaloneDisplay']is True,'ACTUAL_IOS_STANDALONE')
 need(state['timeOrigin']==time_origin and state['documentInstance']==o['documentInstance']and bool(state['documentInstance']),'CURRENT_DOCUMENT')
 r=x['retention'];need(r['completeSinceObserverStart']is True and r['sourceHistoryCount']==r['retainedRecordCount']==len(x['retainedRecords']),'COMPLETE_GLOBAL_RETENTION')
 m=re.fullmatch(r'Frozen (\d+) UTF-8 bytes; records (\d+); SHA-256 ([a-f0-9]{64});.*',frozen);need(m and int(m[1])==n and int(m[2])==len(x['retainedRecords'])and m[3]==digest(data),'FROZEN_STATUS')
 return data,x

def latest(report,count):
 need(report['format']=='actual-native-MediaError-fixture-v1'and report['readOnlyNative']is True and report['readOnlyProduct']is True and report['httpReceiptPending']is False,'NF_REPORT_PENDING_OR_INVALID');f=report['freezes'];need(len(f)==count,'NF_FRESH_COUNT')
 for p in f:need(p['trusted']is True and p['standaloneNavigator']is True and p['standaloneDisplay']is True and p['config']['entrySHA256']==ENTRY and p['config']['candidateSourceTreeSHA256']==SOURCE,'NF_TRUSTED_CURRENT_IOS')
 need(len({p['documentInstance']for p in f})==1 and all(a['atMs']<b['atMs']for a,b in zip(f,f[1:])),'NF_SAME_DOCUMENT_CHRONOLOGY');return f[-1]

def transport(p):
 n=p['native'];d=p['driveVideo'];c=p['capabilities'];adapter=d['nativeAdapter']
 if n['src'].startswith('https://comma-connect-fix-lab-20261016.zippy17.chatgpt.site/')and c['hlsEnginePresent']is False and d['hlsSource']is None and adapter['nativeSourceAttachedForCurrentLoad']is True:return 'NATIVE_HTTP'
 if n['src'].startswith('blob:')and c['hlsEnginePresent']is True and isinstance(d['hlsSource'],str)and d['hlsSource'].startswith('https://')and adapter['readyForCurrentTransport']is True and adapter['nativeSourceAttachedForCurrentLoad']is False:return 'BLOB_HLS_MSE_OR_MMS_NOT_DISTINGUISHED'
 raise Refused('ACTUAL_TRANSPORT_UNQUALIFIED')

def eof(report):
 first=report['freezes'][0];last=latest(report,2);n=last['native'];d=last['driveVideo'];f=first['native'];loop=first['media']['loop']
 need(loop['startTime']==1001 and loop['duration']+1001==20000 and number(f['duration'])<20,'WIDE_REQUEST_REAL_FINITE_EOF_REQUIRED')
 branch=transport(first);need(transport(last)==branch and n['owner']==f['owner']and n['src']==f['src']and d['loadId']==first['driveVideo']['loadId'],'EOF_OWNER_TRANSPORT_CHANGED')
 need(n['paused']is False and n['muted']is True and n['readyState']>=2 and n['error']is None and d['isBufferingVideo']is False and d['videoError']is None and number(d['desiredPlaySpeed'])>0,'EOF_NOT_HEALTHY')
 events=[e for e in report['events']if e.get('trusted')is True and e['atMs']<=last['atMs']and e.get('native',{}).get('owner')==n['owner']];ends=[e for e in events if e['kind']=='native:ended'];need(len(ends)>=3,'THREE_ACTUAL_END_EVENTS_REQUIRED')
 for i,end in enumerate(ends):
  until=ends[i+1]['atMs']if i+1<len(ends)else last['atMs'];interval=[e for e in events if end['atMs']<e['atMs']<=until];ss=[e for e in interval if e['kind']=='native:seeking'];dd=[e for e in interval if e['kind']=='native:seeked'];need(len(ss)==len(dd)==1,'EXACTLY_ONE_EOF_SEEK_PAIR_REQUIRED');a,b=ss[0],dd[0];plays=[e for e in interval if e['kind']=='native:playing']
  need(a['atMs']<b['atMs']and plays and a['native']['seeking']is True and abs(number(a['native']['currentTime'])-1.001)<=.000001 and b['native']['seeking']is False and b['native']['readyState']>=2 and b['native']['error']is None and b['native']['paused']is False and plays[0]['native']['paused']is False and plays[0]['native']['error']is None,'EOF_SEEK_CHRONOLOGY')
  need(all(e['native']['src']==n['src']for e in [end,a,b,plays[0]]),'EOF_EVENT_SOURCE_CHANGED')
 return {'status':'BOUNDED_SETTLED_EOF_EVENTS_QUALIFIED','transport':branch,'actualEnds':len(ends),'frameAcceptancePending':True,'exactInFlightPauseRaceHit':False}
