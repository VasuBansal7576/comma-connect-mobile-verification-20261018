"""Pure bounded acceptance predicates from frozen V16 iOS continuation specs."""
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
 need(state['standaloneNavigator']is False and state['standaloneDisplay']is True,'ACTUAL_ANDROID_STANDALONE')
 need(state['timeOrigin']==time_origin and state['documentInstance']==o['documentInstance']and bool(state['documentInstance']),'CURRENT_DOCUMENT')
 r=x['retention'];need(r['completeSinceObserverStart']is True and r['sourceHistoryCount']==r['retainedRecordCount']==len(x['retainedRecords']),'COMPLETE_GLOBAL_RETENTION')
 m=re.fullmatch(r'Frozen (\d+) UTF-8 bytes; records (\d+); SHA-256 ([a-f0-9]{64});.*',frozen);need(m and int(m[1])==n and int(m[2])==len(x['retainedRecords'])and m[3]==digest(data),'FROZEN_STATUS')
 return data,x

def url_state(x,phase):
 s=x['state'];a=s['app'];n=a['navigation'];q=parse_qsl(s['search'].removeprefix('?'),keep_blank_values=True)
 need(len(q)==len(dict(q)),'DUPLICATE_QUERY');need(n['pathname']==s['pathname']and n['dongleId']=='acced23acced2301'and n['selectedRouteId']is None and n['currentRoute']is None,'URL_REDUX_OWNER_MISMATCH')
 if phase in ['referrals-closed','referrals-forward']:
  need(s['pathname']=='/acced23acced2301'and s['hash']==''and not q and n['route']['page']=='device','CLOSED_REFERRALS_STATE')
 elif phase.startswith('referrals-'):
  need(s['pathname']=='/referrals/'and s['hash']=='#position'and dict(q)=={'candidate':'v16','keep':'native'}and n['route']['page']=='referrals'and 'Refer a friend'in s['ui']['rootText'],'OPEN_REFERRALS_STATE')
 else:
  need(s['pathname']=='/acced23acced2301'and s['hash']=='#position'and dict(q)=={'candidate':'v16','keep':'native'}and n['route']['page']=='device'and n['route'].get('modal')is None and n['route'].get('modalDongleId')is None,'CLOSED_SETTINGS_STATE')
 owners=[o for o in a['owners']if o['kind']=='Explorer/PairResult'];need(len(owners)==1 and owners[0]['state']['pairLoading']is False and owners[0]['state']['pairError']is None,'PAIR_OWNER_UNQUALIFIED')
 return {'document':s['documentInstance'],'timeOrigin':s['timeOrigin'],'atMs':number(s['atMs']),'explorerOwner':owners[0]['identity'],'phase':phase,'navigationType':s.get('navigationType')}
def url_sequence(rows):
 names=['referrals-initial','referrals-closed','referrals-back','referrals-forward','referrals-before-reload','referrals-reloaded','settings-closed','settings-closed-again'];need(list(rows)==names,'URL_PHASE_SET')
 p=[url_state(rows[name],name)for name in names];need(len({r['document']for r in p[:5]})==1 and len({r['explorerOwner']for r in p[:5]})==1 and all(a['atMs']<b['atMs']for a,b in zip(p[:5],p[1:5])),'SAME_DOCUMENT_URL_HISTORY_REQUIRED')
 need(p[5]['document']!=p[0]['document']and p[5]['timeOrigin']!=p[0]['timeOrigin']and p[5]['navigationType']=='reload','ACTUAL_NEW_DOCUMENT_RELOAD_REQUIRED');need(p[6]['document']==p[7]['document']and p[6]['atMs']<p[7]['atMs'],'SETTINGS_SAME_DOCUMENT_REQUIRED')
 return {'status':'BOUNDED_URL_HISTORY_STATES_QUALIFIED','phases':p,'limits':['Modal-open title/device evidence separately retained as native XML/PNG. No full modal Forward/Reload or OAuth/cache fault inference.']}
def latest(report,count):
 need(report['format']=='actual-native-MediaError-fixture-v1'and report['readOnlyNative']is True and report['readOnlyProduct']is True and report['httpReceiptPending']is False,'NF_REPORT_PENDING_OR_INVALID');f=report['freezes'];need(len(f)==count,'NF_FRESH_COUNT')
 for p in f:need(p['trusted']is True and p['standaloneNavigator']is False and p['standaloneDisplay']is True and p['config']['entrySHA256']==ENTRY and p['config']['candidateSourceTreeSHA256']==SOURCE,'NF_TRUSTED_CURRENT_ANDROID')
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
  until=ends[i+1]['atMs']if i+1<len(ends)else last['atMs'];interval=[e for e in events if end['atMs']<e['atMs']<=until];ss=[e for e in interval if e['kind']=='native:seeking'];dd=[e for e in interval if e['kind']=='native:seeked'];need(len(ss)==len(dd)==1,'EXACTLY_ONE_EOF_SEEK_PAIR_REQUIRED');a,b=ss[0],dd[0];plays=[e for e in interval if e['kind']=='native:playing'and e['atMs']>=b['atMs']]
  need(a['atMs']<b['atMs']and plays and a['native']['seeking']is True and abs(number(a['native']['currentTime'])-1.001)<=.000001 and b['native']['seeking']is False and b['native']['readyState']>=2 and b['native']['error']is None and plays[0]['native']['paused']is False,'EOF_SEEK_CHRONOLOGY')
  need(all(e['native']['src']==n['src']for e in [end,a,b,plays[0]]),'EOF_EVENT_SOURCE_CHANGED')
 return {'status':'BOUNDED_SETTLED_EOF_EVENTS_QUALIFIED','transport':branch,'actualEnds':len(ends),'frameAcceptancePending':True,'exactInFlightPauseRaceHit':False}

def failure_initial(report,global_payload):
 p=latest(report,1);n=p['native'];d=p['driveVideo'];branch=transport(p);need(n['muted']is True,'MUTED_NATIVE_FAILURE_FIXTURE_REQUIRED')
 need(global_payload['state']['documentInstance']==p['documentInstance'],'SAME_FAILURE_DOCUMENT_REQUIRED')
 code4=isinstance(n.get('error'),dict)and n['error'].get('code')==4
 unavailable=n['error']is None and d.get('selectionUnavailable')is True and n['ended']is True and isinstance(d['videoError'],str)and number(d['desiredPlaySpeed'])==0
 events=report['events'];matched=[e for e in events if e.get('trusted')is True and e.get('native',{}).get('owner')==n['owner']and ((code4 and e['kind']=='native:error'and(e['native'].get('error')or{}).get('code')==4)or(unavailable and e['kind']=='native:ended'and e['native']['error']is None))]
 native_class=branch=='NATIVE_HTTP'and(code4 or unavailable)and bool(matched)
 codec=global_payload.get('hlsCodecObservation')or{};fatal=[e for e in codec.get('records',[])if e.get('kind')=='hlsError'and(e.get('error')or{}).get('fatal')is True and e.get('isCurrentHls')is True and e.get('binding')==codec.get('currentBinding')and(e.get('native')or{}).get('src')==n['src']]
 sdk_class=branch!='NATIVE_HTTP'and bool(fatal)and isinstance(d.get('videoError'),str)and bool(d['videoError'])and number(d['desiredPlaySpeed'])==0
 return {'status':'ACTUAL_FAILURE_SHAPE_QUALIFIED'if native_class or sdk_class else'ACTUAL_BRANCH_FAILURE_NOT_REPRODUCED','transport':branch,'failureClass':('NATIVE_ERROR4'if code4 else'ENDED_ERROR_NULL_UNAVAILABLE')if native_class else'ACTUAL_FATAL_HLS_CALLBACK_PAUSED_INTENT'if sdk_class else'UNQUALIFIED','nativeHTTPMediaErrorCaseAcquired':bool(native_class),'matchedFatalSDKRows':len(fatal),'nativeErrorEventsInvented':False,'limits':['SDK callback is not a trusted native MediaError event. No branch is forced.']}

def http_pairs(report):
 # Exact generated-server byte receipts; never a client wire-body assertion.
 healthy={'segment-00.ts':(381264,'14548b6cf62bf4d8ebbbe08d6205ed5c8aa3db7e62b67971cefe1acce039f3df'),'segment-01.ts':(411156,'49d2b2af14ffd1b864220bb27d9135d8de0dbd44dc23eb73b78d80f58fa640af'),'segment-02.ts':(404764,'8f295563899026335ecec7c5bd7367123fa38ea20d126cb2c4a0063f23047246'),'segment-03.ts':(416232,'3936b2e4d655e15085ed1fb3a05c4469176c7cac193b38d49a9c99e9867e1e41'),'segment-04.ts':(380888,'3c1a06ac49412684260c5cf1f68122cc6a9a78f732f7cf92caa352e033fe6926'),'segment-05.ts':(397056,'86eb43913676c8636a2c4ae44300dc0bb655bbe0a055135029da7ed7192bd4eb')}
 from datetime import datetime
 from urllib.parse import urlsplit
 restores=[e for e in report['events']if e.get('kind')=='fixture-http-restored'and e.get('trusted')is True];need(len(restores)==1,'ONE_TRUSTED_HTTP_RESTORE_REQUIRED');restore=restores[0]
 states=[report['fixture']]+[p['fixtureAtCapture']for p in report['freezes']if isinstance(p.get('fixtureAtCapture'),dict)]+[restore['fixture']];identifier=report['fixture']['id'];need(identifier and all(s['id']==identifier for s in states),'SAME_HTTP_FIXTURE_ID_REQUIRED')
 receipts=[r for s in states for r in s.get('requests',[])];bad=[r for r in receipts if r['mode']=='broken'];good=[r for r in receipts if r['mode']=='healthy']
 need(all(r['status']==200 and r['bytes']==12032 and r['sha256']=='12a42cfe372b164bdba3fcaf9084fc39b2032c8aec11bdf0c2acb46a6b614fb7'for r in bad),'BROKEN_BYTE_RECEIPT_MISMATCH')
 need(all(urlsplit(r['uri']).path.rsplit('/',1)[-1]in healthy and(r['bytes'],r['sha256'])==healthy[urlsplit(r['uri']).path.rsplit('/',1)[-1]]and r['status']==200 for r in good),'HEALTHY_BYTE_RECEIPT_MISMATCH')
 def utc(v):return datetime.fromisoformat(v.replace('Z','+00:00'))
 restored=utc(restore['fixture']['restoredUTC']);pairs=[{'uri':b['uri'],'broken':b,'healthy':g}for b in bad for g in good if b['uri']==g['uri']and utc(b['atUTC'])<=restored<=utc(g['atUTC'])]
 return {'observed':bool(pairs),'sameURIPairs':pairs,'scope':'Actual generated-server bytes/hash receipts; isolate-local. No client wire-body proof.'}

def _global_owned_completion(global_payload,good,restored_at,request,target_ms,target):
 # Link scope-local WeakMap IDs through the SAME clock observer across both synchronous snapshots.
 state=global_payload['state'];retention=global_payload['retention'];records=global_payload['retainedRecords'];current=state['native'];clock=global_payload['nativeClockObservation']['snapshot'];nfclock=good['clock'];drive=good['driveVideo'];native=good['native']
 need(global_payload['format']=='connect-candidate-observer-export-v1'and global_payload['candidate']['candidateEntrySHA256']==ENTRY and global_payload['candidate']['candidateSourceTreeSHA256']==SOURCE and state['config']['entrySHA256']==ENTRY and state['config']['candidateSourceTreeSHA256']==SOURCE,'PINNED_FULL_GLOBAL_CARRIER_REQUIRED')
 need(retention['completeSinceObserverStart']is True and retention['sourceHistoryCount']==retention['retainedRecordCount']==len(records),'COMPLETE_GLOBAL_COMMAND_HISTORY_REQUIRED')
 need(state['documentInstance']==good['documentInstance']and state['timeOrigin']==good['timeOrigin']and state['standaloneNavigator']is False and state['standaloneDisplay']is True,'SAME_GLOBAL_NF_DOCUMENT_REQUIRED')
 need(native['connected']is True and current['connected']is True and number(nfclock['owner'])==number(clock['owner'])and clock['currentSrc']==nfclock['currentSrc']==native['src']==current['src']and state['app']['driveVideo']['loadId']==drive['loadId'],'SAME_CLOCK_LINKED_CURRENT_NATIVE_REQUIRED')
 global_owner=number(current['owner']);limit=number(good['atMs']);load=drive['loadId']
 for index,row in enumerate(records):
  at=row.get('atMs');n=row.get('native')or{};d=(row.get('app')or{}).get('driveVideo')or{};cmd=d.get('seekCompletion')or{};r=d.get('seekRequest')or{}
  if type(at)not in[int,float]or not restored_at<at<=limit or n.get('owner')!=global_owner or n.get('src')!=native['src']or n.get('connected')is not True or d.get('loadId')!=load or r.get('id')!=request['id']or r.get('offset')!=target_ms or d.get('appliedSeekId')!=request['id']:continue
  if cmd.get('seekId')!=request['id']or cmd.get('target')!=target or type(cmd.get('routeMs'))not in[int,float]or abs(number(cmd['routeMs'])-target_ms)>.000001 or not all(cmd.get(k)is True for k in ['elementMatchesNative','engineMatchesCurrent','sourceMatchesCurrent','loadIdMatchesCurrent','seekIdMatchesCurrent']):continue
  return row,{'origin':'FULL_GLOBAL_RETAINED_RECORD','recordIndex':index,'nfOwner':native['owner'],'clockOwner':clock['owner'],'integratedOwner':global_owner,'currentSrc':native['src'],'loadId':load,'documentInstance':state['documentInstance'],'timeOrigin':state['timeOrigin'],'scope':'IDs from independent observers are not equated. The unchanged shared clock observer bridges synchronous NF/current global snapshots; the command row uses the integrated observer current owner and identical source/load/request/ownership predicates.'}
 raise Refused('EXACT_FULL_GLOBAL_OWNED_COMPLETION_UNACQUIRED')

def global_owned_completion(global_payload,good,restored_at,request,target_ms,target):
 try:return _global_owned_completion(global_payload,good,restored_at,request,target_ms,target)
 except (KeyError,TypeError,IndexError):raise Refused('FULL_GLOBAL_OWNER_LINK_SCHEMA_UNAVAILABLE')from None

def failure_recovery(first_report,latest_report,restored_report,recovered_report,global_first,global_final,branch):
 first=latest(first_report,1);requested=latest(latest_report,2);restored=latest(restored_report,3);good=latest(recovered_report,4);classification=failure_initial(first_report,global_first);need(classification['status']=='ACTUAL_FAILURE_SHAPE_QUALIFIED','ACTUAL_FAILURE_REQUIRED')
 f=first['native'];fd=first['driveVideo'];r=requested['driveVideo'];rn=restored['native'];rd=restored['driveVideo'];n=good['native'];d=good['driveVideo'];request=r['seekRequest'];targetms=number(request['offset']);target=targetms/1000
 need(number(request['id'])>number(fd['seekRequest']['id'])and targetms==number(fd['seekRequest']['offset'])+10000,'LATEST_PLUS10S_REQUEST_REQUIRED')
 need(requested['native']['owner']==rn['owner']==f['owner']and r['loadId']==rd['loadId']==fd['loadId']and r['desiredPlaySpeed']==rd['desiredPlaySpeed']==0,'RESTORE_MUST_NOT_REPLACE_OWNER_OR_AUTO_PLAY')
 need(not(rn['error']is None and rd.get('selectionUnavailable')is not True and rd.get('videoError')is None),'HTTP_RESTORE_AUTOHEALED_FAILURE')
 need(n['muted']is True and n['owner']!=f['owner']and number(d['loadId'])>number(fd['loadId'])and n['readyState']>=2 and n['paused']is False and n['error']is None and d.get('selectionUnavailable')is False and d['videoError']is None and d['isBufferingVideo']is False and number(d['desiredPlaySpeed'])>0,'ORDINARY_PLAY_NEW_OWNER_RECOVERY_REQUIRED')
 need(good['documentInstance']==first['documentInstance']==global_final['state']['documentInstance']and transport(good)==branch,'SAME_DOCUMENT_TRANSPORT_REQUIRED')
 need((n['src']==f['src'])if branch=='NATIVE_HTTP'else(d['hlsSource']==fd['hlsSource']),'SAME_PLAYLIST_URI_REQUIRED')
 need(number(r['videoStartOffset'])==0,'IDENTITY_FIXTURE_TIMEBASE_REQUIRED')
 events=[e for e in recovered_report['events']if e.get('trusted')is True and e['atMs']>restored['atMs']and(e.get('native')or{}).get('owner')==n['owner']]
 seeking=next((e for e in events if e['kind']=='native:seeking'),None);seeked=next((e for e in events if e['kind']=='native:seeked'),None);need(seeking and seeked and seeking['atMs']<seeked['atMs'],'ACTUAL_OWNED_RECOVERY_SEEK_EVENTS_REQUIRED');playing=next((e for e in events if e['kind']=='native:playing'and e['atMs']>=seeked['atMs']),None);need(playing and playing['native']['paused']is False,'ACTUAL_OWNED_RECOVERY_PLAYING_REQUIRED')
 need(seeking['native']['seeking']is True and abs(number(seeking['native']['currentTime'])-target)<=.000001 and seeked['native']['seeking']is False and seeked['native']['readyState']>=2 and seeked['native']['error']is None,'RECOVERY_TARGET_CHRONOLOGY')
 owned=[]
 for row in recovered_report['rows']:
  cmd=(row.get('driveVideo')or{}).get('seekCompletion')or{};drive=row.get('driveVideo')or{};req=drive.get('seekRequest')or{}
  if row['atMs']>restored['atMs']and(row.get('native')or{}).get('owner')==n['owner']and drive.get('loadId')==d['loadId']and req.get('id')==request['id']and req.get('offset')==targetms and drive.get('appliedSeekId')==request['id']and cmd.get('seekId')==request['id']and cmd.get('target')==target and abs(number(cmd.get('routeMs'))-targetms)<=.000001 and all(cmd.get(k)is True for k in ['elementMatchesNative','engineMatchesCurrent','sourceMatchesCurrent','loadIdMatchesCurrent','seekIdMatchesCurrent']):owned.append(row)
 if owned:completion=owned[0];owner_link={'origin':'NF_RECENT_ROW','scope':'Unchanged recent NF owner/load/request/completion predicate.'}
 else:completion,owner_link=global_owned_completion(global_final,good,restored['atMs'],request,targetms,target)
 need(all(e['native']['src']==n['src']for e in [seeking,seeked,playing])and completion['native']['src']==n['src'],'OWNED_COMMAND_COMPLETION_ROW_REQUIRED')
 http=http_pairs(recovered_report)
 return {'status':'BOUNDED_ORDINARY_PLAY_RECOVERY_FACTS_QUALIFIED'if http['observed']else'RECOVERY_FACTS_RETAINED_HTTP_BYTES_UNACQUIRED','failure':classification,'http':http,'request':request,'ownedCompletionRow':completion,'ownedCompletionLink':owner_link,'frameAcceptancePending':True,'limits':['Actual transport classified independently; native HTTP MediaError not inferred for blob SDK branch.','Exact in-flight Pause race and physical audio are outside this phase.']}
