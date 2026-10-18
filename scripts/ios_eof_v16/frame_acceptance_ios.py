"""Additive offline rVFC proof. Original functional contracts remain prerequisites.
Observer-local owner IDs are deliberately NOT equated across WeakMaps.
No frame callback cadence, gaplessness, audio or physical-device claim is made.
"""
import math
SOURCE='24debd4d28470b53f97d41bc46fdc44b060ae0c1bb16f33c331aa5896b5ba07b'
ENTRY='e7ab13f79d01a5784c7879f9a02a2f9b8a0078e3281dbb6cfda01d36a0467641'
class Refused(ValueError):pass
def need(ok,code):
 if not ok:raise Refused(code)
def num(v):need(type(v)in[int,float]and math.isfinite(v),'FINITE_FRAME_NUMBER_REQUIRED');return v
def integer(v):need(type(v)is int and v>=0,'FRAME_COUNTER_INTEGER_REQUIRED');return v
def healthy(n):return n.get('paused')is False and n.get('seeking')is False and n.get('error')is None and type(n.get('readyState'))is int and n['readyState']>=2

def context(payload,report):
 s=payload['state'];clock=payload['nativeClockObservation'];ret=clock['frameRetention'];frames=clock['frameRecords'];last=report['freezes'][-1];point=last['clock'];current=clock['snapshot'];uri=last['native']['src'];owner=point['owner'];records=payload['retainedRecords']
 need(payload['format']=='connect-candidate-observer-export-v1'and payload['candidate']['candidateEntrySHA256']==ENTRY and payload['candidate']['candidateSourceTreeSHA256']==SOURCE and s['config']['entrySHA256']==ENTRY and s['config']['candidateSourceTreeSHA256']==SOURCE,'CURRENT_PINNED_GLOBAL_REQUIRED')
 need(s['standaloneNavigator']is True and s['standaloneDisplay']is True,'ACTUAL_IOS_STANDALONE_REQUIRED')
 need(s['documentInstance']==last['documentInstance']and s['timeOrigin']==last['timeOrigin']and num(s['atMs'])>=num(last['atMs']),'SAME_FRAME_DOCUMENT_REQUIRED')
 need(all(p['documentInstance']==s['documentInstance']and p['timeOrigin']==s['timeOrigin']for p in report['freezes']),'ALL_NF_FREEZES_SAME_DOCUMENT_REQUIRED')
 r=payload['retention'];need(r['completeSinceObserverStart']is True and r['sourceHistoryCount']==r['retainedRecordCount']==len(records),'COMPLETE_GLOBAL_FRAME_LINK_HISTORY_REQUIRED')
 full=payload['nativeFailureObservation'];need(full['freezes']==report['freezes']and full['events'][:len(report['events'])]==report['events'],'NF_REPORT_NOT_ORIGINAL_GLOBAL_PREFIX')
 need(last['native']['connected']is True and s['native']['connected']is True and current['owner']==owner and current['currentSrc']==point['currentSrc']==uri==s['native']['src'],'CURRENT_CLOCK_NATIVE_LINK_REQUIRED')
 need(integer(owner)>0 and integer(s['native']['owner'])>0,'POSITIVE_SCOPE_LOCAL_OWNER_IDS_REQUIRED')
 need(last['driveVideo']['loadId']==s['app']['driveVideo']['loadId'],'CURRENT_FRAME_LOAD_REQUIRED')
 need(healthy(s['native'])and s['app']['driveVideo'].get('frameElementMatchesNative')is True and s['app']['driveVideo'].get('frameEngineMatchesCurrentHls')is True,'CURRENT_SETTLED_FRAME_OWNERS_REQUIRED')
 need(ret['format']=='owned-native-frame-retention-v1'and ret['recordLimit']==6000 and ret['stopped']is False and integer(ret['callbackErrors'])==0,'ACTIVE_ERROR_FREE_FRAME_OBSERVER_REQUIRED')
 total=integer(ret['totalRecords']);dropped=integer(ret['droppedRecords']);kept=integer(ret['retainedRecords']);need(total==kept+dropped and kept==len(frames)and 0<kept<=6000,'FRAME_RETENTION_COUNTS')
 attachments=ret['attachments'];need(attachments and all(a['apiAvailable']is True and a['error']is None for a in attachments),'ACTUAL_FRAME_API_ATTACHMENTS_REQUIRED')
 need(sum(integer(a['observedCallbacks'])for a in attachments)==total and ret['completeSinceAttach']is(dropped==0),'FRAME_ATTACHMENT_COUNTS')
 bindings={}
 for a in attachments:
  need(integer(a['owner'])>0,'POSITIVE_ATTACHMENT_OWNER_REQUIRED');key=(a['owner'],num(a['attachedAtMs']));need(key not in bindings,'AMBIGUOUS_FRAME_ATTACHMENT');bindings[key]=a
  if a['retiredAtMs']is not None:need(num(a['retiredAtMs'])>=a['attachedAtMs'],'FRAME_RETIREMENT_CHRONOLOGY')
 previous=None
 for i,f in enumerate(frames):
  need(f['kind']=='owned-native-frame-callback'and integer(f['sequence'])==dropped+i+1,'FRAME_SEQUENCE_GAP_OR_KIND')
  at=num(f['atMs']);num(f['callbackNowMs']);num(f['expectedDisplayTime']);media=num(f['mediaTime']);presented=integer(f['presentedFrames']);need(presented>0 and media>=0,'FRAME_METADATA_INVALID')
  if f['presentationTime']is not None:num(f['presentationTime'])
  num(f['attachmentAtMs']);n=f['native'];need(integer(f['owner'])>0 and integer(n['owner'])>0 and n['owner']==f['owner'],'FRAME_LOCAL_OWNER_MISMATCH');num(n['currentTime']);need(num(n['duration'])>0 and media<=n['duration'],'FRAME_MEDIA_OUTSIDE_ACTUAL_DURATION')
  a=bindings.get((f['owner'],f['attachmentAtMs']));need(a is not None and a['attachedAtMs']<=at and(a['retiredAtMs']is None or at<=a['retiredAtMs']),'FRAME_ATTACHMENT_INTERVAL')
  if previous:
   need(previous['atMs']<=at,'FRAME_TIME_REVERSED')
   if(previous['owner'],previous['attachmentAtMs'])==(f['owner'],f['attachmentAtMs']):need(previous['presentedFrames']<presented,'FRAME_PRESENTATION_COUNTER_NOT_ADVANCING')
  need(at<=s['atMs'],'FRAME_AFTER_FROZEN_STATE');previous=f
 need(any(a['owner']==owner and a['retiredAtMs']is None for a in attachments),'CURRENT_CLOCK_ATTACHMENT_RETIRED')
 return {'state':s,'clock':clock,'retention':ret,'frames':frames,'owner':owner,'uri':uri,'globalOwner':s['native']['owner'],'load':last['driveVideo']['loadId'],'records':records,'last':last}

def scoped_frames(c,start,end):
 need(num(start)<num(end),'POSITIVE_FRAME_INTERVAL_REQUIRED')
 need(c['retention']['droppedRecords']==0 or c['frames'][0]['atMs']<=start,'FRAME_INTERVAL_PREFIX_NOT_RETAINED')
 xs=[f for f in c['frames']if start<f['atMs']<=end and f['owner']==c['owner']]
 need(xs,'NO_CURRENT_OWNED_FRAMES_IN_INTERVAL')
 need(all(f['native']['currentSrc']==c['uri']for f in xs),'FRAME_CURRENT_SOURCE_CHANGED')
 need(len({f['attachmentAtMs']for f in xs})==1 and xs[0]['attachmentAtMs']<=start,'FRAME_ATTACHMENT_CHANGED_OR_STARTED_WITHIN_INTERVAL')
 return [f for f in xs if healthy(f['native'])]

def progression(xs,minimum=None,low=False,high=False):
 selected=[f for f in xs if minimum is None or f['mediaTime']>=minimum]
 if low:selected=[f for f in selected if f['mediaTime']<2]
 if not selected:return None
 first=selected[0]
 tails=[f for f in xs if f['atMs']>first['atMs']and f['presentedFrames']>first['presentedFrames']and f['mediaTime']>first['mediaTime']and(not high or f['mediaTime']>8)]
 if not tails:return None
 last=tails[0];between=[f for f in xs if first['atMs']<=f['atMs']<=last['atMs']]
 need(all(a['mediaTime']<=b['mediaTime']for a,b in zip(between,between[1:])),'FRAME_MEDIA_REVERSED_WITHIN_POSTSEEK_INTERVAL')
 return {'firstSequence':first['sequence'],'lastSequence':last['sequence'],'firstAtMs':first['atMs'],'lastAtMs':last['atMs'],'firstMediaTime':first['mediaTime'],'lastMediaTime':last['mediaTime'],'firstPresentedFrames':first['presentedFrames'],'lastPresentedFrames':last['presentedFrames'],'callbacksInWitness':len(between)}

def settled_link(c,start,end,request=None):
 for index,r in enumerate(c['records']):
  n=r.get('native')or{};d=(r.get('app')or{}).get('driveVideo')or{};at=r.get('atMs')
  if type(at)not in[int,float]or not start<at<=end or n.get('owner')!=c['globalOwner']or n.get('src')!=c['uri']or n.get('connected')is not True or not healthy(n)or d.get('loadId')!=c['load']:continue
  if d.get('frameElementMatchesNative')is not True or d.get('frameEngineMatchesCurrentHls')is not True or d.get('isBufferingVideo')is not False or d.get('videoError')is not None or d.get('selectionUnavailable')is not False or num(d.get('desiredPlaySpeed'))<=0:continue
  num(d.get('presentedMediaTime'))
  if request:
   req=d.get('seekRequest')or{};cmd=d.get('seekCompletion')or{}
   if req!=request or d.get('appliedSeekId')!=request['id']or cmd.get('seekId')!=request['id']or cmd.get('target')!=request['offset']/1000 or abs(num(cmd.get('routeMs'))-request['offset'])>.000001 or not all(cmd.get(k)is True for k in ['elementMatchesNative','engineMatchesCurrent','sourceMatchesCurrent','loadIdMatchesCurrent','seekIdMatchesCurrent']):continue
  return {'recordIndex':index,'atMs':at,'integratedOwner':c['globalOwner'],'clockOwner':c['owner'],'loadId':c['load'],'frameGeneration':d.get('frameGeneration'),'presentedMediaTime':d['presentedMediaTime']}
 raise Refused('SETTLED_PRODUCT_FRAME_OWNER_LOAD_LINK_UNACQUIRED')

def endpoint_sequence(c, events):
 # Clock uses a document capture listener; NF uses a later passive target listener.
 # Pair the complete shared event sequence, not an arbitrary listener latency cap.
 shared={'loadedmetadata','canplay','playing','seeking','seeked','pause','ended','error'}
 nf=[e for e in events if e['kind'].startswith('native:') and e['kind'][7:] in shared]
 need(nf and nf[0]['kind']=='native:loadedmetadata','INITIAL_SHARED_METADATA_EVENT_REQUIRED')
 rows=c['clock']['records'];previous=None
 for row in rows:
  at=num(row['atMs']);need(previous is None or at>=previous,'CLOCK_EVENT_TIME_REVERSED');previous=at
 matches=[]
 for start,row in enumerate(rows):
  if row.get('type')!=nf[0]['kind'][7:] or start+len(nf)>len(rows):continue
  if any((p.get('native')or{}).get('owner')==c['owner'] and (p.get('native')or{}).get('currentSrc')==c['uri'] for p in rows[:start]):continue
  block=rows[start:start+len(nf)];ok=True
  for j,(capture,target) in enumerate(zip(block,nf)):
   native=capture.get('native')or{};target_at=num(target['atMs']);idx=start+j
   if capture.get('type')!=target['kind'][7:] or native.get('owner')!=c['owner'] or native.get('currentSrc')!=c['uri'] or capture['atMs']>target_at:ok=False;break
   # A later native event cannot have entered capture before this target listener.
   if idx+1<len(rows) and target_at>num(rows[idx+1]['atMs']):ok=False;break
  if ok:matches.append((start,block))
 need(len(matches)==1,'UNIQUE_CLOCK_ENDPOINT_LINK_REQUIRED')
 start,block=matches[0]
 return {id(target):{'clockRecordIndex':start+j,'clockAtMs':capture['atMs'],'native':capture['native'],'observedListenerDelayMs':target['atMs']-capture['atMs']} for j,(capture,target) in enumerate(zip(block,nf)) if target['kind']=='native:ended'}

def eof_frames(payload,report):
 c=context(payload,report);last=c['last'];need(all(p['clock']['owner']==c['owner']and p['clock']['currentSrc']==c['uri']for p in report['freezes']),'SAME_EOF_CLOCK_ELEMENT_SOURCE_REQUIRED');nfowner=last['native']['owner'];events=[e for e in report['events']if e.get('trusted')is True and e['atMs']<=last['atMs']and(e.get('native')or{}).get('owner')==nfowner];ends=[e for e in events if e['kind']=='native:ended'];need(len(ends)>=3,'THREE_NATIVE_EOFS_PREREQUISITE');endpoints=endpoint_sequence(c,events);cycles=[]
 for i,end in enumerate(ends):
  until=ends[i+1]['atMs']if i+1<len(ends)else last['atMs'];endpoint=endpoints[id(end)];ep=endpoint['native'];need(ep['paused']is True and ep['error']is None and abs(num(ep['currentTime'])-num(ep['duration']))<.000001,'ACTUAL_CLOCK_EOF_ENDPOINT_REQUIRED')
  seeked=[e for e in events if end['atMs']<e['atMs']<until and e['kind']=='native:seeked'];need(len(seeked)==1,'ORIGINAL_UNIQUE_SEEKED_PREREQUISITE');plays=[e for e in events if end['atMs']<e['atMs']<until and e['kind']=='native:playing'];need(plays and all(p['native']['paused']is False and p['native']['error']is None and p['native']['src']==c['uri']for p in plays),'NATIVE_PLAYING_PREREQUISITE');start=seeked[0]['atMs'];xs=scoped_frames(c,start,until);proof=progression(xs,minimum=1.001,low=True,high=True);partial=i==len(ends)-1 and proof is None
  if partial:proof=progression(xs,minimum=1.001,low=True);need(proof,'LAST_PARTIAL_EOF_NO_FRAME_PROGRESS')
  else:need(proof,'POST_EOF_LOW_THEN_HIGH_FRAME_PROGRESS_REQUIRED')
  request=last['driveVideo']['seekRequest'];need(request==report['freezes'][0]['driveVideo']['seekRequest']and request['offset']==1001,'UNCHANGED_EOF_HEAD_REQUEST_REQUIRED');link=settled_link(c,start,until,request);cycles.append({'nativeEOFAtMs':end['atMs'],'capturePhaseEndpoint':endpoint,'frameIntervalEndMs':until,'partialLastInterval':partial,'frameProgress':proof,'settledProductLink':link})
 complete=[x for x in cycles if not x['partialLastInterval']];need(len(complete)>=3,'THREE_FULLY_RETAINED_EOF_FRAME_PROGRESS_INTERVALS_REQUIRED')
 return {'status':'BOUNDED_IOS_EOF_FRAME_PROGRESS_QUALIFIED','frameAcceptancePending':False,'qualifiedFullPostEOFIntervals':len(complete),'cycles':cycles,'retention':c['retention'],'limits':LIMITS}

LIMITS=['Requires the additive iOS EOF event contract and original trusted carrier/source identity. Early playing is permitted, but every frame interval starts after actual seeked; this does not establish native failure recovery.','Only actually delivered retained rVFC callbacks are observed; no every-decoded-frame, cadence, pixel correctness or gaplessness claim.','Passive frame rows lack load/seek IDs. Same-document shared-clock element/source binding plus interval-scoped integrated frame/command ownership supplies bounded correlation, not fabricated per-frame command IDs.','No physical phone or audio inference; actual runtime provenance must come from the original acquisition.']
