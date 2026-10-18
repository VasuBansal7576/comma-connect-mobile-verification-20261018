#!/usr/bin/env python3
"""Offline scalar-only current V16 verifier. No network, audio output, or waveform access.
Run: python3 assess-os-recording.py EXPORT --expected-sha CARRIER_ORIGINAL_SHA --witnesses UI.json --out RESULT.json
Calibration may use --calibration; it can never certify a phone or OS acquisition.
"""
from pathlib import Path
import argparse,bisect,collections,hashlib,json,math,statistics
SOURCE='24debd4d28470b53f97d41bc46fdc44b060ae0c1bb16f33c331aa5896b5ba07b'
ENTRY='e7ab13f79d01a5784c7879f9a02a2f9b8a0078e3281dbb6cfda01d36a0467641'
GATES={'offsetGridMs':5,'nonceWholeWindowMarginMs':5,'maximumSingleCandidateClusterWidthMs':150,'maximumIndependentStopResidualMs':150,'phaseMarginMs':1000,'phaseEndValidationAllowanceMs':150,'onOverGuardDb':12,'onPeakDb':-65,'offRelativePowerDb':-20,'minimumPositiveBothSupportMs':5000,'minimumControlSupportMs':3000,'minimumRewindsPerBranch':3,'minimumAttenuationRows':2,'minimumNonceRateHz':32000,'maximumNearestSourceRowDistanceMs':100,'loopAssociationRadiusMs':500,'clockModel':'One additive context-to-file offset; all feasible offsets retained. No affine/dip-specific fit.'}
COLUMNS=['startSample','endSample','centreMs','rms','media440Power','pilot997Power','media440GuardPower','pilot997GuardPower','media440Db','pilot997Db','media440GuardDb','pilot997GuardDb','media440OverGuardDb','pilot997OverGuardDb','toneState']
def sha(b):return hashlib.sha256(b).hexdigest()
def finite(n):return isinstance(n,(int,float))and math.isfinite(n)
def qualified(r,band):
 db,over=(8,12)if band==440 else(9,13)
 return finite(r[db])and finite(r[over])and r[db]>=GATES['onPeakDb']and r[over]>=GATES['onOverGuardDb']
def groups(items,key=lambda x:x):
 out=[]
 for x in items:
  if not out or key(x)-key(out[-1][-1])>GATES['offsetGridMs']+1e-6:out.append([])
  out[-1].append(x)
 return out

def nonce_alignment(channels,decoded,nonce):
 """Exhaustive grid; do not select only an attractive correlation peak."""
 fs=decoded['sampleRate'];duration=decoded['duration']*1000;half=4096/fs*500;centres=[[r[2]for r in rows]for rows in channels]
 medians=[statistics.median([r[5]for r in rows if qualified(r,997)]or[0])for rows in channels]
 trans=nonce.get('transitions',[]);segments=[(a['contextTime']*1000,b['contextTime']*1000,a['value']>0)for a,b in zip(trans,trans[1:])if b['contextTime']>a['contextTime']]
 if len(segments)!=34 or len(nonce.get('bits',''))!=16:raise ValueError('Expected .6s/.6s preamble plus32 Manchester half-bits.')
 boundlo=math.ceil((-segments[0][0])/5)*5;boundhi=math.floor((duration-segments[-1][1])/5)*5
 candidates=[];scores=[];hist=collections.Counter();margin=half+GATES['nonceWholeWindowMarginMs']
 for offset in range(boundlo,boundhi+1,5):
  bad=0;empty=0;tested=0
  for ci,rows in enumerate(channels):
   centre=centres[ci]
   for start,end,on in segments:
    lo=bisect.bisect_left(centre,start+offset+margin);hi=bisect.bisect_right(centre,end+offset-margin)
    selected=rows[lo:hi];tested+=1
    ok=bool(selected)and all(qualified(r,997)if on else r[5]<=medians[ci]/100 for r in selected)
    if not selected:empty+=1
    if not ok:bad+=1
  hist[bad]+=1;scores.append((bad,empty,offset,tested))
  if bad==0:candidates.append(offset)
 clusters=[{'minimumMs':x[0],'maximumMs':x[-1],'widthMs':x[-1]-x[0],'offsetsMs':x}for x in groups(candidates)]
 runner=[{'mismatchedIntervals':a,'emptyIntervals':b,'offsetMs':c,'testedIntervals':d}for a,b,c,d in sorted([x for x in scores if x[0]],key=lambda x:(x[0],x[1],x[2]))[:100]]
 return {'qualified':fs>=32000 and len(clusters)==1 and clusters[0]['widthMs']<=150,'searchBoundsMs':[boundlo,boundhi],'searchGridMs':5,'testedOffsetCount':len(scores),'scheduledSegments':segments,'allCandidateOffsetsMs':candidates,'clusters':clusters,'mismatchHistogram':dict(sorted(hist.items())),'runnerUpOffsets':runner,'perChannelPositivePilotMedianPower':medians,'scalarWindowMs':half*2,'wholeWindowBoundaryMarginMs':margin,'minimumIntervalSamples':1,'intervalMismatchAllowance':0}

def assess(payload,rawsha,expected,witnesses,calibration=False):
 checks=[];warnings=[]
 def check(name,passed,detail=None):checks.append({'name':name,'pass':bool(passed),'detail':detail});return bool(passed)
 os=payload.get('osAudioObservation',payload);a=os.get('analysis')or{};rows=os.get('rows',[]);events=os.get('events',[]);out={'schema':'independent-current-v16-os-recording-assessment-v1','calibrationOnly':calibration,'inputSHA256':rawsha,'gates':GATES,'checks':checks,'warnings':warnings,'classification':'PARTIAL','physicalSpeakerCertified':False,'comparisonScope':{'baseline':'bare native HTMLVideo source','transportMatched':False,'attributionLimit':'Product-versus-control differences leave application versus native/MSE engine causality open.'}}
 check('selected original carrier integrity',expected is not None and rawsha==expected,{'expectedSHA256':expected,'actualSHA256':rawsha})
 check('current source/entry pins',os.get('pin')=={'source':SOURCE,'entry':ENTRY})
 outer=payload.get('candidate');check('outer current payload pins',calibration or(bool(outer)and outer.get('candidateSourceTreeSHA256')==SOURCE and outer.get('candidateEntrySHA256')==ENTRY))
 check('current observer kind',os.get('recordType')=='current_v16_os_gap_source_and_local_scalars')
 check('complete source/event retention',os.get('completeRetention')is True and os.get('totalRows')==len(rows)==os.get('retainedRows')and os.get('totalEvents')==len(events)==os.get('retainedEvents'))
 check('source ended and own cleanup',os.get('sourceEnded')is True and all((os.get('cleanup')or{}).get(k)is True for k in['contextClosed','baselineRemoved','timerCleared','deadlineCleared'])and(os.get('cleanup')or{}).get('microphoneRequested')is False)
 check('local analysis cleanup',a.get('cleanupComplete')is True and a.get('pending')==0 and a.get('audioOutputNodesCreated')==0 and a.get('microphoneRequested')is False and a.get('fileInputCleared')is True and a.get('rawReferencesReleased')is True and not a.get('error'))
 check('original selected file metadata/hash',all((a.get('fileMetadata')or{}).get(k)is not None for k in ['name','bytes','type','lastModified'])and finite((a.get('fileMetadata')or{}).get('bytes'))and a['fileMetadata']['bytes']>0 and len(a.get('fileSHA256',''))==64)
 sourceProof=[r.get('proof')for r in rows if r.get('proof')];check('actual row proofs stable',bool(sourceProof)and all(p.get('candidateSourceTreeSHA256')==SOURCE and p.get('entrySHA256')==ENTRY for p in sourceProof))
 documents={r.get('actualDocument')for r in rows if r.get('actualDocument')};check('one actual product document',len(documents)==1)
 ui=['microphoneOff','recordingActive','recordingSaved','nativeOriginalFileSelection'];wresults=[]
 for name in ui:
  item=(witnesses or{}).get(name,{});p=Path(item.get('path','/nonexistent'));ok=p.is_file()and item.get('observed')is True and sha(p.read_bytes())==item.get('sha256');wresults.append({'name':name,'pass':ok,'path':str(p),'sha256':item.get('sha256'),'observation':item.get('observation')})
 check('independent OS/Photos UI witnesses',not calibration and all(x['pass']for x in wresults),wresults)
 if calibration:warnings.append('Synthetic/AAC calibration only: no phone, OS provenance, physical speaker or product fix claim is permitted even if numeric gates pass.')
 playlist=os.get('playlist')or{};check('retained exact playlist hash',sha(playlist.get('text','').encode())==playlist.get('sha256')and len(playlist.get('text','').encode())==playlist.get('bytes'))
 guard=playlist.get('scalarTimebaseGuard')or{};loop=playlist.get('productLoop')or{}
 check('prepared scalar NF selection',playlist.get('videoStartOffset')==0 and guard.get('routeDuration')==12000 and guard.get('segmentDurations')==[12000]and guard.get('exactKnownNF12sScalar')is True and loop.get('startTime')==1001 and loop.get('duration')in[2998,10999])
 try:
  nf=json.loads((Path(__file__).parent/'nf-source-input/ACQUISITION.json').read_text());known={(x['sha256'],x['bytes'])for x in nf['assets']};assets=playlist.get('assets',[]);check('exact known NF playlist and encoded assets',playlist.get('sha256')==nf['playlist']['sha256']and len(assets)==len(known)and{(x.get('sha256'),x.get('bytes'))for x in assets}==known)
 except Exception as e:check('exact known NF asset manifest',False,str(e))
 decoded=a.get('decoded')or{};channels=[x.get('rows',[])for x in sorted(a.get('perChannel',[]),key=lambda c:c.get('channel',-1))];aggregate=a.get('rows')or[];fs=decoded.get('sampleRate',0);frames=decoded.get('frames',0)
 expectedRows=max(0,(frames-4096)//max(1,round(fs*.05))+1);check('complete decoded per-channel coverage',sorted(c.get('channel')for c in a.get('perChannel',[]))==list(range(decoded.get('channels',0)))and decoded.get('channels')in[1,2]and len(channels)==decoded.get('channels')and all(len(c)==expectedRows for c in channels)and len(aggregate)==expectedRows and expectedRows>0)
 check('exact scalar columns/method window',a.get('columns')==COLUMNS and(a.get('method')or{}).get('windowSamples')==4096 and abs((a.get('method')or{}).get('hopMs',0)-50)<1)
 validRows=True
 for c in channels+[aggregate]:
  for i,r in enumerate(c):
   if len(r)!=15 or r[0]!=i*round(fs*.05)or r[1]!=r[0]+4096 or any(not finite(r[k])or r[k]<0 for k in[3,4,5,6,7])or abs(r[2]-1000*(r[0]+2048)/fs)>1e-5:validRows=False;break
 check('scalar sample ordinals/powers/time complete',validRows)
 aggregateMatches=bool(channels)and all(math.isclose(r[k],sum(c[i][k]for c in channels)/len(channels),rel_tol=1e-8,abs_tol=1e-20)for i,r in enumerate(aggregate)for k in[4,5,6,7])
 check('aggregate raw powers equal per-channel arithmetic mean',aggregateMatches)
 check('source row clocks/document and event ordinals',bool(rows)and all(rows[i]['atMs']>=rows[i-1]['atMs']for i in range(1,len(rows)))and all(r.get('documentId')==os.get('documentId')for r in rows)and[e.get('ordinal')for e in events]==list(range(1,len(events)+1)))
 nonce=os.get('pilotNonce')or{};doc=os.get('documentId','');check('run-specific nonce binds document',nonce.get('bits')==format(int(doc.replace('-','')[-4:]or'0',16),'016b')and nonce.get('kind')=='16bit-Manchester997Hz')
 scheduleValid=False
 try:
  cursor=nonce['originTime'];expectedSchedule=[]
  def step(value,seconds):
   nonlocal cursor
   expectedSchedule.append({'contextTime':cursor,'value':value});cursor+=seconds
  step(.02,.6);step(0,.6)
  for bit in nonce['bits']:step(.02 if bit=='1'else 0,.2);step(0 if bit=='1'else .02,.2)
  step(.02,0);actual=nonce['transitions'];scheduleValid=len(actual)==len(expectedSchedule)and all(abs(x['contextTime']-y['contextTime'])<1e-6 and x['value']==y['value']for x,y in zip(actual,expectedSchedule))and abs(cursor-nonce['steadyPilotContextTime'])<1e-6
 except Exception:pass
 check('nonce schedule exactly matches document bits and half-bits',scheduleValid)
 if not channels or not validRows or not nonce or not fs or not scheduleValid:
  out['missingCoreData']=True;return out
 try:alignment=nonce_alignment(channels,decoded,nonce)
 except Exception as e:check('nonce matching completed',False,str(e));return out
 out['alignment']=alignment;check('all-channel unique bounded coded nonce',alignment['qualified'])
 if not alignment['qualified']:return out
 offsets=alignment['allCandidateOffsetsMs'];offlo,offhi=min(offsets),max(offsets);half=4096/fs*500;hop=round(fs*.05)/fs*1000
 sourceGood=[r for r in rows if r.get('pilot',{}).get('contextState')=='running'and finite(r.get('pilot',{}).get('contextTime'))]
 sourceTimes=[r['atMs']for r in sourceGood]
 def ctx(at):
  if not sourceGood:return None
  j=bisect.bisect_left(sourceTimes,at);near=min(sourceGood[max(0,j-1):j+1],key=lambda r:abs(r['atMs']-at))
  return near['pilot']['contextTime'] if abs(near['atMs']-at)<=100 else None
 def eventctx(e):return(e.get('snapshot')or{}).get('pilot',{}).get('contextTime')if finite((e.get('snapshot')or{}).get('pilot',{}).get('contextTime'))else ctx(e['atMs'])
 out['sourceClockSamples']={'runningRows':len(sourceGood),'performanceMinusContextMsRange':[min((r['atMs']-r['pilot']['contextTime']*1000 for r in sourceGood),default=None),max((r['atMs']-r['pilot']['contextTime']*1000 for r in sourceGood),default=None)],'mapping':'Each source sample uses actual AudioContext.currentTime. Events use retained snapshot or nearest running-context row <=100ms; no file-zero/wall-clock assumption.'}
 stop=next((e for e in events if e['kind']=='pilot-stop-command'and e.get('reason')=='baseline-timed-pilot-stop'),None)
 check('independent timed baseline pilot-stop retained',stop is not None)
 if stop is None:return out
 stopctx=eventctx(stop);check('independent stop actual source context',finite(stopctx))
 if not finite(stopctx):return out
 stopPred=[stopctx*1000+offlo,stopctx*1000+offhi];stopResults=[]
 for ci,c in enumerate(channels):
  window=[r for r in c if stopPred[0]-1000<=r[2]<=stopPred[1]+1000 and qualified(r,440)]
  median=alignment['perChannelPositivePilotMedianPower'][ci];high=[r for r in window if qualified(r,997)and r[5]>=median/2];low=[r for r in window if r[5]<=median/100]
  pairs=[]
  for lowrow in low:
   previous=[r for r in high if 0<lowrow[2]-r[2]<=500]
   if previous:
    h=max(previous,key=lambda r:r[2]);edge=[h[2]-half,lowrow[2]+half];mid=(h[2]+lowrow[2])/2;residual=[mid-stopPred[1],mid-stopPred[0]]
    if edge[1]>=stopPred[0]-150 and edge[0]<=stopPred[1]+150 and min(abs(v)for v in residual)<=150:pairs.append({'lastHighCentreMs':h[2],'firstLowCentreMs':lowrow[2],'edgeIntervalMs':edge,'midpointResidualMs':residual})
  if pairs:pair=min(pairs,key=lambda x:(x['firstLowCentreMs']-x['lastHighCentreMs'],abs(sum(x['midpointResidualMs'])/2)))
  else:pair=None
  stopResults.append({'channel':ci,'pass':pair is not None,'predictedStopRangeMs':stopPred,'candidateTransitions':pairs,'selectedIndependentTransition':pair})
 out['independentPilotStop']=stopResults;check('pilot-stop997 disappears with440 present at predicted clock',all(r['pass']for r in stopResults))
 clicks={e.get('label'):e for e in events if e['kind']=='scheduled-react-button-click'}
 check('actual scheduled product inputs retained explicitly untrusted',all(k in clicks and clicks[k].get('trusted')is False for k in['Pause','Unpause','Mute','Close'])and not any(e['kind']=='scheduled-input-refused'for e in events))
 times={k:eventctx(v)for k,v in clicks.items()};base=next((e for e in events if e['kind']=='baseline-source-attached'),None);basectx=eventctx(base)if base else None
 if not all(finite(times.get(k))for k in ['Pause','Unpause','Mute','Close'])or not finite(basectx):check('all actual phase source clocks',False,times);return out
 check('all actual phase source clocks',True,times)
 # After context closure, media-only file support is measured directly relative to the independently observed stop; before closure everything uses actual context times.
 intervals={'product':(nonce['steadyPilotContextTime'],times['Pause']),'pause':(times['Pause'],times['Unpause']),'resume':(times['Unpause'],times['Mute']),'mute':(times['Mute'],times['Close']),'baseline':(basectx,stopctx)}
 margin=1150+half
 selected={name:[[r for r in c if start*1000+offhi+margin<=r[2]<=end*1000+offlo-margin]for c in channels]for name,(start,end)in intervals.items()}
 medians={name:[statistics.median([r[4]for r in c if qualified(r,440)and qualified(r,997)]or[0])for c in selected[name]]for name in ['product','baseline']}
 supports={};branchDips={};branchCommon={}
 def runs(records,pred):
  out=[];current=[]
  for r in records:
   if pred(r)and(not current or r[0]-current[-1][0]==round(fs*.05)):current.append(r)
   else:
    if len(current)>=2:out.append(current)
    current=[r]if pred(r)else[]
  if len(current)>=2:out.append(current)
  return[{'rowCount':len(g),'firstCentreMs':g[0][2],'lastCentreMs':g[-1][2],'centreSpanMs':g[-1][2]-g[0][2],'windowUnionBoundsMs':[g[0][2]-half,g[-1][2]+half],'sourceContextBoundsSeconds':[(g[0][2]-offhi)/1000,(g[-1][2]-offlo)/1000]}for g in out]
 for name,crows in selected.items():
  values=[]
  for ci,c in enumerate(crows):
   mediaMedian=medians['product'][ci]
   pred=(lambda r:qualified(r,440)and qualified(r,997))if name not in ['pause','mute']else(lambda r:qualified(r,997)and r[4]<=mediaMedian/100)
   good=[r for r in c if pred(r)];required=5000 if name in['product','baseline']else 3000
   values.append({'channel':ci,'interiorRows':len(c),'qualifiedRows':len(good),'supportMs':len(good)*hop,'requiredMs':required,'pass':len(good)*hop>=required})
  supports[name]=values;check(name+' qualified support all channels',all(x['pass']for x in values),values)
 for branch in ['product','baseline']:
  branchDips[branch]=[];branchCommon[branch]=[]
  for ci,c in enumerate(selected[branch]):
   mm=medians[branch][ci];pm=alignment['perChannelPositivePilotMedianPower'][ci]
   branchDips[branch].append({'channel':ci,'positiveMediaMedianPower':mm,'runs':runs(c,lambda r:r[4]<=mm/100 and qualified(r,997))})
   branchCommon[branch].append({'channel':ci,'runs':runs(c,lambda r:r[4]<=mm/100 and r[5]<=pm/100)})
 out['controls']=supports;out['selectiveMediaDips']=branchDips;out['bothToneAttenuation']=branchCommon
 mediaOnly=[]
 # Six-second post-stop control exists; exclude both boundaries plus clock/FFT uncertainty.
 stopSource=next((e for e in events if e['kind']=='source-stop'),None);stopPerf=stop['atMs'];endDelta=(stopSource['atMs']-stopPerf)if stopSource else 6000
 for ci,c in enumerate(channels):
  edge=stopResults[ci]['selectedIndependentTransition'];start=(edge['edgeIntervalMs'][1]if edge else stopPred[1])+margin;end=stopPred[0]+endDelta-margin
  good=[r for r in c if start<=r[2]<=end and qualified(r,440)and r[5]<=alignment['perChannelPositivePilotMedianPower'][ci]/100];mediaOnly.append({'channel':ci,'safeFileIntervalMs':[start,end],'qualifiedRows':len(good),'supportMs':len(good)*hop,'pass':len(good)*hop>=3000})
 check('baseline independent pilot-stop media-only support all channels',all(x['pass']for x in mediaOnly),mediaOnly);out['mediaOnlyAfterPilotStop']=mediaOnly
 loops={}
 for branch,(lo,hi)in [('product',intervals['product']),('baseline',intervals['baseline'])]:
  found=[]
  for e in events:
   if e['kind']!='backward-jump'or e.get('phase')!=('product'if branch=='product'else'bare-native'):continue
   t=eventctx(e)
   if finite(t)and lo+1.15<t<hi-1.15:found.append({'atMs':e['atMs'],'contextTime':t,'fileTimeRangeMs':[t*1000+offlo,t*1000+offhi],'from':e.get('from'),'to':e.get('to')})
  loops[branch]=found;check(branch+' at least three actual rewinds',len(found)>=3,{'count':len(found)})
 out['loops']=loops
 for branch,chlist in branchDips.items():
  for c in chlist:
   for dip in c['runs']:dip['associatedLoopIndices']=[i for i,l in enumerate(loops[branch])if dip['windowUnionBoundsMs'][1]>=l['fileTimeRangeMs'][0]-500 and dip['windowUnionBoundsMs'][0]<=l['fileTimeRangeMs'][1]+500]
 # Source states independently distinguish intentional phases from scheduled UI labels.
 sourceConditions={}
 for name,(lo,hi)in intervals.items():
  subset=[r for r in sourceGood if lo+1.15<=r['pilot']['contextTime']<=hi-1.15]
  def healthy(r):
   n=r.get('baseline')if name=='baseline'else r.get('product');n=n or{}
   if not(n.get('connected')and n.get('readyState',0)>=2 and n.get('error')is None):return False
   if name=='pause':return n.get('paused')is True and r.get('desiredPlaySpeed')==0
   if name=='mute':return n.get('muted')is True and n.get('paused')is False and r.get('desiredPlaySpeed')==1
   if name=='baseline':return not r.get('product')and n.get('muted')is False and n.get('paused')is False
   return n.get('muted')is False and n.get('paused')is False and r.get('desiredPlaySpeed')==1
  fraction=sum(healthy(r)for r in subset)/len(subset)if subset else 0;sourceConditions[name]={'retainedRows':len(subset),'qualifiedFraction':fraction,'pass':fraction>=.9};check(name+' actual native/readiness/intent control',fraction>=.9,sourceConditions[name])
 out['sourceConditions']=sourceConditions
 # Compare separately observed attenuation; merely finding one dip in each branch is insufficient.
 # Duration bounds derive from the existing FFT window and hop. Power IQRs are descriptive observed
 # ranges, NOT statistical confidence intervals, and introduce no new attenuation threshold.
 def overlap(x,y):return max(x[0],y[0])<=min(x[1],y[1])
 def iqr(values):
  q=statistics.quantiles(values,n=4,method='inclusive');return[q[0],q[2]]
 for branch,chlist in branchDips.items():
  for ci,c in enumerate(chlist):
   for dip in c['runs']:
    subset=[r for r in selected[branch][ci]if dip['firstCentreMs']<=r[2]<=dip['lastCentreMs']]
    powers=[r[4]/c['positiveMediaMedianPower']for r in subset]
    dip['relativeMediaPowerIQR']=iqr(powers);dip['minimumRelativeMediaPower']=min(powers);dip['maximumRelativeMediaPower']=max(powers)
    dip['durationResolutionBoundsMs']=[max(0,dip['centreSpanMs']-(half*2+hop)),dip['centreSpanMs']+(half*2+hop)]
 comparison=[]
 for ci,(prod,basech)in enumerate(zip(branchDips['product'],branchDips['baseline'])):
  prodLoops={i for d in prod['runs']for i in d['associatedLoopIndices']};baseLoops={i for d in basech['runs']for i in d['associatedLoopIndices']}
  prate=len(prodLoops)/len(loops['product'])if loops['product']else None;brate=len(baseLoops)/len(loops['baseline'])if loops['baseline']else None
  pairs=[]
  for pi,d in enumerate(prod['runs']):
   matches=[bi for bi,b in enumerate(basech['runs'])if d['associatedLoopIndices']and b['associatedLoopIndices']and overlap(d['durationResolutionBoundsMs'],b['durationResolutionBoundsMs'])and overlap(d['relativeMediaPowerIQR'],b['relativeMediaPowerIQR'])]
   pairs.append({'productDipIndex':pi,'matchingBaselineDipIndices':matches,'matched':bool(matches)})
  allAssociated=all(d['associatedLoopIndices']for d in prod['runs']+basech['runs'])
  supported=bool(prod['runs'])and bool(basech['runs'])and allAssociated and all(x['matched']for x in pairs)and prate is not None and brate is not None and prate<=brate
  comparison.append({'channel':ci,'productAffectedLoopFraction':prate,'baselineAffectedLoopFraction':brate,'allRelevantDipsLoopAssociated':allAssociated,'observedProductDipsMatchedInDurationAndRelativePowerIQR':pairs,'noObservedProductExcessAtDetectorResolution':supported})
 out['branchComparison']={'channels':comparison,'meaning':'Separate branch observations. Comparable requires every relevant dip loop-associated, each product dip matched in same-channel FFT-duration bounds and observed low-row relative-power IQR, and no greater product affected-loop fraction. These are descriptive resolution checks, not equivalence proof or statistical confidence intervals. Product excess/unassociated attenuation remains unresolved otherwise.','allChannelsComparable':bool(comparison)and all(c['noObservedProductExcessAtDetectorResolution']for c in comparison)}
 valid=all(c['pass']for c in checks if not(calibration and c['name']=='independent OS/Photos UI witnesses'))
 pd=any(c['runs']for c in branchDips['product']);bd=any(c['runs']for c in branchDips['baseline']);common=any(c['runs']for b in branchCommon.values()for c in b)
 if valid:
  out['classification']='COMMON_RECORDING_OR_OUTPUT_CANDIDATE'if common else('BOTH_BRANCH_COMPARABLE_LOOP_ATTENUATION'if out['branchComparison']['allChannelsComparable']else'BOTH_BRANCH_ATTENUATION_UNRESOLVED_PRODUCT_EXCESS')if pd and bd else'PRODUCT_SPECIFIC_CONTRIBUTION'if pd else'BASELINE_SELECTIVE_ATTENUATION_ONLY'if bd else'BOUNDED_NO_QUALIFIED_DIP'
  out['status']='CALIBRATION_PASS'if calibration else'PASS_BOUNDED_ATTRIBUTION'
 else:out['status']='PARTIAL'
 out['allRequiredGatesPass']=valid
 return out

def main():
 parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('export',type=Path);parser.add_argument('--expected-sha');parser.add_argument('--witnesses',type=Path);parser.add_argument('--out',type=Path,required=True);parser.add_argument('--calibration',action='store_true');args=parser.parse_args();raw=args.export.read_bytes();payload=json.loads(raw);w=json.loads(args.witnesses.read_text())if args.witnesses else{}
 try:r=assess(payload,sha(raw),args.expected_sha,w,args.calibration)
 except Exception as e:r={'status':'PARTIAL','error':{'type':type(e).__name__,'message':str(e)},'inputSHA256':sha(raw),'physicalSpeakerCertified':False}
 args.out.write_text(json.dumps(r,indent=2));print(json.dumps({'output':str(args.out),'status':r.get('status','PARTIAL'),'classification':r.get('classification','PARTIAL'),'failedChecks':[x['name']for x in r.get('checks',[])if not x['pass']]}))
if __name__=='__main__':main()
