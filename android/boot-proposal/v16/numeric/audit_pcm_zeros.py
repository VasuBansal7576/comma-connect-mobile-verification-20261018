#!/usr/bin/env python3
"""Additive stdlib exact float32 zero-run observer. No playback/filtering/threshold change.
All runs are streamed untruncated to per-channel/joint JSONL. No product/audio pass claim.
"""
import argparse,array,bisect,hashlib,json,math,pathlib,sys
SOURCE='27fd46cd8ecb653e2d6e4cc78c49b67ff9852adfac10a72d08d98ff253436e5d';ENTRY='aca842c376c4711adbfef638afca7142639645015f839f03051c01b37a60e30a'
def sha(b):return hashlib.sha256(b).hexdigest()
def finite(v):return type(v)in(int,float)and math.isfinite(v)
def integer(v):return type(v)is int

def pcm_words(raw,channels):
    if type(channels)is not int or channels not in [1,2]or not raw or len(raw)%(4*channels)or len(raw)>64*1024*1024:raise ValueError('Bounded interleaved f32 shape required')
    words=array.array('I');words.frombytes(raw)
    if words.itemsize!=4:raise ValueError('32bit array words required')
    if sys.byteorder!='little':words.byteswap()
    if any((w&0x7f800000)==0x7f800000 for w in words):raise ValueError('Nonfinite PCM refused')
    return words

def zero_runs(words,channels):
    """Every exact+0/-0 run, including singleton and file-censored runs; no minimum."""
    frames=len(words)//channels;starts=[None]*(channels+1)
    for i in range(frames+1):
        flags=[(words[i*channels+k]&0x7fffffff)==0 for k in range(channels)]if i<frames else[False]*channels
        flags.append(all(flags)if i<frames else False)
        for group,zero in enumerate(flags):
            if zero and starts[group]is None:starts[group]=i
            elif not zero and starts[group]is not None:
                yield group,starts[group],i
                starts[group]=None

def clock_coverage(receipt,frames,channels):
    rate=receipt.get('sampleRate');callbacks=receipt.get('callbacks')
    if type(rate)is not int or rate!=48000 or type(receipt.get('channels'))is not int or receipt.get('channels')!=channels or type(receipt.get('frames'))is not int or receipt.get('frames')!=frames or receipt.get('sampleFormat')!='float32-le-interleaved'or not isinstance(callbacks,list)or not callbacks:raise ValueError('Exact actual PCM callback receipt required')
    cursor=0;gaps=[];prior=None
    for i,row in enumerate(callbacks):
        if not(integer(row.get('sequence'))and row['sequence']==i and integer(row.get('frameOffset'))and row['frameOffset']==cursor and integer(row.get('frames'))and row['frames']>0 and finite(row.get('presentationTimeSeconds'))and finite(row.get('hostUptimeSeconds'))):raise ValueError('Invalid callback ordinal/finite clock')
        if prior:
            if row['hostUptimeSeconds']<prior['hostUptimeSeconds']:raise ValueError('Decreasing callback host uptime')
            residual=row['presentationTimeSeconds']-prior['presentationTimeSeconds']-prior['frames']/rate
            if abs(residual)>2/rate:gaps.append({'atOrdinalFrame':cursor,'beforeSequence':i-1,'afterSequence':i,'ptsResidualSeconds':residual})
        cursor+=row['frames'];prior=row
    if cursor!=frames:raise ValueError('Incomplete callback frame coverage')
    return {'qualifiedContinuousPTS':not gaps,'toleranceSeconds':2/rate,'discontinuities':gaps,'callbacks':callbacks,'offsets':[r['frameOffset']for r in callbacks]}

def source_phases(source,ci,numeric,rate):
    """Reuse exact accepted offsets and frozen1192.667ms phase interior, no new fit."""
    obs=source.get('osAudioObservation',source);align=numeric.get('alignment')or{};offsets=align.get('allCandidateOffsetsMs')or[]
    if not align.get('qualified')or not offsets or not all(finite(v)for v in offsets)or max(offsets)-min(offsets)>150:raise ValueError('Existing qualified bounded nonce alignment required')
    if obs.get('pin')!={'source':SOURCE,'entry':ENTRY}or not obs.get('completeRetention')or not obs.get('sourceEnded'):raise ValueError('Current retained V15 source required')
    rows=obs['rows'];events=obs['events']
    if len(rows)!=obs['totalRows']or len(rows)!=obs['retainedRows']or len(events)!=obs['totalEvents']or len(events)!=obs['retainedEvents']:raise ValueError('Source retention mismatch')
    running=[r for r in rows if r.get('pilot',{}).get('contextState')=='running'and finite(r.get('pilot',{}).get('contextTime'))];times=[r['atMs']for r in running]
    def ctx(event):
        snap=event.get('snapshot')or{}
        if finite(snap.get('pilot',{}).get('contextTime')):return snap['pilot']['contextTime']
        i=bisect.bisect_left(times,event['atMs']);near=running[max(0,i-1):i+1]
        if not near:raise ValueError('No running source context')
        r=min(near,key=lambda r:abs(r['atMs']-event['atMs']))
        if abs(r['atMs']-event['atMs'])>100:raise ValueError('Existing100ms source clock bound exceeded')
        return r['pilot']['contextTime']
    def one(kind,label=None):
        candidates=[e for e in events if e['kind']==kind and(label is None or e.get('label')==label)]
        if len(candidates)!=1:raise ValueError('Unique actual source event required: '+kind+str(label))
        return candidates[0]
    clicks={k:ctx(one('scheduled-react-button-click',k))for k in ['Pause','Unpause','Mute','Close']}
    baseline=ctx(one('baseline-source-attached'));stop=next(e for e in events if e['kind']=='pilot-stop-command'and e.get('reason')=='baseline-timed-pilot-stop');stop=ctx(stop)
    phases=[('product',obs['pilotNonce']['steadyPilotContextTime'],clicks['Pause'],True,True),('pause',clicks['Pause'],clicks['Unpause'],False,True),('resume',clicks['Unpause'],clicks['Mute'],True,True),('mute',clicks['Mute'],clicks['Close'],False,True),('baseline_pilot_on',baseline,stop,True,True)]
    lo,hi=min(offsets),max(offsets);guard=1150+4096/rate*500;out=[]
    for name,start,end,media,pilot in phases:
        if not(finite(start)and finite(end)and end>start):raise ValueError('Invalid actual phase clock')
        out.append({'phase':name,'sourceContextBoundsSeconds':[start,end],'allAcceptedOffsetBoundsMs':[lo,hi],'candidateFileUnionMs':[start*1000+lo,end*1000+hi],'allOffsetsFrozenGuardedInteriorMs':[start*1000+hi+guard,end*1000+lo-guard],'existingGuardMs':guard,'mediaIntendedActive':media,'pilotIntendedActive':pilot,'meaning':'Guarded source intent;50ms native snapshots do not prove sample-instant generation.'})
    mediaOnly=numeric.get('mediaOnlyAfterPilotStop')or[]
    if len(mediaOnly)==ci.get('replacementEvidence',{}).get('systemCapture',{}).get('channels')and mediaOnly and all(x.get('pass')and len(x.get('safeFileIntervalMs',[]))==2 for x in mediaOnly):
        intervals=[x['safeFileIntervalMs']for x in mediaOnly];out.append({'phase':'baseline_pilot_commanded_off','allAcceptedOffsetBoundsMs':[lo,hi],'allOffsetsFrozenGuardedInteriorMs':[max(x[0]for x in intervals),min(x[1]for x in intervals)],'mediaIntendedActive':True,'pilotIntendedActive':False,'meaning':'Exact reused frozen independently validated stop/media-only interval. Low997scalar power is not proof of identically zero residual/no other OS sound.'})
    return out,{'qualified':True,'allCandidateOffsetsMs':offsets,'scope':'Reused nonce/context alignment; no new clock fitting','phaseGuardMs':guard}

def run_record(words,nc,start,end,group,rate,clock,phases,alignmentQualified):
    frames=len(words)//nc;callbacks=clock['callbacks'];a=max(0,bisect.bisect_right(clock['offsets'],start)-1);b=max(0,bisect.bisect_right(clock['offsets'],end-1)-1);first,last=callbacks[a],callbacks[b]
    gaps=[g for g in clock['discontinuities']if start<=g['atOrdinalFrame']<=end]
    selected=list(range(nc))if group==nc else[group]
    edge=lambda f:None if not 0<=f<frames else['%08x'%words[f*nc+k]for k in selected]
    memberships=[];startms,endms=start/rate*1000,end/rate*1000
    if alignmentQualified:
        for phase in phases:
            lo,hi=phase['allOffsetsFrozenGuardedInteriorMs']
            if startms<hi and lo<endms:
                memberships.append({'phase':phase['phase'],'whollyInsideAllOffsetsGuardedInterior':lo<=startms and endms<=hi,'mediaIntendedActive':phase['mediaIntendedActive'],'pilotIntendedActive':phase['pilotIntendedActive'],'sourceAttribution':'NONE; this observes recorded mixed PCM only.'})
    return {'startFrame':start,'endFrameExclusive':end,'recordedZeroFrames':end-start,'recordedSampleDurationMs':(end-start)/rate*1000,'durationMeaning':'Stored zero samples only; not a continuous physical-output duration when censored/PTS discontinuous.','channel':'all'if group==nc else group,'zeroDefinition':'Exact IEEE float32 +0 or -0, no nearzero threshold','leftCensoredAtFileStart':start==0,'rightCensoredAtFileEnd':end==frames,'leftCensoredAtPTSBoundary':any(g['atOrdinalFrame']==start for g in gaps),'rightCensoredAtPTSBoundary':any(g['atOrdinalFrame']==end for g in gaps),'unknownPTSBoundaryInside':any(start<g['atOrdinalFrame']<end for g in gaps),'previousSampleBits':edge(start-1),'nextSampleBits':edge(end),'callbackCoverage':{'firstSequence':first['sequence'],'lastSequence':last['sequence'],'allOrdinalFramesAccounted':True,'continuousPTSWithinAndAtEdges':not gaps,'ptsDiscontinuities':gaps,'recordedPTSStartSeconds':first['presentationTimeSeconds']+(start-first['frameOffset'])/rate,'recordedPTSEndSeconds':last['presentationTimeSeconds']+(end-last['frameOffset'])/rate},'alignedSourcePhaseMembership':memberships}

def audit(rawPath,receiptPath,sourcePath,ciPath,numericPath,out):
    out.mkdir(exist_ok=False);raw=rawPath.read_bytes();receiptBytes=receiptPath.read_bytes();receipt=json.loads(receiptBytes);nc=receipt['channels'];rate=receipt['sampleRate'];words=pcm_words(raw,nc);frames=len(words)//nc;clock=clock_coverage(receipt,frames,nc)
    sourceBytes=sourcePath.read_bytes();source=json.loads(sourceBytes);ci=json.loads(ciPath.read_text());numericBytes=numericPath.read_bytes();numeric=json.loads(numericBytes)
    if ci.get('rawPCMSHA256')!=sha(raw)or ci.get('captureReceiptSHA256')!=sha(receiptBytes)or ci.get('sourceSHA256')!=sha(sourceBytes)or ci.get('derivedViewSHA256')!=numeric.get('inputSHA256'):raise ValueError('Actual CI/source/raw/numeric carrier linkage mismatch')
    try:phases,alignment=source_phases(source,ci,numeric,rate)
    except Exception as e:phases=[];alignment={'qualified':False,'error':{'name':type(e).__name__,'message':str(e)}}
    qualified=clock['qualifiedContinuousPTS']and alignment['qualified'];paths=[out/('channel-'+str(k)+'-zero-runs.jsonl')for k in range(nc)]+[out/'all-channel-zero-runs.jsonl'];handles=[p.open('w')for p in paths];counts=[0]*(nc+1);totals=[0]*(nc+1);maxima=[0]*(nc+1);active=[0]*(nc+1)
    try:
        for group,start,end in zero_runs(words,nc):
            row=run_record(words,nc,start,end,group,rate,clock,phases,qualified);handles[group].write(json.dumps(row,separators=(',',':'))+'\n');counts[group]+=1;totals[group]+=end-start;maxima[group]=max(maxima[group],end-start);active[group]+=any(m['whollyInsideAllOffsetsGuardedInterior']and m['mediaIntendedActive']for m in row['alignedSourcePhaseMembership'])
    finally:
        for h in handles:h.close()
    summary={'schema':'additive-ci-exact-mix-zero-audit-v1','scope':'Recorded hosted ScreenCaptureKit mix PCM; includes Simulator bridge/OS mix/SCK capture. No physical-speaker or historical cause claim.','rawSHA256':sha(raw),'receiptSHA256':sha(receiptBytes),'sourceSHA256':sha(sourceBytes),'ciAssessmentSHA256':sha(ciPath.read_bytes()),'numericReportSHA256':sha(numericBytes),'frames':frames,'channels':nc,'sampleRate':rate,'sourceAlignmentQualified':qualified,'alignment':alignment,'phases':phases,'callbackCoverage':{'qualifiedContinuousPTS':clock['qualifiedContinuousPTS'],'discontinuities':clock['discontinuities'],'callbacks':len(clock['callbacks']),'toleranceSeconds':clock['toleranceSeconds']},'runs':[{'channel':'all'if k==nc else k,'count':counts[k],'totalRecordedZeroFrames':totals[k],'longestRecordedZeroFrames':maxima[k],'guardedMediaIntendedActiveRuns':active[k],'file':p.name,'bytes':p.stat().st_size,'sha256':sha(p.read_bytes())}for k,p in enumerate(paths)],'frozenScalarGatesChanged':False,'functionalPassClaimed':False,'noGapsClaimed':False,'limits':['An18.667ms media-only gap can remain nonzero because997Hz pilot or OS noise survives; no-zero result cannot exclude it.','Exact mixed zeros locate this recording branch, not a specific decoder or the historical provider/capture cause.','Source intent/sample-cadence and accepted clock bounds remain uncertain; only reused frozen guarded interiors are labeled.','All runs including singletons and file/PTS-censored edges retained without minimum duration.','No subtraction, resampling, zero padding, new tone threshold or playback is performed.']}
    (out/'ASSESSMENT.json').write_text(json.dumps(summary,indent=2)+'\n');return summary

def main():
    p=argparse.ArgumentParser();p.add_argument('--raw',type=pathlib.Path,required=True);p.add_argument('--capture',type=pathlib.Path,required=True);p.add_argument('--source',type=pathlib.Path,required=True);p.add_argument('--ci-assessment',type=pathlib.Path,required=True);p.add_argument('--numeric-report',type=pathlib.Path,required=True);p.add_argument('--out',type=pathlib.Path,required=True);a=p.parse_args();s=audit(a.raw,a.capture,a.source,a.ci_assessment,a.numeric_report,a.out);print(json.dumps({'sourceAlignmentQualified':s['sourceAlignmentQualified'],'runs':s['runs'],'functionalPassClaimed':False}))
if __name__=='__main__':main()
