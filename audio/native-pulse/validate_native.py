#!/usr/bin/env python3
"""Observe native Pulse fragment coverage. No generated PTS/no source or audio pass."""
import argparse,array,hashlib,json,math,pathlib,sys
RATE=48000;FRAME_BYTES=8
FAULTS={'pulse-hole-bytes','pulse-overflow','pulse-device-moved','pulse-suspended-or-unknown','pulse-stream-failed','pulse-context-failed','pulse-invalid-fragment','pulse-pcm-write-error','pulse-nonfinite-pcm','pulse-data-drop-error','pulse-hole-drop-error','pulse-frame-bound-exceeded','pulse-peek-error','pulse-read-index-discontinuity'}
def integer(v):return type(v)is int
def finite(v):return type(v)in(int,float)and math.isfinite(v)
def sha(b):return hashlib.sha256(b).hexdigest()
def timing_valid(row):
    return row.get('timingAvailable')is True and row.get('streamTimeResult')==0 and row.get('latencyResult')==0 and row.get('readIndexCorrupt')==0 and row.get('writeIndexCorrupt')==0

def support_coverage(rows,start,end,total):
    if not integer(start)or not integer(end)or not 0<=start<end<=total:raise ValueError('Valid whole file-frame support required')
    # Edge fragments partially consumed by a window are included, not silently omitted.
    relevant=[r for r in rows if r['fileFrameOffset']<end and start<r['fileFrameOffset']+r['frames']]
    valid=[r for r in relevant if timing_valid(r)]
    bases=sorted(set(r['readIndexBytes']-r['fileFrameOffset']*FRAME_BYTES for r in valid))
    last= relevant[-1] if relevant else None
    fresh_after=[]
    if last and last.get('timingAvailable'):
        stamp=(last['timingSystemSeconds'],last['timingSystemUsec'])
        fresh_after=[r for r in rows if r['sequence']>last['sequence']and timing_valid(r)and(r['timingSystemSeconds'],r['timingSystemUsec'])>stamp]
    witness=fresh_after[0]if fresh_after else None
    confirmed=bool(witness)and len(bases)==1 and witness['readIndexBytes']-witness['fileFrameOffset']*FRAME_BYTES==bases[0]
    return {'startFrame':start,'endFrameExclusive':end,'anyOverlapFragments':len(relevant),'readIndexBasisBytes':bases,'sameReadIndexBasisAfterFreshPostSupportTiming':confirmed,'freshPostSupportTimingWitnessSequence':witness['sequence']if witness else None,'allOverlappingFragmentTimingValid':bool(relevant)and all(timing_valid(r)for r in relevant)and confirmed,'invalidFragmentSequences':[r['sequence']for r in relevant if not timing_valid(r)],'perPacketPTSAssumed':False}

def validate(raw,summary,journal,supports=None):
    if len(raw)>64*1024*1024 or len(raw)%FRAME_BYTES:raise ValueError('Bounded complete stereo f32 required')
    x=array.array('f');x.frombytes(raw)
    if x.itemsize!=4:raise ValueError('32bitfloat required')
    if sys.byteorder!='little':x.byteswap()
    if not all(math.isfinite(v)for v in x):raise ValueError('Nonfinite raw PCM')
    if summary.get('schema')!='native-private-pulse-monitor-capture-v1'or summary.get('sampleRate')!=RATE or summary.get('channels')!=2 or summary.get('sampleFormat')!='float32-le-interleaved':raise ValueError('Exact native Pulse summary schema required')
    for k in ['frames','fragments','explicitHoleBytes','requestedCaptureSeconds','capturePID','pulseSourceOutputIndex','pulseMonitorIndex']:
        if not integer(summary.get(k))or summary[k]<0:raise ValueError('Integer native metadata required: '+k)
    if summary['requestedCaptureSeconds']not in [12,150]or summary['capturePID']<=1 or summary['frames']!=len(raw)//FRAME_BYTES:raise ValueError('Native frame/mode/ownPID mismatch')
    if not finite(summary.get('captureElapsedSeconds'))or not finite(summary.get('processElapsedSeconds')):raise ValueError('Finite actual elapsed clocks required')
    rows=[];faults=[];events=[];cursor=0;prior_host=None;prior_time=None;nondecreasing_time=True;timing_count=0
    for item in journal:
        if not isinstance(item,dict)or not finite(item.get('hostMonotonicSeconds')):raise ValueError('Finite native host clock required')
        if prior_host is not None and item['hostMonotonicSeconds']<prior_host:raise ValueError('Decreasing actual host clock')
        prior_host=item['hostMonotonicSeconds']
        if item.get('kind')!='pcm-fragment':
            for k in ['eventSequence','fileFrameOffset','value']:
                if not integer(item.get(k)):raise ValueError('Integer actual native event field required: '+k)
            if item['eventSequence']!=len(events)or item['fileFrameOffset']!=cursor:raise ValueError('Incomplete/reordered native event journal')
            if item.get('kind')=='pulse-suspended-state'and item['value']!=0:faults.append(item)
            if item.get('kind')in FAULTS or item.get('kind','').endswith('-error'):faults.append(item)
            events.append(item);continue
        for k in ['sequence','fileFrameOffset','frames','streamTimeResult','streamTimeUsec','latencyResult','latencyUsec','latencyNegative']:
            if not integer(item.get(k)):raise ValueError('Integer actual native fragment field required: '+k)
        if item['sequence']!=len(rows)or item['fileFrameOffset']!=cursor or item['frames']<=0 or item['streamTimeUsec']<0 or item['latencyUsec']<0 or item['latencyNegative']not in [0,1]:raise ValueError('Native fragment missing/duplicated/invalid')
        if type(item.get('timingAvailable'))is not bool:raise ValueError('Explicit native timing availability required')
        if item['timingAvailable']:
            for k in ['timingSystemSeconds','timingSystemUsec','synchronizedClocks','readIndexCorrupt','writeIndexCorrupt','readIndexBytes','writeIndexBytes','sinkUsec','sourceUsec','transportUsec']:
                if not integer(item.get(k)):raise ValueError('Actual raw timing integer required: '+k)
            if not 0<=item['timingSystemUsec']<1000000 or item['readIndexCorrupt']not in [0,1]or item['writeIndexCorrupt']not in [0,1]:raise ValueError('Malformed actual timing fields')
        if item['streamTimeResult']==0:
            if prior_time is not None and item['streamTimeUsec']<prior_time:nondecreasing_time=False
            prior_time=item['streamTimeUsec']
        timing_count+=timing_valid(item);cursor+=item['frames'];rows.append(item)
    if cursor!=summary['frames']or len(rows)!=summary['fragments']:raise ValueError('Incomplete native journal/raw fragment coverage')
    support_results=[support_coverage(rows,r[0],r[1],cursor)for r in supports]if supports is not None else[]
    checks={'declaredComplete':summary.get('nativeCaptureComplete')is True,'dataReadinessObserved':summary.get('dataReadinessObserved')is True,'filesAndStreamClosed':all(summary.get(k)is True for k in ['streamDisconnected','pcmFileClosed','journalFileClosed']),'noExplicitHoleBytes':summary['explicitHoleBytes']==0,'noObservedCaptureFaults':not faults,'deliveredFragmentCoverageComplete':True,'nativeStreamTimeNondecreasingWhenAvailable':nondecreasing_time,'realCaptureDurationBound':summary['requestedCaptureSeconds']<=summary['captureElapsedSeconds']<=summary['requestedCaptureSeconds']+1,'noGeneratedPerPacketPTS':summary.get('independentPerPacketPTSProvided')is False,'noMicrophone':summary.get('microphoneRequested')is False}
    valid_indexes=[r['readIndexBytes']-r['fileFrameOffset']*FRAME_BYTES for r in rows if timing_valid(r)]
    checks['oneStableValidReadIndexBasis']=bool(valid_indexes)and len(set(valid_indexes))==1
    checks['uniqueReadyDataReadyStop']=all(sum(e['kind']==name for e in events)==1 for name in ['capture-ready','capture-data-ready','capture-stop'])
    checks['reviewedLibrarySeries']=summary.get('libraryVersion')in ['16.1','16.1.0']
    indexes=[{'sequence':r['sequence'],'fileFrameOffset':r['fileFrameOffset'],'rawReadIndexBytes':r['readIndexBytes'],'readIndexMinusFileByteOffset':r['readIndexBytes']-r['fileFrameOffset']*FRAME_BYTES,'timingSystemSeconds':r['timingSystemSeconds'],'timingSystemUsec':r['timingSystemUsec']}for r in rows if r.get('timingAvailable')]
    return {'schema':'native-pulse-fragment-coverage-facts-v1','checks':checks,'nativeCaptureChecksPass':all(checks.values()),'frames':cursor,'fragments':len(rows),'fragmentsWithValidRawTiming':timing_count,'retainedInitialOrOtherInvalidTimingFragments':len(rows)-timing_count,'requestedSupportCoverage':support_results,'allRequestedSupportsHaveValidRawTiming':bool(support_results)and all(x['allOverlappingFragmentTimingValid']for x in support_results),'rawTimingIndexes':indexes,'faults':faults,'nativeEvents':events,'independentPerPacketPTSProvided':False,'rawTimingMeaning':'Actual periodic Pulse timing observations, possibly aged; read-index basis is checked constant with a fresh post-support timing witness, never interpreted as per-packet PTS or forced to zero.','scope':'Owned hosted Pulse monitor mix delivery only; no physical speaker/encoded source/historical cause equivalence.','originalFrozenAndSourceNonceControlsRequired':True,'functionalPWAQualificationClaimed':False}

def main():
    p=argparse.ArgumentParser();p.add_argument('--raw',type=pathlib.Path,required=True);p.add_argument('--summary',type=pathlib.Path,required=True);p.add_argument('--journal',type=pathlib.Path,required=True);p.add_argument('--supports',type=pathlib.Path);p.add_argument('--out',type=pathlib.Path,required=True);a=p.parse_args();raw=a.raw.read_bytes();summary_bytes=a.summary.read_bytes();journal_bytes=a.journal.read_bytes()
    if len(journal_bytes)>128*1024*1024:raise ValueError('Journal exceeds explicit local bound; no truncated acceptance')
    result=validate(raw,json.loads(summary_bytes),[json.loads(s)for s in journal_bytes.splitlines()],json.loads(a.supports.read_bytes())if a.supports else None);result.update({'rawSHA256':sha(raw),'summarySHA256':sha(summary_bytes),'journalSHA256':sha(journal_bytes)});a.out.write_text(json.dumps(result,indent=2)+'\n');print(json.dumps({'nativeCaptureChecksPass':result['nativeCaptureChecksPass'],'functionalPWAQualificationClaimed':False,'independentPerPacketPTSProvided':False}));raise SystemExit(0 if result['nativeCaptureChecksPass']else 2)
if __name__=='__main__':main()
