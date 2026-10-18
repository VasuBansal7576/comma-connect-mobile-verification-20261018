#!/usr/bin/env python3
"""Additive native Pulse exact-zero + unchanged joint-tone diagnostics. No fake PTS."""
import argparse,array,hashlib,importlib.util,json,math,pathlib,sys
ZERO='c45f76908b6cdbfd6eae8d723db270ac261cdb28b7bead1ec3ee696217bb52c7'
JOINT='4a569028fc306798f30612aedb690b2e53bee53db2da928aec15bcec35b32a7a'
def sha(b):return hashlib.sha256(b).hexdigest()
def load(path,name,pin=None):
 if pin and sha(path.read_bytes())!=pin:raise ValueError('Reviewed numerical core changed')
 spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m

def audit(a):
 a.out.mkdir(exist_ok=False);raw=a.raw.read_bytes();sourcebytes=a.source.read_bytes();cb=a.components.read_bytes();nb=a.numeric.read_bytes();vb=a.coverage.read_bytes();c=json.loads(cb);n=json.loads(nb);v=json.loads(vb);source=json.loads(sourcebytes)
 if not(c['numericChecksPass']and c['nativeWholeSourceEnvelopePass']and c['rawPCMSHA256']==sha(raw)and c['sourceSHA256']==sha(sourcebytes)and c['frozenNumericReportSHA256']==sha(nb)and c['nativeSourceCoverageSHA256']==sha(vb)and n['inputSHA256']==c['derivedViewSHA256']and v['nativeCaptureChecksPass']and v['allRequestedSupportsHaveValidRawTiming']):raise ValueError('Complete original numeric/native coverage/hash linkage required')
 joint=load(a.joint,'joint_tones',JOINT);zero=load(a.zero,'native_pulse_zero_core',ZERO)
 # source_phases uses only actual channel count from this metadata; no SCK/PTS fields.
 phases,alignment=zero.source_phases(source,{'replacementEvidence':{'systemCapture':{'channels':2}}},n,48000)
 support=c['sourceEnvelopeFrames'];words=zero.pcm_words(raw,2);paths=[a.out/'channel-0-zeros.jsonl',a.out/'channel-1-zeros.jsonl',a.out/'all-channel-zeros.jsonl'];handles=[p.open('x')for p in paths];counts=[0,0,0]
 try:
  for group,start,end in zero.zero_runs(words,2):
   row={'channel':group if group<2 else'all','startFrame':start,'endFrameExclusive':end,'exactZeroFrames':end-start,'leftFileCensored':start==0,'rightFileCensored':end==len(words)//2,'wholeRunInsideNativeSourceEnvelope':support[0]<=start and end<=support[1],'independentPerPacketPTSProvided':False,'attribution':'Stored native mix zeros only; surviving997Hz/noise can mask media loss.'};handles[group].write(json.dumps(row,separators=(',',':'))+'\n');counts[group]+=1
 finally:
  for h in handles:h.close()
 x=array.array('f');x.frombytes(raw)
 if sys.byteorder!='little':x.byteswap()
 model=joint.JointTones();reports=[]
 for ch in range(2):
  data=x[ch::2];path=a.out/('channel-'+str(ch)+'-short-windows.jsonl');stats=[]
  with path.open('x')as f:
   for phase in phases:
    lo,hi=phase['allOffsetsFrozenGuardedInteriorMs'];first=max(0,math.ceil(lo/1000*48000/joint.HOP)*joint.HOP);last=min(len(data)-joint.WINDOW,math.floor(hi/1000*48000)-joint.WINDOW);branch='baseline'if phase['phase'].startswith('baseline')else'product';ref=n['selectiveMediaDips'][branch][ch]['positiveMediaMedianPower'];pilot=n['alignment']['perChannelPositivePilotMedianPower'][ch];count=low=0
    for i in range(first,last+1,joint.HOP):
     if not(support[0]<=i and i+joint.WINDOW<=support[1]):raise ValueError('Diagnostic window outside qualified native source coverage')
     result=model.estimate(data,i);flags=joint.classify(result,ref,pilot);f.write(json.dumps({'channel':ch,'phase':phase['phase'],'mediaIntendedActive':phase['mediaIntendedActive'],'pilotIntendedActive':phase['pilotIntendedActive'],'startFrame':i,'endFrameExclusive':i+joint.WINDOW,'nativeSourceEnvelopeCovered':True,'independentPerPacketPTSProvided':False,'independentFrozenMediaAmplitudeSquaredReference':ref,**result,**flags},separators=(',',':'))+'\n');count+=1;low+=flags['jointLow440AndLowNonPilotEnergy']
    stats.append({'phase':phase['phase'],'windows':count,'jointLowWindows':low,'mediaIntendedActive':phase['mediaIntendedActive']})
  reports.append({'channel':ch,'file':path.name,'sha256':sha(path.read_bytes()),'phases':stats})
 result={'schema':'additive-native-pulse-short-diagnostics-v1','rawSHA256':sha(raw),'sourceSHA256':sha(sourcebytes),'componentSHA256':sha(cb),'numericSHA256':sha(nb),'nativeCoverageSHA256':sha(vb),'sourceAlignment':alignment,'phases':phases,'sampleRate':48000,'windowFrames':joint.WINDOW,'hopFrames':joint.HOP,'jointCoreSHA256':JOINT,'phaseZeroCoreSHA256':sha(a.zero.read_bytes()),'channels':reports,'exactZeroFiles':[{'file':p.name,'runs':counts[i],'sha256':sha(p.read_bytes())}for i,p in enumerate(paths)],'frozenGatesChanged':False,'independentPerPacketPTSProvided':False,'functionalPassClaimed':False,'noGapsClaimed':False,'limits':['Ordinal coverage is actual Pulse holes/index/final-callback proof, not SCK or per-packet PTS.','Exact-zero absence cannot exclude440-only gaps when997/noise survives.','Joint calibrated5.333ms/2.667ms windows are diagnostic supports, not exact gap/audibility/hardware duration.','All accepted nonce offsets/original guarded phases retained; internal loop edges are included.','Installed/native input/routing/cleanup provenance remains separately mandatory.']}
 (a.out/'ASSESSMENT.json').write_text(json.dumps(result,indent=2)+'\n');return result

def main():
 p=argparse.ArgumentParser()
 for name in ['raw','source','components','numeric','coverage','joint','zero','out']:p.add_argument('--'+name,type=pathlib.Path,required=True)
 audit(p.parse_args())
if __name__=='__main__':main()
