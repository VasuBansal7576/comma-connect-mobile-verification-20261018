#!/usr/bin/env python3
"""Offline numeric/native provenance adapter. Original Frozen remains byte-identical.
This emits component facts, never an installed-PWA acquisition verdict by itself.
"""
import argparse,copy,hashlib,importlib.util,json,math,pathlib,shutil,tempfile
P=pathlib.Path(__file__).resolve().parent
PINS={'source':'24debd4d28470b53f97d41bc46fdc44b060ae0c1bb16f33c331aa5896b5ba07b','entry':'e7ab13f79d01a5784c7879f9a02a2f9b8a0078e3281dbb6cfda01d36a0467641','assessor':'e64a563f3c8ac61045eb8dbd17c25cf5b16714c1324f90f71e2c2b599f6aa923','scalar':'1adaa533a0ff7c709e15c967d39c8d6bd5bdcfbb2dcc8d3d9946b3e7c0061636','nativeValidator':'5b2732b81c187de3976f3dabfbac1f3115c5f272c4ae039e40cc056523da2c5a','assets':'4434abf8f06598c318f074bcfa22ee43139ebd207dec203c7290144a3d400ad3'}
def sha(b):return hashlib.sha256(b).hexdigest()
def require(v,message):
 if not v:raise ValueError(message)
def load_module(path,name,pin):
 require(sha(path.read_bytes())==pin,'Exact reviewed helper pin required: '+name);spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m

def source_envelope(source,numeric,frames):
 obs=source['osAudioObservation'];a=numeric.get('alignment')or{};offs=a.get('allCandidateOffsetsMs')or[]
 require(a.get('qualified')is True and offs and max(offs)-min(offs)<=150 and all(type(x)in[int,float]and math.isfinite(x)for x in offs),'Qualified original all-offset nonce alignment required')
 stops=[e for e in obs['events']if e['kind']=='pilot-stop-command'and e.get('reason')=='baseline-timed-pilot-stop'];ends=[e for e in obs['events']if e['kind']=='source-stop'];require(len(stops)==len(ends)==1,'Unique actual source stop events required')
 stop,end=stops[0],ends[0];ctx=(stop.get('snapshot')or{}).get('pilot',{}).get('contextTime')
 if type(ctx)not in[int,float]or not math.isfinite(ctx):
  running=[r for r in obs['rows']if r.get('pilot',{}).get('contextState')=='running'and type(r.get('pilot',{}).get('contextTime'))in[int,float]]
  require(bool(running),'Actual running source clock required');near=min(running,key=lambda r:abs(r['atMs']-stop['atMs']));require(abs(near['atMs']-stop['atMs'])<=100,'Frozen100ms source-clock bound');ctx=near['pilot']['contextTime']
 half=4096/48000*500
 lo=obs['pilotNonce']['originTime']*1000+min(offs)-half
 hi=ctx*1000+(end['atMs']-stop['atMs'])+max(offs)+half
 support=[math.floor(lo*48),math.ceil(hi*48)]
 require(0<=support[0]<support[1]<=frames,'Full all-offset source envelope must fit actual raw file; no clipping')
 return support,{'fileBoundsMs':[lo,hi],'allAcceptedOffsetsMs':offs,'scope':'Entire source nonce through actual source-stop, extended by original4096-sample half-window; includes intentional controls/idle/loop edges.','newClockFitPerformed':False}

def assess(a):
 a.out.mkdir(exist_ok=False);source_bytes=a.source.read_bytes();source=json.loads(source_bytes);integrity=json.loads(a.integrity.read_bytes());raw=a.raw.read_bytes();sb=a.summary.read_bytes();summary=json.loads(sb);jb=a.journal.read_bytes();journal=[json.loads(x)for x in jb.splitlines()];scalars=json.loads(a.scalars.read_bytes())
 require(integrity.get('pass')is True and integrity.get('platform')=='Android'and integrity['originalSHA256']==sha(source_bytes)and integrity['originalBytes']==len(source_bytes),'Original Android carrier integrity required')
 obs=source['osAudioObservation'];require(obs['analysis']is None and obs['rows']and all(r.get('standaloneNavigator')is False and r.get('standaloneDisplay')is True for r in obs['rows']),'Actual Android standalone rows, no substituted Photos analysis')
 require(summary.get('requestedCaptureSeconds')==150 and summary.get('sampleRate')==48000 and summary.get('channels')==2 and summary.get('finalTimingRefreshComplete')is True and summary.get('sampleWritesFrozenBeforeFinalTimingQuery')is True,'Native150s final-query receipt required')
 require(scalars['schema']=='native-pulse-system-output-scalars-v1'and scalars['rawSHA256']==sha(raw)and scalars['receiptSHA256']==sha(sb)and scalars['coreSHA256']==PINS['scalar']and scalars.get('independentPerPacketPTSProvided')is False,'Exact raw/native/scalar hash linkage required')
 require(scalars['analysis']['decoded']['frames']*8==len(raw),'All decoded scalar frames retained')
 native=load_module(a.native_validator,'native_pulse_validator',PINS['nativeValidator']);base=native.validate(raw,summary,journal)
 require(base['nativeCaptureChecksPass']and base['matchedTimingRefreshAudit']['finalPairConfirmed'],'Actual complete native delivery/final callback required')
 require(sha(a.assets.read_bytes())==PINS['assets'],'Exact known source asset manifest required')
 derived=copy.deepcopy(source);derived['osAudioObservation']['analysis']=scalars['analysis'];db=json.dumps(derived,separators=(',',':')).encode();(a.out/'DERIVED-NUMERIC-VIEW.json').write_bytes(db)
 require(sha(a.frozen_assessor.read_bytes())==PINS['assessor'],'Frozen numeric assessor pin required')
 with tempfile.TemporaryDirectory(prefix='android-pulse-numeric-')as t:
  t=pathlib.Path(t);shutil.copyfile(a.frozen_assessor,t/'assess.py');(t/'nf-source-input').mkdir();shutil.copyfile(a.assets,t/'nf-source-input/ACQUISITION.json');f=load_module(t/'assess.py','frozen_android_numeric',PINS['assessor']);numeric=f.assess(derived,sha(db),sha(db),witnesses={},calibration=False)
 replaced={'local analysis cleanup','original selected file metadata/hash','independent OS/Photos UI witnesses'};require(replaced.issubset({c['name']for c in numeric['checks']}),'Exact known provenance replacements required')
 kept=[c for c in numeric['checks']if c['name']not in replaced];numeric_ok=bool(kept)and all(c['pass']for c in kept)and(numeric.get('alignment')or{}).get('qualified')is True
 envelope=None;coverage=None;error=None
 try:
  envelope,details=source_envelope(source,numeric,summary['frames']);coverage=native.validate(raw,summary,journal,[envelope])
 except Exception as e:error={'name':type(e).__name__,'message':str(e)};details=None
 (a.out/'FROZEN-NUMERIC-REPORT.json').write_text(json.dumps(numeric,indent=2)+'\n')
 if coverage:(a.out/'NATIVE-SOURCE-COVERAGE.json').write_text(json.dumps(coverage,indent=2)+'\n')
 out={'schema':'android-native-pulse-source-numeric-components-v1','numericChecksPass':numeric_ok,'nativeWholeSourceEnvelopePass':bool(coverage and coverage['nativeCaptureChecksPass']and coverage['allRequestedSupportsHaveValidRawTiming']),'numericChecks':kept,'sourceEnvelopeFrames':envelope,'sourceEnvelope':details,'sourceSHA256':sha(source_bytes),'rawPCMSHA256':sha(raw),'nativeSummarySHA256':sha(sb),'nativeJournalSHA256':sha(jb),'scalarSHA256':sha(a.scalars.read_bytes()),'frozenNumericReportSHA256':sha((a.out/'FROZEN-NUMERIC-REPORT.json').read_bytes()),'nativeSourceCoverageSHA256':sha((a.out/'NATIVE-SOURCE-COVERAGE.json').read_bytes())if coverage else None,'derivedViewSHA256':sha(db),'originalSourceModified':False,'replacedFilePhotosProvenanceChecks':sorted(replaced),'nativeValidatorSHA256':PINS['nativeValidator'],'independentPerPacketPTSProvided':False,'PWAVerified':False,'functionalPassClaimed':False,'remainingRequiredEvidence':['Original trusted native installation/Home launch/current standalone proof and byte pins.','Original emulator/daemon PID-startTicks, private socket and all output/monitor graph proofs across acquisition.','Actual top-level trusted Pin/Prepare/Start/baseline/Export/Freeze/Pack native UI trace; capture ACK precedes pilot.','Owned collector/boot daemon/emulator cleanup and original carrier transfer hashes.','Additive exact-zero and calibrated high-resolution media/pilot audit inside this verified source envelope.'],'scope':'Components only; no Photos/phone file selection, SCK timestamp or physical-speaker claim.'}
 if error:out['coverageError']=error
 (a.out/'ASSESSMENT.json').write_text(json.dumps(out,indent=2)+'\n');return out

def main():
 p=argparse.ArgumentParser()
 for n in ['source','integrity','raw','summary','journal','scalars','native-validator','frozen-assessor','assets','out']:p.add_argument('--'+n,type=pathlib.Path,required=True)
 a=p.parse_args();r=assess(a);print(json.dumps({k:r[k]for k in ['numericChecksPass','nativeWholeSourceEnvelopePass','functionalPassClaimed']}));raise SystemExit(0 if r['numericChecksPass']and r['nativeWholeSourceEnvelopePass']else 2)
if __name__=='__main__':main()
