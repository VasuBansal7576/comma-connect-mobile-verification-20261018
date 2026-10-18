#!/usr/bin/env python3
"""Strict finite/ordinal/PTS gate, offline and source-free. No PCM synthesis/playback."""
import argparse,hashlib,json,math,pathlib

def finite(x):return type(x)in(int,float)and math.isfinite(x)
def integer(x):return type(x)is int

def validate_capture(raw_bytes,r):
    assert r['captureAPI']=='ScreenCaptureKit.SCStream.audio'and r['capturesMicrophone']is False
    assert r['sampleRate']==48000 and r['channels']==2 and r['sampleFormat']=='float32-le-interleaved'
    assert integer(r['frames'])and 0<r['frames']<=155*48000 and r['frames']*8==raw_bytes<=64*1024*1024
    assert r['requestedDurationSeconds']==150 and r['streamStopCompleted']is True and r['pcmHandleClosed']is True and r['errors']==[]
    begin,end=r['hostStartUptimeSeconds'],r['hostStopUptimeSeconds'];assert finite(begin)and finite(end)and 0<=begin<=end
    callbacks=r['callbacks'];assert isinstance(callbacks,list)and callbacks
    cursor=0;prior=None;maximumResidual=0
    for i,q in enumerate(callbacks):
        assert integer(q['sequence'])and q['sequence']==i and integer(q['frameOffset'])and q['frameOffset']==cursor
        assert integer(q['frames'])and q['frames']>0 and cursor+q['frames']<=r['frames']
        pts,host=q['presentationTimeSeconds'],q['hostUptimeSeconds'];assert finite(pts)and finite(host)and begin<=host<=end
        if prior:
            assert pts>=prior['presentationTimeSeconds']and host>=prior['hostUptimeSeconds']
            residual=pts-prior['presentationTimeSeconds']-prior['frames']/48000;maximumResidual=max(maximumResidual,abs(residual));assert abs(residual)<=2/48000
        cursor+=q['frames'];prior=q
    assert cursor==r['frames']
    return {'pass':True,'frames':cursor,'callbacks':len(callbacks),'finiteNondecreasingPTSAndHostUptime':True,'maximumPTSResidualSeconds':maximumResidual,'toleranceSeconds':2/48000,'syntheticPaddingApplied':False}

def main():
    p=argparse.ArgumentParser();p.add_argument('raw',type=pathlib.Path);p.add_argument('receipt',type=pathlib.Path);p.add_argument('out',type=pathlib.Path);a=p.parse_args();r=json.loads(a.receipt.read_text());o=validate_capture(a.raw.stat().st_size,r);o.update(rawSHA256=hashlib.sha256(a.raw.read_bytes()).hexdigest(),receiptSHA256=hashlib.sha256(a.receipt.read_bytes()).hexdigest());a.out.write_text(json.dumps(o,indent=2)+'\n')
if __name__=='__main__':main()
