#!/usr/bin/env python3
"""Independent stdlib reader: float32 PCM and callback continuity, no playback."""
import argparse, array, hashlib, json, math, pathlib, sys

def analyze(raw_path, receipt_path):
    raw = pathlib.Path(raw_path).read_bytes()
    receipt = json.loads(pathlib.Path(receipt_path).read_text())
    if receipt.get('sampleFormat') != 'float32-le-interleaved':
        raise ValueError('Unsupported sample format')
    rate, channels = receipt['sampleRate'], receipt['channels']
    if rate != 48000 or channels != 2 or len(raw) != receipt['frames'] * channels * 4:
        raise ValueError('PCM byte count/rate/channel mismatch')
    pcm = array.array('f'); pcm.frombytes(raw)
    if sys.byteorder != 'little': pcm.byteswap()
    if not all(math.isfinite(value) for value in pcm): raise ValueError('Nonfinite PCM')
    windows = []
    for start in range(0, receipt['frames'] - rate + 1, rate):
        row = {'startFrame': start, 'endFrameExclusive': start + rate, 'channels': []}
        for channel in range(channels):
            values = pcm[start * channels + channel:(start + rate) * channels:channels]
            rms = math.sqrt(sum(v*v for v in values) / rate)
            # Coherent 440 Hz projection on 1 s, retained per channel.
            real = sum(v*math.cos(2*math.pi*440*i/rate) for i,v in enumerate(values))
            imag = sum(v*math.sin(2*math.pi*440*i/rate) for i,v in enumerate(values))
            tone_power = 2*(real*real+imag*imag)/(rate*rate)
            row['channels'].append({'rms':rms,'peak':max(map(abs,values)),
                                    'powerFraction440Hz':tone_power/(rms*rms) if rms else 0})
        row['tonePositive'] = all(c['rms'] > .005 and c['powerFraction440Hz'] > .5 for c in row['channels'])
        row['digitalZero'] = all(c['peak'] < 1e-6 for c in row['channels'])
        windows.append(row)
    discontinuities=[]
    callbacks=receipt['callbacks']; cursor=0
    for index, row in enumerate(callbacks):
        if row['sequence'] != index or row['frameOffset'] != cursor or row['frames'] <= 0:
            raise ValueError('Callback coverage mismatch')
        if index:
            previous=callbacks[index-1]
            gap=row['presentationTimeSeconds']-previous['presentationTimeSeconds']-previous['frames']/rate
            if abs(gap) > 2/rate:
                discontinuities.append({'beforeSequence':index,'ptsGapSeconds':gap})
        cursor+=row['frames']
    if cursor != receipt['frames']: raise ValueError('Final callback coverage mismatch')
    positives=[i for i,r in enumerate(windows) if r['tonePositive']]
    zero_between=any(windows[i]['digitalZero'] and any(p<i for p in positives) and any(p>i for p in positives) for i in range(len(windows)))
    passed = bool(positives and zero_between and not discontinuities and not receipt['errors'])
    return {'schema':'ci-pcm-assessment-v1','rawSHA256':hashlib.sha256(raw).hexdigest(),
            'receiptSHA256':hashlib.sha256(pathlib.Path(receipt_path).read_bytes()).hexdigest(),
            'frames':cursor,'windows':windows,'callbackDiscontinuities':discontinuities,
            'nativeToneZeroToneCalibrationPassed':passed,
            'normalProductOutputCertified':False,'physicalHardwareEquivalent':False}

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('raw');parser.add_argument('receipt');parser.add_argument('output')
    args=parser.parse_args();result=analyze(args.raw,args.receipt)
    pathlib.Path(args.output).write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({k:result[k] for k in ['frames','nativeToneZeroToneCalibrationPassed','callbackDiscontinuities']}))
    sys.exit(0 if result['nativeToneZeroToneCalibrationPassed'] else 2)
