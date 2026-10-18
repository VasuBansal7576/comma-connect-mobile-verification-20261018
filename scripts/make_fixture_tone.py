#!/usr/bin/env python3
# Generates bytes only. Does not render audio.
import array, math, pathlib, sys, wave
path=pathlib.Path(sys.argv[1]);rate=48000
samples=array.array('h',(int(.2*32767*math.sin(2*math.pi*440*i/rate)) for i in range(rate*2) for _ in range(2)))
if sys.byteorder!='little':samples.byteswap()
with wave.open(str(path),'wb') as f:
    f.setnchannels(2);f.setsampwidth(2);f.setframerate(rate);f.writeframes(samples.tobytes())
