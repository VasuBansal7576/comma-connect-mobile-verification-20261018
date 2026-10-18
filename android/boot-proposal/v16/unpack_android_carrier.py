#!/usr/bin/env python3
"""Offline Android AX/read-only DOM carrier → original Frozen. Never alter/fill original fields."""
import argparse,base64,gzip,hashlib,json,pathlib,re
SOURCE='24debd4d28470b53f97d41bc46fdc44b060ae0c1bb16f33c331aa5896b5ba07b';ENTRY='e7ab13f79d01a5784c7879f9a02a2f9b8a0078e3281dbb6cfda01d36a0467641'
def sha(b):return hashlib.sha256(b).hexdigest()
def unpack(raw,status):
    if not __debug__:raise ValueError('Integrity verification requires assertion checks enabled')
    if len(raw)>16*1024*1024:raise ValueError('Carrier bound')
    prefix=f'Packed {len(raw)} UTF-8 carrier bytes; SHA-256 {sha(raw)};'
    if not status.startswith(prefix):raise ValueError('Native AX size/hash truncated or mismatch')
    packet=json.loads(raw);assert packet['format']=='v13-gzip-export-carrier-v1'and packet['encoding']=='gzip+base64'
    assert all(packet['packing'][k]is True for k in ['trustedClick','roundTripVerified','originalCachedPayloadPreserved'])
    z=base64.b64decode(packet['compressed']['base64'],validate=True);assert len(z)==packet['compressed']['gzipBytes']and sha(z)==packet['compressed']['gzipSHA256']
    # Bounded decompression prevents a corrupt input allocating arbitrarily large memory.
    import zlib
    dec=zlib.decompressobj(31);original=dec.decompress(z,64*1024*1024+1)
    assert dec.eof and not dec.unused_data and not dec.unconsumed_tail and len(original)<=64*1024*1024
    assert len(original)==packet['original']['utf8Bytes']and sha(original)==packet['original']['sha256']
    payload=json.loads(original);assert payload['format']=='connect-candidate-observer-export-v1'
    assert payload['retention']['completeSinceObserverStart']is True and len(payload['retainedRecords'])==payload['retention']['retainedRecordCount']==payload['retention']['sourceHistoryCount']
    assert payload['candidate']['candidateEntrySHA256']==ENTRY and payload['candidate']['candidateSourceTreeSHA256']==SOURCE
    src=payload['osAudioObservation'];assert src['pin']=={'source':SOURCE,'entry':ENTRY}
    assert src['sourceEnded']is True and src['completeRetention']is True and len(src['rows'])==src['totalRows']==src['retainedRows']and len(src['events'])==src['totalEvents']==src['retainedEvents']
    assert src['rows']and all(r['standaloneNavigator']is False and r['standaloneDisplay']is True for r in src['rows'])
    assert all(r['proof']['entrySHA256']==ENTRY and r['proof']['candidateSourceTreeSHA256']==SOURCE for r in src['rows'])
    assert src['analysis']is None # Native Pulse PCM analysed separately; no fabricated Photos/input provenance.
    assert all(src['cleanup'][k]is True for k in ['contextClosed','baselineRemoved','timerCleared','deadlineCleared'])
    assert not any(e['kind']in ['command-error','scheduled-input-refused']for e in src['events'])
    quick=payload['quickAcquisition'];assert quick['started']is True and quick['phase']=='running'and quick['originalHandlersRetained']is True
    controls=[r for r in quick['records']if r['kind']=='actual-result-control-tap'];assert all(any(r['label']==label and r['trusted']is True for r in controls)for label in ['Export all','Freeze'])
    return original,{'pass':True,'carrierBytes':len(raw),'carrierSHA256':sha(raw),'originalBytes':len(original),'originalSHA256':sha(original),'sourceRows':len(src['rows']),'sourceEvents':len(src['events']),'standaloneRowsAllActual':True,'platform':'Android','navigatorStandaloneExpected':False,'actualDisplayModeStandaloneExpected':True,'analysisSeparateFromSource':True,'phoneHardwareCertified':False}
def main():
    a=argparse.ArgumentParser();a.add_argument('carrier',type=pathlib.Path);a.add_argument('status',type=pathlib.Path);a.add_argument('output',type=pathlib.Path);o=a.parse_args();o.output.mkdir(exist_ok=False)
    original,report=unpack(o.carrier.read_bytes(),o.status.read_text());(o.output/'source-frozen.json').write_bytes(original);(o.output/'integrity.json').write_text(json.dumps(report,indent=2)+'\n')
if __name__=='__main__':main()
