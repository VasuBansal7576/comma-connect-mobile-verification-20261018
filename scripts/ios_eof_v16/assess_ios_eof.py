"""Strict offline iOS EOF acceptance; no native acquisition or runtime actions."""
from pathlib import Path
import argparse,hashlib,json
import eof_contract as contract
import frame_acceptance_ios as frames

def read(path,limit):
    raw=path.read_bytes()
    frames.need(0<len(raw)<=limit,'BOUNDED_INPUT_REQUIRED')
    return raw
def parsed(raw):
    return json.loads(raw,parse_constant=lambda _:(_ for _ in()).throw(ValueError('NONFINITE_JSON_REFUSED')))
def sha(raw):return hashlib.sha256(raw).hexdigest()
def assess_payload(payload,report):
    base=contract.eof(report)
    first=report['freezes'][0]['native']
    frames.need(first['paused']is False and first['muted']is True and first['readyState']>=2 and first['error']is None,'HEALTHY_MUTED_INITIAL_EOF_REQUIRED')
    extra=frames.eof_frames(payload,report)
    return {'status':'BOUNDED_IOS_EOF_EVENTS_AND_FULL_FRAME_PROGRESS_QUALIFIED','eventContract':base,'frameAssessment':extra,'frameAcceptancePending':False,'wholeBugFixed':False,'audioMeasured':False}
def assess(path):
    manifest=parsed(read(path,1024*1024));parent=path.resolve().parent
    report_raw=read(parent/manifest['report'],32*1024*1024);report=parsed(report_raw)
    carrier=read(parent/manifest['carrier'],16*1024*1024)
    frozen=read(parent/manifest['frozenStatus'],65536).decode().strip()
    packed=read(parent/manifest['packedStatus'],65536).decode().strip()
    data,payload=contract.unpack(carrier,packed,frozen,report['freezes'][-1]['timeOrigin'])
    result=assess_payload(payload,report)
    result['actualInputHashes']={'reportSHA256':sha(report_raw),'carrierSHA256':sha(carrier),'originalSHA256':sha(data),'originalBytes':len(data),'carrierBytes':len(carrier)}
    result['scope']='Only supplied original native carrier/report. Model fixtures do not establish a runtime result.'
    return result
def main():
    p=argparse.ArgumentParser();p.add_argument('--input',required=True,type=Path);p.add_argument('--output',required=True,type=Path);args=p.parse_args()
    try:result=assess(args.input);code=0
    except (ValueError,KeyError,TypeError,IndexError,OSError)as error:
        result={'status':'NOT_QUALIFIED_OR_INCOMPLETE','errorClass':type(error).__name__,'reason':str(error),'frameAcceptancePending':True,'wholeBugFixed':False,'audioMeasured':False};code=2
    args.output.write_text(json.dumps(result,indent=2,allow_nan=False)+'\n');return code
if __name__=='__main__':raise SystemExit(main())
