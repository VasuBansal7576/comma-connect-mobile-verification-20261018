"""Prospective owned-Android read-only CDP boundary. No automatic executable entrypoint.
Injected adapters must bound their own I/O and run only after the parent's owned-VM guard.
"""
import hashlib,json,re,time,http.client
from pathlib import Path
from urllib.parse import urlsplit
SERIAL='emulator-5554'
SOCKET='chrome_devtools_remote'
URL='https://comma-connect-fix-lab-20261016.zippy17.chatgpt.site/acced17acced1701/0000010a--a51155e496/1.001/3.999?candidate=v16&experiment=nqa'
DEVICE_URL='https://comma-connect-fix-lab-20261016.zippy17.chatgpt.site/acced17acced1701?candidate=v16&experiment=nqa'
def allowed_url(value,allow_closed_device):return value==URL or (allow_closed_device is True and value==DEVICE_URL)
ENTRY='/lab-v16/dist/assets/index-ojoFR-wi.js'
BADGE='V16 e7ab13f79d01'
MAX=32*1024*1024
class Refused(Exception):pass

def decode_json(data,limit=MAX):
    if not isinstance(data,bytes) or len(data)>limit:raise Refused('BOUNDED_BYTES_REQUIRED')
    def pairs(items):
        obj={}
        for k,v in items:
            if k in obj:raise Refused('DUPLICATE_JSON_MEMBER')
            obj[k]=v
        return obj
    try:return json.loads(data.decode('utf-8'),object_pairs_hook=pairs,parse_constant=lambda v:(_ for _ in ()).throw(Refused('NONFINITE_JSON')))
    except (ValueError,UnicodeError):raise Refused('JSON_INVALID')

def discover_socket(data):
    if not isinstance(data,bytes) or len(data)>1024*1024:raise Refused('BOUNDED_SOCKET_INVENTORY_REQUIRED')
    rows=data.decode('ascii').splitlines()
    if not rows or rows[0].split()!=['Num','RefCount','Protocol','Flags','Type','St','Inode','Path']:raise Refused('UNIX_SCHEMA_UNKNOWN')
    matches=[]
    for row in rows[1:]:
        cells=row.split()
        if len(cells)==8 and cells[-1]=='@'+SOCKET:
            if not re.fullmatch(r'[1-9]\d*',cells[6]) or cells[3]!='00010000' or cells[4]!='0001' or cells[5]!='01':raise Refused('CHROME_SOCKET_STATE_UNKNOWN')
            matches.append({'name':SOCKET,'inode':cells[6]})
    if len(matches)!=1:raise Refused('EXACT_CHROME_SOCKET_UNAVAILABLE_OR_AMBIGUOUS')
    return matches[0]

def parse_forwards(data):
    if not isinstance(data,bytes) or len(data)>65536:raise Refused('BOUNDED_FORWARD_LIST_REQUIRED')
    rows=[]
    for line in data.decode('ascii').replace('\r','\n').split('\n'):
        if not line.strip(' \t\r\n\v\f'):continue
        fields=line.split()
        if len(fields)!=3:raise Refused('FORWARD_LIST_SCHEMA_UNKNOWN')
        rows.append(tuple(fields))
    return rows

def verify_forward(data,port):
    expected=(SERIAL,'tcp:'+str(port),'localabstract:'+SOCKET)
    rows=parse_forwards(data)
    if rows.count(expected)!=1 or sum(row[1]==expected[1] for row in rows)!=1:raise Refused('OWN_FORWARD_IDENTITY_REQUIRED')
    return expected

def browser_and_target(version,targets,port,allow_closed_device=False):
    if not isinstance(version,dict) or not re.fullmatch(r'Chrome/124\.0\.6367\.219',version.get('Browser','')):raise Refused('EXACT_CHROME_VERSION_REQUIRED')
    if version.get('Android-Package')!='com.android.chrome':raise Refused('CHROME_PACKAGE_SCHEMA_NOT_CONFIRMED')
    if not isinstance(targets,list) or len(targets)>128:raise Refused('BOUNDED_TARGET_LIST_REQUIRED')
    matches=[t for t in targets if isinstance(t,dict) and t.get('type')=='page' and allowed_url(t.get('url'),allow_closed_device)]
    if len(matches)!=1:raise Refused('EXACT_OWNED_PAGE_REQUIRED')
    target=matches[0];identifier=target.get('id');endpoint=target.get('webSocketDebuggerUrl')
    if not isinstance(identifier,str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,128}',identifier) or not isinstance(endpoint,str):raise Refused('TARGET_IDENTITY_REQUIRED')
    u=urlsplit(endpoint)
    if u.scheme!='ws' or u.hostname not in ['127.0.0.1','localhost'] or u.port!=port or u.username or u.password or u.query or u.fragment or u.path!='/devtools/page/'+identifier:raise Refused('OWN_LOOPBACK_PAGE_ENDPOINT_REQUIRED')
    return target

def validate_observation(value,require_carrier=True,allow_closed_device=False):
    if not isinstance(value,list) or len(value)!=10:raise Refused('READONLY_DOM_SCHEMA_REQUIRED')
    href,origin,ua,nav,display,entry,badge,carrier,packed,frozen=value
    if not allowed_url(href,allow_closed_device) or type(origin) not in [int,float] or not 0<origin<1e15:raise Refused('SAME_OWNED_DOCUMENT_REQUIRED')
    if not isinstance(ua,str) or 'Android' not in ua or not re.search(r'Chrome/124\.\d+\.\d+\.\d+',ua):raise Refused('ACTUAL_ANDROID_CHROME_REQUIRED')
    if nav is not False or display is not False:raise Refused('ACTUAL_ANDROID_BROWSER_DISPLAY_REQUIRED')
    if entry!=ENTRY or badge!=BADGE:raise Refused('CURRENT_V15_ENTRY_BADGE_REQUIRED')
    if any(v is not None and not isinstance(v,str) for v in [carrier,packed,frozen]):raise Refused('ORIGINAL_TEXT_FIELDS_REQUIRED')
    if any(isinstance(v,str) and len(v.encode('utf-8'))>MAX for v in [carrier,packed,frozen]):raise Refused('DOM_TEXT_LIMIT')
    if require_carrier and (not carrier or not packed or not frozen):raise Refused('ORIGINAL_PACK_NOT_AVAILABLE')
    return {'href':href,'timeOrigin':origin,'standaloneNavigator':nav,'standaloneDisplay':display,'acquisitionMode':'browser','entry':entry,'badge':badge,'carrier':carrier,'packStatus':packed,'exportStatus':frozen}

def local_http_get(port,path):
    if type(port) is not int or not 1024<=port<=65535 or path not in ['/json/version','/json/list']:raise Refused('EXACT_LOOPBACK_HTTP_REQUEST_REQUIRED')
    connection=http.client.HTTPConnection('127.0.0.1',port,timeout=3)
    try:
        connection.request('GET',path,headers={'Host':'127.0.0.1:'+str(port)})
        response=connection.getresponse()
        if response.status!=200:raise Refused('LOCAL_CDP_HTTP_NOT_200')
        body=response.read(1024*1024+1)
        if len(body)>1024*1024:raise Refused('LOCAL_CDP_BODY_LIMIT')
        return body
    finally:connection.close()

def observe_owned_pwa(adb,http_get,evaluate,output,*,owned_vm_guard,require_carrier=True,allow_closed_device=False):
    """Adapters: adb(list)->bytes; http_get(port,path)->bytes; evaluate(endpoint)->bytes.
    evaluate MUST be the sealed fixed-expression read_dom.mjs, never arbitrary JS.
    Each adapter call <=5s except evaluate <=10s; no retries. Caller owns VM/serial guard.
    """
    if owned_vm_guard is not True:raise Refused('CALLER_OWNED_VM_GUARD_REQUIRED')
    if type(allow_closed_device) is not bool:raise Refused('EXPLICIT_CLOSED_DEVICE_SCOPE_REQUIRED')
    if type(require_carrier) is not bool:raise Refused('EXPLICIT_TRANSFER_MODE_REQUIRED')
    output=Path(output)
    if output.exists():raise Refused('FRESH_OUTPUT_REQUIRED')
    output.mkdir(parents=True,mode=0o700)
    started=time.monotonic();receipt={'status':'STARTING','PWAVerified':False,'audioMeasured':False,'inputCommands':0,'sourceWrites':0,'cleanupVerified':False};port=None;mapping=None;allocation_attempted=False
    def forward_list():
        data=adb(['forward','--list'])
        if isinstance(data,bytes) and len(data)<=65536:
            receipt.setdefault('forwardListReads',[]).append({'bytes':len(data),'asciiWhitespaceOnly':not data.strip(b' \t\r\n\v\f')})
        return data
    def bound():
        if time.monotonic()-started>=45:raise Refused('READONLY_BRIDGE_DEADLINE')
    try:
        devices=adb(['devices']).decode('ascii').splitlines()
        if [line.split() for line in devices[1:] if line.strip()]!=[[SERIAL,'device']]:raise Refused('EXACT_SINGLE_OWNED_SERIAL_REQUIRED')
        bound();socket=discover_socket(adb(['-s',SERIAL,'shell','cat','/proc/net/unix']));receipt['socket']=socket
        prior=parse_forwards(forward_list())
        if any(r[0]==SERIAL and r[2]=='localabstract:'+SOCKET for r in prior):raise Refused('PREEXISTING_SAME_SOCKET_FORWARD_REFUSED')
        bound();allocation_attempted=True;raw=adb(['-s',SERIAL,'forward','tcp:0','localabstract:'+SOCKET]).strip()
        if not re.fullmatch(rb'[1-9]\d{0,4}',raw) or not 1024<=int(raw)<=65535:raise Refused('ALLOCATED_FORWARD_PORT_REQUIRED')
        port=int(raw);mapping=verify_forward(forward_list(),port);receipt['forward']={'serial':SERIAL,'port':port,'remote':mapping[2]}
        bound();version=decode_json(http_get(port,'/json/version'),65536);targets=decode_json(http_get(port,'/json/list'),1024*1024)
        if isinstance(version,dict):receipt['chromeVersionObserved']={k:version[k] for k in ['Browser','Android-Package','Protocol-Version'] if isinstance(version.get(k),str) and len(version[k])<=128}
        if isinstance(targets,list):receipt['targetSummaryObserved']=[{'type':t.get('type'),'isExactOwnedURL':t.get('url')==URL} for t in targets[:128] if isinstance(t,dict)]
        target=browser_and_target(version,targets,port,allow_closed_device)
        receipt['targetId']=target['id'];bound();data=evaluate(target['webSocketDebuggerUrl']);bound();observation=validate_observation(decode_json(data),require_carrier,allow_closed_device)
        # Re-query identity after the read; no attach/activate/focus/navigation/input commands.
        again=browser_and_target(version,decode_json(http_get(port,'/json/list'),1024*1024),port,allow_closed_device)
        bound()
        if again['id']!=target['id']:raise Refused('DOCUMENT_TARGET_CHANGED')
        receipt.update(status='CURRENT_DOCUMENT_OBSERVATION_RETAINED_NO_CARRIER',observation={k:v for k,v in observation.items() if k!='carrier'})
        if require_carrier:
            raw=observation['carrier'].encode('utf-8');(output/'original-carrier.txt').write_bytes(raw)
            receipt.update(status='ORIGINAL_READONLY_CARRIER_RETAINED_NOT_VALIDATED',carrierBytes=len(raw),carrierSHA256=hashlib.sha256(raw).hexdigest())
    except Refused as error:receipt['status']='REFUSED';receipt['refusalCode']=str(error)
    except Exception as error:receipt['status']='REFUSED';receipt['errorClass']=type(error).__name__
    finally:
        if port is not None:
            try:
                verify_forward(forward_list(),port)
                adb(['-s',SERIAL,'forward','--remove','tcp:'+str(port)])
                receipt['cleanupVerified']=not any(r[1]=='tcp:'+str(port) for r in parse_forwards(forward_list()))
            except Exception:receipt['cleanupCode']='OWN_FORWARD_CLEANUP_UNVERIFIED'
        else:
            receipt['cleanupVerified']=not allocation_attempted
            if allocation_attempted:receipt['cleanupCode']='ALLOCATED_PORT_UNKNOWN_NO_BROAD_REMOVE'
        receipt['elapsedSeconds']=time.monotonic()-started
        (output/'receipt.json').write_text(json.dumps(receipt,indent=2)+'\n')
    return receipt
