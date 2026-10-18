"""Test-only host loopback state machine. No product/remote service endpoint.
Only native XCTest→owned127.0.0.1 ready/ack/done receipts; no original page commands.
"""
import json,re,secrets,threading,time
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
SOURCE='27fd46cd8ecb653e2d6e4cc78c49b67ff9852adfac10a72d08d98ff253436e5d';ENTRY='aca842c376c4711adbfef638afca7142639645015f839f03051c01b37a60e30a'
class RunState:
    def __init__(self,run_id,attempt,udid,clock=time.monotonic):
        self.clock=clock;self.identity={'schema':'owned-ci-v15-loopback-v1','runId':str(run_id),'runAttempt':str(attempt),'expectedUDID':udid,'serverNonce':secrets.token_hex(16),'sourceSHA256':SOURCE,'entrySHA256':ENTRY};self.stage='WAIT_READY';self.client=None;self.events=[];self.errors=[];self.lock=threading.Lock();self.ready=threading.Event();self.done=threading.Event();self.ackAt=None;self.count=0;self.closed=False
    def _event(self,kind,detail):self.events.append({'sequence':len(self.events),'hostMonotonic':self.clock(),'kind':kind,**detail})
    def handle(self,method,path,body=None):
        with self.lock:
            if self.closed:raise ValueError('Owned observer closed; late request refused')
            self.count+=1
            if self.count>256:raise ValueError('Bounded loopback request count exceeded')
            if method=='GET'and path=='/session':return {**self.identity,'stage':self.stage}
            if method!='POST'or path not in ['/ready','/ack','/done','/abort']or not isinstance(body,dict):raise ValueError('Unknown own handshake operation')
            if any(body.get(k)!=v for k,v in self.identity.items()):raise ValueError('Own run/nonce/device/build binding refused')
            client=body.get('clientNonce');assert isinstance(client,str)and re.fullmatch('[0-9a-f]{32}',client)
            if self.client is not None and self.client!=client:raise ValueError('Native client changed')
            if path=='/ready':
                if self.stage!='WAIT_READY':raise ValueError('One READY only')
                if not body.get('preparedAX','').startswith('READY: native playing and unmuted.')or 'playlist=PINNED assets=6'not in body.get('pinAX',''):raise ValueError('Actual native prepared/pin receipts required')
                actual=body.get('nativeEnvironmentUDID')
                if actual is not None and actual!=self.identity['expectedUDID']:raise ValueError('Actual native simulator environment differs')
                self.client=client;self.stage='READY';self._event('native-ready',{'receipt':body});self.ready.set()
            elif path=='/ack':
                if self.stage not in ['READY','ACK']:raise ValueError('ACK poll outside prepared acquisition')
            elif path=='/done':
                if self.stage!='ACK'or self.clock()-self.ackAt>130:raise ValueError('DONE outside bounded active protocol')
                n=body.get('carrierBytes');digest=body.get('carrierSHA256')
                if type(n)is not int or not 0<n<=16*1024*1024 or not isinstance(digest,str)or not re.fullmatch('[0-9a-f]{64}',digest):raise ValueError('Actual native carrier receipt required')
                if not body.get('packedAX','').startswith(f'Packed {n} UTF-8 carrier bytes; SHA-256 {digest};'):raise ValueError('Native packed status/hash mismatch')
                if 'source=stopped'not in body.get('cleanupAX','')or 'cleanup=true'not in body['cleanupAX']:raise ValueError('Actual source cleanup receipt required')
                self.stage='DONE';self._event('native-done',{'receipt':body});self.done.set()
            else:
                self.stage='FAILED';self.errors.append({'error':'native-abort','message':str(body.get('message',''))[:1024]});self._event('native-abort',{'message':str(body.get('message',''))[:1024]})
            return {**self.identity,'stage':self.stage,'captureStarted':self.stage in ['ACK','DONE'],'captureAckHostMonotonic':self.ackAt}
    def acknowledge_capture(self):
        with self.lock:
            if self.closed or self.stage!='READY':raise ValueError('Cannot ACK without actual native READY')
            self.stage='ACK';self.ackAt=self.clock();self._event('host-capture-ack',{'evidence':'Owned collector emitted CAPTURE_STARTED'})
    def snapshot(self):
        with self.lock:return {**self.identity,'stage':self.stage,'clientNonce':self.client,'events':self.events.copy(),'errors':self.errors.copy(),'requests':self.count}

def serve(state):
    class Handler(BaseHTTPRequestHandler):
        protocol_version='HTTP/1.1'
        def setup(self):super().setup();self.connection.settimeout(3)
        def log_message(self,*_):pass
        def operation(self):
            try:
                if self.client_address[0]!='127.0.0.1':raise ValueError('Loopback only')
                length=int(self.headers.get('Content-Length','0'))
                if not 0<=length<=8192:raise ValueError('Body cap')
                raw=self.rfile.read(length);body=json.loads(raw)if length else None
                if length and len(raw)!=length:raise ValueError('Truncated body')
                result=state.handle(self.command,self.path,body);code=200
            except Exception as error:result={'error':type(error).__name__,'message':str(error)};code=409
            data=json.dumps(result,separators=(',',':')).encode();self.send_response(code);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(data)));self.send_header('Connection','close');self.end_headers();self.wfile.write(data);self.close_connection=True
        do_GET=operation;do_POST=operation
    server=ThreadingHTTPServer(('127.0.0.1',5831),Handler);server.daemon_threads=True
    thread=threading.Thread(target=lambda:server.serve_forever(poll_interval=.05),daemon=True);thread.start();return server,thread
