// Fixed installed-target identity observation only (8 fields; no carrier read). No caller-supplied expression, DOM writes or events.
// throwOnSideEffect is omitted: V8 conservatively rejects known DOM/media-query reads.
export const EXPRESSION = `[location.href,performance.timeOrigin,navigator.userAgent,navigator.standalone===true,matchMedia('(display-mode: standalone)').matches,document.querySelector('script[type="module"][src^="/lab-v16/dist/assets/index-"]')?.getAttribute('src')??null,document.getElementById('v16-build-badge')?.textContent??null,document.visibilityState]`;
export function command() {
  return {id:1,method:'Runtime.evaluate',params:{expression:EXPRESSION,returnByValue:true,silent:true,timeout:3000}};
}
export function endpoint(raw) {
  const u=new URL(raw);
  if(u.protocol!=='ws:'||!['127.0.0.1','localhost'].includes(u.hostname)||!/^\d+$/.test(u.port)||+u.port<1024||+u.port>65535||u.username||u.password||u.search||u.hash||!/^\/devtools\/page\/[A-Za-z0-9_-]{1,128}$/.test(u.pathname))throw Error('OWN_LOOPBACK_PAGE_ENDPOINT_REQUIRED');
  return u.href;
}
const CODES=new Set(['OWN_LOOPBACK_PAGE_ENDPOINT_REQUIRED','EXISTING_NODE_WEBSOCKET_REQUIRED','READONLY_CDP_TIMEOUT','CDP_CONNECT_REFUSED','CDP_CONNECTION_ERROR','CDP_CLOSED_BEFORE_RESULT','CDP_MESSAGE_LIMIT','READONLY_CDP_JSON_INVALID','READONLY_CDP_UNEXPECTED_ID','READONLY_CDP_PROTOCOL_REFUSED','READONLY_DEBUG_SIDE_EFFECT_REFUSAL','READONLY_EVALUATION_EXCEPTION','READONLY_DOM_SCHEMA_REFUSED','ONE_OBSERVED_ENDPOINT_REQUIRED']);
function refused(code,details={}){const e=new Error(code);e.readonlyCode=code;e.readonlyDiagnostic=details;return e;}
export function diagnostic(error){
 const code=CODES.has(error?.readonlyCode)?error.readonlyCode:CODES.has(error?.message)?error.message:'READONLY_INTERNAL_FAILURE';
 const d=error?.readonlyDiagnostic??{},out={schema:'fixed-readonly-cdp-diagnostic-v1',code};
 if(/^\d+\.\d+\.\d+$/.test(process.versions.node))out.nodeVersion=process.versions.node;
 if(['METHOD_NOT_FOUND','INVALID_PARAMS','SERVER_REFUSED','OTHER'].includes(d.protocolClass))out.protocolClass=d.protocolClass;
 if(['EvalError','TypeError','ReferenceError','SyntaxError','Error','RangeError','DOMException','OTHER'].includes(d.exceptionClass))out.exceptionClass=d.exceptionClass;
 if(Number.isInteger(d.expectedFields)&&d.expectedFields>=0&&d.expectedFields<=64)out.expectedFields=d.expectedFields;
 if(d.actualFields===null||Number.isInteger(d.actualFields)&&d.actualFields>=0&&d.actualFields<=1000000)out.actualFields=d.actualFields;
 return out; // No protocol messages/descriptions, target text/URLs, stack or environment.
}
export function result(message) {
  if(message?.id!==1)throw refused('READONLY_CDP_UNEXPECTED_ID');
  if(message.error){const n=message.error.code;throw refused('READONLY_CDP_PROTOCOL_REFUSED',{protocolClass:n===-32601?'METHOD_NOT_FOUND':n===-32602?'INVALID_PARAMS':n===-32000?'SERVER_REFUSED':'OTHER'});}
  if(message.result?.exceptionDetails){const e=message.result.exceptionDetails.exception;const klass=['EvalError','TypeError','ReferenceError','SyntaxError','Error','RangeError','DOMException'].includes(e?.className)?e.className:'OTHER';const side=klass==='EvalError'&&/^EvalError: Possible side-effect in debug-evaluate(?:\n|$)/.test(typeof e?.description==='string'?e.description:'');throw refused(side?'READONLY_DEBUG_SIDE_EFFECT_REFUSAL':'READONLY_EVALUATION_EXCEPTION',{exceptionClass:klass});}
  const value=message.result?.result?.value;
  if(!Array.isArray(value)||value.length!==8)throw refused('READONLY_DOM_SCHEMA_REFUSED',{expectedFields:8,actualFields:Array.isArray(value)?value.length:null});
  return value;
}
export async function read(raw) {
  if(typeof WebSocket!=='function')throw Error('EXISTING_NODE_WEBSOCKET_REQUIRED');
  return await new Promise((resolve,reject)=>{
    let ws,settled=false,count=0;
    const timer=setTimeout(()=>finish(Error('READONLY_CDP_TIMEOUT')),10000);
    function finish(error,value){if(settled)return;settled=true;clearTimeout(timer);ws?.close();error?reject(error):resolve(value);}
    try{ws=new WebSocket(endpoint(raw));}catch{finish(Error('CDP_CONNECT_REFUSED'));return;}
    ws.addEventListener('open',()=>ws.send(JSON.stringify(command())));
    ws.addEventListener('error',()=>finish(Error('CDP_CONNECTION_ERROR')));
    ws.addEventListener('close',()=>finish(Error('CDP_CLOSED_BEFORE_RESULT')));
    ws.addEventListener('message',event=>{
      try{
        if(typeof event.data!=='string'||Buffer.byteLength(event.data)>64*1024*1024||++count>32)throw Error('CDP_MESSAGE_LIMIT');
        const message=JSON.parse(event.data);
        if(message.id===1)finish(null,result(message));
      }catch(error){finish(error?.readonlyCode?error:refused('READONLY_CDP_JSON_INVALID'));}
    });
  });
}
if(process.argv[1]&&import.meta.url===new URL('file:'+process.argv[1]).href){
  try{if(process.argv.length!==3)throw Error('ONE_OBSERVED_ENDPOINT_REQUIRED');const value=await read(process.argv[2]);process.stdout.write(JSON.stringify(value));}
  catch(error){process.stderr.write(JSON.stringify(diagnostic(error))+'\n');process.exitCode=2;}
}
