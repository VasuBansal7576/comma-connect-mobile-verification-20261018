// Prospective observer: this is the entire permitted Runtime.evaluate expression.
export const EXPRESSION = `[location.href,performance.timeOrigin,navigator.userAgent,navigator.standalone===true,matchMedia('(display-mode: standalone)').matches,document.querySelector('script[type="module"][src^="/lab-v16/dist/assets/index-"]')?.getAttribute('src')??null,document.getElementById('v16-build-badge')?.textContent??null,document.getElementById('lab-export-json')?.value??document.getElementById('lab-export-json')?.textContent??null,document.getElementById('lab-pack-status')?.textContent??null,document.getElementById('lab-export-status')?.textContent??null]`;
export function command() {
  return {id:1,method:'Runtime.evaluate',params:{expression:EXPRESSION,returnByValue:true,throwOnSideEffect:true,silent:true,timeout:3000}};
}
export function endpoint(raw) {
  const u=new URL(raw);
  if(u.protocol!=='ws:'||!['127.0.0.1','localhost'].includes(u.hostname)||!/^\d+$/.test(u.port)||+u.port<1024||+u.port>65535||u.username||u.password||u.search||u.hash||!/^\/devtools\/page\/[A-Za-z0-9_-]{1,128}$/.test(u.pathname))throw Error('OWN_LOOPBACK_PAGE_ENDPOINT_REQUIRED');
  return u.href;
}
export function result(message) {
  if(message?.id!==1||message.error||message.result?.exceptionDetails||!Array.isArray(message.result?.result?.value)||message.result.result.value.length!==10)throw Error('READONLY_DOM_NOT_AVAILABLE');
  return message.result.result.value;
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
      }catch{finish(Error('READONLY_DOM_RESPONSE_REFUSED'));}
    });
  });
}
if(process.argv[1]&&import.meta.url===new URL('file:'+process.argv[1]).href){
  try{if(process.argv.length!==3)throw Error('ONE_OBSERVED_ENDPOINT_REQUIRED');const value=await read(process.argv[2]);process.stdout.write(JSON.stringify(value));}
  catch{process.stderr.write('READONLY_DOM_ACQUISITION_REFUSED\n');process.exitCode=2;}
}
