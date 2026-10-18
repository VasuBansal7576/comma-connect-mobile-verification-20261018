/* Bounded response-stage diagnostic. Never supplies status, headers, body or auth. */
import{ORIGIN}from'./browser_default_preflight_v16.mjs';
export const PATHS=Object.freeze(['/lab-mobile/capability.js','/lab-v16/helpers/production/v13/export.js','/lab-mobile/hls-1.5.18.min.js']);
export const BODY_LIMIT=65536,BODY_DEADLINE_MS=4000,MAX_PAUSES=12;
export function createResponseBodyTap(client,sessionId,{summarizeBody,selectHeaders,onFatal}){
 const report={schema:'fixed-three-script-original-response-body-v1',enabled:false,responseStageOnly:true,requestOrResponseOverrides:false,measurementTimingChanged:true,APIBytesNotWireBytes:true,responses:[],failureCode:null};const pending=new Set();let stopped=false,closing=false;
 const fatal=code=>{report.failureCode??=code;if(!stopped){stopped=true;onFatal(code);}};
 async function paused(event){
  const a=event.params??{};let row,canContinue=true;
  try{
   const u=new URL(a.request?.url);if(u.origin!==ORIGIN||u.search||u.hash||u.username||u.password||!PATHS.includes(u.pathname)||a.resourceType!=='Script'||!a.requestId||!(Number.isInteger(a.responseStatusCode)||typeof a.responseErrorReason==='string'))throw Error('FETCH_FIXED_RESPONSE_SCOPE_REQUIRED');
   if(report.responses.length>=MAX_PAUSES)throw Error('FETCH_PAUSE_COUNT_LIMIT');
   const headers=Array.isArray(a.responseHeaders)?a.responseHeaders:[];row={path:u.pathname,status:a.responseStatusCode??null,headers:selectHeaders(Object.fromEntries(headers.map(h=>[h.name,h.value]))),bodyReadAttempted:false,continuedOriginalResponse:false};report.responses.push(row);
   if(a.responseErrorReason)row.transportError=true;
   const lengths=headers.filter(h=>h.name.toLowerCase()==='content-length');const size=lengths.length===1&&/^\d{1,6}$/.test(lengths[0].value)?Number(lengths[0].value):null;
   const html=headers.some(h=>h.name.toLowerCase()==='content-type'&&/^text\/html(?:;|$)/i.test(h.value));
   if(!closing&&a.responseStatusCode===500&&html&&size>0&&size<=BODY_LIMIT){
    row.bodyReadAttempted=true;let timer;
    try{
     const data=await Promise.race([client.send('Fetch.getResponseBody',{requestId:a.requestId},sessionId),new Promise((_,reject)=>{timer=setTimeout(()=>reject(Error('FETCH_ORIGINAL_BODY_TIMEOUT')),BODY_DEADLINE_MS)})]);
     if(typeof data?.body!=='string'||typeof data.base64Encoded!=='boolean')throw Error('FETCH_ORIGINAL_BODY_SCHEMA');
     const raw=Buffer.from(data.body,data.base64Encoded?'base64':'utf8');if(raw.length>BODY_LIMIT)throw Error('FETCH_ORIGINAL_BODY_LIMIT');row.body=summarizeBody(raw);row.bodyStatus='CAPTURED_ORIGINAL_API_BYTES';
    }catch(e){const code=['FETCH_ORIGINAL_BODY_TIMEOUT','FETCH_ORIGINAL_BODY_SCHEMA','FETCH_ORIGINAL_BODY_LIMIT'].includes(e.message)?e.message:'FETCH_ORIGINAL_BODY_UNAVAILABLE';row.bodyStatus=code;
     if(code==='FETCH_ORIGINAL_BODY_TIMEOUT'){canContinue=false;fatal(code);} // Do not continue/disable while body read is still pending.
    }finally{clearTimeout(timer);}
   }else row.bodyStatus=closing?'CLOSING_ORIGINAL_CONTINUED_NO_READ':a.responseStatusCode===500?'FETCH_ERROR_SIZE_OR_HTML_NOT_CONFIRMED':'NOT_REQUESTED_NON500';
   if(canContinue&&!stopped){await client.send('Fetch.continueResponse',{requestId:a.requestId},sessionId);row.continuedOriginalResponse=true;}
  }catch(e){fatal(['FETCH_FIXED_RESPONSE_SCOPE_REQUIRED','FETCH_PAUSE_COUNT_LIMIT'].includes(e.message)?e.message:'FETCH_ORIGINAL_CONTINUATION_UNVERIFIED');if(row)row.continuationFailure=true;}
 }
 const listener=event=>{if(event.sessionId!==sessionId||event.method!=='Fetch.requestPaused')return;const p=paused(event).finally(()=>pending.delete(p));pending.add(p);};
 return{report,async enable(){client.listeners.add(listener);try{await client.send('Fetch.enable',{patterns:PATHS.map(p=>({urlPattern:ORIGIN+p,resourceType:'Script',requestStage:'Response'})),handleAuthRequests:false},sessionId);report.enabled=true;}catch{client.listeners.delete(listener);throw Error('FETCH_RESPONSE_OBSERVER_UNAVAILABLE');}},async settle(){closing=true;while(pending.size)await Promise.allSettled([...pending]);},detach(){client.listeners.delete(listener);}};
}
