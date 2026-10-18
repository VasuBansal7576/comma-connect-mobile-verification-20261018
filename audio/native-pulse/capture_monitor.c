/* Test-only hosted private Pulse monitor observer. No output/mic/default device.
 * Build only against official libpulse headers. Real packet PTS are NOT fabricated.
 */
#define _POSIX_C_SOURCE 200809L
#include <pulse/pulseaudio.h>
#include <errno.h>
#include <inttypes.h>
#include <math.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#define RATE 48000u
#define FRAME_BYTES 8u
#define MONITOR "ci_silent.monitor"
_Static_assert(sizeof(float)==4,"32-bit float required");
static pa_mainloop *loop; static pa_context *context; static pa_stream *stream;
static pa_operation *timing_operation;
static double timing_request_at,last_timing_request;
static uint64_t timing_requests,timing_replies;
static int final_timing_complete;
static FILE *pcm,*events; static uint64_t frames,sequence,event_sequence,holes;
static int failed,ready,stopping,data_ready,index_basis_set; static int64_t index_basis; static double began,ready_at,stop_at;
static uint32_t source_output_index=PA_INVALID_INDEX,monitor_index=PA_INVALID_INDEX; static unsigned duration;
static double mono(void){struct timespec t;if(clock_gettime(CLOCK_MONOTONIC,&t))_exit(125);return(double)t.tv_sec+t.tv_nsec/1e9;}
static void watchdog(int sig){(void)sig;static const char msg[]="OWN_PULSE_CAPTURE_HARD_DEADLINE\n";ssize_t written=write(STDERR_FILENO,msg,sizeof(msg)-1);(void)written;_exit(124);}
static void event(const char *kind,int value){
    if(!events)return;
    if(fprintf(events,"{\"eventSequence\":%"PRIu64",\"kind\":\"%s\",\"hostMonotonicSeconds\":%.9f,\"fileFrameOffset\":%"PRIu64",\"value\":%d}\n",event_sequence++,kind,mono(),frames,value)<0)failed=1;
}
static void refuse(const char *kind,int value){if(!failed)event(kind,value);failed=1;}
/* Only read-only GET_RECORD_LATENCY metadata queries; never audio/source setters.
 * One explicit operation is owned here; Pulse's existing auto refresh stays enabled. */
static void timing_reply(pa_stream*s,int success,void*u){
    (void)u;pa_operation*completed=timing_operation;timing_operation=NULL;
    if(!completed){refuse("pulse-unmatched-timing-reply-error",1);return;}
    pa_operation_unref(completed);timing_replies++;
    const pa_timing_info*ti=pa_stream_get_timing_info(s);
    if(fprintf(events,"{\"eventSequence\":%"PRIu64",\"kind\":\"timing-refresh-reply\",\"hostMonotonicSeconds\":%.9f,\"fileFrameOffset\":%"PRIu64",\"value\":%d,\"requestOrdinal\":%"PRIu64",\"timingAvailable\":%s",event_sequence++,mono(),frames,success,timing_requests,ti?"true":"false")<0)failed=1;
    if(ti&&fprintf(events,",\"timingSystemSeconds\":%lld,\"timingSystemUsec\":%ld,\"readIndexBytes\":%"PRId64",\"readIndexCorrupt\":%d,\"writeIndexCorrupt\":%d",(long long)ti->timestamp.tv_sec,(long)ti->timestamp.tv_usec,ti->read_index,ti->read_index_corrupt,ti->write_index_corrupt)<0)failed=1;
    if(fputs("}\n",events)==EOF)failed=1;
    if(!success||!ti||ti->read_index_corrupt||ti->write_index_corrupt)refuse("pulse-timing-refresh-error",success);
}
static void request_timing(double now){
    last_timing_request=timing_request_at=now;timing_requests++;event("timing-refresh-request",(int)timing_requests);
    timing_operation=pa_stream_update_timing_info(stream,timing_reply,NULL);
    if(!timing_operation)refuse("pulse-timing-refresh-start-error",1);
}
static void refresh_timing(double now){
    if(!ready||stopping||failed)return;
    if(timing_operation){if(now-timing_request_at>=2.0)refuse("pulse-timing-refresh-deadline-error",1);return;}
    if(now-last_timing_request<0.5)return;
    request_timing(now);
}
static void overflow(pa_stream*s,void*u){(void)s;(void)u;refuse("pulse-overflow",1);}
static void moved(pa_stream*s,void*u){(void)s;(void)u;refuse("pulse-device-moved",1);}
static void suspended(pa_stream*s,void*u){(void)u;int x=pa_stream_is_suspended(s);event("pulse-suspended-state",x);if(x!=0)refuse("pulse-suspended-or-unknown",x);}
static void stream_state(pa_stream*s,void*u){
    (void)u;pa_stream_state_t state=pa_stream_get_state(s);event("pulse-stream-state",state);
    if(state==PA_STREAM_FAILED||state==PA_STREAM_TERMINATED){if(!stopping)refuse("pulse-stream-failed",state);return;}
    if(state==PA_STREAM_READY){
        const pa_sample_spec*ss=pa_stream_get_sample_spec(s);const char*name=pa_stream_get_device_name(s);
        if(!ss||ss->format!=PA_SAMPLE_FLOAT32LE||ss->rate!=RATE||ss->channels!=2||!name||strcmp(name,MONITOR)){refuse("pulse-original-format-or-device-mismatch",1);return;}
        if(pa_stream_is_suspended(s)!=0||pa_stream_is_corked(s)!=0){refuse("pulse-initial-suspended-or-corked",1);return;}
        source_output_index=pa_stream_get_index(s);monitor_index=pa_stream_get_device_index(s);
        if(source_output_index==PA_INVALID_INDEX||monitor_index==PA_INVALID_INDEX){refuse("pulse-missing-original-device-index",1);return;}
        if(ready){refuse("pulse-duplicate-ready",1);return;}ready=1;ready_at=mono();last_timing_request=ready_at-0.5;event("capture-ready",0);puts("CAPTURE_READY");fflush(stdout);
    }
}
static void receive(pa_stream*s,size_t hint,void*u){
    (void)hint;(void)u;size_t callback_bytes=0;
    while(!failed&&!stopping){
        const void *data=NULL;size_t n=0;
        if(pa_stream_peek(s,&data,&n)<0){refuse("pulse-peek-error",1);break;}
        if(!n)break;
        if(!ready||sequence>=100000u||n%FRAME_BYTES||n>1024u*1024u||callback_bytes+n>2u*1024u*1024u){refuse("pulse-invalid-fragment",1);break;}
        if(!data){holes+=n;event("pulse-hole-bytes",(int)n);if(pa_stream_drop(s)<0)event("pulse-hole-drop-error",1);failed=1;break;}
        if(frames+n/FRAME_BYTES>(uint64_t)RATE*(duration+1u)){refuse("pulse-frame-bound-exceeded",1);break;}
        for(size_t i=0;i<n/sizeof(float);i++){float sample;memcpy(&sample,(const unsigned char*)data+i*sizeof(float),sizeof(sample));if(!isfinite(sample)){refuse("pulse-nonfinite-pcm",1);break;}}
        if(failed)break;
        pa_usec_t stream_usec=0,latency=0;int negative=0;
        int tr=pa_stream_get_time(s,&stream_usec),lr=pa_stream_get_latency(s,&latency,&negative);
        const pa_timing_info*ti=pa_stream_get_timing_info(s);double host=mono();
        int index_jump=0;
        if(ti&&!ti->read_index_corrupt){int64_t basis=ti->read_index-(int64_t)(frames*FRAME_BYTES);if(index_basis_set&&basis!=index_basis)index_jump=1;else if(!index_basis_set){index_basis=basis;index_basis_set=1;}}
        if(fwrite(data,1,n,pcm)!=n){refuse("pulse-pcm-write-error",errno);break;}
        if(fprintf(events,"{\"sequence\":%"PRIu64",\"kind\":\"pcm-fragment\",\"fileFrameOffset\":%"PRIu64",\"frames\":%zu,\"hostMonotonicSeconds\":%.9f,\"streamTimeResult\":%d,\"streamTimeUsec\":%"PRIu64",\"latencyResult\":%d,\"latencyUsec\":%"PRIu64",\"latencyNegative\":%d,\"timingAvailable\":%s",sequence++,frames,n/FRAME_BYTES,host,tr,stream_usec,lr,latency,negative,ti?"true":"false")<0)failed=1;
        if(ti&&fprintf(events,",\"timingSystemSeconds\":%lld,\"timingSystemUsec\":%ld,\"synchronizedClocks\":%d,\"readIndexCorrupt\":%d,\"writeIndexCorrupt\":%d,\"readIndexBytes\":%"PRId64",\"writeIndexBytes\":%"PRId64",\"sinkUsec\":%"PRIu64",\"sourceUsec\":%"PRIu64",\"transportUsec\":%"PRIu64,(long long)ti->timestamp.tv_sec,(long)ti->timestamp.tv_usec,ti->synchronized_clocks,ti->read_index_corrupt,ti->write_index_corrupt,ti->read_index,ti->write_index,ti->sink_usec,ti->source_usec,ti->transport_usec)<0)failed=1;
        if(fputs("}\n",events)==EOF)failed=1;
        frames+=n/FRAME_BYTES;callback_bytes+=n;
        if(!data_ready&&sequence>=3&&frames>=1440&&tr==0&&ti&&!ti->read_index_corrupt&&!ti->write_index_corrupt){data_ready=1;event("capture-data-ready",0);puts("CAPTURE_DATA_READY");fflush(stdout);}
        if(pa_stream_drop(s)<0){refuse("pulse-data-drop-error",1);break;}
        if(index_jump){refuse("pulse-read-index-discontinuity",1);break;}
    }
}
static void context_state(pa_context*c,void*u){
    (void)u;pa_context_state_t state=pa_context_get_state(c);event("pulse-context-state",state);
    if(state==PA_CONTEXT_FAILED||state==PA_CONTEXT_TERMINATED){if(!stopping)refuse("pulse-context-failed",state);return;}
    if(state==PA_CONTEXT_READY){
        if(stream){refuse("pulse-duplicate-context-ready",1);return;}
        pa_sample_spec spec={PA_SAMPLE_FLOAT32LE,RATE,2};pa_channel_map map;pa_channel_map_init_stereo(&map);
        stream=pa_stream_new(c,"owned-ci-private-monitor",&spec,&map);if(!stream){refuse("pulse-stream-new-error",1);return;}
        pa_stream_set_state_callback(stream,stream_state,NULL);pa_stream_set_read_callback(stream,receive,NULL);pa_stream_set_overflow_callback(stream,overflow,NULL);pa_stream_set_moved_callback(stream,moved,NULL);pa_stream_set_suspended_callback(stream,suspended,NULL);
        pa_buffer_attr attr={.maxlength=RATE*FRAME_BYTES*2u,.tlength=UINT32_MAX,.prebuf=UINT32_MAX,.minreq=UINT32_MAX,.fragsize=480u*FRAME_BYTES};
        if(pa_stream_connect_record(stream,MONITOR,&attr,PA_STREAM_AUTO_TIMING_UPDATE|PA_STREAM_DONT_MOVE)<0)refuse("pulse-record-connect-error",1);
    }
}
static int private_server(const char *server){
    const char *prefix="unix:/tmp/v15pa-";if(!server||strncmp(server,prefix,strlen(prefix)))return 0;
    const char *end=strstr(server+strlen(prefix),"/native");if(!end||strcmp(end,"/native")||end==server+strlen(prefix))return 0;
    for(const char*p=server+strlen(prefix);p<end;p++)if(!((*p>='a'&&*p<='z')||(*p>='A'&&*p<='Z')||(*p>='0'&&*p<='9')||*p=='_'))return 0;
    char dir[108];size_t n=(size_t)(end-(server+5));if(n>=sizeof(dir))return 0;memcpy(dir,server+5,n);dir[n]=0;
    struct stat d,s;if(lstat(dir,&d)||!S_ISDIR(d.st_mode)||(d.st_mode&0777)!=0700||d.st_uid!=getuid()||lstat(server+5,&s)||!S_ISSOCK(s.st_mode)||s.st_uid!=getuid())return 0;
    return 1;
}
static int env_equal(const char*k,const char*v){const char*x=getenv(k);return x&&!strcmp(x,v);}
int main(int argc,char**argv){
    signal(SIGALRM,watchdog);alarm(170);
    if(!env_equal("GITHUB_ACTIONS","true")||!env_equal("RUNNER_OS","Linux")||!env_equal("RUNNER_ARCH","X64")||!env_equal("PULSE_SINK","ci_silent")||!env_equal("PULSE_SOURCE",MONITOR)||!private_server(getenv("PULSE_SERVER"))){fputs("OWN_HOSTED_PRIVATE_PULSE_REQUIRED\n",stderr);return 2;}
    if(argc!=5||(strcmp(argv[1],"protocol")&&strcmp(argv[1],"calibration"))){fputs("Usage: capture_monitor protocol|calibration NEW.f32 NEW.jsonl NEW-summary.json\n",stderr);return 2;}
    if(!strcmp(argv[2],argv[3])||!strcmp(argv[2],argv[4])||!strcmp(argv[3],argv[4])||access(argv[4],F_OK)==0)return 2;
    const char*library_version=pa_get_library_version();if(!library_version||strlen(library_version)>63||strspn(library_version,"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ._+-")!=strlen(library_version))return 2;
    duration=!strcmp(argv[1],"protocol")?150u:12u;began=mono();alarm(duration==150u?170:30);
    pcm=fopen(argv[2],"wbx");events=fopen(argv[3],"wx");if(!pcm||!events){if(pcm)fclose(pcm);if(events)fclose(events);return 2;}
    loop=pa_mainloop_new();if(!loop){refuse("pulse-mainloop-new-error",1);goto done;}
    context=pa_context_new(pa_mainloop_get_api(loop),"owned-ci-private-output-capture");if(!context){refuse("pulse-context-new-error",1);goto done;}
    pa_context_set_state_callback(context,context_state,NULL);
    if(pa_context_connect(context,getenv("PULSE_SERVER"),PA_CONTEXT_NOAUTOSPAWN,NULL)<0){refuse("pulse-private-context-connect-error",1);goto done;}
    while(!failed){
        double now=mono();if(!ready&&now-began>8){refuse("pulse-readiness-deadline",1);break;}if(ready&&now-ready_at>=duration)break;
        refresh_timing(now);if(failed)break;
        int ret=0;if(pa_mainloop_iterate(loop,0,&ret)<0){refuse("pulse-mainloop-error",ret);break;}
        struct timespec delay={0,1000000};nanosleep(&delay,NULL);
    }
 done:
    stop_at=mono();stopping=1;alarm(5);event("capture-stop",failed);
    if(timing_operation){pa_operation_cancel(timing_operation);pa_operation_unref(timing_operation);timing_operation=NULL;event("timing-refresh-cancel-at-stop",0);}
    /* Sample writes are frozen by stopping=1. Request metadata after that final
     * batch, within the existing five-second cleanup watchdog. No PCM is added. */
    if(!failed&&ready&&stream&&pa_stream_get_state(stream)==PA_STREAM_READY){
        event("timing-refresh-final-begin",(int)(timing_requests+1));request_timing(mono());
        double until=mono()+2.0;
        while(timing_operation&&!failed){
            if(mono()>=until){refuse("pulse-final-timing-deadline-error",1);break;}
            int ret=0;if(pa_mainloop_iterate(loop,0,&ret)<0){refuse("pulse-final-timing-mainloop-error",ret);break;}
            struct timespec delay={0,1000000};nanosleep(&delay,NULL);
        }
        final_timing_complete=!failed&&!timing_operation;event("timing-refresh-final-end",final_timing_complete);
        if(timing_operation){pa_operation_cancel(timing_operation);pa_operation_unref(timing_operation);timing_operation=NULL;event("timing-refresh-cancel-at-stop",0);}
    }
    int disconnected=1;if(stream){if(pa_stream_disconnect(stream)<0)disconnected=0;pa_stream_unref(stream);}if(context){pa_context_disconnect(context);pa_context_unref(context);}if(loop)pa_mainloop_free(loop);
    int file_ok=fflush(pcm)==0;if(fclose(pcm))file_ok=0;int journal_ok=fflush(events)==0;if(fclose(events))journal_ok=0;
    FILE*out=fopen(argv[4],"wx");if(!out)return 2;
    int ok=!failed&&ready&&data_ready&&final_timing_complete&&frames>0&&holes==0&&file_ok&&journal_ok&&disconnected;
    fprintf(out,"{\"schema\":\"native-private-pulse-monitor-capture-v1\",\"libraryVersion\":\"%s\",\"sampleRate\":48000,\"channels\":2,\"sampleFormat\":\"float32-le-interleaved\",\"frames\":%"PRIu64",\"fragments\":%"PRIu64",\"explicitHoleBytes\":%"PRIu64",\"requestedCaptureSeconds\":%u,\"capturePID\":%ld,\"pulseSourceOutputIndex\":%u,\"pulseMonitorIndex\":%u,\"dataReadinessObserved\":%s,\"captureElapsedSeconds\":%.9f,\"processElapsedSeconds\":%.9f,\"independentProcessDeadlineSeconds\":%u,\"cleanupDeadlineSeconds\":5,\"streamDisconnected\":%s,\"pcmFileClosed\":%s,\"journalFileClosed\":%s,\"nativeCaptureComplete\":%s,\"finalTimingRefreshComplete\":%s,\"sampleWritesFrozenBeforeFinalTimingQuery\":true,\"explicitTimingRefreshIntervalMilliseconds\":500,\"explicitTimingRefreshDeadlineMilliseconds\":2000,\"explicitTimingRefreshRequests\":%"PRIu64",\"explicitTimingRefreshReplies\":%"PRIu64",\"independentPerPacketPTSProvided\":false,\"microphoneRequested\":false,\"sourceContextOrNonceInvented\":false,\"functionalPWAQualificationClaimed\":false}\n",library_version,frames,sequence,holes,duration,(long)getpid(),source_output_index,monitor_index,data_ready?"true":"false",ready?stop_at-ready_at:0,mono()-began,duration==150u?170u:30u,disconnected?"true":"false",file_ok?"true":"false",journal_ok?"true":"false",ok?"true":"false",final_timing_complete?"true":"false",timing_requests,timing_replies);if(fclose(out))ok=0;alarm(0);return ok?0:2;
}
