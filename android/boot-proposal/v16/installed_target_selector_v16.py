"""Fixed read-only installed-window selection; no attach/focus/input or JS mutation.
Caller supplies pinned readers and its unchanged strict target/full validators.
This does not establish video readiness, installation mechanism or physical audio.
"""
import hashlib,re,time
ENTRY='/lab-v16/dist/assets/index-ojoFR-wi.js'
BADGE='V16 e7ab13f79d01'
class Refused(Exception):pass

def identity(value,expected_url):
    if not isinstance(value,list)or len(value)!=8:raise Refused('TARGET_IDENTITY_DOM_SCHEMA_REQUIRED')
    href,origin,ua,nav,display,entry,badge,visibility=value
    if href!=expected_url or type(origin)not in [int,float]or not 0<origin<1e15:raise Refused('TARGET_IDENTITY_DOCUMENT_REQUIRED')
    if not isinstance(ua,str)or'Android'not in ua or not re.search(r'Chrome/124\.\d+\.\d+\.\d+',ua):raise Refused('TARGET_IDENTITY_ANDROID_CHROME_REQUIRED')
    if nav is not False or type(display)is not bool:raise Refused('TARGET_IDENTITY_PLATFORM_MODE_REQUIRED')
    if entry!=ENTRY or badge!=BADGE:raise Refused('TARGET_IDENTITY_CURRENT_SOURCE_REQUIRED')
    if visibility not in ['visible','hidden']:raise Refused('TARGET_IDENTITY_VISIBILITY_REQUIRED')
    return {'href':href,'timeOrigin':origin,'standaloneNavigator':nav,'standaloneDisplay':display,'visibility':visibility}

def candidates(version,targets,port,validate_target):
    if not isinstance(targets,list)or not 1<=len(targets)<=2:raise Refused('ONE_OR_TWO_ONLY_REVIEWED_TARGETS_REQUIRED')
    result=[]
    for target in targets:
        # The original caller validator retains its exact URL/version/package/
        # endpoint rules. Every row must qualify before any DOM read is made.
        checked=validate_target(version,[target],port)
        result.append(checked)
    if len({t['id']for t in result})!=len(result):raise Refused('DUPLICATE_TARGET_ID_REQUIRED_REFUSAL')
    if len({t['url']for t in result})!=1:raise Refused('SAME_EXACT_OWNED_URL_REQUIRED')
    return sorted(result,key=lambda t:t['id'])

def select(version,targets,port,*,read_identity,read_full,list_targets,decode,validate_target,validate_full,evidence):
    """Each read(endpoint,seconds) uses only a pinned fixed expression.
    All active selection work shares one20s absolute deadline. No retry/activation.
    Original full validator runs after mode selection. Caller always removes its
    owned forward in finally, including selection/deadline/reader failures.
    """
    started=time.monotonic();deadline=started+20
    evidence.update(schema='installed-target-selection-v1',status='STARTING',selectionLimitSeconds=20,identityReads=[],inputCommands=0,sourceWrites=0)
    def remaining():
        left=deadline-time.monotonic()
        if left<=0:raise Refused('INSTALLED_SELECTION_ABSOLUTE_DEADLINE')
        return min(10,left)
    def checked_targets(rows):
        remaining();result=candidates(version,rows,port,validate_target);remaining();return result
    def signature(rows):return [(t['id'],t['url'],t['webSocketDebuggerUrl'])for t in rows]
    def mode_read(target,phase):
        before=time.monotonic();raw=read_identity(target['webSocketDebuggerUrl'],remaining());remaining()
        value=decode(raw,1024*1024);mode=identity(value,target['url']);remaining()
        evidence['identityReads'].append({'targetId':target['id'],'phase':phase,'sameReviewedURL':True,'rawSHA256':hashlib.sha256(raw).hexdigest(),'bytes':len(raw),'startSelectionSeconds':before-started,'completeSelectionSeconds':time.monotonic()-started,**{k:v for k,v in mode.items()if k!='href'}})
        return value,mode
    try:
        initial=checked_targets(targets);evidence['candidateIDs']=[t['id']for t in initial]
        observations={t['id']:mode_read(t,'BEFORE_FULL_READ')for t in initial}
        pwa=[t for t in initial if observations[t['id']][1]['standaloneDisplay']is True]
        if len(pwa)!=1:raise Refused('EXACTLY_ONE_ACTUAL_INSTALLED_MODE_REQUIRED')
        selected=pwa[0];first_value,first=observations[selected['id']]
        if first['visibility']!='visible':raise Refused('SELECTED_INSTALLED_DOCUMENT_NOT_VISIBLE')
        evidence['selectedId']=selected['id']
        raw=read_full(selected['webSocketDebuggerUrl'],remaining());remaining()
        full=validate_full(decode(raw));remaining()
        if full.get('timeOrigin')!=first['timeOrigin']or full.get('href')!=first['href']:raise Refused('SELECTED_FULL_DOCUMENT_CHANGED')
        after=checked_targets(list_targets(remaining()))
        if signature(after)!=signature(initial):raise Refused('SELECTION_TARGET_SET_CHANGED')
        for target in after:
            old_value,old=observations[target['id']];value,mode=mode_read(target,'AFTER_FULL_READ')
            if value[:7]!=old_value[:7]:raise Refused('SELECTION_DOCUMENT_OR_MODE_CHANGED')
            if target['id']==selected['id']and mode['visibility']!='visible':raise Refused('SELECTED_INSTALLED_DOCUMENT_NOT_VISIBLE')
        # Final target-list identity checks cannot activate or select a browser.
        final=checked_targets(list_targets(remaining()))
        if signature(final)!=signature(initial):raise Refused('SELECTION_TARGET_SET_CHANGED')
        remaining();evidence.update(status='ONE_ACTUAL_VISIBLE_INSTALLED_DOCUMENT_STABLY_OBSERVED',elapsedSeconds=time.monotonic()-started)
        return selected,raw
    except Exception as error:
        evidence.update(status='REFUSED',elapsedSeconds=time.monotonic()-started,errorClass=type(error).__name__)
        if isinstance(error,Refused):evidence['refusalCode']=str(error)
        raise
