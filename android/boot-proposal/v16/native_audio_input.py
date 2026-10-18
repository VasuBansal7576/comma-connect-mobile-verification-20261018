"""Current native XML-only target resolution. Never caches/retries a dispatched tap."""
import re,struct,xml.etree.ElementTree as ET
class Refused(ValueError):pass
LABELS={'V16 verification controls','Pin actual playlist','Prepare playback','Start pilot and run','Start bare native','Export all','Freeze','Pack frozen witness','V16 OS audio test','Evidence export'}
def resolve(xml,png,label):
 if label not in LABELS:raise Refused('UNREVIEWED_NATIVE_AUDIO_LABEL')
 if not isinstance(xml,bytes)or len(xml)>2*1024*1024 or b'<!DOCTYPE'in xml.upper()or b'<!ENTITY'in xml.upper():raise Refused('BOUNDED_NATIVE_XML_REQUIRED')
 if not isinstance(png,bytes)or len(png)<24 or png[:8]!=b'\x89PNG\r\n\x1a\n'or png[12:16]!=b'IHDR':raise Refused('CURRENT_NATIVE_PNG_REQUIRED')
 w,h=struct.unpack('>II',png[16:24])
 if not(0<w<=16384 and 0<h<=16384):raise Refused('FINITE_NATIVE_SCREEN')
 try:tree=ET.fromstring(xml)
 except ET.ParseError:raise Refused('NATIVE_XML_INVALID')
 nodes=list(tree.iter());parents={c:p for p in nodes for c in p};positions={id(e):i for i,e in enumerate(nodes)}
 packages={e.get('package')for e in nodes if e.get('package')}
 app=[p for p in packages if p=='com.android.chrome'or re.fullmatch(r'org\.chromium\.webapk\.[A-Za-z0-9_.]+',p)]
 if len(app)!=1 or not packages.issubset({app[0],'android','com.android.systemui'}):raise Refused('OWNED_CHROME_OR_WEBAPK_NATIVE_CONTEXT_REQUIRED')
 # Any explicit native modal refuses rather than guessing a dismissal.
 if any(e.get('resource-id','').endswith(('/parentPanel','/permission_message','/alertTitle','/tab_modal_dialog_container','/bottom_sheet'))for e in nodes):raise Refused('UNKNOWN_NATIVE_MODAL')
 def chain(e):
  out=[e]
  while e in parents:e=parents[e];out.append(e)
  return out
 def eligible(e):return all(x.get('enabled')!='false'and x.get('visible-to-user')!='false'and x.get('displayed')!='false'for x in chain(e))
 def rect(e):
  m=re.fullmatch(r'\[(-?\d+),(-?\d+)\]\[(-?\d+),(-?\d+)\]',e.get('bounds',''))
  if not m:return None
  a,b,c,d=map(int,m.groups());return(a,b,c,d)if a<c and b<d else None
 def observed_compositor_background(e):
  # Exact blank compositor layer retained in actual39118188086; not a generic overlay bypass.
  parent=parents.get(e);holder=parents.get(parent)
  return (not list(e)and e.get('class')=='android.view.View'and e.get('index')=='0'
   and all(e.get(k,'')==''for k in ['text','content-desc','resource-id'])
   and all(e.get(k)=='false'for k in ['clickable','focusable','scrollable','long-clickable'])
   and parent is not None and parent.get('class')=='android.widget.FrameLayout'and parent.get('index')=='0'
   and holder is not None and holder.get('resource-id')=='com.android.chrome:id/compositor_view_holder'
   and rect(e)==rect(parent)==rect(holder)and rect(e)is not None)
 labels=[e for e in nodes if e.get('package')==app[0]and(label==e.get('text')or label==e.get('content-desc'))]
 if not labels:raise Refused('CURRENT_NATIVE_LABEL_ABSENT')
 hits={}
 for e in labels:
  if not eligible(e):raise Refused('CURRENT_NATIVE_LABEL_INELIGIBLE')
  clickable=next((x for x in chain(e)if x.get('clickable')=='true'and x.get('package')==app[0]),None)
  if clickable is None:
   # Android exposes a labeled structural wrapper plus the same-label clickable child.
   descendants=[x for x in e.iter()if x is not e and x.get('package')==app[0]and(label==x.get('text')or label==x.get('content-desc'))and x.get('clickable')=='true'and eligible(x)and rect(x)]
   if len(descendants)!=1 or not rect(e):raise Refused('UNIQUE_SAME_LABEL_CLICKABLE_DESCENDANT_REQUIRED')
   child=descendants[0];er=rect(e);cr=rect(child)
   if not(er[0]<=cr[0]<cr[2]<=er[2]and er[1]<=cr[1]<cr[3]<=er[3]):raise Refused('CLICKABLE_DESCENDANT_OUTSIDE_LABEL_WRAPPER')
   e=clickable=child
  if not eligible(clickable)or not rect(e)or not rect(clickable):raise Refused('NATIVE_CLICKABLE_ANCESTOR_REQUIRED')
  hits[id(clickable)]=(e,clickable)
 if len(hits)!=1:raise Refused('AMBIGUOUS_NATIVE_AUDIO_TARGET')
 e,target=next(iter(hits.values()));a,b,c,d=rect(e);ta,tb,tc,td=rect(target)
 if not(ta<=a<c<=tc and tb<=b<d<=td):raise Refused('NATIVE_LABEL_OUTSIDE_ANCESTOR')
 x,y=(a+c)//2,(b+d)//2
 if not(0<=a<c<=w and 0<=b<d<=h):
  scrolls=[s for s in chain(target)if s.get('scrollable')=='true'and eligible(s)and rect(s)]
  if len(scrolls)!=1:raise Refused('UNIQUE_KNOWN_SCROLL_ANCESTOR_REQUIRED')
  sr=rect(scrolls[0]);sa,sb,sc,sd=sr
  if not(0<=sa<sc<=w and 0<=sb<sd<=h)or sb<=y<sd:raise Refused('KNOWN_SCROLL_DIRECTION_UNAVAILABLE')
  sx=(sa+sc)//2;sy=sb+3*(sd-sb)//4 if y>=sd else sb+(sd-sb)//4;ey=sb+(sd-sb)//4 if y>=sd else sb+3*(sd-sb)//4
  family=set(chain(target))|set(target.iter())
  for other in nodes:
   if other in family or list(other)or not eligible(other)or observed_compositor_background(other):continue
   r=rect(other)
   if r and any(r[0]<=sx<r[2]and r[1]<=py<r[3]for py in [sy,ey]):raise Refused('NATIVE_SCROLL_ENDPOINT_OCCLUDED')
  return {'kind':'scroll','label':label,'scrollBounds':sr,'x':sx,'fromY':sy,'toY':ey,'screen':[w,h]}
 family=set(chain(target))|set(target.iter());blockers=[]
 for other in nodes:
  if other in family or list(other)or not eligible(other)or observed_compositor_background(other):continue
  r=rect(other)
  if r and max(a,r[0])<min(c,r[2])and max(b,r[1])<min(d,r[3]):blockers.append(r)
 avoided=False
 if any(r[0]<=x<r[2]and r[1]<=y<r[3]for r in blockers):
  # Do not ignore an overlapping leaf. Find an interior portion of this fresh
  # native Button rectangle outside every unrelated observed leaf rectangle.
  if target.get('class')!='android.widget.Button':raise Refused('NATIVE_AUDIO_TARGET_OCCLUDED_OR_UNKNOWN_OVERLAP')
  free=[(a,b,c,d)]
  for left,top,right,bottom in blockers:
   next_free=[]
   for aa,bb,cc,dd in free:
    il,it,ir,ib=max(aa,left),max(bb,top),min(cc,right),min(dd,bottom)
    if il>=ir or it>=ib:next_free.append((aa,bb,cc,dd));continue
    next_free.extend(r for r in [(aa,bb,il,dd),(ir,bb,cc,dd),(il,bb,ir,it),(il,ib,ir,dd)]if r[2]-r[0]>=3 and r[3]-r[1]>=3)
   if len(next_free)>128:raise Refused('NATIVE_CLEAR_POINT_PARTITION_LIMIT')
   free=next_free
  candidates=sorted(free,key=lambda r:-(r[2]-r[0])*(r[3]-r[1]))
  if not candidates:raise Refused('NATIVE_AUDIO_TARGET_OCCLUDED_OR_UNKNOWN_OVERLAP')
  aa,bb,cc,dd=candidates[0];x,y=(aa+cc)//2,(bb+dd)//2
  if not(a<x<c and b<y<d and ta<x<tc and tb<y<td)or any(r[0]<=x<r[2]and r[1]<=y<r[3]for r in blockers):raise Refused('NATIVE_AUDIO_TARGET_OCCLUDED_OR_UNKNOWN_OVERLAP')
  avoided=True
 return {'kind':'tap','label':label,'x':x,'y':y,'labelBounds':[a,b,c,d],'clickableBounds':[ta,tb,tc,td],'screen':[w,h],'package':app[0],'nativeClassObserved':target.get('class'),'documentOrder':positions[id(target)],'avoidedObservedLeafRectangles':avoided}

class Sequence:
 ORDER=['Pin actual playlist','Prepare playback','Start pilot and run','Start bare native','Export all','Freeze','Pack frozen witness']
 def __init__(self):self.next=0;self.cancelled=False;self.ack=False;self.closed=False;self.clean=False;self.dispatched=[]
 def allow(self,label):
  if self.cancelled:raise Refused('ACQUISITION_CANCELLED')
  if label not in self.ORDER:return
  if self.next>=len(self.ORDER)or self.ORDER[self.next]!=label:raise Refused('NATIVE_PROTOCOL_ORDER')
  if label=='Start pilot and run'and not self.ack:raise Refused('ACTUAL_NATIVE_CAPTURE_ACK_REQUIRED')
  if label=='Start bare native'and not self.closed:raise Refused('ACTUAL_PRODUCT_CLOSE_REQUIRED')
  if label=='Export all'and not self.clean:raise Refused('ACTUAL_SOURCE_CLEANUP_REQUIRED')
 def dispatched_once(self,label):
  self.allow(label)
  if label in self.ORDER:self.dispatched.append(label);self.next+=1
