"""Classify retained private source-outputs; only a corked, live owned QEMU input may accompany the collector."""
import os,re
from pathlib import Path
class Refused(ValueError):pass
def need(ok,why):
 if not ok:raise Refused(why)
def bind(outputs,monitor,recorder,routing,b,emulator,executable=None):
 need(routing.pulse_index(monitor)and isinstance(outputs,list)and len(outputs)<=2,'BOUNDED_ORIGINAL_WINDOWED_SOURCE_OUTPUT_ROWS_REQUIRED')
 routing.require_owned(emulator,routing.proc_record)
 collector=[];extra=[];indices=set()
 witness=b.STATE.get('windowedSourceBackend',{})
 for row in outputs:
  need(isinstance(row,dict)and routing.pulse_index(row.get('index'))and routing.pulse_index(row.get('source'))and isinstance(row.get('properties'),dict),'TYPED_ORIGINAL_SOURCE_OUTPUT_REQUIRED')
  need(row['index']not in indices,'DUPLICATE_ORIGINAL_SOURCE_OUTPUT_INDEX');indices.add(row['index'])
  pid=row['properties'].get('application.process.id')
  need(isinstance(pid,str)and re.fullmatch(r'[1-9][0-9]*',pid)and row['source']==monitor,'EXACT_MONITOR_AND_TYPED_ORIGINAL_PID_REQUIRED')
  if pid==str(recorder['pid']):collector.append(row);continue
  need(not extra and row.get('corked')is True,'ONLY_ONE_EXACTLY_CORKED_QEMU_INPUT_ALLOWED')
  need(witness.get('verifiedBeforeNativeChromeInput')is True and type(witness.get('headfulPID'))is int and witness['headfulPID']>1 and pid==str(witness['headfulPID']),'EXACT_PREBOUND_HEADFUL_PID_REQUIRED')
  prior=witness.get('currentHeadfulIdentity',{});current=b.group_member(int(pid))
  need(isinstance(prior,dict)and type(prior.get('pid'))is int and prior['pid']==int(pid)and str(prior.get('startTicks'))==str(witness.get('headfulStartTicks')),'ORIGINAL_HEADFUL_IDENTITY_WITNESS_REQUIRED')
  need(current and current['pid']==int(pid)and current['startTicks']==prior['startTicks']and current['uid']==prior['uid']==os.getuid()and current['sid']==prior['sid']==emulator['pid']and current['pgid']==prior['pgid']==emulator['pid']and current['state']not in ['Z','X','x'],'CURRENT_HEADFUL_UID_TICKS_GROUP_REQUIRED')
  path=(executable or(lambda selected:os.readlink('/proc/'+str(selected)+'/exe')))(int(pid))
  need(path==witness.get('headfulBinary',{}).get('path'),'CURRENT_PREBOUND_HEADFUL_EXECUTABLE_REQUIRED')
  routing.descendant(int(pid),emulator,routing.proc_record)
  extra.append({'index':row['index'],'source':monitor,'pid':int(pid),'startTicks':current['startTicks'],'uid':current['uid'],'sid':current['sid'],'pgid':current['pgid'],'corked':True,'role':'OWNED_CORKED_QEMU_MONITOR_INPUT_NOT_CAPTURE_RECORDER','originalRow':row})
 # Delegate the unique actual collector row unchanged to the original strict binding.
 result=routing.recorder_binding(collector,monitor,recorder,routing.proc_record)
 routing.require_owned(emulator,routing.proc_record)
 return result,{'schema':'windowed-private-source-output-classification-v1','originalRawRowsRetained':True,'originalRowCount':len(outputs),'collectorRowIndex':result['index'],'corkedOwnedQEMUInputs':extra,'unknownRowsDiscarded':0,'collectorBindingUsesOriginalFunction':True,'hostMicrophoneAllowed':False}
