"""Pure explicit-mode boundaries. No commands, boot, stream changes or UI on import."""
def audio_arguments(original,actual_help,boot,sinks,sources,env,process,routing,explicit_audio_mode=False):
 if explicit_audio_mode is not True:raise ValueError('Separate explicit audio mode required; default boot stays unchanged')
 routing.remote_private(boot,env,process);routing.private_devices(sinks,sources)
 return routing.future_emulator_args(original,actual_help)

def ready_graph(boot,env,process,routing,sinks,sources,inputs,outputs,emulator,recorder):
 routing.remote_private(boot,env,process);si,mo=routing.private_devices(sinks,sources)
 routed=routing.input_bindings(inputs,si,emulator,process);recorded=routing.recorder_binding(outputs,mo,recorder,process)
 return {'sinkIndex':si,'monitorIndex':mo,'emulatorOutputs':routed,'nativeRecorder':recorded,'microphoneRequested':False,'scope':'Fresh ORIGINAL process/Pulse observations prerequisite before actual native pilot tap; not source/audio/PWA qualification.'}

def bind_completed_summary(graph,summary):
 if graph['nativeRecorder']['pid']!=summary['capturePID']or graph['nativeRecorder']['index']!=summary['pulseSourceOutputIndex']or graph['monitorIndex']!=summary['pulseMonitorIndex']:raise ValueError('Completed native summary must match the original pre-pilot graph')
 return True
