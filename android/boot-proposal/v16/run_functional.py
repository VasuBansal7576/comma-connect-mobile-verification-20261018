"""Separate explicit entrypoint: sealed default source remains byte-exact on disk."""
import hashlib,json,re,shutil,subprocess,sys,types
from pathlib import Path
HERE=Path(__file__).resolve().parent

def checked_source():
 manifest=json.loads((HERE/'functional-manifest.json').read_text())
 if manifest.get('schema')!='v16-owned-android-functional-input-set-v1':raise ValueError('FUNCTIONAL_MANIFEST_SCHEMA')
 expected={'boot.py','readonly_bridge_v16.py','read_dom_v16.mjs','derive_functional_boot.py','functional_acquire.py','functional_contracts.py','native_functional_input.py','readonly_functional_bridge.py','read_functional_state.mjs'}
 if set(manifest.get('runtimeFiles',{}))!=expected:raise ValueError('CLOSED_RUNTIME_DEPENDENCIES_REQUIRED')
 for name,pin in manifest['runtimeFiles'].items():
  raw=(HERE/name).read_bytes()
  if len(raw)!=pin['bytes']or hashlib.sha256(raw).hexdigest()!=pin['sha256']:raise ValueError('FUNCTIONAL_RUNTIME_DEPENDENCY_MISMATCH')
 import derive_functional_boot
 source=derive_functional_boot.derive((HERE/'boot.py').read_bytes())
 if hashlib.sha256(source.encode()).hexdigest()!=manifest.get('derivedSourceSHA256'):raise ValueError('DERIVED_FUNCTIONAL_SOURCE_MISMATCH')
 return source

def existing_node_readonly_preflight():
 node=shutil.which('node')
 if not node:raise ValueError('EXISTING_NODE_REQUIRED')
 script="process.stdout.write(JSON.stringify({websocket:typeof WebSocket,version:process.version}))"
 try:r=subprocess.run([node,'--input-type=module','-e',script],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=3)
 except subprocess.TimeoutExpired:raise ValueError('EXISTING_NODE_PREFLIGHT_TIMEOUT')from None
 if r.returncode or len(r.stdout)>256:raise ValueError('EXISTING_NODE_PREFLIGHT_REFUSED')
 v=json.loads(r.stdout)
 if v.get('websocket')!='function'or not isinstance(v.get('version'),str)or not re.fullmatch(r'v\d+\.\d+\.\d+',v['version']):raise ValueError('EXISTING_NODE_WEBSOCKET_REQUIRED')
 return {'existingNodeVersion':v['version'],'webSocketFunctionObserved':True,'browserOrDeviceInput':False}

def main(argv=None):
 if argv is not None:sys.argv=[str(HERE/'run_functional.py')]+list(argv)
 source=checked_source();name='owned_v16_functional_boot'
 if name in sys.modules:raise ValueError('FRESH_OWN_HARNESS_MODULE_REQUIRED')
 module=types.ModuleType(name);module.__file__=str(HERE/'boot.py');sys.modules[name]=module
 try:
  exec(compile(source,str(HERE/'boot.py')+'::functional-harness','exec'),module.__dict__)
  if sys.argv[1:]!=['--cleanup']:
   module.functional_mode_and_original_args(sys.argv[1:]);module.STATE['functionalReadonlyDependency']=existing_node_readonly_preflight()
  return module.main()
 finally:sys.modules.pop(name,None)
if __name__=='__main__':
 try:raise SystemExit(main())
 except Exception as error:
  codes={'FUNCTIONAL_MANIFEST_SCHEMA','CLOSED_RUNTIME_DEPENDENCIES_REQUIRED','FUNCTIONAL_RUNTIME_DEPENDENCY_MISMATCH','DERIVED_FUNCTIONAL_SOURCE_MISMATCH','EXISTING_NODE_REQUIRED','EXISTING_NODE_PREFLIGHT_TIMEOUT','EXISTING_NODE_PREFLIGHT_REFUSED','EXISTING_NODE_WEBSOCKET_REQUIRED','FRESH_OWN_HARNESS_MODULE_REQUIRED','EXACT_EXPLICIT_FUNCTIONAL_PLUS_SIX_FLAGS_REQUIRED','ORIGINAL_INSTALL_FLAG_SCOPE_REQUIRED'}
  code=str(error)if str(error)in codes else'HARNESS_SCHEMA_OR_IO_REFUSED'
  out=Path('evidence/android-functional');out.mkdir(parents=True,exist_ok=True)
  (out/'harness-entry-refusal.json').write_text(json.dumps({'status':'OWN_FUNCTIONAL_HARNESS_REFUSED','code':code,'errorClass':type(error).__name__,'scope':'Own entry/dependency/cleanup error only; inspect original receipt if main began. No exception body exported.'},indent=2)+'\n')
  sys.stderr.write('OWN_FUNCTIONAL_HARNESS_REFUSED '+code+'\n');raise SystemExit(2)
