"""Version-bound owned-test harness derivation. Never rewrites the default boot source."""
import ast,hashlib
DEFAULT_SHA='a8b10a84c2b0126b00744fac2926a87734ab9e58fb86ac095076e63b9b17c14b'
HELPERS='''
def functional_mode_and_original_args(argv):
    original=[CHROME_TERMS_APPROVAL_FLAG,OWNED_LAB_CONTINUATION_FLAG,OWNED_MENU_OBSERVATION_FLAG,OWNED_ADD_HOME_FLAG,OWNED_INSTALL_OPTION_FLAG,OWNED_CONFIRM_INSTALL_FLAG]
    if len(argv)!=7 or argv[:6]!=original or argv[-1]not in ['--explicit-v16-functional-url','--explicit-v16-functional-eof','--explicit-v16-functional-failure']:raise Refused('EXACT_EXPLICIT_FUNCTIONAL_PLUS_SIX_FLAGS_REQUIRED')
    if selected_phase_cap(original)!=480:raise Refused('ORIGINAL_INSTALL_FLAG_SCOPE_REQUIRED')
    return argv[-1].removeprefix('--explicit-v16-functional-'),original

def selected_functional_phase_cap(argv):
    mode,_=functional_mode_and_original_args(argv);STATE['functionalMode']=mode;return 900

'''
def derive(raw):
 if not isinstance(raw,bytes)or hashlib.sha256(raw).hexdigest()!=DEFAULT_SHA:raise ValueError('EXACT_DEFAULT073E_BOOT_REQUIRED')
 source=raw.decode('utf-8');after=source;edits=[
  ("OUT=Path('evidence/android-boot')","OUT=Path('evidence/android-functional')"),
  ("value=min(limit,CAP-(time.monotonic()-START))","value=min(limit,CAP-80-(time.monotonic()-START))"),
  ("    observe_installed_pwa_readonly()\n\ndef observe_installed_pwa_readonly():","    observe_installed_pwa_readonly()\n    if STATE.get('installedPWAStandaloneObserved')is not True:raise Refused('STOP_NO_ACTUAL_INSTALLED_STANDALONE')\n    import functional_acquire\n    STATE['functionalObservation']=functional_acquire.acquire(sys.modules[__name__],STATE['functionalMode']);save()\n    expected={'url':'BOUNDED_URL_HISTORY_STATES_QUALIFIED','eof':'BOUNDED_SETTLED_EOF_EVENTS_QUALIFIED','failure':'BOUNDED_ORDINARY_PLAY_RECOVERY_FACTS_QUALIFIED'}[STATE['functionalMode']]\n    if STATE['functionalObservation'].get('status')!=expected:raise Refused('REQUESTED_BOUNDED_FUNCTIONAL_FACTS_UNACQUIRED')\n    STATE['status']='STOP_AFTER_BOUNDED_FUNCTIONAL_FACTS_NO_AUDIO_VERDICT';save()\n\ndef observe_installed_pwa_readonly():"),
  ("def main():\n",HELPERS+"def main():\n"),
  ("    if '--cleanup' in sys.argv:\n", "    if '--cleanup' in sys.argv and sys.argv[1:]!=['--cleanup']:raise Refused('EXACT_CLEANUP_ONLY_REQUIRED')\n    if '--cleanup' in sys.argv:\n"),
  ("CAP=selected_phase_cap(sys.argv[1:]);STATE['phaseCapSeconds']=CAP;STATE['phaseCapScope']='EXPLICIT_FINAL_INSTALL_480' if CAP==480 else 'DEFAULT_OBSERVATION_360';save()","CAP=selected_functional_phase_cap(sys.argv[1:]);STATE['phaseCapSeconds']=CAP;STATE['phaseCapScope']='EXPLICIT_FUNCTIONAL_900_WORK_820_CLEANUP_80';save()"),
  ("if maybe_approved_chrome_terms_action(lines,sys.argv[1:]):return 0", "if maybe_approved_chrome_terms_action(lines,functional_mode_and_original_args(sys.argv[1:])[1]):return 0")]
 for old,new in edits:
  if after.count(old)!=1:raise ValueError('UNIQUE_SEALED_FUNCTIONAL_ANCHOR_REQUIRED')
  after=after.replace(old,new)
 ast.parse(after);return after
