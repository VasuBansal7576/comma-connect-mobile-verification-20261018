#!/bin/bash
set -euo pipefail
mkdir -p evidence
uname -a > evidence/uname.txt
sw_vers > evidence/macos.txt
xcodebuild -version > evidence/xcode.txt
xcrun simctl list --json > evidence/simulators.json
xcrun simctl io help > evidence/simctl-io-help.txt 2>&1 || true
system_profiler SPAudioDataType -json > evidence/audio-devices.json
if command -v SwitchAudioSource >/dev/null; then
  SwitchAudioSource -a -f json > evidence/switchaudio-devices.json
  SwitchAudioSource -c -f json > evidence/default-output.json
fi
# Inspect licenses/runtime only. No -license accept, firstLaunch, sdkmanager, TCC writes.
