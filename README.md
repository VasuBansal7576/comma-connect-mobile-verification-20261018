# Comma Connect mobile verification lab

Free, bounded verification helpers for the public Comma Connect candidate test lab. Current product build: V15. This repository contains test-only code and generated fixture definitions; it contains no account credentials.

The first manual workflow inventories a fresh GitHub macOS runner, checks existing screen-capture permission without requesting or changing it, then calibrates digital system-audio capture with a native 440 Hz / silence / 440 Hz WAV. Audio generation refuses to run outside the remote GitHub macOS job. Nothing plays on the user’s Mac. It installs no SDKs or drivers, accepts no license agreements and does not change privacy settings.

A passing calibration establishes the capture path only. It does not verify an iPhone, installed PWA, physical speakers or either product issue. Results are retained as short-lived workflow artifacts. The product test lab is https://comma-connect-fix-lab-20261016.zippy17.chatgpt.site/v15/menu.

The installed-PWA feasibility workflow uses only preinstalled iOS runtimes and Xcode. It adds the owned fixture to Home Screen through actual Safari UI, launches the icon and checks both standalone flags. It captures the remote simulator’s digital output while the test taps playback controls. No HAL driver or extra SDK is installed. Simulator results remain distinct from physical iPhone results and from actual product verification.
