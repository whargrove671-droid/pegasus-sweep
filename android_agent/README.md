# Android agent — source

This is the on-device side of Pegasus-Sweep for Android. It enumerates
programmatically-accessible signals that a surveillance impl/agent would
commonly rely on and POSTs a JSON snapshot to your dashboard's `/api/ingest`.

**Scope & honesty.** Modern Android (10+) drops most APIs that could see other
apps' runtime details or read their data. This agent can reliably see:
installed packages + their grants (`PACKAGE_USAGE_STATS`, accessibility
services, device admin / device owner, overlay permission), and app-visible
process names via `ActivityManager`/`Runtime.exec("ps")` where permitted by the
OS. It **cannot** see another app's files or memory — so absence of findings is
not proof of non-infection; treat output as triage.

This is your own tooling running on a device you control. Install it yourself;
the server-side token (`PSM_SWEEP_TOKEN`) keeps your dashboard private.

## Build

Requires Android SDK (AGP 8.x) + JDK 17.

```bash
cd android_agent
echo "sdk.dir=C\\:/path/to/Android/Sdk" > local.properties
./gradlew :app:assembleDebug      # -> app/build/outputs/apk/debug/app-debug.apk
adb install -r app/build/outputs/apk/debug/app-debug.apk
```

## Run / configure

1. Open the app, grant **Usage Access** when prompted (required to see package
   usage + enabled accessibility services). Grant BATTERY_OPTIMIZATION exemption
   so background collection isn't killed.
2. Set the server URL and API token in the app's UI, then start the agent.
3. The agent collects a snapshot and POSTs it to
   `POST {server}/api/ingest` with body
   `{"target":"android","source_label":<label>,"snapshot":{…}}` and header
   `X-Api-Key: <token>`.

## What the snapshot contains

Each field is what public Android APIs expose to a normal app:

- `packages` — every get-installed-applications package; per package the
  flags `is_device_owner`, `device_admin`, `has_accessibility`,
  `can_overlay` (from Settings).
- `services_abusing` — the currently-enabled AccessibilityService classes
  (impls/accessibility abuse often show up here).
- `processes` — process names visible via `ActivityManager` / `ps` (often empty
  on Android 10+; best-effort).
- `artifacts` — optional list of `{path, content?}` the device owner drops in
  (e.g. MVT output). Only included if explicitly provided.

Code is under `app/src/main/java/ios/spyware/sweep/`.