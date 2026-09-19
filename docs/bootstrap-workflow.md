# Pixel LAN Direct - Night Bootstrap Workflow

Purpose: install the Pixel agent onto a physical Pixel from an approved APK,
verify the installation, and prepare the LAN for self-hosting the signaling
broker - with **zero** changes to WireGuard, VPN config, VPS networking,
DNS, DHCP, routing, or firewall, and **no** credentials/keys created in this
repository.

## Safety contract

This workflow (scripts, tests, docs) never:

- modifies WireGuard / VPN configuration or interfaces,
- changes routes, firewall, DNS, DHCP, or VPS networking,
- creates Android or management-channel credentials/secrets,
- silently changes Android security settings,
- grants privileged permissions without explicit user interaction,
- uses ADB for anything beyond **install/bootstrap**.

The persistent management channel is the **WebRTC DataChannel (DTLS/SCTP)**.
Signaling is a rendezvous (SDP/ICE) only; the controller and the agent
self-host the LAN broker (port `8990`) when the phone and controller share a
Wi-Fi network. No VPS hostname or public IP is baked into any run-time config
(the agent defaults to Google STUN), so the system remains VPS-independent.

## Components

| Path | Purpose |
|---|---|
| `scripts/pixel_bootstrap.sh` | Interactive bootstrap (detect, authorize, install, verify, launch, readiness) |
| `scripts/pixel_night_bootstrap.sh` | Unattended night wrapper (waits for the Pixel, then delegates) |
| `scripts/lib/pixel_bootstrap_lib.sh` | Shared helpers, exit codes, ADB wrapper |
| `scripts/tests/fake_adb.sh` | Deterministic ADB shim for offline tests |
| `scripts/tests/test_pixel_bootstrap.sh` | Offline (no-hardware) test suite |
| `docs/bootstrap-workflow.md` | This document |

### Repo-approved artifact (single source of truth)

- Approved commit: `632484f8d2453e84f3e1a6c83fb8effec3ead7ef`
- APK: `android-agent/app/build/outputs/apk/debug/app-debug.apk`
- SHA-256: `7f733504a7c57eb7ee4f032f1e248b36d7f6db3dc2f7812e4207d2da714a05c4`
- Package: `com.pixel.lanagent` (versionCode 1, versionName 1.0.0)
- Main activity: `com.pixel.lanagent/.MainActivity`

The scripts verify HEAD equals the approved commit, the working tree has no
modifications to tracked files, and the APK's SHA-256 matches before any
device is touched.

## Run order

### 1. Inventory (no device required)

```bash
scripts/pixel_bootstrap.sh --check-only
```

Verifies repository state, APK integrity, architectural scans (no forbidden
dependencies: WireGuard / VPN / VPS identity / hard-coded LAN IPs; no ADB
usage as a management transport), signaling/STUN configuration, and a secret
scan. Exit codes: `0` pass, `7` APK problem, `12` preflight / scan failure.

### 2. Interactive bootstrap (Pixel physically present)

```bash
scripts/pixel_bootstrap.sh                # or add --serial <S>, --no-launch
```

1. **Device detection** - waits for exactly one authorized device. If one is
   present but `unauthorized`, instructs the user to tap *Allow USB debugging*
   (and *Always allow from this computer*). Never guesses between multiple
   devices (`--serial` required).
2. **Install** - `adb install -r`; on platform-blocked installs, surfaces
   the exact Android setting to enable (*Special app access -> Install unknown
   apps* / USB install confirmation).
3. **Verify install** - package present, version reported.
4. **Optional launch** - `am start` for `com.pixel.lanagent` (skip with
   `--no-launch`).
5. **Readiness checks** (read-only): foreground service, accessibility
   service, notification permission, battery (doze), LAN signaling listener
   on local address `:8990`, plus current device-reported IP/gateway/SSID.
   None of these change state; they only report.
6. **Report** - `[OUT key=value]` lines for automation.

Exit codes (stable, machine-readable):

| Code | Meaning |
|---|---|
| 0 | Done / inventory pass |
| 1 | Generic abort |
| 2 | Usage error |
| 3 | Waiting for Pixel (none detected; night wrapper timed out) |
| 4 | Device present but not authorized (physical action required) |
| 5 | Device disconnected mid-operation (safe stop) |
| 6 | Multiple devices - selection required |
| 7 | APK missing or SHA mismatch |
| 8 | Install failed |
| 9 | Package not present after install / verify failed |
| 10 | App launch failed |
| 11 | Physical user action required |
| 12 | Preflight / repository or scan failure |

### 3. Night bootstrap (unattended)

```bash
scripts/pixel_night_bootstrap.sh --timeout 3600 --poll 15 [--serial <S>] [--no-launch]
```

- Polls until an authorized Pixel appears (or `--timeout`),
- optionally honors `PIXEL_ADB_CONNECT_TARGETS` (user-supplied
  `host:port` list; purely a convenience, never hard-coded),
- delegates to `pixel_bootstrap.sh --serial <S>`,
- supports `--until-ready` to optionally wait for a controller-side
  reachability confirmation (requires an authorized controller over the
  WebRTC DataChannel; this script does not probe reachability itself).

## Physical actions (automated scripts will stop and wait here)

For a fully unattended night run, have these already set on the Pixel:

1. **USB debugging** enabled (Developer options), screen unlocked, USB
   configured for *File transfer* (or *USB debugging* on some builds).
2. **Allow USB debugging** - accept once; check *Always allow from this
   computer*, otherwise the machine will get exit `4`.
3. **Install unknown apps / USB install confirmation** (Settings -> Apps ->
   Special app access), since Android blocks `adb install` otherwise;
   otherwise exit `8`.
4. **Grant permissions at first launch** (read-only checks report, but the
   user must approve): notifications, accessibility service enablement,
   and *Battery optimization -> Don't optimize*.
5. Keep the device awake (long cable, no screen-off-deep-sleep during
   install); `stay_awake` is fine if enabled.

None of these are **silently** granted by the workflow - the bootstrapper
reports and waits; it never automates security-sensitive grants.

## Post-install verification plan (PROVISIONAL - requires hardware)

The items below MUST be re-run against the physical Pixel the night of the
bootstrap. They are intentionally **NOT** executed by the offline suite.

### Transport & signaling (T-relay = T01-T06)

- [ ] T01 Signaling broker reachable on LAN http://`<pixel-wifi-ip>`:`8990`
- [ ] T02 Signaling handshake abandoned when type not in strict whitelist
- [ ] T03 Signaling drops forbidden message keys (no commands/telemetry)
- [ ] T04 STUN ICE candidates generated (default Google STUN) on both ends
- [ ] T05 DTLS certificate for DataChannel verified on both ends
- [ ] T06 Media/loopback test on the DataChannel (echo)

### Pairing & security (T-sec = T07-T12)

- [ ] T07 6-digit PIN UI on controller; PIN-entry on controller side
- [ ] T08 Pairing transcript = SHA-256(pixel_id|pixel_pub|ctl_pub|pin|nonce)
- [ ] T09 PIN TTL ~5 minutes enforced
- [ ] T10 3-attempt lockout enforced
- [ ] T11 ECDSA P-256 keypair persisted on device across reboot
- [ ] T12 No PIN/PK stored in signaling payloads (greps agree)

### Agent runtime (T-run = T13-T18)

- [ ] T13 Agent foreground service restored after reboot
- [ ] T14 LAN signaling listener re-binds `:8990` after reboot
- [ ] T15 Accessibility service stays enabled after reboot
- [ ] T16 Device-reported network state matches controller expectation
- [ ] T17 Doze/battery exemption holds after reboot
- [ ] T18 Notification permission persists after reboot

### Controller & flows (T-ctl = T19-T26)

- [ ] T19 Controller pairs over LAN tunnel establishing `:8990`
- [ ] T20 Controller-specific challenge/response over the DataChannel
- [ ] T21 Command execution round-trip (echo) < 1s
- [ ] T22 No command/screenshot/telemetry via signaling (audit)
- [ ] T23 WebRTC connection torn down cleanly on disconnect
- [ ] T24 Re-pair works after app force-stop
- [ ] T25 10 devices boot-storm test (steady-state)
- [ ] T26 Lane/Bandwidth usage on the shared account (no spike)

### Security & regression (T-reg = T27-T33)

- [ ] T27 No port 5555 (ADB over TCP) after bootstrap
- [ ] T28 `adb` no longer a management dependency (removed path)
- [ ] T29 No WireGuard/vpn/tun interface present on device after proof
- [ ] T30 All commits come from the machine, no foreign artifacts
- [ ] T31 No VPS hostname/public-IP in run-time config (gate SCAN_PASS)
- [ ] T32 Device shows no unexpected root/SUDAVAIL provisioning
- [ ] T33 `aapt dump badging` equals the pinned APK (SHA)

### Night-bootstrapper (T-night = T34-T35)

- [ ] T34 Night wrapper completes full install-line end-to-end with one
      authorized device after waiting up to `--timeout`
- [ ] T35 Night wrapper exits `6` (never guesses) on multiple devices

**Current status: all T01-T35 UNVERIFIED** until the physical Pixel run.

## Reporting

Every `[OUT key=value]` line is stable and intended for downstream
automation (dashboard/CI). Examples:

```
[OUT ] APK_VERIFIED=YES
[OUT ] ARCHITECTURE_SCAN=PASS
[OUT ] DEVICE=SER_OK
[OUT ] PACKAGE_INSTALLED=YES
[OUT ] NET_GATEWAY=... dev ...
[OUT ] LOCAL_BOOTSTRAP_ENDPOINT=http://<ip>:8990
```

## Developer / test mode

```bash
scripts/tests/test_pixel_bootstrap.sh
```

Runs the entire offline suite against `fake_adb.sh` (no hardware): syntax,
inventory, APK-integrity failure, device-class handling, install/verify/
launch failure paths, disconnect-safe-stop, and night-wrapper behaviour.

Environment hooks (never needed for normal operation):

- `ADB_BIN` - substitute an ADB shim/bin (used by the test suite)
- `PIXEL_APK_OVERRIDE` - test an alternate APK path (integrity must match)
- `PIXEL_SERIAL` / `--serial` - force a specific authorized serial
- `PIXEL_ADB_CONNECT_TARGETS` - optional `host:port` connect list (night only)
- `SIGNALING_PORT` - rendezvous port override (default `8991`)

## Out of scope (never done by these scripts)

- Creating GitHub releases, tokens, or publishing to any registry.
- Configuring WireGuard / VPN / firewall / DNS / DHCP / router.
- Fabricating device state; every network claim comes from the device.
- Installing anything on the Pixel outside `adb install -r` of the approved APK.