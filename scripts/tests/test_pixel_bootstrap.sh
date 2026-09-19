#!/usr/bin/env bash
# =============================================================================
# test_pixel_bootstrap.sh
# Offline (no-hardware) test-suite for the pixel bootstrap workflow.
#
# Exercises:
#   - script/library syntax
#   - inventory mode (no device required; verifies INTEGRITY + architecture)
#   - APK SHA mismatch handling
#   - device-class handling: none / unauthorized / multiple / forced serial
#   - install / verify-install / launch failure paths (via fake adb)
#   - device disconnecting mid-run (safe stop)
#   - night wrapper timeout behavior
#
# Run:  scripts/tests/test_pixel_bootstrap.sh
# Exit: 0 all PASS, 1 any FAIL.
# =============================================================================

set -uo pipefail

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
REPO_ROOT="$(CDPATH= cd -- "$SCRIPT_DIR/../.." >/dev/null 2>&1 && pwd)"
LIB="$REPO_ROOT/scripts/lib/pixel_bootstrap_lib.sh"
BOOTSTRAP="$REPO_ROOT/scripts/pixel_bootstrap.sh"
NIGHT="$REPO_ROOT/scripts/pixel_night_bootstrap.sh"
FAKE_ADB="$SCRIPT_DIR/fake_adb.sh"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

PASS=0
FAIL=0
CURRENT=""

note() { :; }

report() {
    local status="$1" name="$2"
    if [ "$status" = "PASS" ]; then
        PASS=$((PASS + 1))
        printf '  [PASS] %s\n' "$name"
    else
        FAIL=$((FAIL + 1))
        printf '  [FAIL] %s\n' "$name"
    fi
}

check() {
    local name="$1" rc="$2" expect="$3"
    if [ "$rc" -eq "$expect" ]; then
        report PASS "$name"
    else
        report FAIL "$name (rc=$rc, expected $expect)"
    fi
}

syntax_ok() {
    local file="$1"
    bash -n "$file"
}
check_syntax() {
    if syntax_ok "$1"; then report PASS "syntax: $(basename "$1")"; else report FAIL "syntax: $(basename "$1")"; fi
}

run_bootstrap() {
    ADB_BIN="$FAKE_ADB" \
    PIXEL_APK_OVERRIDE="${PIXEL_APK_OVERRIDE:-$REPO_ROOT/android-agent/app/build/outputs/apk/debug/app-debug.apk}" \
    FAKE_DEVICES="${FAKE_DEVICES:-}" \
        "$BOOTSTRAP" "$@"
}

run_night() {
    ADB_BIN="$FAKE_ADB" \
    PIXEL_APK_OVERRIDE="${PIXEL_APK_OVERRIDE:-$REPO_ROOT/android-agent/app/build/outputs/apk/debug/app-debug.apk}" \
    FAKE_DEVICES="${FAKE_DEVICES:-}" \
        "$NIGHT" "$@"
}

# ---------------------------------------------------------------------------
printf '\n== Syntax ==\n'
check_syntax "$LIB"
check_syntax "$BOOTSTRAP"
check_syntax "$NIGHT"
check_syntax "$FAKE_ADB"

printf '\n== Inventory (no device required) ==\n'
# The approved APK must exist for the integrity test to be meaningful.
if [ -f "$REPO_ROOT/android-agent/app/build/outputs/apk/debug/app-debug.apk" ]; then
    ADB_BIN="$FAKE_ADB" "$BOOTSTRAP" --check-only >"$TMP/inv.log" 2>&1
    check "inventory mode exits 0 (integrity+arch PASS on real repo)" $? 0
    grep -q 'APK verified' "$TMP/inv.log" && report PASS "inventory verifies APK SHA-256" \
        || report FAIL "inventory verifies APK SHA-256"
    grep -q 'ARCHITECTURE_SCAN=PASS' "$TMP/inv.log" && report PASS "architecture/forbidden-dep scan PASS" \
        || report FAIL "architecture/forbidden-dep scan PASS"
    grep -qi 'no secret' "$TMP/inv.log" && report PASS "secret scan clean on real repo" \
        || report FAIL "secret scan clean on real repo"
else
    report FAIL "precondition: approved debug APK exists (build required before tests)"
fi

tmp_apk="$TMP/bad.apk"
printf 'not-an-apk-not-the-real-sha\n' > "$tmp_apk"
ADB_BIN="$FAKE_ADB" PIXEL_APK_OVERRIDE="$tmp_apk" "$BOOTSTRAP" --check-only >"$TMP/apk.log" 2>&1
check "APK SHA mismatch -> exit 7" $? 7

printf '\n== Device-class handling ==\n'
ADB_BIN="$FAKE_ADB" FAKE_DEVICES= "$BOOTSTRAP" >"$TMP/none.log" 2>&1
check "no device -> WAITING exit 3" $? 3

ADB_BIN="$FAKE_ADB" FAKE_DEVICES='FAKESERIAL01  unauthorized model=Pixel_8' "$BOOTSTRAP" >"$TMP/unauth.log" 2>&1
check "unauthorized device -> exit 4" $? 4
grep -q 'AWAITING_ANDROID_AUTHORIZATION' "$TMP/unauth.log" && report PASS "authorization prompt is explicit" \
    || report FAIL "authorization prompt is explicit"

ADB_BIN="$FAKE_ADB" FAKE_DEVICES=$'SER_A  device model=Pixel_8\nSER_B  device model=Pixel_9' \
    "$BOOTSTRAP" >"$TMP/multi.log" 2>&1
check "two authorized devices, no serial -> exit 6 (never guess)" $? 6

ADB_BIN="$FAKE_ADB" FAKE_DEVICES=$'SER_A  device model=Pixel_8\nSER_B  device model=Pixel_9' \
    FAKE_INSTALL_RESULT='Success' \
    "$BOOTSTRAP" --serial SER_B >"$TMP/forced.log" 2>&1
check "forced serial selection succeeds -> exit 0" $? 0
grep -q 'DEVICE=SER_B' "$TMP/forced.log" && report PASS "forced serial honored (SER_B)" \
    || report FAIL "forced serial honored (SER_B)"

printf '\n== Install / launch failure paths ==\n'
ADB_BIN="$FAKE_ADB" FAKE_INSTALL_RESULT='Failure [INSTALL_FAILED_USER_RESTRICTED]' \
    FAKE_DEVICES='SER_X  device model=Pixel_8' \
    "$BOOTSTRAP" --no-launch >"$TMP/instfail.log" 2>&1
check "install rejected -> exit 8" $? 8
grep -q 'Install unknown apps' "$TMP/instfail.log" && report PASS "physical user-action hint surfaced for install" \
    || report FAIL "physical user-action hint surfaced for install"

ADB_BIN="$FAKE_ADB" FAKE_INSTALL_RESULT='Success' FAKE_PM_LIST='package:com.other.junk' \
    FAKE_DEVICES='SER_Y  device model=Pixel_8' \
    "$BOOTSTRAP" --no-launch >"$TMP/verifyfail.log" 2>&1
check "package not present after install -> exit 9" $? 9

ADB_BIN="$FAKE_ADB" FAKE_INSTALL_RESULT='Success' FAKE_AM_START='Error type 3' \
    FAKE_DEVICES='SER_Z  device model=Pixel_8' \
    "$BOOTSTRAP" >"$TMP/launchfail.log" 2>&1
check "app launch fails -> exit 10" $? 10

printf '\n== Happy path with device (deterministic report) ==\n'
ADB_BIN="$FAKE_ADB" FAKE_INSTALL_RESULT='Success' \
    FAKE_DEVICES='SER_OK  device model=Pixel_8' \
    "$BOOTSTRAP" --no-launch >"$TMP/ok.log" 2>&1
rc=$?
check "install+verify+ready path -> exit 0" $rc 0
for key in APK_VERIFIED=YES PACKAGE_INSTALLED=YES FOREGROUND_SERVICE=YES AGENT_PROCESS=YES \
           NET_GATEWAY ARCHITECTURE_SCAN=PASS; do
    grep -qF "$key" "$TMP/ok.log" && report PASS "report contains '$key'" \
        || report FAIL "report contains '$key'"
done
grep -q 'DEVICE=SER_OK' "$TMP/ok.log" && report PASS "report DEVICE=SER_OK" \
    || report FAIL "report DEVICE=SER_OK"

printf '\n== Device disconnection (safe stop) ==\n'
devfile="$TMP/devices.txt"
printf 'DISC_DEV  device model=Pixel_8\n' > "$devfile"
ADB_BIN="$FAKE_ADB" FAKE_DEVICES_FILE="$devfile" FAKE_DEVICES='DISC_DEV  device model=Pixel_8' \
    FAKE_INSTALL_RESULT='Success' FAKE_DISCONNECT_ON_CHANNEL='dumpsys package' \
    "$BOOTSTRAP" --no-launch >"$TMP/disc.log" 2>&1
rc=$?
check "device disappears mid-run -> safe stop exit 5" $rc 5
grep -q 'DEVICE_DISCONNECTED' "$TMP/disc.log" && report PASS "disconnect diagnostic printed" \
    || report FAIL "disconnect diagnostic printed"

printf '\n== Night wrapper ==\n'
ADB_BIN="$FAKE_ADB" FAKE_DEVICES= "$NIGHT" --timeout 1 --poll 1 >"$TMP/night1.log" 2>&1
check "night wrapper timeout with no device -> exit 3" $? 3

printf 'NIGHT_SER  device model=Pixel_8\n' > "$TMP/nightdev.txt"
ADB_BIN="$FAKE_ADB" FAKE_DEVICES_FILE="$TMP/nightdev.txt" FAKE_INSTALL_RESULT='Success' \
    "$NIGHT" --timeout 2 --poll 1 --no-launch >"$TMP/night2.log" 2>&1 &
NPID=$!
sleep 0.5
printf 'NIGHT_SER  device model=Pixel_8\n' > "$TMP/nightdev.txt"
wait "$NPID"
check "night wrapper reaches authorized device -> exit 0" $? 0

printf '\n== Fake adb shim sanity ==\n'
out="$(ADB_BIN="$FAKE_ADB" FAKE_DEVICES='SANITY1 device model=Pixel_8' "$FAKE_ADB" devices -l)"
printf '%s' "$out" | grep -q 'SANITY1' && report PASS "fake adb reports device" \
    || report FAIL "fake adb reports device"

printf '\n== Summary ==\n'
printf '  PASS: %d   FAIL: %d\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ] || exit 1
exit 0