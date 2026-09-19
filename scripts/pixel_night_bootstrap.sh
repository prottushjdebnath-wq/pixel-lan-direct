#!/usr/bin/env bash
# =============================================================================
# pixel_night_bootstrap.sh
# Night bootstrap wrapper: waits (physically, unattended) for the Pixel to be
# plugged in and authorized, then delegates install + readiness to
# bootstrap.sh. Optionally blocks until a controller confirms reachability.
#
# ADB is used ONLY for install/bootstrap. The persistent management path is
# the WebRTC DataChannel (DTLS/SCTP). No WireGuard/VPN/firewall/DHCP/DNS/VPS
# configuration is every created or modified here.
#
# Inputs:
#   ADB_BIN             (env) adb binary
#   PIXEL_SERIAL        (env) force a specific authorized serial
#   PIXEL_ADB_CONNECT_TARGETS (env, optional) space- or comma-separated
#                             "host:port" endpoints to attempt before waiting
#                             (purely a convenience; NEVER hard-coded)
#
# Flags:
#   --timeout <s>   max seconds to wait for the Pixel (default 3600)
#   --poll <s>      poll interval (default 15)
#   --once          exit as soon as install+readiness are done (default)
#   --until-ready   additionally wait for the controller to verify reachability
#   --serial <S>    force serial (equivalent to PIXEL_SERIAL)
#   --no-launch     install + verify, do NOT auto-start the agent
#
# Exit codes: mirror bootstrap.sh (0=done, 3=timeout waiting for device,
# 4=unauthorized, 6=multiple, 8/9/10 install/verify/launch, 12=preflight).
# =============================================================================

set -uo pipefail

PIXEL_LIB="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/lib" >/dev/null 2>&1 && pwd)/pixel_bootstrap_lib.sh"
# shellcheck source=scripts/lib/pixel_bootstrap_lib.sh
. "$PIXEL_LIB"

WAIT_TIMEOUT=3600
POLL_SECONDS=15
ONCE=1
WAIT_READY=0
FORCE_SERIAL=""
NO_LAUNCH=0

usage() {
    cat <<EOF
Usage: $(basename "$0") [OPTIONS]

  --timeout <s>     max seconds to wait for the Pixel (default 3600)
  --poll <s>        poll interval (default 15)
  --once            exit after install+readiness (default)
  --until-ready     keep waiting for controller-side reachability (paired via
                    the WebRTC DataChannel; requires an authorized controller)
  --serial <S>      force an authorized pixel serial (also env PIXEL_SERIAL)
  --no-launch       install + verify, do NOT auto-start the agent
  -h|--help         help
EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        --timeout) shift; WAIT_TIMEOUT="$1" ;;
        --poll) shift; POLL_SECONDS="$1" ;;
        --once) ONCE=1 ;;
        --until-ready) ONCE=0; WAIT_READY=1 ;;
        --serial) shift; FORCE_SERIAL="$1" ;;
        --no-launch) NO_LAUNCH=1 ;;
        -h | --help) usage; exit 0 ;;
        *) plx_die "$PIXEL_EXIT_USAGE" "unknown option: $1" ;;
    esac
    shift
done

case "$WAIT_TIMEOUT" in
    ''|*[!0-9]*) plx_die "$PIXEL_EXIT_USAGE" "--timeout must be a non-negative integer (seconds)" ;;
esac
case "$POLL_SECONDS" in
    ''|*[!0-9]*) plx_die "$PIXEL_EXIT_USAGE" "--poll must be a positive integer (seconds)" ;;
esac

if [ -n "$FORCE_SERIAL" ]; then
    PIXEL_SERIAL_FORCED="$FORCE_SERIAL"
elif [ -n "${PIXEL_SERIAL:-}" ]; then
    PIXEL_SERIAL_FORCED="$PIXEL_SERIAL"
fi

plx_step "=== Pixel LAN Direct night bootstrap ==="

# Optional convenience: user-supplied adb-wired endpoints (NEVER guessed).
if [ -n "${PIXEL_ADB_CONNECT_TARGETS:-}" ]; then
    (IFS=', ' read -ra targets <<<"$PIXEL_ADB_CONNECT_TARGETS"; for t in "${targets[@]}"; do [ -n "$t" ] && plx_adb connect "$t" >/dev/null 2>&1 || true; done) \
        || plx_warn "ignoring PIXEL_ADB_CONNECT_TARGETS (unparsable)"
    plx_info "Attempted user-supplied adb connect targets (optional convenience only)"
fi

# -- Wait for an authorized device (respects serial selection / multi-device) --
plx_step "Waiting for Pixel (timeout ${WAIT_TIMEOUT}s, poll ${POLL_SECONDS}s)"
elapsed=0
while :; do
    plx_classify_device
    case "$PIXEL_DEVICE_CLASS" in
        DEVICE)
            plx_ok "Pixel reached authorized state: $PIXEL_SERIAL"
            break
            ;;
        UNAUTHORIZED)
            plx_info "device(s) present but USB authorization pending; keep the Pixel screen unlocked and accept \"Allow USB debugging\""
            ;;
        MULTIPLE)
            plx_print_device_list
            plx_die "$PIXEL_EXIT_MULTIPLE" "multiple devices - select exactly one via --serial / PIXEL_SERIAL"
            ;;
        NO_DEVICE)
            plx_info "no Android device yet - keep the Pixel plugged in (USB) with wire debugging enabled"
            ;;
    esac
    if [ "$elapsed" -ge "$WAIT_TIMEOUT" ]; then
        plx_fail "WAITING_FOR_PIXEL (timeout ${WAIT_TIMEOUT}s)"
        exit "$PIXEL_EXIT_WAITING"
    fi
    sleep "$POLL_SECONDS"
    elapsed=$((elapsed + POLL_SECONDS))
done

# -- Install + readiness (delegate; same exit codes) --------------------------
SERIAL="$PIXEL_SERIAL"

BOOTSTRAP="$PIXEL_REPO_ROOT/scripts/pixel_bootstrap.sh"
plx_step "Installing approved APK on $SERIAL (via bootstrap.sh)"
args=("--serial" "$SERIAL")
[ "$NO_LAUNCH" -eq 1 ] && args+=("--no-launch")
args+=("--quiet-reports")
"$BOOTSTRAP" "${args[@]}"
rc=$?
case "$rc" in
    0) ;;
    *) exit "$rc" ;;
esac

# -- Optional: wait for controller-side reachability (requires a controller) --
if [ "$WAIT_READY" -eq 1 ]; then
    plx_step "Waiting for controller verifiable reachability (Ctrl+C to abort, timeout ${WAIT_TIMEOUT}s)"
    elapsed=0
    while :; do
        # Reachability is confirmed by the CONTROLLER over the WebRTC
        # DataChannel, never by this script. Exact probe is out of scope here;
        # defer to a controller-side watchdog (pairing transcript) instead.
        plx_info "controller-side probe pending (verified with an authorized controller app)"
        sleep "$POLL_SECONDS"
        elapsed=$((elapsed + POLL_SECONDS))
        [ "$elapsed" -lt "$WAIT_TIMEOUT" ] || {
            plx_fail "controller reachability not confirmed before timeout"
            exit "$PIXEL_EXIT_WAITING"
        }
    done
fi

plx_step "=== Night bootstrap complete (install + readiness) ==="
exit "$PIXEL_EXIT_OK"