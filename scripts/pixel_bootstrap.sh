#!/usr/bin/env bash
# =============================================================================
# pixel_bootstrap.sh
# Night bootstrap for the Pixel LAN Direct Agent.
#
# Strips the workflow to two runs:
#   run 1 (inventory)  - verify repository, APK integrity, no forbidden deps
#   run 2 (bootstrap)  - detect pixel, install, verify, launch, prepare pairing
#
# ADB is used ONLY for install/bootstrap. The persistent management path is
# the WebRTC DataChannel (DTLS/SCTP). This script never touches WireGuard,
# VPN config, firewalls, DHCP, DNS, or VPS networking.
#
# Inputs:
#   PIXEL_APK_OVERRIDE  (env)  path to APK (default: repo debug APK)
#   ADB_BIN             (env)  adb binary (tests substitute a fake)
#   PIXEL_SERIAL        (env)  force a specific authorized serial
#   SIGNALING_PORT      (env)  rendezvous port override (default 8991)
#
# Flags:
#   --check-only      run inventory checks only, exit before device detection
#   --verify-only     verify APK + repo, exit before touching any device
#   --serial <S>      force serial (equivalent to PIXEL_SERIAL)
#   --no-launch       do not auto-start the agent after install
#   --quiet-reports   print [OUT ...] report lines as they are produced
#
# Exit codes (stable): see PIXEL_EXIT_* in scripts/lib/pixel_bootstrap_lib.sh
#
#  0  OK
#  2  usage error
#  7  APK missing or SHA mismatch
#  12 preflight failure
#  3  no device detected
#  4  device present but not authorized
#  6  multiple devices (must select one)
#  8  install failed
#  9  package not present after install
#  10 launch failed
# =============================================================================

set -uo pipefail

PIXEL_LIB="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/lib" >/dev/null 2>&1 && pwd)/pixel_bootstrap_lib.sh"
# shellcheck source=scripts/lib/pixel_bootstrap_lib.sh
. "$PIXEL_LIB"

MODE="bootstrap"
FORCE_SERIAL=""
NO_LAUNCH=0
QUIET_REPORTS=0

usage() {
    cat <<EOF
Usage: $(basename "$0") [--check-only|--verify-only|--serial SERIAL|--no-launch|--quiet-reports]

  --check-only      inventory only (repo, APK integrity, architectural scans); no device needed
  --verify-only     same as --check-only (kept for symmetry with the night wrapper)
  --serial <S>      force an authorized pixel serial (also: env PIXEL_SERIAL)
  --no-launch       install + verify, but do NOT auto-start the agent
  --quiet-reports   show [OUT key=value] report lines as they are produced
  -h|--help         this help

Exit codes: 0 done, 2 usage, 3 device missing, 4 device unauthorized,
6 multiple devices, 7 apk, 8 install, 9 verify, 10 launch, 12 preflight.
EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        --check-only | --verify-only) MODE="inventory" ;;
        --serial) shift; FORCE_SERIAL="$1" ;;
        --no-launch) NO_LAUNCH=1 ;;
        --quiet-reports) QUIET_REPORTS=1 ;;
        -h | --help) usage; exit 0 ;;
        *) plx_die "$PIXEL_EXIT_USAGE" "unknown option: $1" ;;
    esac
    shift
done

if [ -n "$FORCE_SERIAL" ]; then
    PIXEL_SERIAL_FORCED="$FORCE_SERIAL"
elif [ -n "${PIXEL_SERIAL:-}" ]; then
    PIXEL_SERIAL_FORCED="$PIXEL_SERIAL"
fi

plx_step "=== Pixel LAN Direct bootstrap ==="

# -- Phase A: repository / artifact integrity (no device required) -----------
plx_preflight || exit $?
plx_verify_repo_state || plx_die "$PIXEL_EXIT_PREFLIGHT" "repository not at approved state"
plx_verify_apk || exit $?
plx_architecture_scan || plx_die "$PIXEL_EXIT_PREFLIGHT" "forbidden functional dependency detected"
plx_adb_transport_scan || plx_die "$PIXEL_EXIT_PREFLIGHT" "ADB-as-management usage detected"
plx_verify_transport_config

if [ "$MODE" = "inventory" ]; then
    plx_secret_scan || plx_die "$PIXEL_EXIT_PREFLIGHT" "secret scan failed"
    plx_step "=== Inventory complete (no device touched) ==="
    exit "$PIXEL_EXIT_OK"
fi

# -- Phase B: device detection + Android authorization ------------------------
plx_require_authorized || exit $?
SERIAL="$PIXEL_SERIAL"

# -- Phase C: install, verify, launch -----------------------------------------
plx_install_apk "$SERIAL" || exit $?
plx_verify_install "$SERIAL" || exit $?

if [ "$NO_LAUNCH" -eq 0 ]; then
    plx_launch_app "$SERIAL" || exit $?
fi

# -- Phase D: post-install readiness + LAN discovery (read-only) --------------
plx_post_install_checks "$SERIAL"
plx_collect_network_info "$SERIAL"

# -- Phase E: reporting --------------------------------------------------------
plx_report "DEVICE" "$SERIAL"
plx_management_channel_statement

plx_step "=== Bootstrap install phase complete ==="
plx_info "Pixel agent installed from approved APK and (optionally) launched."
plx_info "Machine-visible state is reported above; remaining tests require an"
plx_info "authorized controller and are part of the device-side run."
[ "$QUIET_REPORTS" -eq 1 ] && : # reports already emitted inline

exit "$PIXEL_EXIT_OK"