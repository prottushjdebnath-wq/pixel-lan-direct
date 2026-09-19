#!/usr/bin/env bash
# =============================================================================
# fake_adb.sh
# Deterministic ADB shim for the bootstrap test-suite. Mirrors the exact
# subcommand surface that pixel_bootstrap_lib.sh uses, so that the night
# bootstrap logic can be exercised WITHOUT any Android hardware.
#
# Control knobs (environment):
#   FAKE_DEVICES         newline-joined "<serial>  <state> model=..."; omit/empty = none
#   FAKE_DEVICES_FILE    if set, re-read FAKE_DEVICES from this file every call
#   FAKE_INSTALL_RESULT  install output (default "Failure [INSTALL_FAILED_USER_RESTRICTED]")
#   FAKE_PM_LIST         output of `pm list packages`
#   FAKE_PIDOF           output of `pidof`
#   FAKE_DUMPSYS_ACTIVITY  output of `dumpsys activity services`
#   FAKE_SETTINGS_ACCESS output of `settings get secure enabled_accessibility_services`
#   FAKE_APP_OPS         output of `appops get ... POST_NOTIFICATION`
#   FAKE_DEVICEIDLE      output of `dumpsys deviceidle whitelist`
#   FAKE_PROC_TCP        output of `cat /proc/net/tcp`
#   FAKE_BATTERY         output of `dumpsys battery`
#   FAKE_IP_ADDR         output of `ip -o addr show`
#   FAKE_IP_ROUTE        output of `ip route`
#   FAKE_DUMPSYS_CONN    output of `dumpsys connectivity`
#   FAKE_AM_START        output of `am start -n` (default success)
#   FAKE_DUMPSYS_PKG     version-name line for `dumpsys package`
#   FAKE_LOG             output of `logcat -d`
#   FAKE_DISCONNECT_ON_CHANNEL  shell command substring; when a shell command
#                               matches it, the device record is erased FIRST
#                               (`FAKE_DEVICES_FILE` is required for this) so a
#                               subsequent reconcile observes the device gone.
#
# The shim never inspects or modifies anything outside its own environment.
# =============================================================================

set -uo pipefail

fake_devices() {
    if [ -n "${FAKE_DEVICES_FILE:-}" ] && [ -r "$FAKE_DEVICES_FILE" ]; then
        cat "$FAKE_DEVICES_FILE"
    else
        printf '%s' "${FAKE_DEVICES:-}"
    fi
}

fake_maybe_disconnect() {
    local needle="${FAKE_DISCONNECT_ON_CHANNEL:-}"
    [ -n "$needle" ] || return 0
    case "$*" in
        *"$needle"*)
            if [ -n "${FAKE_DEVICES_FILE:-}" ]; then
                : > "$FAKE_DEVICES_FILE"
            fi
            ;;
    esac
}

fake_shell() {
    local cmd="$1"
    shift
    case "$cmd" in
        pm) [ "$1" = "list" ] && [ "$2" = "packages" ] && printf '%s\n' "${FAKE_PM_LIST:-package:com.pixel.lanagent}"; return 0 ;;
        dumpsys)
            case "$1" in
                package) printf '%s\n' "${FAKE_DUMPSYS_PKG:-versionCode=1 versionName=1.0.0}" ;;
                activity) printf '%s\n' "${FAKE_DUMPSYS_ACTIVITY:-isForeground=true}" ;;
                connectivity) printf '%s\n' "${FAKE_DUMPSYS_CONN:-WifiSsid: <+ SSID: 'PixelNet'>}" ;;
                deviceidle) printf '%s\n' "${FAKE_DEVICEIDLE:-sysui whitelist}" ;;
                battery) printf '%s\n' "${FAKE_BATTERY:-  level: 88}" ;;
                *) : ;;
            esac
            return 0 ;;
        am) [ "$1" = "start" ] && printf '%s\n' "${FAKE_AM_START:-Starting: Intent { cmp=com.pixel.lanagent/.MainActivity }}" ; return 0 ;;
        pidof) printf '%s\n' "${FAKE_PIDOF:-12345}" ; return 0 ;;
        settings) printf '%s\n' "${FAKE_SETTINGS_ACCESS:-com.pixel.lanagent/.RemoteAccessibilityService}" ; return 0 ;;
        appops) printf '%s\n' "${FAKE_APP_OPS:-allow}" ; return 0 ;;
        cat) [ "$1" = "/proc/net/tcp" ] && printf '%s\n' "${FAKE_PROC_TCP:-     5: 0000000000000000:231E 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1 0000000000000000 100 0 0 10 0}" ; return 0 ;;
        ip)
            case "$1" in
                -o) [ "$2" = "addr" ] && printf '%s\n' "${FAKE_IP_ADDR:-1: lo    inet 127.0.0.1/8 scope host
2: wlan0  inet 192.168.1.71/24 brd 192.168.1.255 scope global wlan0}" ;;
                route) printf '%s\n' "${FAKE_IP_ROUTE:-default via 192.168.1.1 dev wlan0}" ;;
                *) : ;;
            esac
            return 0 ;;
        logcat) printf '%s\n' "${FAKE_LOG:-<logcat: no agent events>}" ; return 0 ;;
        *) : ;;
    esac
    return 0
}

fake_record() {
    : # trace hook (unused)
}

ADB_CLASS="${FAKE_ADB_CLASS:-fake}"
a_case="$1"
case "$a_case" in
    devices)
        [ "$2" = "-l" ] || :
        printf 'List of devices attached\n'
        fake_devices
        printf '\n'
        ;;
    connect)
        printf '%s\n' "${FAKE_CONNECT_RESULT:-connected to $2}"
        ;;
    -s)
        serial="$2"
        sub="$3"
        shift 3
        case "$sub" in
            shell) fake_maybe_disconnect "$@"; fake_shell "$@" ;;
            install)
                [ "$1" = "-r" ] && shift
                printf '%s\n' "${FAKE_INSTALL_RESULT:-Failure [INSTALL_FAILED_USER_RESTRICTED]}"
                ;;
            *) : ;;
        esac
        ;;
    install)
        printf '%s\n' "${FAKE_INSTALL_RESULT:-Failure [INSTALL_FAILED_USER_RESTRICTED]}"
        ;;
    start-server)
        printf '* daemon started successfully\n'
        ;;
    version)
        printf 'Android Debug Bridge version 1.0.41\n'
        ;;
    kill-server)
        :
        ;;
    *)
        printf 'unknown fake adb subcommand: %s\n' "$a_case" >&2
        exit 42
        ;;
esac
exit 0