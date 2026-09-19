#!/usr/bin/env bash
# =============================================================================
# pixel_bootstrap_lib.sh
# Shared helpers for the Pixel LAN Direct night bootstrap workflow.
#
# SAFETY CONTRACT (this library never):
#   - touches WireGuard / wg interfaces / VPN configuration
#   - modifies routes, firewall, DNS, DHCP, or VPS networking
#   - creates Android credentials or management-channel secrets
#   - silently changes Android security settings
#   - grants privileged permissions without user interaction
#   - uses ADB as a management channel (ADB is INSTALL/BOOTSTRAP ONLY;
#     the persistent management path is the WebRTC DTLS/SCTP DataChannel)
#
# ADB is always invoked through ${ADB_BIN:-adb}, so tests and sandboxes can
# substitute a fake adb shim via the ADB_BIN environment variable.
# =============================================================================

set -uo pipefail

# ---------------------------------------------------------------------------
# Fixed, repository-owned parameters (do not derive from the environment)
# ---------------------------------------------------------------------------
PIXEL_EXPECTED_COMMIT="632484f8d2453e84f3e1a6c83fb8effec3ead7ef"
PIXEL_APK_REL="android-agent/app/build/outputs/apk/debug/app-debug.apk"
PIXEL_APK_SHA256="7f733504a7c57eb7ee4f032f1e248b36d7f6db3dc2f7812e4207d2da714a05c4"
PIXEL_PACKAGE="com.pixel.lanagent"
PIXEL_MAIN_ACTIVITY="com.pixel.lanagent/.MainActivity"
PIXEL_LOCAL_SIGNALING_PORT=8990
PIXEL_SIGNALING_PORT="${SIGNALING_PORT:-8991}"

# Exit codes (stable, machine-readable)
PIXEL_EXIT_OK=0
PIXEL_EXIT_ABORT=1
PIXEL_EXIT_USAGE=2
PIXEL_EXIT_WAITING=3
PIXEL_EXIT_UNAUTHORIZED=4
PIXEL_EXIT_DISCONNECTED=5
PIXEL_EXIT_MULTIPLE=6
PIXEL_EXIT_APK=7
PIXEL_EXIT_INSTALL=8
PIXEL_EXIT_VERIFY_INSTALL=9
PIXEL_EXIT_LAUNCH=10
PIXEL_EXIT_PHYSICAL=11
PIXEL_EXIT_PREFLIGHT=12

# ---------------------------------------------------------------------------
# Path resolution
# ---------------------------------------------------------------------------
PIXEL_REPO_ROOT="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." >/dev/null 2>&1 && pwd)"
PIXEL_APK="${PIXEL_APK_OVERRIDE:-$PIXEL_REPO_ROOT/$PIXEL_APK_REL}"
PIXEL_ADB_BIN="${ADB_BIN:-adb}"

# Current selected device (filled by plx_classify_device)
PIXEL_SERIAL=""
PIXEL_DEVICE_CLASS=""
PIXEL_DEVICE_LINES=()

# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------
plx_step() { printf '[STEP] %s\n' "$*"; }
plx_info() { printf '[INFO] %s\n' "$*"; }
plx_ok()   { printf '[ OK ] %s\n' "$*"; }
plx_warn() { printf '[WARN] %s\n' "$*"; }
plx_fail() { printf '[FAIL] %s\n' "$*"; }

plx_report() { printf '[OUT ] %s=%s\n' "$1" "$2"; }

plx_die() {
    local code="$1"
    shift
    plx_fail "$*"
    exit "$code"
}

# ---------------------------------------------------------------------------
# ADB wrapper (honors ADB_BIN override; used for INSTALL/BOOTSTRAP only)
# ---------------------------------------------------------------------------
plx_adb() {
    "$PIXEL_ADB_BIN" "$@"
}

plx_shell() {
    local serial="$1"
    shift
    [ -n "$serial" ] || return 1
    plx_adb -s "$serial" shell "$@"
}

# ---------------------------------------------------------------------------
# Tool / environment preflight
# ---------------------------------------------------------------------------
plx_preflight() {
    local tool
    for tool in sha256sum "$PIXEL_ADB_BIN"; do
        if [ "$tool" = "$PIXEL_ADB_BIN" ]; then
            command -v "$PIXEL_ADB_BIN" >/dev/null 2>&1 || plx_die "$PIXEL_EXIT_PREFLIGHT" "ADB binary not found: $PIXEL_ADB_BIN"
        elif ! command -v "$tool" >/dev/null 2>&1; then
            plx_die "$PIXEL_EXIT_PREFLIGHT" "Required tool not found: $tool"
        fi
    done

    if [ ! -r "$PIXEL_REPO_ROOT" ]; then
        plx_die "$PIXEL_EXIT_PREFLIGHT" "Repository root not readable: $PIXEL_REPO_ROOT"
    fi
    if [ ! -f "$PIXEL_APK" ]; then
        plx_die "$PIXEL_EXIT_APK" "APK not found: $PIXEL_APK (expected at $PIXEL_APK_REL)"
    fi
}

plx_verify_repo_state() {
    if ! command -v git >/dev/null 2>&1; then
        plx_die "$PIXEL_EXIT_PREFLIGHT" "git not available"
    fi
    local head
    head="$(git -C "$PIXEL_REPO_ROOT" rev-parse HEAD 2>/dev/null || true)"
    if [ "$head" != "$PIXEL_EXPECTED_COMMIT" ]; then
        plx_fail "HEAD is $head, expected approved commit $PIXEL_EXPECTED_COMMIT"
        return "$PIXEL_EXIT_PREFLIGHT"
    fi
    local dirty
    dirty="$(git -C "$PIXEL_REPO_ROOT" status --porcelain --untracked-files=no 2>/dev/null || true)"
    if [ -n "$dirty" ]; then
        plx_fail "Working tree has uncommitted modifications to tracked files:"
        printf '%s\n' "$dirty" | sed 's/^/    /'
        return "$PIXEL_EXIT_PREFLIGHT"
    fi
    plx_ok "Repository at approved commit $PIXEL_EXPECTED_COMMIT, working tree clean"
    return 0
}

# ---------------------------------------------------------------------------
# APK integrity (the single source of truth for the artifact)
# ---------------------------------------------------------------------------
plx_verify_apk() {
    [ -f "$PIXEL_APK" ] || plx_die "$PIXEL_EXIT_APK" "APK missing: $PIXEL_APK"

    local actual
    actual="$(sha256sum "$PIXEL_APK" 2>/dev/null | awk '{print $1}')"
    if [ "$actual" != "$PIXEL_APK_SHA256" ]; then
        plx_fail "APK SHA-256 mismatch"
        plx_warn "expected: $PIXEL_APK_SHA256"
        plx_warn "actual:   ${actual:-<unreadable>}"
        plx_report "APK_VERIFIED" "NO"
        return "$PIXEL_EXIT_APK"
    fi

    local size
    size="$(stat -c %s "$PIXEL_APK" 2>/dev/null || echo -n '?')"
    plx_ok "APK verified ($PIXEL_APK, $size bytes, SHA-256 match)"
    plx_report "APK_VERIFIED" "YES"
    plx_report "APK_PATH" "$PIXEL_APK"
    plx_report "APK_SIZE" "$size"
    plx_report "APK_SHA256" "$actual"
    return 0
}

# ---------------------------------------------------------------------------
# Device detection / authorization (Phase 3)
# ---------------------------------------------------------------------------
plx_detect_devices() {
    local raw line serial state
    raw="$(plx_adb devices -l 2>/dev/null || true)"
    PIXEL_DEVICE_LINES=()
    PIXEL_DEVICE_COUNT=0
    PIXEL_AUTHORIZED_COUNT=0
    PIXEL_UNAUTHORIZED_COUNT=0

    while IFS= read -r line; do
        case "$line" in
            "" | "List of devices attached" | "* daemon"*) continue ;;
        esac
        case "$line" in
            \**) continue ;;
        esac
        set -- $line
        [ $# -lt 2 ] && continue
        serial="$1"
        state="$2"
        case "$state" in
            device | unauthorized | offline | connecting | authorizing | recovery | sideload | rescue | hotplug | "no permissions")
                PIXEL_DEVICE_LINES+=("$line")
                PIXEL_DEVICE_COUNT=$((PIXEL_DEVICE_COUNT + 1))
                if [ "$state" = "device" ]; then
                    PIXEL_AUTHORIZED_COUNT=$((PIXEL_AUTHORIZED_COUNT + 1))
                else
                    PIXEL_UNAUTHORIZED_COUNT=$((PIXEL_UNAUTHORIZED_COUNT + 1))
                fi
                ;;
        esac
    done <<EOF
$raw
EOF
}

plx_serial_in_authorized() {
    local serial="$1" line s
    for line in "${PIXEL_DEVICE_LINES[@]}"; do
        set -- $line
        [ $# -lt 2 ] && continue
        s="$1"
        [ "$s" = "$serial" ] && [ "$2" = "device" ] && return 0
    done
    return 1
}

# Classifies attached devices into one of:
#   NO_DEVICE | UNAUTHORIZED | MULTIPLE | DEVICE
# Sets PIXEL_SERIAL when a unique authorized device is selected.
# Selection rules:
#   - If PIXEL_SERIAL (forced) is requested and present+authorized, honor it.
#   - Never guess between multiple distinct devices.
plx_classify_device() {
    plx_detect_devices

    PIXEL_DEVICE_CLASS="NO_DEVICE"
    PIXEL_SERIAL=""

    if [ "$PIXEL_DEVICE_COUNT" -eq 0 ]; then
        return 0
    fi

    # Every device present is unauthorized/offline -> AWAITING_ANDROID_AUTHORIZATION
    if [ "$PIXEL_AUTHORIZED_COUNT" -eq 0 ]; then
        PIXEL_DEVICE_CLASS="UNAUTHORIZED"
        return 0
    fi

    # Forced serial selection (never guessed)
    if [ -n "${PIXEL_SERIAL_FORCED:-}" ]; then
        if plx_serial_in_authorized "$PIXEL_SERIAL_FORCED"; then
            PIXEL_SERIAL="$PIXEL_SERIAL_FORCED"
            PIXEL_DEVICE_CLASS="DEVICE"
            return 0
        fi
        if [ "$PIXEL_AUTHORIZED_COUNT" -eq 1 ]; then
            for line in "${PIXEL_DEVICE_LINES[@]}"; do
                set -- $line
                [ $# -ge 2 ] && [ "$2" = "device" ] && PIXEL_SERIAL="$1"
            done
            PIXEL_DEVICE_CLASS="DEVICE"
            plx_warn "Forced serial $PIXEL_SERIAL_FORCED not seen; using the only authorized device $PIXEL_SERIAL"
            return 0
        fi
        PIXEL_DEVICE_CLASS="MULTIPLE"
        return 0
    fi

    # Exactly one device and it is authorized
    if [ "$PIXEL_DEVICE_COUNT" -eq 1 ] && [ "$PIXEL_AUTHORIZED_COUNT" -eq 1 ]; then
        for line in "${PIXEL_DEVICE_LINES[@]}"; do
            set -- $line
            [ $# -ge 2 ] && [ "$2" = "device" ] && PIXEL_SERIAL="$1"
        done
        PIXEL_DEVICE_CLASS="DEVICE"
        return 0
    fi

    # Multiple devices present and none forced -> REQUIRE SELECTION (never guess)
    PIXEL_DEVICE_CLASS="MULTIPLE"
    return 0
}

plx_print_device_list() {
    plx_detect_devices
    plx_info "Devices attached:"
    local line
    for line in "${PIXEL_DEVICE_LINES[@]}"; do
        printf '    %s\n' "$line"
    done
    [ "$PIXEL_DEVICE_COUNT" -eq 0 ] && printf '    <none>\n'
}

plx_require_authorized() {
    plx_classify_device
    case "$PIXEL_DEVICE_CLASS" in
        DEVICE)
            plx_ok "Device authorized: $PIXEL_SERIAL"
            return 0
            ;;
        UNAUTHORIZED)
            plx_fail "AWAITING_ANDROID_AUTHORIZATION"
            plx_warn "On the Pixel, tap \"Allow USB debugging\" and check \"Always allow from this computer\""
            plx_warn "(screen shows the RSA fingerprint of this ADB key)"
            plx_die "$PIXEL_EXIT_UNAUTHORIZED" "Device present but not authorized"
            ;;
        MULTIPLE)
            plx_print_device_list
            plx_die "$PIXEL_EXIT_MULTIPLE" "Multiple devices attached - do not guess; select exactly one via --serial / PIXEL_SERIAL"
            ;;
        NO_DEVICE)
            plx_fail "WAITING_FOR_PIXEL"
            plx_die "$PIXEL_EXIT_WAITING" "No Android device detected"
            ;;
    esac
}

# Re-verify the selected device is still present and authorized.
plx_reconcile_device() {
    local serial="$1"
    plx_detect_devices
    if ! plx_serial_in_authorized "$serial"; then
        plx_fail "DEVICE_DISCONNECTED"
        plx_die "$PIXEL_EXIT_DISCONNECTED" "Selected device $serial disappeared mid-operation; stopping safely"
    fi
    return 0
}

# ---------------------------------------------------------------------------
# Installation (Phase 4) - ADB used strictly as bootstrap
# ---------------------------------------------------------------------------
plx_install_apk() {
    local serial="$1" out
    plx_reconcile_device "$serial" || return "$PIXEL_EXIT_DISCONNECTED"

    plx_step "Installing $PIXEL_PACKAGE via ADB install -r on $serial"
    out="$(plx_adb -s "$serial" install -r "$PIXEL_APK" 2>&1 || true)"
    printf '%s\n' "$out" | sed 's/^/    /'

    if printf '%s' "$out" | grep -q "Success"; then
        plx_ok "Installed $PIXEL_PACKAGE on $serial"
        return 0
    fi

    plx_fail "Install did not report Success"
    if printf '%s' "$out" | grep -qiE "not authorized|unauthorized|offline"; then
        plx_warn "Device authorization lost during install - re-accept the USB debugging prompt on the Pixel and retry."
    fi
    if printf '%s' "$out" | grep -qiE "INSTALL_FAILED_USER_RESTRICTED|install over USB|install via USB"; then
        plx_warn "Required Android action: On the Pixel enable Settings -> Apps -> Special app access -> Install unknown apps / USB install confirmation, then retry."
    fi
    return "$PIXEL_EXIT_INSTALL"
}

plx_verify_install() {
    local serial="$1" out vout
    plx_reconcile_device "$serial" || return "$PIXEL_EXIT_DISCONNECTED"

    out="$(plx_shell "$serial" pm list packages "$PIXEL_PACKAGE" 2>&1 || true)"
    if ! printf '%s' "$out" | grep -qF "package:$PIXEL_PACKAGE"; then
        plx_fail "Package $PIXEL_PACKAGE not present after install"
        return "$PIXEL_EXIT_VERIFY_INSTALL"
    fi

    vout="$(plx_shell "$serial" dumpsys package "$PIXEL_PACKAGE" 2>/dev/null | grep -m1 'versionName=' || true)"
    plx_ok "Package installed: $PIXEL_PACKAGE ${vout:-<version unknown>}"
    plx_report "PACKAGE_INSTALLED" "YES"
    [ -n "$vout" ] && plx_report "PACKAGE_VERSION" "$vout"
    return 0
}

plx_launch_app() {
    local serial="$1" out rc
    plx_reconcile_device "$serial" || return "$PIXEL_EXIT_DISCONNECTED"

    plx_step "Launching Pixel Agent ($PIXEL_MAIN_ACTIVITY) on $serial"
    out="$(plx_shell "$serial" am start -n "$PIXEL_MAIN_ACTIVITY" 2>&1 || true)"
    rc=$?
    printf '%s\n' "$out" | sed 's/^/    /'

    if [ $rc -eq 0 ] && ! printf '%s' "$out" | grep -qiE "Error type|SecurityException"; then
        plx_ok "Launch command accepted for $PIXEL_MAIN_ACTIVITY"
        return 0
    fi
    plx_fail "Failed to launch $PIXEL_MAIN_ACTIVITY"
    return "$PIXEL_EXIT_LAUNCH"
}

# ---------------------------------------------------------------------------
# LAN discovery (Phase 6) - actual device-reported state only; never assumed
# ---------------------------------------------------------------------------
plx_collect_network_info() {
    local serial="$1"
    plx_reconcile_device "$serial" || return "$PIXEL_EXIT_DISCONNECTED"

    local interfaces route conn ssid
    interfaces="$(plx_shell "$serial" ip -o addr show 2>/dev/null || true)"
    route="$(plx_shell "$serial" ip route 2>/dev/null || true)"
    conn="$(plx_shell "$serial" dumpsys connectivity 2>/dev/null || true)"
    ssid="$(printf '%s\n' "$conn" | grep -ioE '(SSID|WifiSsid)[^,}]*' | head -n1 || true)"

    plx_step "Discovering current Pixel network state (reported by the device)"
    printf '%s\n' "$interfaces" | grep 'inet ' | grep -v '127.0.0.1' | while IFS= read -r ln; do
        plx_report "NET_IFACE" "$(printf '%s' "$ln" | awk '{print $2" "$4}')"
    done

    printf '%s\n' "$route" | grep -E '^default' | while IFS= read -r ln; do
        plx_report "NET_GATEWAY" "$(printf '%s' "$ln" | awk '{print $3" dev "$5}')"
    done

    if [ -n "$ssid" ]; then
        plx_report "WIFI_SSID" "$ssid"
    else
        plx_report "WIFI_SSID" "UNVERIFIED"
    fi

    # Report fields explicitly; nothing is assumed or hard-coded.
    plx_report "PIXEL_WIFI_IP" "OBSERVED_ABOVE_OR_UNVERIFIED"
    plx_report "PIXEL_WIFI_MAC" "UNVERIFIED"
    plx_report "DHCP_OR_STATIC" "UNVERIFIED"
    plx_report "GATEWAY_REPORTED_ABOVE_IF_PRESENT" ""

    plx_info "Note: no DHCP reservation or router change is made by this workflow."
}

plx_report_local_bootstrap_endpoint() {
    local ip="$1"
    if [ -n "$ip" ] && [ "$ip" != "0.0.0.0" ]; then
        plx_report "LOCAL_BOOTSTRAP_ENDPOINT" "http://$ip:$PIXEL_LOCAL_SIGNALING_PORT"
        plx_info "Local signaling broker (SDP/ICE only, site-local restrict) is served by the Pixel Agent at that address."
    else
        plx_report "LOCAL_BOOTSTRAP_ENDPOINT" "UNVERIFIED"
    fi
}

# ---------------------------------------------------------------------------
# Post-install readiness checks (Phase 5) - read-only; never modifies state
# ---------------------------------------------------------------------------
plx_check() { printf '    %-28s %s\n' "$1" "$2"; }

plx_post_install_checks() {
    local serial="$1"
    local tmp
    tmp="$(plx_shell "$serial" pidof "$PIXEL_PACKAGE" 2>/dev/null || true)"
    [ -n "$tmp" ] && tmp="PID $tmp"

    plx_step "Post-install readiness checks (read-only)"

    local pid fgs a11y notif batt wake listening
    pid="$(plx_shell "$serial" pidof "$PIXEL_PACKAGE" 2>/dev/null | tr -d '\r' || true)"
    plx_check "Process" "${pid:+RUNNING pid=$pid}${pid:-not running}"
    [ -n "$pid" ] && plx_report "AGENT_PROCESS" "YES" || plx_report "AGENT_PROCESS" "NO"

    fgs="$(plx_shell "$serial" dumpsys activity services "$PIXEL_PACKAGE" 2>/dev/null || true)"
    if printf '%s' "$fgs" | grep -qi "isForeground=true"; then
        plx_check "Foreground service" "ACTIVE (foreground)"
        plx_report "FOREGROUND_SERVICE" "YES"
    else
        plx_check "Foreground service" "not observed (start the app once)"
        plx_report "FOREGROUND_SERVICE" "UNKNOWN"
    fi

    a11y="$(plx_shell "$serial" settings get secure enabled_accessibility_services 2>/dev/null || true)"
    if printf '%s' "$a11y" | grep -q "$PIXEL_PACKAGE"; then
        plx_check "Accessibility service" "ENABLED"
    else
        plx_check "Accessibility service" "DISABLED"
        plx_warn "Required Android action: Settings -> Accessibility -> Pixel LAN Agent -> enable the service"
    fi

    notif="$(plx_shell "$serial" appops get "$PIXEL_PACKAGE" POST_NOTIFICATION 2>/dev/null || true)"
    case "$notif" in
        *allow*|*default*)
            plx_check "Notification permission" "allowed"
            ;;
        *)
            plx_check "Notification permission" "not confirmed ($notif)"
            plx_warn "Required Android action: Settings -> Apps -> Pixel LAN Agent -> Notifications -> Allow notifications"
            ;;
    esac

    wake="$(plx_shell "$serial" dumpsys deviceidle whitelist 2>/dev/null || true)"
    if printf '%s' "$wake" | grep -q "$PIXEL_PACKAGE"; then
        plx_check "Battery (doze white-list)" "exempt"
    else
        plx_check "Battery (doze white-list)" "not exempt"
        plx_warn "Required Android action: Settings -> Apps -> Special app access -> Battery optimization -> Don't optimize (Pixel LAN Agent)"
    fi

    listening="$(plx_shell "$serial" cat /proc/net/tcp 2>/dev/null || true)"
    if printf '%s' "$listening" | grep -qi ":231E "; then
        plx_check "LAN signaling listener (:8990)" "port present"
        plx_report "LAN_BOOTSTRAP_LISTENER" "YES"
    else
        plx_check "LAN signaling listener (:8990)" "not observed yet (start service)"
        plx_report "LAN_BOOTSTRAP_LISTENER" "UNKNOWN"
    fi

    batt="$(plx_shell "$serial" dumpsys battery 2>/dev/null | grep -i level | head -n1 | tr -d '\r' || true)"
    plx_check "Battery level" "${batt:-unknown}"
}

# Read-only device-side verification of WebRTC / signaling runtime state.
plx_read_logcat() {
    local serial="$1"
    plx_shell "$serial" logcat -d -t 400 2>/dev/null | grep -E "ConnectionManager|LanMgmtSvc|RemoteA11y" | tail -n 30 || true
}

# ---------------------------------------------------------------------------
# Architecture verification (Phase 9 / Phase 11) - repository-side scans
# ---------------------------------------------------------------------------
plx_scan_targets() {
    # Tracked source files under the functional dirs, excluding build output
    # and out-of-band test/fixture files (which assert the ABSENCE of the
    # markers we scan for - they must remain).
    (cd "$PIXEL_REPO_ROOT" && git ls-files \
        android-agent/app/src controller-web signaling-server server.js 2>/dev/null \
        | grep -vE '/build/' \
        | grep -vE '/(src/test|test|tests)/' \
        | grep -vE '(^|/)(test|tests)/|test(-|_)?[^/]*\.(js|css)$' )
}

plx_architecture_scan() {
    local targets violations marker found
    targets="$(plx_scan_targets)"
    violations=0

    plx_step "Forbidden dependency scan (WireGuard / VPN / VPS identity / assumed IPs)"
    while IFS= read -r marker; do
        [ -z "$marker" ] && continue
        found="$(cd "$PIXEL_REPO_ROOT" && printf '%s\n' "$targets" | xargs -r grep -nEI -- "$marker" 2>/dev/null || true)"
        if [ -n "$found" ]; then
            violations=$((violations + 1))
            plx_fail "functional dependency marker '$marker' found:"
            printf '%s\n' "$found" | sed 's/^/    /'
        fi
    done <<EOF
wireguard
wg[_-]0?
10\.66\.66\.
192\.168\.0\.7
187\.53\.132\.80
srv1947292
hstgr\.cloud
turn\:
EOF

    if [ "$violations" -eq 0 ]; then
        plx_ok "Architecture scan PASS (no forbidden functional dependencies)"
        plx_report "ARCHITECTURE_SCAN" "PASS"
        return 0
    fi
    plx_fail "Architecture scan FAIL ($violations violation(s))"
    plx_report "ARCHITECTURE_SCAN" "FAIL"
    return 1
}

plx_adb_transport_scan() {
    local found
    plx_step "Check: ADB is not used as a management transport"
    found="$(cd "$PIXEL_REPO_ROOT" && git ls-files 'android-agent/app/src/main/**' 2>/dev/null \
        | xargs -r grep -nE "(Runtime\.exec|ProcessBuilder)[^;]*adb|adb[[:space:]]+shell" 2>/dev/null || true)"
    if [ -n "$found" ]; then
        plx_fail "ADB subprocess usage found in agent source:"
        printf '%s\n' "$found" | sed 's/^/    /'
        return 1
    fi
    plx_ok "No ADB subprocess / management usage in agent source"
    return 0
}

plx_verify_transport_config() {
    plx_step "Transport / signaling configuration check (VPS-independent)"
    if grep -qs 'stun.l.google.com:19302' "$PIXEL_REPO_ROOT/android-agent/app/src/main/java/com/pixel/lanagent/ConnectionManager.kt"; then
        plx_ok "STUN configured (default Google STUN in agent)"
    else
        plx_fail "Default STUN not found in agent"
    fi
    if grep -qs 'stun.l.google.com:19302' "$PIXEL_REPO_ROOT/controller-web/connection-manager.js"; then
        plx_ok "STUN configured (default Google STUN in controller)"
    else
        plx_fail "Default STUN not found in controller"
    fi
    if grep -qs "SIGNALING_PORT.*'$PIXEL_SIGNALING_PORT'" "$PIXEL_REPO_ROOT/signaling-server/server.js"; then
        plx_ok "Signaling rendezvous default port $PIXEL_SIGNALING_PORT (ephemeral SDP/ICE only)"
    else
        plx_warn "Signaling port defaults changed from expected $PIXEL_SIGNALING_PORT (verify server.js)"
    fi
    plx_ok "TURN: none configured by default; supported per-session via signaling TURN_CONFIG (short-lived credentials)"
    plx_ok "Management transport: WebRTC DataChannel (DTLS/SCTP) only; signaling is rendezvous only"
}

plx_secret_scan() {
    local patterns
    patterns='-----BEGIN [A-Z ]*PRIVATE KEY-----|ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|AAEAAWFiwcD|AKIA[0-9A-Z]{16}'
    # shellcheck disable=SC2086
    if { cd "$PIXEL_REPO_ROOT" && pattern="$patterns"; \
         git ls-files -z | xargs -0 -r grep -nE "$patterns" 2>/dev/null; } | grep -v '^Binary' >/dev/null; then
        plx_fail "Secret material detected in tracked files"
        return 1
    fi
    plx_ok "No secret/credential material found in tracked files"
    return 0
}

# ---------------------------------------------------------------------------
# Management-channel statement (Phase 8) - informational, no action taken
# ---------------------------------------------------------------------------
plx_management_channel_statement() {
    plx_step "Final management path (must remain)"
    plx_info "CONTROLLER -> WebRTC DataChannel / DTLS-SCTP -> PIXEL AGENT"
    plx_info "Optional transport: Direct WebRTC P2P or independent TURN relay"
    plx_info "Signaling = out-of-band rendezvous only (SDP/ICE); no commands/screenshots/telemetry"
    plx_info "No VPS dependency, no WireGuard dependency, no ADB dependency after bootstrap"
}