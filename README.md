# Pixel LAN Direct / Global Secure Tunnel

Secure WebRTC management architecture pairing an authorized iPhone/iPad PWA controller with a Google Pixel management agent.

## Architecture Overview

1. **Pixel Core Agent (`android-agent/`)**:
   - Native Android management agent running as a standard foreground service (`LanManagementService`) with connected device type.
   - Cryptographic identity: Persistent ECDSA P-256 keypair loaded/generated in Android `EncryptedSharedPreferences`.
   - Screen control: Supported accessibility actions (`AccessibilityService`) for tap, swipe, hardware/global navigation (Back, Home, Recents), and text entry.
   - Screen capture: Android accessibility screenshot capture API.
   - Dual signaling: Ephemeral restricted local HTTP listener for LAN bootstrap + Outbound WebSocket client connecting to remote signaling rendezvous.
   - WebRTC Transport: Stream WebRTC library providing DTLS/SCTP DataChannels for all management commands, telemetry, and touch input.
   - Transport path classification: Automatically detects Direct LAN (host candidate pair), Internet P2P (STUN / srflx candidate pair), or TURN Relay (relay candidate pair).
   - Dynamic transport recovery & ICE restart: `ConnectivityManager.NetworkCallback` detects Wi-Fi <-> Cellular handovers and triggers ICE restart while preserving the logical session.

2. **Ephemeral Signaling Server (`signaling-server/`)**:
   - Lightweight WebSocket rendezvous service strictly limited to WebRTC signaling:
     * SDP offer/answer
     * ICE candidates
     * ICE restart signals
     * Ephemeral rendezvous/session metadata
     * Short-lived TURN credentials
   - Strictly drops and rejects any management commands, screenshots, telemetry, private keys, or pairing secrets.

3. **Authorized Controller PWA (`controller-web/`)**:
   - Progressive Web App designed for iPhone / iPad with standalone viewport support.
   - WebCrypto ECDSA P-256 non-extractable cryptographic key management in IndexedDB.
   - Exact pairing transcript binding: `SHA-256(Pixel_ID || Pixel_Public_Key || Controller_Public_Key || Pairing_PIN || Ephemeral_Nonce)`.
   - Context-bound application-layer challenge-response authentication (`PIXEL_SECURE_AUTH_V1`).
   - ConnectionManager separating physical transport from logical session.
   - Lost-ACK and cross-reconnect idempotency recovery for unacknowledged commands.
   - Interactive screen viewport, touch coordinate scaling, navigation buttons, and text injection.

---

## Mandatory Security Qualifications

* “The controller utilizes a browser-managed WebCrypto key with non-extractable API semantics; persistent browser storage security is platform/browser dependent and is not equivalent to hardware-backed Secure Enclave storage.”
* “WebRTC provides encrypted DTLS/SCTP transport for DataChannels; exact protocol version and cipher suite are implementation dependent.”
* “The Pixel core agent is PERSISTENT WHILE ANDROID PERMITS EXECUTION USING SUPPORTED LIFECYCLE MECHANISMS.”
* “The controller is a RECONNECTABLE CLIENT CONSTRAINED BY IOS/IPADOS LIFECYCLE.”
* “The system is DESIGNED FOR AUTOMATIC TRANSPORT RECOVERY AND SESSION RESYNCHRONIZATION; PHYSICAL MIGRATION REMAINS UNVERIFIED.”

---

## Security & Anti-Replay Model

- **Device Identity & Whitelisting**: Pixel maintains an authoritative whitelist of paired controllers in encrypted storage. Pixel-side revocation is the absolute authority.
- **Context-Bound Challenge-Response**: Every session requires signing a canonical challenge bound to:
  `PIXEL_SECURE_AUTH_V1:${sessionId}:${nonce}:${timestamp}:${pixelId}:${pixelPubkey}:${controllerId}:${controllerPubkey}`
- **Session & Epoch Protection**: Monotonic persistent epoch counter incremented on process start. Commands outside active epoch/session are rejected.
- **Persistent Replay Defense**: Persistent journal surviving process death/restart. Duplicate commands from the same controller across reconnect return the cached response (`RECONNECT_RECOVERY_DUPLICATE`) without re-executing destructive actions.
- **Strict Transport Boundaries**: All management commands, telemetry, and screen captures are carried strictly over WebRTC DataChannels (DTLS/SCTP). No management traffic is ever routed through signaling.

---

## Building & Testing

### Android Agent
```bash
cd android-agent
./gradlew testDebugUnitTest
./gradlew assembleDebug
```

### Signaling Server
```bash
cd signaling-server
npm install
npm test
npm start
```

### Controller Web App
```bash
cd controller-web
node test-controller.js
```
