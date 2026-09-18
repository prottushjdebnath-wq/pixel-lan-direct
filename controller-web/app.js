/**
 * Pixel WebRTC Controller Application Logic
 *
 * Implements:
 * - Application-layer context-bound authentication (PIXEL_SECURE_AUTH_V1).
 * - Exact pairing transcript binding.
 * - Monotonic command sequencing and unacknowledged command resynchronization.
 * - Remote viewport touch dispatch and accessibility commands.
 *
 * MANDATORY SECURITY QUALIFICATIONS:
 * - “The controller utilizes a browser-managed WebCrypto key with non-extractable API semantics; persistent browser storage security is platform/browser dependent and is not equivalent to hardware-backed Secure Enclave storage.”
 * - “WebRTC provides encrypted DTLS/SCTP transport for DataChannels; exact protocol version and cipher suite are implementation dependent.”
 * - “The controller is a RECONNECTABLE CLIENT CONSTRAINED BY IOS/IPADOS LIFECYCLE.”
 * - “The system is DESIGNED FOR AUTOMATIC TRANSPORT RECOVERY AND SESSION RESYNCHRONIZATION; PHYSICAL MIGRATION REMAINS UNVERIFIED.”
 */

const cryptoClient = new ControllerCrypto();
let connectionManager = null;

let activeSessionId = null;
let activeEpoch = null;
let seqCounter = 0;

// Idempotency tracking across session reconnects (lost ACK recovery)
let lastSentCommand = null;

// Target Pixel metadata from bootstrap
let expectedPixelId = "pixel-managed-device";
let expectedPixelPubkey = null;
let expectedPixelFp = null;
let ephemeralNonce = null;

async function initController() {
  const identity = await cryptoClient.init();
  document.getElementById('val-fp').innerText = identity.fingerprint || "--";
  document.getElementById('val-ctl-id').innerText = identity.controllerId || "--";

  connectionManager = new ConnectionManager({
    onStateChange: (state, detail) => {
      updateTransportBadge(state, detail);
    },
    onDataChannelOpen: async () => {
      console.log("[App] DataChannel open. Ready for authentication.");
      const pin = document.getElementById('pairing-pin').value.trim();
      if (pin) {
        await sendPairRequest(pin);
      }
    },
    onDataChannelClose: () => {
      activeSessionId = null;
      activeEpoch = null;
      document.getElementById('val-session').innerText = "Disconnected";
      document.getElementById('val-session').style.color = "#E57373";
    },
    onDataChannelMessage: async (data) => {
      try {
        const msg = JSON.parse(data);
        await handleIncomingDataChannelMessage(msg);
      } catch (err) {
        console.error("Error handling message:", err);
      }
    }
  });

  console.log("Pixel Remote Controller initialized.");
}

async function handleIncomingDataChannelMessage(msg) {
  switch (msg.type) {
    case "CHALLENGE": {
      console.log("[Auth] Cryptographic challenge received:", msg.session_id);
      if (msg.pixel_fingerprint && expectedPixelFp && msg.pixel_fingerprint !== expectedPixelFp) {
        alert("SECURITY ALERT: Pixel fingerprint mismatch in challenge!");
        return;
      }
      if (msg.pixel_pubkey) expectedPixelPubkey = msg.pixel_pubkey;
      if (msg.pixel_id) expectedPixelId = msg.pixel_id;

      const authResp = await cryptoClient.signChallenge(msg);
      connectionManager.sendDataChannel(authResp);
      break;
    }

    case "AUTH_RESULT": {
      if (msg.status === "ok") {
        activeSessionId = msg.session_id;
        activeEpoch = msg.epoch;
        document.getElementById('val-session').innerText = `Auth (Epoch ${activeEpoch || 1})`;
        document.getElementById('val-session').style.color = "#81C784";
        console.log("[Auth] Authenticated successfully! Session:", activeSessionId, "Epoch:", activeEpoch);

        // Reconnect recovery: resubmit unacknowledged command if connection was dropped in-flight
        if (lastSentCommand) {
          console.log("[Recovery] Resubmitting unacknowledged command across reconnect:", lastSentCommand.command_id);
          const retryPayload = {
            type: "COMMAND",
            command_id: lastSentCommand.command_id,
            session_id: activeSessionId,
            epoch: activeEpoch,
            seq_num: ++seqCounter,
            timestamp: lastSentCommand.timestamp,
            action: lastSentCommand.action,
            parameters: lastSentCommand.parameters
          };
          connectionManager.sendDataChannel(retryPayload);
        } else {
          fetchTelemetry();
        }
      } else {
        document.getElementById('val-session').innerText = "Auth Rejected";
        document.getElementById('val-session').style.color = "#E57373";
        alert("Authentication failed: " + msg.message);
      }
      break;
    }

    case "PAIR_RESULT": {
      if (msg.status === "ok") {
        alert("Pairing authorized via verified transcript binding!");
        document.getElementById('pairing-pin').value = "";
      } else {
        alert("Pairing error: " + msg.message);
      }
      break;
    }

    case "COMMAND_RESULT": {
      handleCommandResult(msg);
      break;
    }
  }
}

// --- Exact Pairing Transcript Binding ---
// SHA-256(Pixel_ID || Pixel_Public_Key || Controller_Public_Key || Pairing_PIN || Ephemeral_Nonce)
async function sendPairRequest(pin) {
  if (!ephemeralNonce) {
    alert("Pairing requires ephemeral nonce from Pixel QR bootstrap.");
    return;
  }
  if (!expectedPixelPubkey) {
    alert("Pixel public key not available for transcript hash.");
    return;
  }

  const transcriptHash = await cryptoClient.computePairingTranscriptHash(
    expectedPixelId,
    expectedPixelPubkey,
    pin,
    ephemeralNonce
  );

  const payload = {
    type: "PAIR",
    controller_id: cryptoClient.controllerId,
    controller_pubkey: cryptoClient.publicKeyDerB64,
    transcript_hash: transcriptHash,
    nonce: ephemeralNonce
  };

  connectionManager.sendDataChannel(payload);
}

// --- Command Dispatch & Idempotent Tracking ---

function sendCommand(action, params = {}) {
  if (!connectionManager || !activeSessionId) {
    console.warn("Cannot send command: session not active/authenticated");
    return;
  }

  const cmdId = (typeof crypto !== 'undefined' && crypto.randomUUID)
    ? crypto.randomUUID()
    : "cmd-" + Math.random().toString(36).substring(2, 10);
  const now = Date.now();

  const payload = {
    type: "COMMAND",
    command_id: cmdId,
    session_id: activeSessionId,
    epoch: activeEpoch,
    seq_num: ++seqCounter,
    timestamp: now,
    action: action,
    parameters: params
  };

  // Track unacknowledged command for reconnect idempotency recovery
  lastSentCommand = {
    command_id: cmdId,
    action: action,
    parameters: params,
    timestamp: now
  };

  connectionManager.sendDataChannel(payload);
}

function handleCommandResult(res) {
  if (lastSentCommand && res.command_id === lastSentCommand.command_id) {
    lastSentCommand = null;
  }

  if (res.is_idempotent_duplicate) {
    console.log(`[Idempotency] Duplicate result returned (${res.duplicate_type || 'SAME_SESSION'}). Command not re-executed.`);
  }

  if (res.action === "GET_TELEMETRY" || res.device_model) {
    document.getElementById('val-model').innerText = res.device_model || "Pixel";
    document.getElementById('val-battery').innerText = (res.battery_level ?? "--") + "% " + (res.is_charging ? "⚡" : "");
    if (res.path) {
      document.getElementById('val-path').innerText = res.path;
    }
  }

  if (res.image_base64) {
    const img = document.getElementById('screen-img');
    img.src = "data:image/jpeg;base64," + res.image_base64;
    img.style.display = "block";
    document.getElementById('placeholder').style.display = "none";
  }
}

// --- Controller Actions ---

function fetchTelemetry() {
  sendCommand("GET_TELEMETRY");
}

function takeScreenshot() {
  sendCommand("TAKE_SCREENSHOT");
}

function sendNav(action) {
  sendCommand(action);
}

function injectText() {
  const field = document.getElementById('text-to-inject');
  const txt = field.value;
  if (!txt) return;
  sendCommand("TEXT_ENTRY", { text: txt });
  field.value = "";
}

function onViewportClick(e) {
  const rect = e.currentTarget.getBoundingClientRect();
  const x = ((e.clientX - rect.left) / rect.width) * 1080;
  const y = ((e.clientY - rect.top) / rect.height) * 2400;
  sendCommand("TAP", { x: Math.round(x), y: Math.round(y) });
}

// --- Connections (Direct LAN or Remote Signaling) ---

function parseBootstrapPayload() {
  const raw = document.getElementById('bootstrap-payload').value.trim();
  if (!raw) return;
  try {
    const data = JSON.parse(raw);
    if (data.ip) document.getElementById('target-ip').value = data.ip;
    if (data.port) document.getElementById('target-port').value = data.port;
    if (data.pin) document.getElementById('pairing-pin').value = data.pin;
    if (data.pixel_id) expectedPixelId = data.pixel_id;
    if (data.pubkey) expectedPixelPubkey = data.pubkey;
    if (data.fp) expectedPixelFp = data.fp;
    if (data.nonce) ephemeralNonce = data.nonce;
    alert("Bootstrap parameters parsed successfully. Target Device FP: " + (expectedPixelFp || "N/A"));
  } catch (err) {
    alert("Invalid JSON: " + err.message);
  }
}

async function connectDirectLan() {
  const ip = document.getElementById('target-ip').value.trim();
  const port = parseInt(document.getElementById('target-port').value.trim() || "8990", 10);
  if (!ip) {
    alert("Please enter Pixel LAN IP or parse QR bootstrap data first.");
    return;
  }
  try {
    await connectionManager.connectDirectLan(ip, port);
  } catch (err) {
    alert("Direct LAN connection failed: " + err.message);
  }
}

function connectRemoteSignaling() {
  const url = document.getElementById('signaling-url').value.trim();
  if (!url) {
    alert("Please enter remote WebSocket signaling URL (e.g. ws://...:8991/signaling)");
    return;
  }
  connectionManager.connectRemoteSignaling(url, cryptoClient.controllerId, expectedPixelId);
}

function triggerIceRestart() {
  if (connectionManager) {
    connectionManager.initiateIceRestart("USER_REQUESTED");
  }
}

// --- UI Helpers ---

function updateTransportBadge(state, detail) {
  const badge = document.getElementById('badge-transport');
  document.getElementById('val-path').innerText = detail;

  let cls = "badge-disc";
  if (state === "DIRECT_LAN") cls = "badge-lan";
  else if (state === "INTERNET_P2P") cls = "badge-stun";
  else if (state === "TURN_RELAY") cls = "badge-turn";
  else if (state === "CONNECTING") cls = "badge-cap";

  badge.className = "status-badge " + cls;
  badge.innerText = detail.toUpperCase();
}

// Initialize on page load
if (typeof window !== 'undefined') {
  window.addEventListener('load', () => {
    initController().catch(console.error);

    // Register Service Worker for PWA
    if ('serviceWorker' in navigator) {
      navigator.serviceWorker.register('./sw.js').catch(console.warn);
    }
  });
}
