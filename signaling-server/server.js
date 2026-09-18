/**
 * Pixel Secure WebSocket Rendezvous & Signaling Server
 *
 * STRICT SECURITY BOUNDARIES:
 * - Strictly limited to ephemeral WebRTC signaling:
 *     * SDP offer/answer
 *     * ICE candidates
 *     * ICE restart requests
 *     * Ephemeral rendezvous/session metadata
 *     * Short-lived TURN credentials
 * - NEVER carries management commands, screenshots, telemetry, private keys, controller secrets, or pairing secrets.
 * - Any management or unauthorized payload is immediately rejected and connection terminated.
 *
 * MANDATORY SECURITY QUALIFICATIONS:
 * - “WebRTC provides encrypted DTLS/SCTP transport for DataChannels; exact protocol version and cipher suite are implementation dependent.”
 * - “The system is DESIGNED FOR AUTOMATIC TRANSPORT RECOVERY AND SESSION RESYNCHRONIZATION; PHYSICAL MIGRATION REMAINS UNVERIFIED.”
 */

const http = require('http');
const { WebSocketServer, WebSocket } = require('ws');

const PORT = parseInt(process.env.SIGNALING_PORT || '8991', 10);
const HOST = process.env.SIGNALING_HOST || '0.0.0.0';

// Permitted signaling message types ONLY
const PERMITTED_SIGNALING_TYPES = new Set([
  'REGISTER',
  'OFFER',
  'ANSWER',
  'ICE_CANDIDATE',
  'ICE_RESTART',
  'TURN_CONFIG',
  'PING',
  'PONG'
]);

// Forbidden keywords/payload patterns (management commands, secrets, screenshots, telemetry)
const FORBIDDEN_KEYS = new Set([
  'command_id',
  'command',
  'commands',
  'action',
  'parameters',
  'image_base64',
  'screenshot',
  'telemetry',
  'private_key',
  'privkey',
  'pairing_code',
  'pairing_pin',
  'pin',
  'secret'
]);

// Recursively inspect payload objects and arrays for forbidden management/secret keys
function findForbiddenField(obj) {
  if (!obj || typeof obj !== 'object') return null;
  if (Array.isArray(obj)) {
    for (const item of obj) {
      const forbidden = findForbiddenField(item);
      if (forbidden) return forbidden;
    }
    return null;
  }
  for (const k of Object.keys(obj)) {
    if (FORBIDDEN_KEYS.has(k.toLowerCase())) {
      return k;
    }
    const forbidden = findForbiddenField(obj[k]);
    if (forbidden) return forbidden;
  }
  return null;
}

function createSignalingServer(options = {}) {
  const server = http.createServer((req, res) => {
    // Health / probe check
    if (req.url === '/health' || req.url === '/') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        status: 'ok',
        service: 'pixel-secure-signaling',
        time: Date.now()
      }));
      return;
    }
    res.writeHead(404, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'Not found' }));
  });

  const wss = new WebSocketServer({ noServer: true });

  server.on('upgrade', (request, socket, head) => {
    const { pathname } = new URL(request.url, `http://${request.headers.host || 'localhost'}`);
    if (pathname === '/signaling' || pathname === '/') {
      wss.handleUpgrade(request, socket, head, (ws) => {
        wss.emit('connection', ws, request);
      });
    } else {
      socket.destroy();
    }
  });

  // Ephemeral in-memory registry: deviceId -> ws, controllerId -> ws, paired routing
  const devices = new Map(); // deviceId -> ws
  const controllers = new Map(); // controllerId -> ws
  const peerRouting = new Map(); // ws -> targetWs

  wss.on('connection', (ws, req) => {
    ws.isAlive = true;
    ws.clientId = null;
    ws.clientRole = null;

    ws.on('pong', () => {
      ws.isAlive = true;
    });

    ws.on('message', (data) => {
      try {
        const text = data.toString('utf8');
        let msg;
        try {
          msg = JSON.parse(text);
        } catch (parseErr) {
          ws.send(JSON.stringify({ type: 'ERROR', message: 'Invalid JSON payload' }));
          return;
        }

        // Strict validation: must have valid type
        const type = msg.type;
        if (!type || !PERMITTED_SIGNALING_TYPES.has(type)) {
          ws.send(JSON.stringify({
            type: 'ERROR',
            code: 'FORBIDDEN_MESSAGE_TYPE',
            message: `Signaling channel strictly rejects message type: ${type}. Management commands must use WebRTC DataChannel.`
          }));
          // Terminate connection on attempted management traffic
          ws.close(1008, 'Policy violation: management traffic in signaling');
          return;
        }

        // Deep inspection: verify no management parameters or secrets are leaked into signaling (recursive)
        const forbiddenField = findForbiddenField(msg);
        if (forbiddenField) {
          ws.send(JSON.stringify({
            type: 'ERROR',
            code: 'FORBIDDEN_PAYLOAD_CONTENT',
            message: `Signaling rejects field '${forbiddenField}'. Management commands, private keys, screenshots, and telemetry are forbidden in signaling.`
          }));
          ws.close(1008, 'Policy violation: forbidden field in signaling');
          return;
        }

        handleSignalingMessage(ws, msg);
      } catch (err) {
        ws.send(JSON.stringify({ type: 'ERROR', message: 'Internal signaling processing error' }));
      }
    });

    ws.on('close', () => {
      cleanupClient(ws);
    });

    ws.on('error', (err) => {
      cleanupClient(ws);
    });
  });

  function handleSignalingMessage(ws, msg) {
    switch (msg.type) {
      case 'REGISTER': {
        const role = msg.role; // 'device' or 'controller'
        const id = msg.id || (role === 'device' ? msg.device_id : msg.controller_id);
        const targetDeviceId = msg.target_device_id || 'pixel-managed-device';

        if (!role || !id) {
          ws.send(JSON.stringify({ type: 'ERROR', message: 'REGISTER requires role and id' }));
          return;
        }

        ws.clientId = id;
        ws.clientRole = role;

        if (role === 'device') {
          devices.set(id, ws);
          ws.send(JSON.stringify({
            type: 'REGISTERED',
            role: 'device',
            id: id,
            status: 'online'
          }));
        } else if (role === 'controller') {
          controllers.set(id, ws);
          ws.targetDeviceId = targetDeviceId;

          const targetDevice = devices.get(targetDeviceId);
          if (targetDevice && targetDevice.readyState === WebSocket.OPEN) {
            peerRouting.set(ws, targetDevice);
            peerRouting.set(targetDevice, ws);
            ws.send(JSON.stringify({
              type: 'REGISTERED',
              role: 'controller',
              id: id,
              target_device: targetDeviceId,
              target_status: 'online'
            }));
          } else {
            ws.send(JSON.stringify({
              type: 'REGISTERED',
              role: 'controller',
              id: id,
              target_device: targetDeviceId,
              target_status: 'waiting_for_device'
            }));
          }
        }
        break;
      }

      case 'OFFER':
      case 'ANSWER':
      case 'ICE_CANDIDATE':
      case 'ICE_RESTART':
      case 'TURN_CONFIG': {
        // Relay to paired peer
        let targetWs = peerRouting.get(ws);

        // Fallback resolution if routing not yet established in peerRouting
        if (!targetWs || targetWs.readyState !== WebSocket.OPEN) {
          if (ws.clientRole === 'controller' && ws.targetDeviceId) {
            targetWs = devices.get(ws.targetDeviceId);
            if (targetWs) {
              peerRouting.set(ws, targetWs);
              peerRouting.set(targetWs, ws);
            }
          } else if (ws.clientRole === 'device') {
            // Find the active controller for this device
            for (const [cId, cWs] of controllers) {
              if (cWs.targetDeviceId === ws.clientId && cWs.readyState === WebSocket.OPEN) {
                targetWs = cWs;
                peerRouting.set(ws, targetWs);
                peerRouting.set(targetWs, ws);
                break;
              }
            }
          }
        }

        if (targetWs && targetWs.readyState === WebSocket.OPEN) {
          // Forward message
          targetWs.send(JSON.stringify(msg));
        } else {
          ws.send(JSON.stringify({
            type: 'STATUS',
            status: 'PEER_UNREACHABLE',
            message: 'Target peer not currently connected to signaling rendezvous'
          }));
        }
        break;
      }

      case 'PING':
        ws.send(JSON.stringify({ type: 'PONG', timestamp: Date.now() }));
        break;

      case 'PONG':
        // Keep-alive acknowledged
        break;
    }
  }

  function cleanupClient(ws) {
    if (ws.clientRole === 'device' && ws.clientId) {
      if (devices.get(ws.clientId) === ws) {
        devices.delete(ws.clientId);
      }
    } else if (ws.clientRole === 'controller' && ws.clientId) {
      if (controllers.get(ws.clientId) === ws) {
        controllers.delete(ws.clientId);
      }
    }
    const targetWs = peerRouting.get(ws);
    if (targetWs) {
      peerRouting.delete(ws);
      if (peerRouting.get(targetWs) === ws) {
        peerRouting.delete(targetWs);
      }
      if (targetWs.readyState === WebSocket.OPEN) {
        targetWs.send(JSON.stringify({
          type: 'STATUS',
          status: 'PEER_DISCONNECTED',
          peer_id: ws.clientId
        }));
      }
    }
  }

  // Heartbeat ping interval
  const pingInterval = setInterval(() => {
    wss.clients.forEach((ws) => {
      if (ws.isAlive === false) {
        return ws.terminate();
      }
      ws.isAlive = false;
      ws.ping();
    });
  }, 30000);

  wss.on('close', () => {
    clearInterval(pingInterval);
  });

  return { server, wss };
}

if (require.main === module) {
  const { server } = createSignalingServer();
  server.listen(PORT, HOST, () => {
    console.log(`[Pixel Signaling] Listening on ws://${HOST}:${PORT}/signaling`);
    console.log(`[Pixel Signaling] Strictly limited to SDP, ICE, and ephemeral rendezvous metadata.`);
  });
}

module.exports = { createSignalingServer, PERMITTED_SIGNALING_TYPES, FORBIDDEN_KEYS };
