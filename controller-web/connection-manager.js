/**
 * ConnectionManager for Pixel WebRTC Controller
 *
 * Separates physical network transport from the application logical session.
 * Manages WebRTC PeerConnection, ICE restarts, dual signaling, and automatic recovery.
 *
 * MANDATORY SECURITY QUALIFICATIONS:
 * - “WebRTC provides encrypted DTLS/SCTP transport for DataChannels; exact protocol version and cipher suite are implementation dependent.”
 * - “The controller is a RECONNECTABLE CLIENT CONSTRAINED BY IOS/IPADOS LIFECYCLE.”
 * - “The system is DESIGNED FOR AUTOMATIC TRANSPORT RECOVERY AND SESSION RESYNCHRONIZATION; PHYSICAL MIGRATION REMAINS UNVERIFIED.”
 */

class ConnectionManager {
  constructor(options = {}) {
    this.onStateChange = options.onStateChange || (() => {});
    this.onDataChannelOpen = options.onDataChannelOpen || (() => {});
    this.onDataChannelClose = options.onDataChannelClose || (() => {});
    this.onDataChannelMessage = options.onDataChannelMessage || (() => {});

    this.pc = null;
    this.dataChannel = null;
    this.wsSignaling = null;

    this.transportState = "DISCONNECTED"; // DISCONNECTED, CONNECTING, DIRECT_LAN, INTERNET_P2P, TURN_RELAY
    this.activePathDetail = "Disconnected";

    // Configurable ICE Servers (Default Google STUN + Configurable STUN/TURN relays)
    this.iceServers = [
      { urls: "stun:stun.l.google.com:19302" },
      { urls: "stun:stun1.l.google.com:19302" }
    ];

    this.signalingUrl = null;
    this.controllerId = null;
    this.targetDeviceId = "pixel-managed-device";

    this.setupLifecycleListeners();
  }

  setIceServers(servers) {
    if (Array.isArray(servers) && servers.length > 0) {
      this.iceServers = servers;
    }
  }

  setupLifecycleListeners() {
    if (typeof document !== 'undefined') {
      document.addEventListener("visibilitychange", () => {
        if (document.visibilityState === "visible") {
          console.log("[Lifecycle] Returned to foreground. Verifying WebRTC transport...");
          if (!this.dataChannel || this.dataChannel.readyState !== "open") {
            console.log("[Lifecycle] Re-establishing connection after foreground resume...");
            this.reconnect();
          }
        }
      });
    }

    if (typeof window !== 'undefined') {
      window.addEventListener("online", () => {
        console.log("[Network] Device came online. Initiating transport recovery...");
        this.reconnect();
      });
    }
  }

  updateState(state, detail) {
    this.transportState = state;
    this.activePathDetail = detail;
    this.onStateChange(state, detail);
  }

  // --- WebRTC PeerConnection Setup ---

  createPeerConnection() {
    if (this.pc) {
      try { this.pc.close(); } catch (_) {}
    }

    const config = {
      iceServers: this.iceServers,
      iceTransportPolicy: "all", // Direct LAN preferred, then STUN, then TURN
      bundlePolicy: "max-bundle",
      rtcpMuxPolicy: "require"
    };

    this.pc = new RTCPeerConnection(config);

    // Create reliable, ordered DataChannel for management
    this.dataChannel = this.pc.createDataChannel("management", { ordered: true });
    this.setupDataChannel(this.dataChannel);

    this.pc.oniceconnectionstatechange = () => {
      console.log("[WebRTC] ICE state:", this.pc.iceConnectionState);
      const state = this.pc.iceConnectionState;
      if (state === "connected" || state === "completed") {
        this.classifyTransportPath();
      } else if (state === "disconnected" || state === "failed") {
        this.updateState("DISCONNECTED", "Disconnected");
        // Attempt ICE restart
        setTimeout(() => {
          if (this.pc && (this.pc.iceConnectionState === "disconnected" || this.pc.iceConnectionState === "failed")) {
            this.initiateIceRestart("ICE_FAILED_RECOVERY");
          }
        }, 2000);
      } else if (state === "checking") {
        this.updateState("CONNECTING", "Gathering ICE candidates...");
      }
    };

    this.pc.onicecandidate = (event) => {
      if (event.candidate) {
        this.sendSignalingCandidate(event.candidate);
      }
    };

    return this.pc;
  }

  setupDataChannel(dc) {
    dc.onopen = () => {
      console.log("[DataChannel] OPEN");
      this.onDataChannelOpen();
    };

    dc.onmessage = (event) => {
      this.onDataChannelMessage(event.data);
    };

    dc.onclose = () => {
      console.log("[DataChannel] CLOSED");
      this.onDataChannelClose();
    };
  }

  // --- Dynamic Transport Classification ---

  async classifyTransportPath() {
    if (!this.pc) return;
    try {
      const stats = await this.pc.getStats();
      let classified = false;

      stats.forEach((report) => {
        if (report.type === "candidate-pair" && (report.nominated || report.state === "succeeded")) {
          const localCandidate = stats.get(report.localCandidateId);
          const remoteCandidate = stats.get(report.remoteCandidateId);

          const localType = localCandidate ? localCandidate.candidateType : "";
          const remoteType = remoteCandidate ? remoteCandidate.candidateType : "";

          if (localType === "relay" || remoteType === "relay") {
            this.updateState("TURN_RELAY", "TURN Relay");
            classified = true;
          } else if (localType === "host" && remoteType === "host") {
            this.updateState("DIRECT_LAN", "Direct LAN");
            classified = true;
          } else {
            this.updateState("INTERNET_P2P", "Internet P2P (STUN)");
            classified = true;
          }
        }
      });

      if (!classified) {
        this.updateState("DIRECT_LAN", "Direct LAN / P2P");
      }
    } catch (e) {
      console.warn("Error classifying transport:", e);
      this.updateState("DIRECT_LAN", "Active (WebRTC)");
    }
  }

  // --- ICE Restart ---

  async initiateIceRestart(reason = "USER_REQUESTED") {
    console.log("[WebRTC] Initiating ICE restart:", reason);
    if (!this.pc) return;

    // Send signal if remote signaling is connected
    if (this.wsSignaling && this.wsSignaling.readyState === WebSocket.OPEN) {
      this.wsSignaling.send(JSON.stringify({
        type: "ICE_RESTART",
        reason: reason
      }));
    }

    try {
      const offer = await this.pc.createOffer({ iceRestart: true });
      await this.pc.setLocalDescription(offer);

      if (this.wsSignaling && this.wsSignaling.readyState === WebSocket.OPEN) {
        this.wsSignaling.send(JSON.stringify({
          type: "OFFER",
          sdp: offer.sdp,
          ice_restart: true
        }));
      }
    } catch (e) {
      console.error("ICE restart error:", e);
    }
  }

  // --- Remote WebSocket Signaling ---

  connectRemoteSignaling(url, controllerId, targetDeviceId = "pixel-managed-device") {
    this.signalingUrl = url;
    this.controllerId = controllerId;
    this.targetDeviceId = targetDeviceId;

    if (this.wsSignaling) {
      try { this.wsSignaling.close(); } catch (_) {}
    }

    this.updateState("CONNECTING", "Connecting to remote signaling...");
    this.wsSignaling = new WebSocket(url);

    this.wsSignaling.onopen = async () => {
      console.log("[Signaling] Connected to rendezvous:", url);
      // Register with role controller
      this.wsSignaling.send(JSON.stringify({
        type: "REGISTER",
        role: "controller",
        controller_id: controllerId,
        target_device_id: targetDeviceId
      }));

      // Initialize WebRTC and send initial Offer
      this.createPeerConnection();
      const offer = await this.pc.createOffer();
      await this.pc.setLocalDescription(offer);

      this.wsSignaling.send(JSON.stringify({
        type: "OFFER",
        sdp: offer.sdp
      }));
    };

    this.wsSignaling.onmessage = async (event) => {
      try {
        const msg = JSON.parse(event.data);
        console.log("[Signaling] Received:", msg.type);

        if (msg.type === "ANSWER" && msg.sdp) {
          await this.pc.setRemoteDescription(new RTCSessionDescription({
            type: "answer",
            sdp: msg.sdp
          }));
        } else if (msg.type === "ICE_CANDIDATE") {
          await this.pc.addIceCandidate(new RTCIceCandidate({
            candidate: msg.candidate,
            sdpMid: msg.sdpMid,
            sdpMLineIndex: msg.sdpMLineIndex
          }));
        } else if (msg.type === "ICE_RESTART") {
          console.log("[Signaling] Peer requested ICE restart");
          this.initiateIceRestart("REMOTE_SIGNAL");
        } else if (msg.type === "REGISTERED") {
          console.log("[Signaling] Registered successfully. Status:", msg.target_status);
        }
      } catch (err) {
        console.warn("Signaling message handling error:", err);
      }
    };

    this.wsSignaling.onclose = () => {
      console.log("[Signaling] Disconnected from rendezvous");
    };
  }

  sendSignalingCandidate(candidate) {
    if (this.wsSignaling && this.wsSignaling.readyState === WebSocket.OPEN) {
      this.wsSignaling.send(JSON.stringify({
        type: "ICE_CANDIDATE",
        candidate: candidate.candidate,
        sdpMid: candidate.sdpMid,
        sdpMLineIndex: candidate.sdpMLineIndex
      }));
    }
  }

  // --- Local LAN Direct Signaling (HTTP Bootstrap) ---

  async connectDirectLan(ip, port = 8990) {
    const baseUrl = `http://${ip}:${port}`;
    this.updateState("CONNECTING", "Negotiating direct LAN bootstrap...");

    this.createPeerConnection();

    this.pc.onicecandidate = (event) => {
      if (event.candidate) {
        fetch(`${baseUrl}/bootstrap/ice`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            candidate: event.candidate.candidate,
            sdpMid: event.candidate.sdpMid,
            sdpMLineIndex: event.candidate.sdpMLineIndex
          })
        }).catch(console.warn);
      }
    };

    try {
      const offer = await this.pc.createOffer();
      await this.pc.setLocalDescription(offer);

      const res = await fetch(`${baseUrl}/bootstrap/offer`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ sdp: offer.sdp })
      });

      const answerJson = await res.json();
      if (answerJson.status !== "ok" || !answerJson.sdp) {
        throw new Error(answerJson.message || "Failed to obtain SDP answer from LAN bootstrap");
      }

      await this.pc.setRemoteDescription(new RTCSessionDescription({
        type: "answer",
        sdp: answerJson.sdp
      }));

      // Gather candidate list from device
      const candRes = await fetch(`${baseUrl}/bootstrap/candidates`);
      const candData = await candRes.json();
      if (candData.candidates && Array.isArray(candData.candidates)) {
        for (const c of candData.candidates) {
          await this.pc.addIceCandidate(new RTCIceCandidate(c)).catch(console.warn);
        }
      }

      return answerJson;
    } catch (err) {
      console.error("Direct LAN bootstrap error:", err);
      this.updateState("DISCONNECTED", "Direct LAN connection failed");
      throw err;
    }
  }

  reconnect() {
    if (this.signalingUrl && this.controllerId) {
      this.connectRemoteSignaling(this.signalingUrl, this.controllerId, this.targetDeviceId);
    }
  }

  sendDataChannel(obj) {
    if (this.dataChannel && this.dataChannel.readyState === "open") {
      this.dataChannel.send(JSON.stringify(obj));
      return true;
    }
    return false;
  }
}

if (typeof module !== 'undefined' && module.exports) {
  module.exports = { ConnectionManager };
} else if (typeof window !== 'undefined') {
  window.ConnectionManager = ConnectionManager;
}
