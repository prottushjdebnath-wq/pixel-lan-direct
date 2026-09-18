/**
 * Pixel Controller Cryptographic Identity & Authentication Module
 *
 * MANDATORY SECURITY QUALIFICATIONS:
 * “The controller utilizes a browser-managed WebCrypto key with non-extractable API semantics; persistent browser storage security is platform/browser dependent and is not equivalent to hardware-backed Secure Enclave storage.”
 */

const PROTOCOL_CONTEXT = "PIXEL_SECURE_AUTH_V1";
const DB_NAME = "PixelControllerDB";
const DB_VERSION = 1;
const STORE_NAME = "KeyStore";
const KEY_ID = "controller_ecdsa_identity";

class ControllerCrypto {
  constructor() {
    this.keyPair = null;
    this.publicKeyDerB64 = null;
    this.fingerprint = null;
    this.controllerId = null;
    this.subtle = (typeof window !== 'undefined' && window.crypto && window.crypto.subtle)
      ? window.crypto.subtle
      : (typeof globalThis !== 'undefined' && globalThis.crypto && globalThis.crypto.subtle)
        ? globalThis.crypto.subtle
        : null;
  }

  async init(customSubtle = null) {
    if (customSubtle) {
      this.subtle = customSubtle;
    }
    if (!this.subtle) {
      throw new Error("WebCrypto API not supported in this environment");
    }

    let record = await this.loadFromStorage();
    if (!record) {
      // Generate non-extractable ECDSA P-256 keypair
      this.keyPair = await this.subtle.generateKey(
        { name: "ECDSA", namedCurve: "P-256" },
        false, // Non-extractable API semantics
        ["sign", "verify"]
      );

      const pubSpki = await this.subtle.exportKey("spki", this.keyPair.publicKey);
      this.publicKeyDerB64 = this.arrayBufferToBase64(pubSpki);

      const fpBuffer = await this.subtle.digest("SHA-256", pubSpki);
      this.fingerprint = this.arrayBufferToHex(fpBuffer);
      this.controllerId = "ctl-" + Math.random().toString(36).substring(2, 10);

      await this.saveToStorage({
        id: KEY_ID,
        keyPair: this.keyPair,
        pubB64: this.publicKeyDerB64,
        fp: this.fingerprint,
        controllerId: this.controllerId
      });
    } else {
      this.keyPair = record.keyPair;
      this.publicKeyDerB64 = record.pubB64;
      this.fingerprint = record.fp;
      this.controllerId = record.controllerId;
    }

    return {
      controllerId: this.controllerId,
      publicKeyDerB64: this.publicKeyDerB64,
      fingerprint: this.fingerprint
    };
  }

  async computePairingTranscriptHash(pixelId, pixelPubKeyB64, pairingPin, nonce) {
    const canonical = `${pixelId}:${pixelPubKeyB64}:${this.publicKeyDerB64}:${pairingPin}:${nonce}`;
    const enc = new TextEncoder();
    const hashBuf = await this.subtle.digest("SHA-256", enc.encode(canonical));
    return Array.from(new Uint8Array(hashBuf))
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');
  }

  async signChallenge(challenge) {
    // Protocol context binding: PROTOCOL_CONTEXT || sessionId || nonce || timestamp || pixelId || pixelPubkey || controllerId || controllerPubkey
    const sessionId = challenge.session_id;
    const nonce = challenge.nonce;
    const timestamp = challenge.timestamp;
    const pixelId = challenge.pixel_id || "pixel-managed-device";
    const pixelPubkey = challenge.pixel_pubkey;

    const canonicalPayload = `${PROTOCOL_CONTEXT}:${sessionId}:${nonce}:${timestamp}:${pixelId}:${pixelPubkey}:${this.controllerId}:${this.publicKeyDerB64}`;
    const enc = new TextEncoder();
    const sigBuf = await this.subtle.sign(
      { name: "ECDSA", hash: { name: "SHA-256" } },
      this.keyPair.privateKey,
      enc.encode(canonicalPayload)
    );

    return {
      type: "AUTH_RESPONSE",
      protocol_context: PROTOCOL_CONTEXT,
      session_id: sessionId,
      controller_id: this.controllerId,
      controller_pubkey: this.publicKeyDerB64,
      timestamp: Date.now(),
      signature: this.arrayBufferToBase64(sigBuf)
    };
  }

  // --- Deterministic Command Canonicalization & Per-Command Signing ---
  // Canonical representation: Length-prefixed fields joined by '|':
  // PROTOCOL_CONTEXT | command_id | session_id | epoch | seq_num | timestamp | action | canonical_parameters | controller_id | controller_pubkey

  canonicalizeParameters(params) {
    if (!params || typeof params !== 'object') return "";
    const keys = Object.keys(params).sort();
    if (keys.length === 0) return "";
    return keys.map(k => {
      const val = String(params[k]);
      return `${k.length}:${k}=${val.length}:${val}`;
    }).join(",");
  }

  buildCanonicalCommandPayload({
    protocolContext = PROTOCOL_CONTEXT,
    commandId,
    sessionId,
    epoch,
    seqNum,
    timestamp,
    action,
    parameters = {},
    controllerId,
    controllerPubkey
  }) {
    const canonicalParams = this.canonicalizeParameters(parameters);
    const fields = [
      String(protocolContext),
      String(commandId),
      String(sessionId),
      String(epoch),
      String(seqNum),
      String(timestamp),
      String(action),
      String(canonicalParams),
      String(controllerId),
      String(controllerPubkey)
    ];
    return fields.map(f => `${f.length}:${f}`).join("|");
  }

  async signCommand(commandObj) {
    if (!this.keyPair || !this.keyPair.privateKey) {
      throw new Error("Controller private key not initialized");
    }
    const canonicalPayload = this.buildCanonicalCommandPayload({
      protocolContext: commandObj.protocol_context || PROTOCOL_CONTEXT,
      commandId: commandObj.command_id,
      sessionId: commandObj.session_id,
      epoch: commandObj.epoch,
      seqNum: commandObj.seq_num,
      timestamp: commandObj.timestamp,
      action: commandObj.action,
      parameters: commandObj.parameters,
      controllerId: this.controllerId,
      controllerPubkey: this.publicKeyDerB64
    });

    const enc = new TextEncoder();
    const sigBuf = await this.subtle.sign(
      { name: "ECDSA", hash: { name: "SHA-256" } },
      this.keyPair.privateKey,
      enc.encode(canonicalPayload)
    );

    return this.arrayBufferToBase64(sigBuf);
  }

  // --- Helpers & Storage ---

  arrayBufferToBase64(buffer) {
    let binary = "";
    const bytes = new Uint8Array(buffer);
    for (let i = 0; i < bytes.byteLength; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    if (typeof btoa !== 'undefined') {
      return btoa(binary);
    }
    return Buffer.from(binary, 'binary').toString('base64');
  }

  arrayBufferToHex(buffer) {
    const bytes = new Uint8Array(buffer);
    return Array.from(bytes)
      .map(b => b.toString(16).padStart(2, '0').toUpperCase())
      .join(':');
  }

  async loadFromStorage() {
    if (typeof indexedDB === 'undefined') return null;
    return new Promise((resolve) => {
      try {
        const req = indexedDB.open(DB_NAME, DB_VERSION);
        req.onupgradeneeded = (e) => {
          e.target.result.createObjectStore(STORE_NAME, { keyPath: "id" });
        };
        req.onsuccess = () => {
          const db = req.result;
          const tx = db.transaction(STORE_NAME, "readonly");
          const getReq = tx.objectStore(STORE_NAME).get(KEY_ID);
          getReq.onsuccess = () => resolve(getReq.result || null);
          getReq.onerror = () => resolve(null);
        };
        req.onerror = () => resolve(null);
      } catch (_) {
        resolve(null);
      }
    });
  }

  async saveToStorage(record) {
    if (typeof indexedDB === 'undefined') return;
    return new Promise((resolve) => {
      try {
        const req = indexedDB.open(DB_NAME, DB_VERSION);
        req.onupgradeneeded = (e) => {
          e.target.result.createObjectStore(STORE_NAME, { keyPath: "id" });
        };
        req.onsuccess = () => {
          const db = req.result;
          const tx = db.transaction(STORE_NAME, "readwrite");
          tx.objectStore(STORE_NAME).put(record);
          tx.oncomplete = () => resolve();
          tx.onerror = () => resolve();
        };
        req.onerror = () => resolve();
      } catch (_) {
        resolve();
      }
    });
  }
}

if (typeof module !== 'undefined' && module.exports) {
  module.exports = { ControllerCrypto, PROTOCOL_CONTEXT };
} else if (typeof window !== 'undefined') {
  window.ControllerCrypto = ControllerCrypto;
  window.PROTOCOL_CONTEXT = PROTOCOL_CONTEXT;
}
