package com.pixel.lanagent

import android.content.Context
import android.util.Base64
import android.util.Log
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import org.json.JSONObject
import java.security.*
import java.security.spec.ECGenParameterSpec
import java.security.spec.X509EncodedKeySpec
import java.util.*
import kotlin.collections.LinkedHashMap

/**
 * Manages Pixel cryptographic identity, controller authorization whitelist,
 * exact pairing transcript binding, challenge-response authentication,
 * and cross-reconnect command idempotency.
 */
class LanSecurityManager(context: Context) {

    companion object {
        private const val TAG = "LanSecurityManager"
        private const val PREFS_FILE = "pixel_lan_security_prefs"
        private const val KEY_DEVICE_PUBKEY = "device_pubkey_der"
        private const val KEY_DEVICE_PRIVKEY = "device_privkey_der"
        private const val KEY_PAIRED_CONTROLLERS = "paired_controllers"
        private const val KEY_ACTIVE_PAIRING_CODE = "active_pairing_code"
        private const val KEY_ACTIVE_PAIRING_NONCE = "active_pairing_nonce"
        private const val KEY_PAIRING_CODE_EXPIRY = "pairing_code_expiry"
        private const val KEY_PAIRING_ATTEMPTS = "pairing_attempts"
        private const val MAX_PAIRING_ATTEMPTS = 3
        private const val RING_BUFFER_MAX_SIZE = 200
        private const val CHALLENGE_TTL_MS = 60_000L // 1 minute
        private const val MAX_CLOCK_DRIFT_MS = 300_000L // 5 minutes
    }

    private val masterKey = MasterKey.Builder(context)
        .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
        .build()

    private val prefs = EncryptedSharedPreferences.create(
        context,
        PREFS_FILE,
        masterKey,
        EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
        EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
    )

    // Pixel persistent ECDSA P-256 keypair
    private val deviceKeyPair: KeyPair = loadOrCreateDeviceKeyPair()

    // Active session and ephemeral challenge state
    private var pendingChallenge: EphemeralChallenge? = null
    var activeSession: AuthSession? = null
        private set

    // Command execution record for reconnect-safe idempotency
    data class CommandRecord(
        val commandId: String,
        val sessionId: String,
        val controllerId: String,
        val seqNum: Long,
        val timestamp: Long,
        val responseJson: String
    )

    // Sliding ring buffer for command idempotency (max 200 entries, preserved across session reconnects)
    private val commandRingBuffer = object : LinkedHashMap<String, CommandRecord>(RING_BUFFER_MAX_SIZE, 0.75f, true) {
        override fun removeEldestEntry(eldest: MutableMap.MutableEntry<String, CommandRecord>?): Boolean {
            return size > RING_BUFFER_MAX_SIZE
        }
    }

    data class EphemeralChallenge(
        val sessionId: String,
        val controllerId: String,
        val nonce: String,
        val timestamp: Long
    )

    data class AuthSession(
        val sessionId: String,
        val controllerId: String,
        val epoch: Long,
        var lastSeqNum: Long = 0L
    )

    data class PairingBootstrapData(
        val pin: String,
        val nonce: String,
        val expiry: Long
    )

    sealed class CommandValidationResult {
        object Valid : CommandValidationResult()
        data class Duplicate(val cachedResponse: String, val duplicateType: String) : CommandValidationResult()
        data class Rejected(val reason: String) : CommandValidationResult()
    }

    // --- Device Identity (Layer 2) ---

    private fun loadOrCreateDeviceKeyPair(): KeyPair {
        val pubB64 = prefs.getString(KEY_DEVICE_PUBKEY, null)
        val privB64 = prefs.getString(KEY_DEVICE_PRIVKEY, null)

        if (pubB64 != null && privB64 != null) {
            try {
                val keyFactory = KeyFactory.getInstance("EC")
                val pubSpec = X509EncodedKeySpec(Base64.decode(pubB64, Base64.NO_WRAP))
                val privSpec = java.security.spec.PKCS8EncodedKeySpec(Base64.decode(privB64, Base64.NO_WRAP))
                val pub = keyFactory.generatePublic(pubSpec)
                val priv = keyFactory.generatePrivate(privSpec)
                return KeyPair(pub, priv)
            } catch (e: Exception) {
                Log.w(TAG, "Failed to load device keypair, generating new: ${e.message}")
            }
        }

        // Generate ECDSA P-256 (secp256r1)
        val kpg = KeyPairGenerator.getInstance("EC")
        kpg.initialize(ECGenParameterSpec("secp256r1"), SecureRandom())
        val newKp = kpg.generateKeyPair()

        val pubEncoded = Base64.encodeToString(newKp.public.encoded, Base64.NO_WRAP)
        val privEncoded = Base64.encodeToString(newKp.private.encoded, Base64.NO_WRAP)
        prefs.edit()
            .putString(KEY_DEVICE_PUBKEY, pubEncoded)
            .putString(KEY_DEVICE_PRIVKEY, privEncoded)
            .apply()

        Log.i(TAG, "New device keypair created. Fingerprint: ${computeSha256Fingerprint(newKp.public.encoded)}")
        return newKp
    }

    fun getDevicePublicKey(): PublicKey = deviceKeyPair.public

    fun getDevicePublicKeyBase64(): String = Base64.encodeToString(deviceKeyPair.public.encoded, Base64.NO_WRAP)

    fun getDeviceFingerprint(): String = computeSha256Fingerprint(deviceKeyPair.public.encoded)

    fun getDeviceId(): String = "pixel-managed-device"

    fun computeSha256Fingerprint(derBytes: ByteArray): String {
        val md = MessageDigest.getInstance("SHA-256")
        val digest = md.digest(derBytes)
        return digest.joinToString(":") { "%02X".format(it) }
    }

    // --- Exact Pairing Transcript Binding (Layer 1) ---
    // Formula: SHA-256(Pixel_ID || Pixel_Public_Key || Controller_Public_Key || Pairing_PIN || Ephemeral_Nonce)

    fun generatePairingBootstrapData(): PairingBootstrapData {
        val pin = (100000..999999).random().toString()
        val nonceBytes = ByteArray(32)
        SecureRandom().nextBytes(nonceBytes)
        val nonce = Base64.encodeToString(nonceBytes, Base64.NO_WRAP)
        val expiry = System.currentTimeMillis() + (5 * 60 * 1000L) // 5 min TTL

        prefs.edit()
            .putString(KEY_ACTIVE_PAIRING_CODE, pin)
            .putString(KEY_ACTIVE_PAIRING_NONCE, nonce)
            .putLong(KEY_PAIRING_CODE_EXPIRY, expiry)
            .putInt(KEY_PAIRING_ATTEMPTS, 0)
            .apply()

        return PairingBootstrapData(pin, nonce, expiry)
    }

    fun computeCanonicalPairingTranscriptHash(
        pixelId: String,
        pixelPubKeyB64: String,
        controllerPubKeyB64: String,
        pairingPin: String,
        nonce: String
    ): String {
        // Unambiguous canonical string: Pixel_ID || Pixel_Public_Key || Controller_Public_Key || Pairing_PIN || Ephemeral_Nonce
        val canonical = "$pixelId:$pixelPubKeyB64:$controllerPubKeyB64:$pairingPin:$nonce"
        val md = MessageDigest.getInstance("SHA-256")
        val digest = md.digest(canonical.toByteArray(Charsets.UTF_8))
        return digest.joinToString("") { "%02x".format(it) }
    }

    fun verifyPairingTranscript(
        controllerId: String,
        controllerPubKeyB64: String,
        candidateTranscriptHash: String,
        candidateNonce: String
    ): Boolean {
        val activePin = prefs.getString(KEY_ACTIVE_PAIRING_CODE, null) ?: return false
        val activeNonce = prefs.getString(KEY_ACTIVE_PAIRING_NONCE, null) ?: return false
        val expiry = prefs.getLong(KEY_PAIRING_CODE_EXPIRY, 0L)
        val attempts = prefs.getInt(KEY_PAIRING_ATTEMPTS, 0)

        if (attempts >= MAX_PAIRING_ATTEMPTS || System.currentTimeMillis() > expiry) {
            clearPairingCode()
            return false
        }

        if (candidateNonce != activeNonce) {
            recordFailedPairingAttempt(attempts)
            return false
        }

        val expectedHash = computeCanonicalPairingTranscriptHash(
            getDeviceId(),
            getDevicePublicKeyBase64(),
            controllerPubKeyB64,
            activePin,
            activeNonce
        )

        // Constant-time hash comparison
        val match = MessageDigest.isEqual(
            candidateTranscriptHash.lowercase().toByteArray(Charsets.UTF_8),
            expectedHash.lowercase().toByteArray(Charsets.UTF_8)
        )

        if (match) {
            clearPairingCode()
            registerController(controllerId, controllerPubKeyB64)
            return true
        } else {
            recordFailedPairingAttempt(attempts)
            return false
        }
    }

    private fun recordFailedPairingAttempt(currentAttempts: Int) {
        val newAttempts = currentAttempts + 1
        if (newAttempts >= MAX_PAIRING_ATTEMPTS) {
            clearPairingCode()
            Log.w(TAG, "Pairing locked out after $MAX_PAIRING_ATTEMPTS failed attempts")
        } else {
            prefs.edit().putInt(KEY_PAIRING_ATTEMPTS, newAttempts).apply()
        }
    }

    fun clearPairingCode() {
        prefs.edit()
            .remove(KEY_ACTIVE_PAIRING_CODE)
            .remove(KEY_ACTIVE_PAIRING_NONCE)
            .remove(KEY_PAIRING_CODE_EXPIRY)
            .remove(KEY_PAIRING_ATTEMPTS)
            .apply()
    }

    fun registerController(controllerId: String, publicKeyDerBase64: String): Boolean {
        return try {
            val pubBytes = Base64.decode(publicKeyDerBase64, Base64.NO_WRAP)
            val fingerprint = computeSha256Fingerprint(pubBytes)

            val controllers = getPairedControllersMap()
            controllers.put(controllerId, JSONObject().apply {
                put("public_key", publicKeyDerBase64)
                put("fingerprint", fingerprint)
                put("paired_at", System.currentTimeMillis())
                put("revoked", false)
            })
            prefs.edit().putString(KEY_PAIRED_CONTROLLERS, controllers.toString()).apply()
            Log.i(TAG, "Controller registered: $controllerId, FP: $fingerprint")
            true
        } catch (e: Exception) {
            Log.e(TAG, "Error registering controller $controllerId: ${e.message}")
            false
        }
    }

    fun isControllerAuthorized(controllerId: String): Boolean {
        val controllers = getPairedControllersMap()
        val record = controllers.optJSONObject(controllerId) ?: return false
        return !record.optBoolean("revoked", false)
    }

    fun getControllerPublicKey(controllerId: String): PublicKey? {
        val controllers = getPairedControllersMap()
        val record = controllers.optJSONObject(controllerId) ?: return null
        if (record.optBoolean("revoked", false)) return null

        val pubB64 = record.optString("public_key", "")
        if (pubB64.isEmpty()) return null

        return try {
            val keyFactory = KeyFactory.getInstance("EC")
            val pubSpec = X509EncodedKeySpec(Base64.decode(pubB64, Base64.NO_WRAP))
            keyFactory.generatePublic(pubSpec)
        } catch (e: Exception) {
            Log.e(TAG, "Failed to decode controller public key: ${e.message}")
            null
        }
    }

    fun revokeController(controllerId: String) {
        val controllers = getPairedControllersMap()
        val record = controllers.optJSONObject(controllerId)
        if (record != null) {
            record.put("revoked", true)
            prefs.edit().putString(KEY_PAIRED_CONTROLLERS, controllers.toString()).apply()
        }
        if (activeSession?.controllerId == controllerId) {
            terminateActiveSession()
        }
        Log.i(TAG, "Controller $controllerId revoked.")
    }

    fun revokeAllControllers() {
        prefs.edit().remove(KEY_PAIRED_CONTROLLERS).apply()
        terminateActiveSession()
        Log.i(TAG, "All controllers revoked.")
    }

    fun getPairedControllersMap(): JSONObject {
        val raw = prefs.getString(KEY_PAIRED_CONTROLLERS, null) ?: return JSONObject()
        return try {
            JSONObject(raw)
        } catch (_: Exception) {
            JSONObject()
        }
    }

    // --- Challenge-Response Authentication (Layer 4 & Layer 5) ---

    fun createChallenge(controllerId: String): JSONObject {
        val sessionId = UUID.randomUUID().toString()
        val nonceBytes = ByteArray(32)
        SecureRandom().nextBytes(nonceBytes)
        val nonce = Base64.encodeToString(nonceBytes, Base64.NO_WRAP)
        val timestamp = System.currentTimeMillis()

        pendingChallenge = EphemeralChallenge(sessionId, controllerId, nonce, timestamp)

        return JSONObject().apply {
            put("type", "CHALLENGE")
            put("session_id", sessionId)
            put("nonce", nonce)
            put("timestamp", timestamp)
            put("pixel_id", getDeviceId())
            put("pixel_pubkey", getDevicePublicKeyBase64())
            put("pixel_fingerprint", getDeviceFingerprint())
        }
    }

    fun verifyChallengeResponse(responseJson: JSONObject): AuthSession? {
        val challenge = pendingChallenge ?: run {
            Log.w(TAG, "No pending challenge to verify")
            return null
        }

        val sessionId = responseJson.optString("session_id")
        val controllerId = responseJson.optString("controller_id")
        val sigB64 = responseJson.optString("signature")

        if (sessionId != challenge.sessionId || controllerId != challenge.controllerId) {
            Log.w(TAG, "Session ID or Controller ID mismatch in challenge response")
            return null
        }

        if (System.currentTimeMillis() - challenge.timestamp > CHALLENGE_TTL_MS) {
            Log.w(TAG, "Challenge response expired")
            pendingChallenge = null
            return null
        }

        val controllerKey = getControllerPublicKey(controllerId) ?: run {
            Log.w(TAG, "Controller $controllerId public key not found or revoked")
            return null
        }

        return try {
            // Canonical challenge payload: "$sessionId:$nonce:$timestamp:$pixelPubkey"
            val canonicalPayload = "${challenge.sessionId}:${challenge.nonce}:${challenge.timestamp}:${getDevicePublicKeyBase64()}"
            val verifier = Signature.getInstance("SHA256withECDSA")
            verifier.initVerify(controllerKey)
            verifier.update(canonicalPayload.toByteArray(Charsets.UTF_8))
            val sigBytes = Base64.decode(sigB64, Base64.NO_WRAP)

            if (verifier.verify(sigBytes)) {
                pendingChallenge = null
                val session = AuthSession(
                    sessionId = challenge.sessionId,
                    controllerId = controllerId,
                    epoch = System.currentTimeMillis(),
                    lastSeqNum = 0L
                )
                activeSession = session
                // Note: commandRingBuffer is NOT cleared so cross-reconnect duplicate suppression survives!
                Log.i(TAG, "Controller $controllerId authenticated! Session: ${session.sessionId}")
                session
            } else {
                Log.w(TAG, "ECDSA challenge signature verification failed for $controllerId")
                null
            }
        } catch (e: Exception) {
            Log.e(TAG, "Exception verifying challenge response: ${e.message}")
            null
        }
    }

    fun terminateActiveSession() {
        activeSession = null
        pendingChallenge = null
    }

    // --- Reconnect-Safe Anti-Replay & Idempotency Engine (Layer 6) ---

    fun validateCommand(cmdJson: JSONObject): CommandValidationResult {
        val session = activeSession ?: return CommandValidationResult.Rejected("No active authenticated session")

        val cmdSessionId = cmdJson.optString("session_id")
        val commandId = cmdJson.optString("command_id")
        val seqNum = cmdJson.optLong("seq_num", -1L)
        val timestamp = cmdJson.optLong("timestamp", 0L)

        if (commandId.isEmpty()) {
            return CommandValidationResult.Rejected("Missing command_id")
        }

        if (seqNum < 0) {
            return CommandValidationResult.Rejected("Missing or invalid seq_num")
        }

        val now = System.currentTimeMillis()
        if (Math.abs(now - timestamp) > MAX_CLOCK_DRIFT_MS) {
            return CommandValidationResult.Rejected("Command timestamp expired or excessive clock drift (> 5 min)")
        }

        synchronized(commandRingBuffer) {
            val cachedRecord = commandRingBuffer[commandId]
            if (cachedRecord != null) {
                // Determine whether this is a same-session duplicate or reconnect duplicate
                return if (cachedRecord.sessionId == session.sessionId) {
                    CommandValidationResult.Duplicate(cachedRecord.responseJson, "SAME_SESSION_DUPLICATE")
                } else if (cachedRecord.controllerId == session.controllerId) {
                    // Safe duplicate determination across reconnect (lost ACK recovery)
                    CommandValidationResult.Duplicate(cachedRecord.responseJson, "RECONNECT_RECOVERY_DUPLICATE")
                } else {
                    CommandValidationResult.Rejected("Duplicate command_id from different controller")
                }
            }
        }

        // If not in cache, verify that the command belongs strictly to the current session epoch
        if (cmdSessionId != session.sessionId) {
            return CommandValidationResult.Rejected("Invalid session_id for current epoch; command not found in idempotency cache")
        }

        // Monotonic sequence number enforcement within the session
        if (seqNum <= session.lastSeqNum) {
            return CommandValidationResult.Rejected("Stale sequence number: received $seqNum <= last seen ${session.lastSeqNum}")
        }

        return CommandValidationResult.Valid
    }

    fun recordCommandResult(commandId: String, seqNum: Long, timestamp: Long, responseJson: String) {
        val session = activeSession ?: return
        if (seqNum > session.lastSeqNum) {
            session.lastSeqNum = seqNum
        }
        synchronized(commandRingBuffer) {
            commandRingBuffer[commandId] = CommandRecord(
                commandId = commandId,
                sessionId = session.sessionId,
                controllerId = session.controllerId,
                seqNum = seqNum,
                timestamp = timestamp,
                responseJson = responseJson
            )
        }
    }
}
