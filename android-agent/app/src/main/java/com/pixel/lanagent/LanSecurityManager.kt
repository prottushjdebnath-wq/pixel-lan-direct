package com.pixel.lanagent

import android.content.Context
import android.content.SharedPreferences
import android.util.Log
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import org.json.JSONArray
import org.json.JSONObject
import java.math.BigInteger
import java.security.*
import java.security.spec.ECGenParameterSpec
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import java.util.*
import kotlin.collections.LinkedHashMap

/**
 * Manages Pixel cryptographic identity, controller authorization whitelist,
 * exact pairing transcript binding, context-bound challenge-response authentication,
 * persistent session epochs, and replay defense that survives process restarts.
 *
 * MANDATORY SECURITY QUALIFICATIONS:
 * - “The controller utilizes a browser-managed WebCrypto key with non-extractable API semantics; persistent browser storage security is platform/browser dependent and is not equivalent to hardware-backed Secure Enclave storage.”
 * - “The Pixel core agent is PERSISTENT WHILE ANDROID PERMITS EXECUTION USING SUPPORTED LIFECYCLE MECHANISMS.”
 */
class LanSecurityManager(
    context: Context? = null,
    customPrefs: SharedPreferences? = null
) {
    init {
        require(context != null || customPrefs != null) {
            "Either context or customPrefs must be provided"
        }
    }

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
        private const val KEY_CURRENT_EPOCH = "current_epoch"
        private const val KEY_PERSISTENT_JOURNAL = "persistent_command_journal"
        private const val KEY_PERSISTENT_SIGNALING_URL = "persistent_remote_signaling_url"

        const val PROTOCOL_CONTEXT = "PIXEL_SECURE_AUTH_V1"
        private const val MAX_PAIRING_ATTEMPTS = 3
        private const val RING_BUFFER_MAX_SIZE = 200
        private const val CHALLENGE_TTL_MS = 60_000L // 1 minute
        private const val MAX_CLOCK_DRIFT_MS = 300_000L // 5 minutes

        fun b64Encode(bytes: ByteArray): String =
            Base64.getEncoder().encodeToString(bytes)

        fun b64Decode(str: String): ByteArray =
            Base64.getDecoder().decode(str.trim())

        fun p1363ToDer(sigBytes: ByteArray): ByteArray {
            if (sigBytes.size != 64) return sigBytes
            val rBytes = sigBytes.copyOfRange(0, 32)
            val sBytes = sigBytes.copyOfRange(32, 64)
            val r = BigInteger(1, rBytes).toByteArray()
            val s = BigInteger(1, sBytes).toByteArray()
            val len = 2 + r.size + 2 + s.size
            val der = ByteArray(2 + len)
            der[0] = 0x30.toByte()
            der[1] = len.toByte()
            der[2] = 0x02.toByte()
            der[3] = r.size.toByte()
            System.arraycopy(r, 0, der, 4, r.size)
            val sOffset = 4 + r.size
            der[sOffset] = 0x02.toByte()
            der[sOffset + 1] = s.size.toByte()
            System.arraycopy(s, 0, der, sOffset + 2, s.size)
            return der
        }

        // --- Deterministic Command Canonicalization & Verification ---
        // Format: Length-prefixed fields separated by '|':
        // PROTOCOL_CONTEXT | command_id | session_id | epoch | seq_num | timestamp | action | canonical_parameters | controller_id | controller_pubkey
        // NOTE ON LENGTH PREFIXES: Length prefixes represent UTF-16 code-unit length (i.e. String.length in JS and Java),
        // which is identical across both runtimes for all Unicode characters (including BMP, CJK, and surrogate pairs like emoji).
        // NOTE ON PARAMETERS: Parameters MUST be flat key-value pairs with primitive scalar values (string, number, boolean).
        // Nested JSON objects and arrays are strictly prohibited.

        fun canonicalizeParameters(params: JSONObject?): String {
            if (params == null || params.length() == 0) return ""
            val keys = params.keys().asSequence().toList().sorted()
            return keys.joinToString(",") { k ->
                val raw = params.get(k)
                if (raw is JSONObject || raw is JSONArray) {
                    throw IllegalArgumentException("Command parameter '$k' has non-scalar value. Only primitive scalar values are permitted.")
                }
                val v = raw.toString()
                "${k.length}:$k=${v.length}:$v"
            }
        }

        fun buildCanonicalCommandPayload(
            protocolContext: String = PROTOCOL_CONTEXT,
            commandId: String,
            sessionId: String,
            epoch: Long,
            seqNum: Long,
            timestamp: Long,
            action: String,
            parameters: JSONObject?,
            controllerId: String,
            controllerPubkey: String
        ): String {
            val canonicalParams = canonicalizeParameters(parameters)
            val fields = listOf(
                protocolContext,
                commandId,
                sessionId,
                epoch.toString(),
                seqNum.toString(),
                timestamp.toString(),
                action,
                canonicalParams,
                controllerId,
                controllerPubkey
            )
            return fields.joinToString("|") { "${it.length}:$it" }
        }

        fun signCommandPayload(
            privateKey: PrivateKey,
            commandId: String,
            sessionId: String,
            epoch: Long,
            seqNum: Long,
            timestamp: Long,
            action: String,
            parameters: JSONObject?,
            controllerId: String,
            controllerPubkey: String
        ): String {
            val canonical = buildCanonicalCommandPayload(
                PROTOCOL_CONTEXT,
                commandId,
                sessionId,
                epoch,
                seqNum,
                timestamp,
                action,
                parameters,
                controllerId,
                controllerPubkey
            )
            val signer = Signature.getInstance("SHA256withECDSA")
            signer.initSign(privateKey)
            signer.update(canonical.toByteArray(Charsets.UTF_8))
            return b64Encode(signer.sign())
        }
    }

    private val prefs: SharedPreferences = customPrefs ?: run {
        val ctx = context ?: throw IllegalArgumentException("Context required when customPrefs is not provided")
        val masterKey = MasterKey.Builder(ctx)
            .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
            .build()
        EncryptedSharedPreferences.create(
            ctx,
            PREFS_FILE,
            masterKey,
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
        )
    }

    // Persistent monotonic epoch counter (incremented across agent process restart to invalidate stale commands)
    val persistentEpoch: Long = (prefs.getLong(KEY_CURRENT_EPOCH, 0L) + 1L).also {
        prefs.edit().putLong(KEY_CURRENT_EPOCH, it).commit()
    }

    // Pixel persistent ECDSA P-256 keypair
    private val deviceKeyPair: KeyPair = loadOrCreateDeviceKeyPair()

    // Active session and ephemeral challenge state
    private var pendingChallenge: EphemeralChallenge? = null
    var activeSession: AuthSession? = null
        private set

    // Command execution record for reconnect-safe idempotency & persistent replay defense
    data class CommandRecord(
        val commandId: String,
        val sessionId: String,
        val controllerId: String,
        val seqNum: Long,
        val timestamp: Long,
        val responseJson: String
    )

    // Sliding ring buffer for command idempotency (max 200 entries, loaded from persistent journal on restart)
    private val commandRingBuffer = object : LinkedHashMap<String, CommandRecord>(RING_BUFFER_MAX_SIZE, 0.75f, true) {
        override fun removeEldestEntry(eldest: MutableMap.MutableEntry<String, CommandRecord>?): Boolean {
            return size > RING_BUFFER_MAX_SIZE
        }
    }

    init {
        loadPersistentJournal()
    }

    private fun loadPersistentJournal() {
        val rawJournal = prefs.getString(KEY_PERSISTENT_JOURNAL, null) ?: return
        try {
            val json = JSONObject(rawJournal)
            val keys = json.keys()
            synchronized(commandRingBuffer) {
                while (keys.hasNext()) {
                    val k = keys.next()
                    val obj = json.getJSONObject(k)
                    commandRingBuffer[k] = CommandRecord(
                        commandId = obj.getString("command_id"),
                        sessionId = obj.getString("session_id"),
                        controllerId = obj.getString("controller_id"),
                        seqNum = obj.getLong("seq_num"),
                        timestamp = obj.getLong("timestamp"),
                        responseJson = obj.getString("response_json")
                    )
                }
            }
        } catch (e: Exception) {
            Log.w(TAG, "Failed to load persistent command journal: ${e.message}")
        }
    }

    private fun persistJournal() {
        try {
            val json = JSONObject()
            synchronized(commandRingBuffer) {
                for ((k, v) in commandRingBuffer) {
                    json.put(k, JSONObject().apply {
                        put("command_id", v.commandId)
                        put("session_id", v.sessionId)
                        put("controller_id", v.controllerId)
                        put("seq_num", v.seqNum)
                        put("timestamp", v.timestamp)
                        put("response_json", v.responseJson)
                    })
                }
            }
            prefs.edit().putString(KEY_PERSISTENT_JOURNAL, json.toString()).apply()
        } catch (e: Exception) {
            Log.w(TAG, "Failed to persist command journal: ${e.message}")
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

    // --- Device Identity ---

    private fun loadOrCreateDeviceKeyPair(): KeyPair {
        val pubB64 = prefs.getString(KEY_DEVICE_PUBKEY, null)
        val privB64 = prefs.getString(KEY_DEVICE_PRIVKEY, null)

        if (pubB64 != null && privB64 != null) {
            try {
                val keyFactory = KeyFactory.getInstance("EC")
                val pubSpec = X509EncodedKeySpec(b64Decode(pubB64))
                val privSpec = PKCS8EncodedKeySpec(b64Decode(privB64))
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

        val pubEncoded = b64Encode(newKp.public.encoded)
        val privEncoded = b64Encode(newKp.private.encoded)
        prefs.edit()
            .putString(KEY_DEVICE_PUBKEY, pubEncoded)
            .putString(KEY_DEVICE_PRIVKEY, privEncoded)
            .apply()

        Log.i(TAG, "New device keypair created. Fingerprint: ${computeSha256Fingerprint(newKp.public.encoded)}")
        return newKp
    }

    fun getDevicePublicKey(): PublicKey = deviceKeyPair.public

    fun getDevicePublicKeyBase64(): String = b64Encode(deviceKeyPair.public.encoded)

    fun getDeviceFingerprint(): String = computeSha256Fingerprint(deviceKeyPair.public.encoded)

    fun getDeviceId(): String = "pixel-managed-device"

    fun computeSha256Fingerprint(derBytes: ByteArray): String {
        val md = MessageDigest.getInstance("SHA-256")
        val digest = md.digest(derBytes)
        return digest.joinToString(":") { "%02X".format(it) }
    }

    // --- Exact Pairing Transcript Binding ---
    // Formula: SHA-256(Pixel_ID || Pixel_Public_Key || Controller_Public_Key || Pairing_PIN || Ephemeral_Nonce)

    fun generatePairingBootstrapData(): PairingBootstrapData {
        val pin = (100000..999999).random().toString()
        val nonceBytes = ByteArray(32)
        SecureRandom().nextBytes(nonceBytes)
        val nonce = b64Encode(nonceBytes)
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
            val pubBytes = b64Decode(publicKeyDerBase64)
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
            val pubSpec = X509EncodedKeySpec(b64Decode(pubB64))
            keyFactory.generatePublic(pubSpec)
        } catch (e: Exception) {
            Log.e(TAG, "Failed to decode controller public key: ${e.message}")
            null
        }
    }

    fun getControllerPublicKeyBase64(controllerId: String): String? {
        val controllers = getPairedControllersMap()
        val record = controllers.optJSONObject(controllerId) ?: return null
        if (record.optBoolean("revoked", false)) return null
        val pubB64 = record.optString("public_key", "")
        return pubB64.ifEmpty { null }
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

    // --- Persistent Signaling Configuration ---

    fun setRemoteSignalingUrl(url: String?) {
        if (url.isNullOrBlank()) {
            prefs.edit().remove(KEY_PERSISTENT_SIGNALING_URL).apply()
        } else {
            prefs.edit().putString(KEY_PERSISTENT_SIGNALING_URL, url.trim()).apply()
        }
    }

    fun getRemoteSignalingUrl(): String? {
        return prefs.getString(KEY_PERSISTENT_SIGNALING_URL, null)
    }

    // --- Context-Bound Challenge-Response Authentication ---
    // Payload explicitly binds: PROTOCOL_CONTEXT || Session_UUID || Nonce || Timestamp || Pixel_ID || Pixel_PubKey || Controller_ID || Controller_PubKey

    fun createChallenge(controllerId: String): JSONObject {
        val sessionId = UUID.randomUUID().toString()
        val nonceBytes = ByteArray(32)
        SecureRandom().nextBytes(nonceBytes)
        val nonce = b64Encode(nonceBytes)
        val timestamp = System.currentTimeMillis()

        pendingChallenge = EphemeralChallenge(sessionId, controllerId, nonce, timestamp)

        return JSONObject().apply {
            put("type", "CHALLENGE")
            put("protocol_context", PROTOCOL_CONTEXT)
            put("session_id", sessionId)
            put("epoch", persistentEpoch)
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
        val protoContext = responseJson.optString("protocol_context", "")

        if (protoContext.isNotEmpty() && protoContext != PROTOCOL_CONTEXT) {
            Log.w(TAG, "Protocol context mismatch in challenge response")
            return null
        }

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
            val controllerPubkeyB64 = responseJson.optString("controller_pubkey").ifEmpty {
                b64Encode(controllerKey.encoded)
            }

            // Bind authentication to Pixel identity, controller key, session UUID, nonce, and protocol context
            val canonicalPayload = "$PROTOCOL_CONTEXT:${challenge.sessionId}:${challenge.nonce}:${challenge.timestamp}:${getDeviceId()}:${getDevicePublicKeyBase64()}:$controllerId:$controllerPubkeyB64"
            val verifier = Signature.getInstance("SHA256withECDSA")
            verifier.initVerify(controllerKey)
            verifier.update(canonicalPayload.toByteArray(Charsets.UTF_8))
            val sigBytes = p1363ToDer(b64Decode(sigB64))

            if (verifier.verify(sigBytes)) {
                pendingChallenge = null
                val session = AuthSession(
                    sessionId = challenge.sessionId,
                    controllerId = controllerId,
                    epoch = persistentEpoch,
                    lastSeqNum = 0L
                )
                activeSession = session
                Log.i(TAG, "Controller $controllerId authenticated! Session: ${session.sessionId}, Epoch: ${session.epoch}")
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

    // --- Hardened Command Validation & Persistent Replay Engine ---

    fun validateCommand(cmdJson: JSONObject): CommandValidationResult {
        // 1. Active authenticated session
        val session = activeSession ?: return CommandValidationResult.Rejected("No active authenticated session")

        // 2. Basic command structure
        val commandId = cmdJson.optString("command_id")
        val cmdSessionId = cmdJson.optString("session_id")
        val seqNum = cmdJson.optLong("seq_num", -1L)
        val timestamp = cmdJson.optLong("timestamp", 0L)
        val action = cmdJson.optString("action")
        val signature = cmdJson.optString("signature")

        if (commandId.isEmpty()) {
            return CommandValidationResult.Rejected("Missing command_id")
        }

        if (seqNum < 0) {
            return CommandValidationResult.Rejected("Missing or invalid seq_num")
        }

        if (action.isEmpty()) {
            return CommandValidationResult.Rejected("Missing action")
        }

        if (signature.isEmpty()) {
            return CommandValidationResult.Rejected("Missing command signature")
        }

        // 3. Mandatory epoch validation
        if (!cmdJson.has("epoch")) {
            return CommandValidationResult.Rejected("Missing mandatory session epoch")
        }
        val epoch = try {
            cmdJson.getLong("epoch")
        } catch (_: Exception) {
            return CommandValidationResult.Rejected("Invalid non-numeric session epoch")
        }

        // 4. Epoch == active session epoch
        if (epoch != session.epoch) {
            return CommandValidationResult.Rejected("Stale epoch: received $epoch != active ${session.epoch}")
        }

        // 5. Timestamp validation
        val now = System.currentTimeMillis()
        if (Math.abs(now - timestamp) > MAX_CLOCK_DRIFT_MS) {
            return CommandValidationResult.Rejected("Command timestamp expired or excessive clock drift (> 5 min)")
        }

        // 6. Session_id validation
        if (cmdSessionId != session.sessionId) {
            return CommandValidationResult.Rejected("Invalid session_id for current epoch; command not found in idempotency cache")
        }

        // 7. Application-layer command signature verification
        val controllerKey = getControllerPublicKey(session.controllerId)
            ?: return CommandValidationResult.Rejected("Controller public key not found or revoked")
        val controllerPubB64 = getControllerPublicKeyBase64(session.controllerId)
            ?: return CommandValidationResult.Rejected("Controller public key not available")

        val params = cmdJson.optJSONObject("parameters")
        val canonicalPayload = buildCanonicalCommandPayload(
            protocolContext = PROTOCOL_CONTEXT,
            commandId = commandId,
            sessionId = cmdSessionId,
            epoch = epoch,
            seqNum = seqNum,
            timestamp = timestamp,
            action = action,
            parameters = params,
            controllerId = session.controllerId,
            controllerPubkey = controllerPubB64
        )

        val isValidSig = try {
            val sigBytes = p1363ToDer(b64Decode(signature))
            val verifier = Signature.getInstance("SHA256withECDSA")
            verifier.initVerify(controllerKey)
            verifier.update(canonicalPayload.toByteArray(Charsets.UTF_8))
            verifier.verify(sigBytes)
        } catch (e: Exception) {
            Log.w(TAG, "Command signature verification exception: ${e.message}")
            false
        }

        if (!isValidSig) {
            return CommandValidationResult.Rejected("Invalid command signature")
        }

        // 8. Duplicate / idempotency handling against persistent ring buffer
        synchronized(commandRingBuffer) {
            val cachedRecord = commandRingBuffer[commandId]
            if (cachedRecord != null) {
                return if (cachedRecord.sessionId == session.sessionId) {
                    CommandValidationResult.Duplicate(cachedRecord.responseJson, "SAME_SESSION_DUPLICATE")
                } else if (cachedRecord.controllerId == session.controllerId) {
                    CommandValidationResult.Duplicate(cachedRecord.responseJson, "RECONNECT_RECOVERY_DUPLICATE")
                } else {
                    CommandValidationResult.Rejected("Duplicate command_id from different controller")
                }
            }
        }

        // 9. Monotonic sequence number enforcement within the session
        if (seqNum <= session.lastSeqNum) {
            return CommandValidationResult.Rejected("Stale sequence number: received $seqNum <= last seen ${session.lastSeqNum}")
        }

        // 10. Authorization / session consistency: verified in Steps 1, 6, 7
        // 11. Execution: caller proceeds
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
        persistJournal()
    }
}
