package com.pixel.lanagent

import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import java.security.KeyPairGenerator
import java.security.SecureRandom
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.util.*

class LanSecurityManagerTest {

    private lateinit var mockPrefs: MockSharedPreferences
    private lateinit var securityManager: LanSecurityManager

    @Before
    fun setUp() {
        mockPrefs = MockSharedPreferences()
        securityManager = LanSecurityManager(customPrefs = mockPrefs)
    }

    @Test
    fun testDeviceIdentityPersistence() {
        val pubKeyB64 = securityManager.getDevicePublicKeyBase64()
        val fp = securityManager.getDeviceFingerprint()

        assertNotNull(pubKeyB64)
        assertTrue(pubKeyB64.isNotEmpty())
        assertTrue(fp.contains(":"))

        // Create new instance with same prefs: identity must be preserved
        val mgr2 = LanSecurityManager(customPrefs = mockPrefs)
        assertEquals(pubKeyB64, mgr2.getDevicePublicKeyBase64())
        assertEquals(fp, mgr2.getDeviceFingerprint())
        assertEquals("pixel-managed-device", mgr2.getDeviceId())
    }

    @Test
    fun testPairingBootstrapAndTranscriptVerification() {
        val bootstrap = securityManager.generatePairingBootstrapData()
        assertEquals(6, bootstrap.pin.length)
        assertNotNull(bootstrap.nonce)

        // Generate simulated controller keypair
        val kpg = KeyPairGenerator.getInstance("EC")
        kpg.initialize(ECGenParameterSpec("secp256r1"), SecureRandom())
        val controllerKp = kpg.generateKeyPair()
        val controllerPubB64 = LanSecurityManager.b64Encode(controllerKp.public.encoded)
        val controllerId = "controller-test-1"

        // Candidate transcript hash
        val transcriptHash = securityManager.computeCanonicalPairingTranscriptHash(
            securityManager.getDeviceId(),
            securityManager.getDevicePublicKeyBase64(),
            controllerPubB64,
            bootstrap.pin,
            bootstrap.nonce
        )

        // Verify valid pairing
        val verified = securityManager.verifyPairingTranscript(
            controllerId,
            controllerPubB64,
            transcriptHash,
            bootstrap.nonce
        )
        assertTrue(verified)
        assertTrue(securityManager.isControllerAuthorized(controllerId))

        // Re-use of PIN must fail (cleared on success)
        val retry = securityManager.verifyPairingTranscript(
            controllerId,
            controllerPubB64,
            transcriptHash,
            bootstrap.nonce
        )
        assertFalse(retry)
    }

    @Test
    fun testContextBoundChallengeResponseAuthentication() {
        // Register controller
        val kpg = KeyPairGenerator.getInstance("EC")
        kpg.initialize(ECGenParameterSpec("secp256r1"), SecureRandom())
        val controllerKp = kpg.generateKeyPair()
        val controllerPubB64 = LanSecurityManager.b64Encode(controllerKp.public.encoded)
        val controllerId = "controller-test-auth"

        securityManager.registerController(controllerId, controllerPubB64)
        assertTrue(securityManager.isControllerAuthorized(controllerId))

        // Create challenge
        val challenge = securityManager.createChallenge(controllerId)
        assertEquals("CHALLENGE", challenge.getString("type"))
        assertEquals(LanSecurityManager.PROTOCOL_CONTEXT, challenge.getString("protocol_context"))
        val sessionId = challenge.getString("session_id")
        val nonce = challenge.getString("nonce")
        val timestamp = challenge.getLong("timestamp")

        // Controller signs canonical string:
        // PROTOCOL_CONTEXT:sessionId:nonce:timestamp:pixelId:pixelPubKey:controllerId:controllerPubKey
        val canonicalPayload = "${LanSecurityManager.PROTOCOL_CONTEXT}:$sessionId:$nonce:$timestamp:${securityManager.getDeviceId()}:${securityManager.getDevicePublicKeyBase64()}:$controllerId:$controllerPubB64"
        val signer = Signature.getInstance("SHA256withECDSA")
        signer.initSign(controllerKp.private)
        signer.update(canonicalPayload.toByteArray(Charsets.UTF_8))
        val sigB64 = LanSecurityManager.b64Encode(signer.sign())

        val responseJson = JSONObject().apply {
            put("type", "AUTH_RESPONSE")
            put("protocol_context", LanSecurityManager.PROTOCOL_CONTEXT)
            put("session_id", sessionId)
            put("controller_id", controllerId)
            put("controller_pubkey", controllerPubB64)
            put("signature", sigB64)
        }

        val session = securityManager.verifyChallengeResponse(responseJson)
        assertNotNull(session)
        assertEquals(sessionId, session?.sessionId)
        assertEquals(controllerId, session?.controllerId)
        assertEquals(securityManager.persistentEpoch, session?.epoch)
        assertEquals(session, securityManager.activeSession)
    }

    @Test
    fun testReplayProtectionAndEpochSurvivesProcessRestart() {
        // Setup authenticated session
        val kpg = KeyPairGenerator.getInstance("EC")
        kpg.initialize(ECGenParameterSpec("secp256r1"), SecureRandom())
        val controllerKp = kpg.generateKeyPair()
        val controllerPubB64 = LanSecurityManager.b64Encode(controllerKp.public.encoded)
        val controllerId = "controller-persistent-test"

        securityManager.registerController(controllerId, controllerPubB64)
        val challenge = securityManager.createChallenge(controllerId)
        val sessionId = challenge.getString("session_id")
        val nonce = challenge.getString("nonce")
        val timestamp = challenge.getLong("timestamp")

        val canonical = "${LanSecurityManager.PROTOCOL_CONTEXT}:$sessionId:$nonce:$timestamp:${securityManager.getDeviceId()}:${securityManager.getDevicePublicKeyBase64()}:$controllerId:$controllerPubB64"
        val signer = Signature.getInstance("SHA256withECDSA")
        signer.initSign(controllerKp.private)
        signer.update(canonical.toByteArray(Charsets.UTF_8))
        val sigB64 = LanSecurityManager.b64Encode(signer.sign())

        val session = securityManager.verifyChallengeResponse(JSONObject().apply {
            put("type", "AUTH_RESPONSE")
            put("protocol_context", LanSecurityManager.PROTOCOL_CONTEXT)
            put("session_id", sessionId)
            put("controller_id", controllerId)
            put("controller_pubkey", controllerPubB64)
            put("signature", sigB64)
        })
        assertNotNull(session)

        val cmdId = "cmd-unique-12345"
        val cmdJson = JSONObject().apply {
            put("type", "COMMAND")
            put("command_id", cmdId)
            put("session_id", sessionId)
            put("epoch", session?.epoch)
            put("seq_num", 1L)
            put("timestamp", System.currentTimeMillis())
            put("action", "TAP")
        }

        // 1. Initial valid command
        val val1 = securityManager.validateCommand(cmdJson)
        assertTrue(val1 is LanSecurityManager.CommandValidationResult.Valid)

        // Record execution result
        val responseJson = JSONObject().apply {
            put("status", "ok")
            put("action", "TAP")
        }.toString()
        securityManager.recordCommandResult(cmdId, 1L, System.currentTimeMillis(), responseJson)

        // 2. Immediate replay in same session -> Same session duplicate
        val val2 = securityManager.validateCommand(cmdJson)
        assertTrue(val2 is LanSecurityManager.CommandValidationResult.Duplicate)
        assertEquals("SAME_SESSION_DUPLICATE", (val2 as LanSecurityManager.CommandValidationResult.Duplicate).duplicateType)
        assertEquals(responseJson, val2.cachedResponse)

        // 3. Stale sequence number with new command ID must be rejected
        val staleSeqCmd = JSONObject().apply {
            put("type", "COMMAND")
            put("command_id", "cmd-different-id")
            put("session_id", sessionId)
            put("epoch", session?.epoch)
            put("seq_num", 1L) // <= lastSeqNum (1)
            put("timestamp", System.currentTimeMillis())
            put("action", "TAP")
        }
        val valStale = securityManager.validateCommand(staleSeqCmd)
        assertTrue(valStale is LanSecurityManager.CommandValidationResult.Rejected)

        // 4. Simulate process death & restart:
        // Instantiate a new LanSecurityManager with the SAME persistent preferences
        val restartedSecurityManager = LanSecurityManager(customPrefs = mockPrefs)
        assertTrue(restartedSecurityManager.persistentEpoch > securityManager.persistentEpoch)

        // In new process without active session, new commands are rejected
        val valInNew = restartedSecurityManager.validateCommand(cmdJson)
        assertTrue(valInNew is LanSecurityManager.CommandValidationResult.Rejected)

        // Authenticate in new process
        val ch2 = restartedSecurityManager.createChallenge(controllerId)
        val s2Id = ch2.getString("session_id")
        val s2Nonce = ch2.getString("nonce")
        val s2Time = ch2.getLong("timestamp")
        val canon2 = "${LanSecurityManager.PROTOCOL_CONTEXT}:$s2Id:$s2Nonce:$s2Time:${restartedSecurityManager.getDeviceId()}:${restartedSecurityManager.getDevicePublicKeyBase64()}:$controllerId:$controllerPubB64"
        val signer2 = Signature.getInstance("SHA256withECDSA")
        signer2.initSign(controllerKp.private)
        signer2.update(canon2.toByteArray(Charsets.UTF_8))

        val session2 = restartedSecurityManager.verifyChallengeResponse(JSONObject().apply {
            put("type", "AUTH_RESPONSE")
            put("protocol_context", LanSecurityManager.PROTOCOL_CONTEXT)
            put("session_id", s2Id)
            put("controller_id", controllerId)
            put("controller_pubkey", controllerPubB64)
            put("signature", LanSecurityManager.b64Encode(signer2.sign()))
        })
        assertNotNull(session2)

        // Resubmission of cmd-unique-12345 across reconnect:
        // Must be recognized from persistent journal and returned as RECONNECT_RECOVERY_DUPLICATE
        val resubmittedCmd = JSONObject().apply {
            put("type", "COMMAND")
            put("command_id", cmdId)
            put("session_id", s2Id)
            put("epoch", session2?.epoch)
            put("seq_num", 1L)
            put("timestamp", System.currentTimeMillis())
            put("action", "TAP")
        }
        val valRecovered = restartedSecurityManager.validateCommand(resubmittedCmd)
        assertTrue(valRecovered is LanSecurityManager.CommandValidationResult.Duplicate)
        assertEquals("RECONNECT_RECOVERY_DUPLICATE", (valRecovered as LanSecurityManager.CommandValidationResult.Duplicate).duplicateType)
        assertEquals(responseJson, valRecovered.cachedResponse)
    }

    @Test
    fun testRevocationAuthority() {
        val controllerId = "revoked-test-controller"
        val kpg = KeyPairGenerator.getInstance("EC")
        val kp = kpg.generateKeyPair()
        val pubB64 = LanSecurityManager.b64Encode(kp.public.encoded)

        securityManager.registerController(controllerId, pubB64)
        assertTrue(securityManager.isControllerAuthorized(controllerId))

        // Revoke
        securityManager.revokeController(controllerId)
        assertFalse(securityManager.isControllerAuthorized(controllerId))
        assertNull(securityManager.getControllerPublicKey(controllerId))
    }

    @Test
    fun testMandatoryEpochValidation() {
        val controllerId = "controller-epoch-test"
        val kpg = KeyPairGenerator.getInstance("EC")
        val kp = kpg.generateKeyPair()
        val pubB64 = LanSecurityManager.b64Encode(kp.public.encoded)

        securityManager.registerController(controllerId, pubB64)
        val challenge = securityManager.createChallenge(controllerId)
        val sessionId = challenge.getString("session_id")
        val nonce = challenge.getString("nonce")
        val timestamp = challenge.getLong("timestamp")

        val canonical = "${LanSecurityManager.PROTOCOL_CONTEXT}:$sessionId:$nonce:$timestamp:${securityManager.getDeviceId()}:${securityManager.getDevicePublicKeyBase64()}:$controllerId:$pubB64"
        val signer = Signature.getInstance("SHA256withECDSA")
        signer.initSign(kp.private)
        signer.update(canonical.toByteArray(Charsets.UTF_8))
        val sigB64 = LanSecurityManager.b64Encode(signer.sign())

        val session = securityManager.verifyChallengeResponse(JSONObject().apply {
            put("type", "AUTH_RESPONSE")
            put("protocol_context", LanSecurityManager.PROTOCOL_CONTEXT)
            put("session_id", sessionId)
            put("controller_id", controllerId)
            put("controller_pubkey", pubB64)
            put("signature", sigB64)
        })
        assertNotNull(session)
        val activeEpoch = session!!.epoch

        // 1. Missing epoch -> Rejected
        val cmdMissingEpoch = JSONObject().apply {
            put("type", "COMMAND")
            put("command_id", "cmd-missing-epoch")
            put("session_id", sessionId)
            put("seq_num", 1L)
            put("timestamp", System.currentTimeMillis())
            put("action", "TAP")
        }
        val resMissing = securityManager.validateCommand(cmdMissingEpoch)
        assertTrue(resMissing is LanSecurityManager.CommandValidationResult.Rejected)
        assertEquals("Missing mandatory session epoch", (resMissing as LanSecurityManager.CommandValidationResult.Rejected).reason)

        // 2. Non-numeric epoch -> Rejected
        val cmdNonNumericEpoch = JSONObject().apply {
            put("type", "COMMAND")
            put("command_id", "cmd-non-numeric-epoch")
            put("session_id", sessionId)
            put("epoch", "not-a-number")
            put("seq_num", 1L)
            put("timestamp", System.currentTimeMillis())
            put("action", "TAP")
        }
        val resNonNum = securityManager.validateCommand(cmdNonNumericEpoch)
        assertTrue(resNonNum is LanSecurityManager.CommandValidationResult.Rejected)
        assertEquals("Invalid non-numeric session epoch", (resNonNum as LanSecurityManager.CommandValidationResult.Rejected).reason)

        // 3. Stale / wrong epoch -> Rejected
        val cmdWrongEpoch = JSONObject().apply {
            put("type", "COMMAND")
            put("command_id", "cmd-wrong-epoch")
            put("session_id", sessionId)
            put("epoch", activeEpoch + 99L)
            put("seq_num", 1L)
            put("timestamp", System.currentTimeMillis())
            put("action", "TAP")
        }
        val resWrong = securityManager.validateCommand(cmdWrongEpoch)
        assertTrue(resWrong is LanSecurityManager.CommandValidationResult.Rejected)
        assertTrue((resWrong as LanSecurityManager.CommandValidationResult.Rejected).reason.contains("Stale epoch"))

        // 4. Valid epoch -> Valid
        val cmdValid = JSONObject().apply {
            put("type", "COMMAND")
            put("command_id", "cmd-valid-epoch")
            put("session_id", sessionId)
            put("epoch", activeEpoch)
            put("seq_num", 1L)
            put("timestamp", System.currentTimeMillis())
            put("action", "TAP")
        }
        val resValid = securityManager.validateCommand(cmdValid)
        assertTrue(resValid is LanSecurityManager.CommandValidationResult.Valid)

        // Record execution
        val cachedResp = JSONObject().apply { put("status", "ok") }.toString()
        securityManager.recordCommandResult("cmd-valid-epoch", 1L, System.currentTimeMillis(), cachedResp)

        // 5. Duplicate with current epoch -> Preserved as Duplicate
        val resDuplicateCurrentEpoch = securityManager.validateCommand(cmdValid)
        assertTrue(resDuplicateCurrentEpoch is LanSecurityManager.CommandValidationResult.Duplicate)
        assertEquals(cachedResp, (resDuplicateCurrentEpoch as LanSecurityManager.CommandValidationResult.Duplicate).cachedResponse)

        // 6. Duplicate with missing or stale epoch -> Rejected
        val duplicateMissingEpoch = JSONObject(cmdValid.toString()).apply {
            remove("epoch")
        }
        val resDupMissing = securityManager.validateCommand(duplicateMissingEpoch)
        assertTrue(resDupMissing is LanSecurityManager.CommandValidationResult.Rejected)
    }

    @Test
    fun testOldSessionEpochCannotExecuteInNewSession() {
        val controllerId = "controller-stale-epoch"
        val kpg = KeyPairGenerator.getInstance("EC")
        val kp = kpg.generateKeyPair()
        val pubB64 = LanSecurityManager.b64Encode(kp.public.encoded)

        securityManager.registerController(controllerId, pubB64)
        val ch1 = securityManager.createChallenge(controllerId)
        val s1Id = ch1.getString("session_id")
        val s1Nonce = ch1.getString("nonce")
        val s1Time = ch1.getLong("timestamp")

        val canon1 = "${LanSecurityManager.PROTOCOL_CONTEXT}:$s1Id:$s1Nonce:$s1Time:${securityManager.getDeviceId()}:${securityManager.getDevicePublicKeyBase64()}:$controllerId:$pubB64"
        val signer1 = Signature.getInstance("SHA256withECDSA")
        signer1.initSign(kp.private)
        signer1.update(canon1.toByteArray(Charsets.UTF_8))

        val session1 = securityManager.verifyChallengeResponse(JSONObject().apply {
            put("type", "AUTH_RESPONSE")
            put("protocol_context", LanSecurityManager.PROTOCOL_CONTEXT)
            put("session_id", s1Id)
            put("controller_id", controllerId)
            put("controller_pubkey", pubB64)
            put("signature", LanSecurityManager.b64Encode(signer1.sign()))
        })
        assertNotNull(session1)
        val epoch1 = session1!!.epoch

        // Simulate device reboot / service restart with new epoch
        val mgr2 = LanSecurityManager(customPrefs = mockPrefs)
        assertTrue(mgr2.persistentEpoch > epoch1)

        val ch2 = mgr2.createChallenge(controllerId)
        val s2Id = ch2.getString("session_id")
        val s2Nonce = ch2.getString("nonce")
        val s2Time = ch2.getLong("timestamp")

        val canon2 = "${LanSecurityManager.PROTOCOL_CONTEXT}:$s2Id:$s2Nonce:$s2Time:${mgr2.getDeviceId()}:${mgr2.getDevicePublicKeyBase64()}:$controllerId:$pubB64"
        val signer2 = Signature.getInstance("SHA256withECDSA")
        signer2.initSign(kp.private)
        signer2.update(canon2.toByteArray(Charsets.UTF_8))

        val session2 = mgr2.verifyChallengeResponse(JSONObject().apply {
            put("type", "AUTH_RESPONSE")
            put("protocol_context", LanSecurityManager.PROTOCOL_CONTEXT)
            put("session_id", s2Id)
            put("controller_id", controllerId)
            put("controller_pubkey", pubB64)
            put("signature", LanSecurityManager.b64Encode(signer2.sign()))
        })
        assertNotNull(session2)

        // Attempting to execute command with old epoch1 in new session2
        val staleEpochCmd = JSONObject().apply {
            put("type", "COMMAND")
            put("command_id", "cmd-old-epoch")
            put("session_id", s2Id)
            put("epoch", epoch1)
            put("seq_num", 1L)
            put("timestamp", System.currentTimeMillis())
            put("action", "TAP")
        }
        val res = mgr2.validateCommand(staleEpochCmd)
        assertTrue(res is LanSecurityManager.CommandValidationResult.Rejected)
        assertTrue((res as LanSecurityManager.CommandValidationResult.Rejected).reason.contains("Stale epoch"))
    }

    @Test
    fun testSignalingUrlPersistenceAndRetrieval() {
        assertNull(securityManager.getRemoteSignalingUrl())

        val testUrl = "wss://pixel-relay.example.com:8991/signaling"
        securityManager.setRemoteSignalingUrl(testUrl)
        assertEquals(testUrl, securityManager.getRemoteSignalingUrl())

        // Survives process restart with same preferences
        val mgr2 = LanSecurityManager(customPrefs = mockPrefs)
        assertEquals(testUrl, mgr2.getRemoteSignalingUrl())

        // Clearing removes from preferences
        mgr2.setRemoteSignalingUrl(null)
        assertNull(mgr2.getRemoteSignalingUrl())

        // Blank string also clears
        mgr2.setRemoteSignalingUrl("   ")
        assertNull(mgr2.getRemoteSignalingUrl())
    }
}
