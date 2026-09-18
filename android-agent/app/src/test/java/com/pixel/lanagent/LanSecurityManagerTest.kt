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
        val cmdTime = System.currentTimeMillis()
        val sig1 = LanSecurityManager.signCommandPayload(
            controllerKp.private, cmdId, sessionId, session!!.epoch, 1L, cmdTime, "TAP", null, controllerId, controllerPubB64
        )
        val cmdJson = JSONObject().apply {
            put("type", "COMMAND")
            put("command_id", cmdId)
            put("session_id", sessionId)
            put("epoch", session?.epoch)
            put("seq_num", 1L)
            put("timestamp", cmdTime)
            put("action", "TAP")
            put("signature", sig1)
        }

        // 1. Initial valid command
        val val1 = securityManager.validateCommand(cmdJson)
        assertTrue(val1 is LanSecurityManager.CommandValidationResult.Valid)

        // Record execution result
        val responseJson = JSONObject().apply {
            put("status", "ok")
            put("action", "TAP")
        }.toString()
        securityManager.recordCommandResult(cmdId, 1L, cmdTime, responseJson)

        // 2. Immediate replay in same session -> Same session duplicate
        val val2 = securityManager.validateCommand(cmdJson)
        assertTrue(val2 is LanSecurityManager.CommandValidationResult.Duplicate)
        assertEquals("SAME_SESSION_DUPLICATE", (val2 as LanSecurityManager.CommandValidationResult.Duplicate).duplicateType)
        assertEquals(responseJson, val2.cachedResponse)

        // 3. Stale sequence number with new command ID must be rejected
        val staleTime = System.currentTimeMillis()
        val staleSig = LanSecurityManager.signCommandPayload(
            controllerKp.private, "cmd-different-id", sessionId, session!!.epoch, 1L, staleTime, "TAP", null, controllerId, controllerPubB64
        )
        val staleSeqCmd = JSONObject().apply {
            put("type", "COMMAND")
            put("command_id", "cmd-different-id")
            put("session_id", sessionId)
            put("epoch", session?.epoch)
            put("seq_num", 1L) // <= lastSeqNum (1)
            put("timestamp", staleTime)
            put("action", "TAP")
            put("signature", staleSig)
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
        val resubTime = System.currentTimeMillis()
        val sigResub = LanSecurityManager.signCommandPayload(
            controllerKp.private, cmdId, s2Id, session2!!.epoch, 1L, resubTime, "TAP", null, controllerId, controllerPubB64
        )
        val resubmittedCmd = JSONObject().apply {
            put("type", "COMMAND")
            put("command_id", cmdId)
            put("session_id", s2Id)
            put("epoch", session2?.epoch)
            put("seq_num", 1L)
            put("timestamp", resubTime)
            put("action", "TAP")
            put("signature", sigResub)
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
        val now = System.currentTimeMillis()

        // 1. Missing epoch -> Rejected
        val sigMissing = LanSecurityManager.signCommandPayload(
            kp.private, "cmd-missing-epoch", sessionId, activeEpoch, 1L, now, "TAP", null, controllerId, pubB64
        )
        val cmdMissingEpoch = JSONObject().apply {
            put("type", "COMMAND")
            put("command_id", "cmd-missing-epoch")
            put("session_id", sessionId)
            put("seq_num", 1L)
            put("timestamp", now)
            put("action", "TAP")
            put("signature", sigMissing)
        }
        val resMissing = securityManager.validateCommand(cmdMissingEpoch)
        assertTrue(resMissing is LanSecurityManager.CommandValidationResult.Rejected)
        assertEquals("Missing mandatory session epoch", (resMissing as LanSecurityManager.CommandValidationResult.Rejected).reason)

        // 2. Non-numeric epoch -> Rejected
        val sigNonNum = LanSecurityManager.signCommandPayload(
            kp.private, "cmd-non-numeric-epoch", sessionId, activeEpoch, 1L, now, "TAP", null, controllerId, pubB64
        )
        val cmdNonNumericEpoch = JSONObject().apply {
            put("type", "COMMAND")
            put("command_id", "cmd-non-numeric-epoch")
            put("session_id", sessionId)
            put("epoch", "not-a-number")
            put("seq_num", 1L)
            put("timestamp", now)
            put("action", "TAP")
            put("signature", sigNonNum)
        }
        val resNonNum = securityManager.validateCommand(cmdNonNumericEpoch)
        assertTrue(resNonNum is LanSecurityManager.CommandValidationResult.Rejected)
        assertEquals("Invalid non-numeric session epoch", (resNonNum as LanSecurityManager.CommandValidationResult.Rejected).reason)

        // 3. Stale / wrong epoch -> Rejected
        val wrongEpochVal = activeEpoch + 99L
        val sigWrong = LanSecurityManager.signCommandPayload(
            kp.private, "cmd-wrong-epoch", sessionId, wrongEpochVal, 1L, now, "TAP", null, controllerId, pubB64
        )
        val cmdWrongEpoch = JSONObject().apply {
            put("type", "COMMAND")
            put("command_id", "cmd-wrong-epoch")
            put("session_id", sessionId)
            put("epoch", wrongEpochVal)
            put("seq_num", 1L)
            put("timestamp", now)
            put("action", "TAP")
            put("signature", sigWrong)
        }
        val resWrong = securityManager.validateCommand(cmdWrongEpoch)
        assertTrue(resWrong is LanSecurityManager.CommandValidationResult.Rejected)
        assertTrue((resWrong as LanSecurityManager.CommandValidationResult.Rejected).reason.contains("Stale epoch"))

        // 4. Valid epoch -> Valid
        val sigValid = LanSecurityManager.signCommandPayload(
            kp.private, "cmd-valid-epoch", sessionId, activeEpoch, 1L, now, "TAP", null, controllerId, pubB64
        )
        val cmdValid = JSONObject().apply {
            put("type", "COMMAND")
            put("command_id", "cmd-valid-epoch")
            put("session_id", sessionId)
            put("epoch", activeEpoch)
            put("seq_num", 1L)
            put("timestamp", now)
            put("action", "TAP")
            put("signature", sigValid)
        }
        val resValid = securityManager.validateCommand(cmdValid)
        assertTrue(resValid is LanSecurityManager.CommandValidationResult.Valid)

        // Record execution
        val cachedResp = JSONObject().apply { put("status", "ok") }.toString()
        securityManager.recordCommandResult("cmd-valid-epoch", 1L, now, cachedResp)

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
        val now = System.currentTimeMillis()
        val oldSig = LanSecurityManager.signCommandPayload(
            kp.private, "cmd-old-epoch", s2Id, epoch1, 1L, now, "TAP", null, controllerId, pubB64
        )
        val staleEpochCmd = JSONObject().apply {
            put("type", "COMMAND")
            put("command_id", "cmd-old-epoch")
            put("session_id", s2Id)
            put("epoch", epoch1)
            put("seq_num", 1L)
            put("timestamp", now)
            put("action", "TAP")
            put("signature", oldSig)
        }
        val res = mgr2.validateCommand(staleEpochCmd)
        assertTrue(res is LanSecurityManager.CommandValidationResult.Rejected)
        assertTrue((res as LanSecurityManager.CommandValidationResult.Rejected).reason.contains("Stale epoch"))
    }

    @Test
    fun testCommandCryptographicAuthentication() {
        val controllerId = "controller-crypto-test"
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

        val cmdId = "cmd-crypto-1"
        val now = System.currentTimeMillis()
        val params = JSONObject().apply {
            put("x", 100)
            put("y", 200)
        }

        val validSig = LanSecurityManager.signCommandPayload(
            kp.private, cmdId, sessionId, activeEpoch, 1L, now, "TAP", params, controllerId, pubB64
        )

        // 1. Missing command signature -> rejected
        val cmdMissingSig = JSONObject().apply {
            put("type", "COMMAND")
            put("command_id", cmdId)
            put("session_id", sessionId)
            put("epoch", activeEpoch)
            put("seq_num", 1L)
            put("timestamp", now)
            put("action", "TAP")
            put("parameters", params)
        }
        val resMissingSig = securityManager.validateCommand(cmdMissingSig)
        assertTrue(resMissingSig is LanSecurityManager.CommandValidationResult.Rejected)
        assertEquals("Missing command signature", (resMissingSig as LanSecurityManager.CommandValidationResult.Rejected).reason)

        // 2. Invalid signature -> rejected
        val cmdInvalidSig = JSONObject(cmdMissingSig.toString()).apply {
            put("signature", LanSecurityManager.b64Encode(ByteArray(64) { 1.toByte() }))
        }
        val resInvalidSig = securityManager.validateCommand(cmdInvalidSig)
        assertTrue(resInvalidSig is LanSecurityManager.CommandValidationResult.Rejected)
        assertEquals("Invalid command signature", (resInvalidSig as LanSecurityManager.CommandValidationResult.Rejected).reason)

        // 3. Signature generated by an unauthorized controller key -> rejected
        val unauthorizedKp = kpg.generateKeyPair()
        val unauthorizedSig = LanSecurityManager.signCommandPayload(
            unauthorizedKp.private, cmdId, sessionId, activeEpoch, 1L, now, "TAP", params, controllerId, pubB64
        )
        val cmdUnauthorized = JSONObject(cmdMissingSig.toString()).apply {
            put("signature", unauthorizedSig)
        }
        val resUnauthorized = securityManager.validateCommand(cmdUnauthorized)
        assertTrue(resUnauthorized is LanSecurityManager.CommandValidationResult.Rejected)
        assertEquals("Invalid command signature", (resUnauthorized as LanSecurityManager.CommandValidationResult.Rejected).reason)

        // 4. Modified command_id after signing -> rejected
        val cmdModifiedCmdId = JSONObject(cmdMissingSig.toString()).apply {
            put("command_id", "cmd-tampered-id")
            put("signature", validSig)
        }
        val resModCmdId = securityManager.validateCommand(cmdModifiedCmdId)
        assertTrue(resModCmdId is LanSecurityManager.CommandValidationResult.Rejected)
        assertEquals("Invalid command signature", (resModCmdId as LanSecurityManager.CommandValidationResult.Rejected).reason)

        // 5. Modified session_id after signing -> rejected
        val cmdModifiedSessionId = JSONObject(cmdMissingSig.toString()).apply {
            put("session_id", "session-tampered")
            put("signature", validSig)
        }
        val resModSession = securityManager.validateCommand(cmdModifiedSessionId)
        assertTrue(resModSession is LanSecurityManager.CommandValidationResult.Rejected)

        // 6. Modified epoch after signing -> rejected
        val cmdModifiedEpoch = JSONObject(cmdMissingSig.toString()).apply {
            put("epoch", activeEpoch + 1)
            put("signature", validSig)
        }
        val resModEpoch = securityManager.validateCommand(cmdModifiedEpoch)
        assertTrue(resModEpoch is LanSecurityManager.CommandValidationResult.Rejected)
        assertTrue((resModEpoch as LanSecurityManager.CommandValidationResult.Rejected).reason.contains("Stale epoch"))

        // 7. Modified seq_num after signing -> rejected
        val cmdModifiedSeqNum = JSONObject(cmdMissingSig.toString()).apply {
            put("seq_num", 2L)
            put("signature", validSig)
        }
        val resModSeq = securityManager.validateCommand(cmdModifiedSeqNum)
        assertTrue(resModSeq is LanSecurityManager.CommandValidationResult.Rejected)
        assertEquals("Invalid command signature", (resModSeq as LanSecurityManager.CommandValidationResult.Rejected).reason)

        // 8. Modified timestamp after signing -> rejected
        val cmdModifiedTimestamp = JSONObject(cmdMissingSig.toString()).apply {
            put("timestamp", now + 1000L)
            put("signature", validSig)
        }
        val resModTime = securityManager.validateCommand(cmdModifiedTimestamp)
        assertTrue(resModTime is LanSecurityManager.CommandValidationResult.Rejected)
        assertEquals("Invalid command signature", (resModTime as LanSecurityManager.CommandValidationResult.Rejected).reason)

        // 9. Modified action after signing -> rejected
        val cmdModifiedAction = JSONObject(cmdMissingSig.toString()).apply {
            put("action", "NAV_BACK")
            put("signature", validSig)
        }
        val resModAction = securityManager.validateCommand(cmdModifiedAction)
        assertTrue(resModAction is LanSecurityManager.CommandValidationResult.Rejected)
        assertEquals("Invalid command signature", (resModAction as LanSecurityManager.CommandValidationResult.Rejected).reason)

        // 10. Modified parameters after signing -> rejected
        val tamperedParams = JSONObject().apply {
            put("x", 100)
            put("y", 999) // tampered
        }
        val cmdModifiedParams = JSONObject(cmdMissingSig.toString()).apply {
            put("parameters", tamperedParams)
            put("signature", validSig)
        }
        val resModParams = securityManager.validateCommand(cmdModifiedParams)
        assertTrue(resModParams is LanSecurityManager.CommandValidationResult.Rejected)
        assertEquals("Invalid command signature", (resModParams as LanSecurityManager.CommandValidationResult.Rejected).reason)

        // 11. Correct signature over the exact command -> accepted
        val cmdValid = JSONObject(cmdMissingSig.toString()).apply {
            put("signature", validSig)
        }
        val resValid = securityManager.validateCommand(cmdValid)
        assertTrue(resValid is LanSecurityManager.CommandValidationResult.Valid)

        // Record execution result
        val responseStr = JSONObject().apply { put("status", "ok") }.toString()
        securityManager.recordCommandResult(cmdId, 1L, now, responseStr)

        // 12. Correct signature + current epoch + duplicate command -> cached result, no second execution
        val resDup = securityManager.validateCommand(cmdValid)
        assertTrue(resDup is LanSecurityManager.CommandValidationResult.Duplicate)
        assertEquals(responseStr, (resDup as LanSecurityManager.CommandValidationResult.Duplicate).cachedResponse)

        // 13. Old epoch + otherwise valid signature -> rejected BEFORE duplicate lookup
        val oldEpoch = activeEpoch - 1
        val oldEpochSig = LanSecurityManager.signCommandPayload(
            kp.private, "cmd-old-epoch", sessionId, oldEpoch, 2L, now, "TAP", params, controllerId, pubB64
        )
        val cmdOldEpoch = JSONObject().apply {
            put("type", "COMMAND")
            put("command_id", "cmd-old-epoch")
            put("session_id", sessionId)
            put("epoch", oldEpoch)
            put("seq_num", 2L)
            put("timestamp", now)
            put("action", "TAP")
            put("parameters", params)
            put("signature", oldEpochSig)
        }
        val resOldEpoch = securityManager.validateCommand(cmdOldEpoch)
        assertTrue(resOldEpoch is LanSecurityManager.CommandValidationResult.Rejected)
        assertTrue((resOldEpoch as LanSecurityManager.CommandValidationResult.Rejected).reason.contains("Stale epoch"))

        // 14. Old signature from another command -> rejected
        val cmdNewWithOldSig = JSONObject().apply {
            put("type", "COMMAND")
            put("command_id", "cmd-new-2")
            put("session_id", sessionId)
            put("epoch", activeEpoch)
            put("seq_num", 2L)
            put("timestamp", now)
            put("action", "TAP")
            put("parameters", params)
            put("signature", validSig) // using signature from cmdId (cmd-crypto-1)
        }
        val resNewWithOldSig = securityManager.validateCommand(cmdNewWithOldSig)
        assertTrue(resNewWithOldSig is LanSecurityManager.CommandValidationResult.Rejected)
        assertEquals("Invalid command signature", (resNewWithOldSig as LanSecurityManager.CommandValidationResult.Rejected).reason)

        // 15. Revoked controller key -> rejected
        securityManager.revokeController(controllerId)
        val cmdAfterRevoke = JSONObject(cmdValid.toString())
        val resAfterRevoke = securityManager.validateCommand(cmdAfterRevoke)
        assertTrue(resAfterRevoke is LanSecurityManager.CommandValidationResult.Rejected)

        // 16. Process/reboot epoch change -> old signed command rejected
        val mgr2 = LanSecurityManager(customPrefs = mockPrefs)
        assertTrue(mgr2.persistentEpoch > activeEpoch)
        val resAfterReboot = mgr2.validateCommand(cmdValid)
        assertTrue(resAfterReboot is LanSecurityManager.CommandValidationResult.Rejected)
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

    @Test
    fun testP1363ToDerEdgeCasesAndSafeFailureContainment() {
        // 1. High-bit R & S (MSB >= 0x80)
        val sigHighBit = ByteArray(64).apply {
            this[0] = 0x85.toByte()
            this[31] = 0x01.toByte()
            this[32] = 0xFE.toByte()
            this[63] = 0x09.toByte()
        }
        val derHighBit = LanSecurityManager.p1363ToDer(sigHighBit)
        assertEquals(0x30.toByte(), derHighBit[0])
        assertEquals(70.toByte(), derHighBit[1]) // len = 2 + 33 + 2 + 33 = 70
        assertEquals(0x02.toByte(), derHighBit[2])
        assertEquals(33.toByte(), derHighBit[3]) // 33 bytes for R with 0x00 prepended
        assertEquals(0x00.toByte(), derHighBit[4])
        assertEquals(0x85.toByte(), derHighBit[5])
        assertEquals(0x02.toByte(), derHighBit[37])
        assertEquals(33.toByte(), derHighBit[38]) // 33 bytes for S with 0x00 prepended
        assertEquals(0x00.toByte(), derHighBit[39])
        assertEquals(0xFE.toByte(), derHighBit[40])

        // 2. Leading zeros in R
        val sigLeadingZerosR = ByteArray(64).apply {
            this[4] = 0x07.toByte() // 4 leading zero bytes
            this[32] = 0x10.toByte()
        }
        val derLeadingZerosR = LanSecurityManager.p1363ToDer(sigLeadingZerosR)
        assertEquals(0x30.toByte(), derLeadingZerosR[0])
        assertEquals(0x02.toByte(), derLeadingZerosR[2])
        assertEquals(28.toByte(), derLeadingZerosR[3]) // 32 - 4 = 28 bytes

        // 3. Leading zeros in S
        val sigLeadingZerosS = ByteArray(64).apply {
            this[0] = 0x12.toByte()
            this[40] = 0x24.toByte() // 8 leading zero bytes in S
        }
        val derLeadingZerosS = LanSecurityManager.p1363ToDer(sigLeadingZerosS)
        assertEquals(0x30.toByte(), derLeadingZerosS[0])

        // 4. Zero R / Zero S
        val sigZeroRS = ByteArray(64)
        val derZeroRS = LanSecurityManager.p1363ToDer(sigZeroRS)
        assertEquals(0x30.toByte(), derZeroRS[0])
        assertEquals(0x02.toByte(), derZeroRS[2])
        assertEquals(1.toByte(), derZeroRS[3]) // R is single zero byte
        assertEquals(0x00.toByte(), derZeroRS[4])

        // 5. Truncated signature (< 64 bytes)
        val sigTrunc = ByteArray(32) { 0x11.toByte() }
        val derTrunc = LanSecurityManager.p1363ToDer(sigTrunc)
        assertArrayEquals(sigTrunc, derTrunc)

        // 6. Oversized signature (> 64 bytes)
        val sigOver = ByteArray(65) { 0x22.toByte() }
        val derOver = LanSecurityManager.p1363ToDer(sigOver)
        assertArrayEquals(sigOver, derOver)

        // 7. Verify Signature.verify safe failure containment
        val kpg = KeyPairGenerator.getInstance("EC")
        kpg.initialize(ECGenParameterSpec("secp256r1"), SecureRandom())
        val kp = kpg.generateKeyPair()
        val verifier = Signature.getInstance("SHA256withECDSA")
        verifier.initVerify(kp.public)
        verifier.update("test-payload".toByteArray(Charsets.UTF_8))

        // Truncated, oversized, zero-bytes, and random garbage should all fail safely without crashing
        assertFalse(try { verifier.verify(derTrunc) } catch (_: Exception) { false })
        assertFalse(try { verifier.verify(derOver) } catch (_: Exception) { false })
        assertFalse(try { verifier.verify(derZeroRS) } catch (_: Exception) { false })
        assertFalse(try { verifier.verify(ByteArray(64) { 0xAA.toByte() }) } catch (_: Exception) { false })
    }

    @Test
    fun testCanonicalizeParametersNonScalarRejectionAndUnicode() {
        // 1. Non-scalar JSONObject rejection
        val paramsWithObj = JSONObject().apply {
            put("valid", "hello")
            put("illegal_obj", JSONObject().apply { put("nested", 123) })
        }
        try {
            LanSecurityManager.canonicalizeParameters(paramsWithObj)
            fail("Expected IllegalArgumentException for nested JSONObject parameter")
        } catch (e: IllegalArgumentException) {
            assertTrue(e.message!!.contains("non-scalar"))
        }

        // 2. Non-scalar JSONArray rejection
        val paramsWithArr = JSONObject().apply {
            put("valid", "hello")
            put("illegal_arr", org.json.JSONArray().apply { put(1); put(2) })
        }
        try {
            LanSecurityManager.canonicalizeParameters(paramsWithArr)
            fail("Expected IllegalArgumentException for JSONArray parameter")
        } catch (e: IllegalArgumentException) {
            assertTrue(e.message!!.contains("non-scalar"))
        }

        // 3. Deterministic Unicode canonicalization matching JS test-controller
        val unicodeParams = JSONObject().apply {
            put("symbols", ":=|")
            put("emoji", "🚀")
            put("cjk", "こんにちは")
            put("accent", "Café")
        }
        val canonical = LanSecurityManager.canonicalizeParameters(unicodeParams)
        val expected = "6:accent=4:Café,3:cjk=5:こんにちは,5:emoji=2:🚀,7:symbols=3::=|"
        assertEquals(expected, canonical)
    }
}
