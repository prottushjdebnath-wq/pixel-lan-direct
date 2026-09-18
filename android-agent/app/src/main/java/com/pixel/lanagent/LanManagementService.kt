package com.pixel.lanagent

import android.accessibilityservice.AccessibilityService
import android.app.*
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.net.ConnectivityManager
import android.net.nsd.NsdManager
import android.net.nsd.NsdServiceInfo
import android.os.*
import android.util.Base64
import android.util.Log
import kotlinx.coroutines.*
import org.json.JSONObject

/**
 * Core Foreground Management Service implementing the secure Pixel <-> Controller channel.
 *
 * Transports & Architecture:
 *  - Logical-session separation from network transport via ConnectionManager.
 *  - WebRTC DataChannel (DTLS/SCTP) exclusively for management commands, telemetry, and touch/gestures.
 *  - Direct LAN / Internet P2P (ICE/STUN) / TURN Relay fallback.
 *  - Ephemeral local HTTP listener strictly for out-of-band SDP/ICE candidate exchange (signaling only).
 *  - Remote WebSocket rendezvous/signaling strictly for SDP/ICE candidates without carrying management traffic.
 *
 * MANDATORY SECURITY QUALIFICATIONS:
 * - “The Pixel core agent is PERSISTENT WHILE ANDROID PERMITS EXECUTION USING SUPPORTED LIFECYCLE MECHANISMS.”
 * - “WebRTC provides encrypted DTLS/SCTP transport for DataChannels; exact protocol version and cipher suite are implementation dependent.”
 * - “The system is DESIGNED FOR AUTOMATIC TRANSPORT RECOVERY AND SESSION RESYNCHRONIZATION; PHYSICAL MIGRATION REMAINS UNVERIFIED.”
 */
class LanManagementService : Service(), ConnectionManager.ConnectionListener {

    companion object {
        private const val TAG = "LanMgmtSvc"
        private const val SERVICE_TYPE = "_pixel-remote._tcp."
        private const val SERVICE_NAME = "PixelManagedDevice"
        const val LOCAL_BOOTSTRAP_PORT = 8990
        private const val NOTIFICATION_CHANNEL_ID = "pixel_lan_channel"
        private const val NOTIFICATION_ID = 4001

        const val EXTRA_SIGNALING_URL = "extra_signaling_url"

        var instance: LanManagementService? = null
            private set
    }

    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    lateinit var securityManager: LanSecurityManager
        private set
    lateinit var connectionManager: ConnectionManager
        private set

    private var nsdManager: NsdManager? = null
    private var registrationListener: NsdManager.RegistrationListener? = null
    private var connectivityManager: ConnectivityManager? = null

    private var isRunning = false

    override fun onCreate() {
        super.onCreate()
        instance = this
        securityManager = LanSecurityManager(this)
        connectionManager = ConnectionManager(this, this)
        nsdManager = getSystemService(Context.NSD_SERVICE) as NsdManager
        connectivityManager = getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager

        createNotificationChannel()
        startForeground(NOTIFICATION_ID, buildNotification("Management link: Standby / Ready for connection"))

        // Initialize PeerConnection and local signaling listener
        connectionManager.createOrResetPeerConnection()
        connectionManager.startLocalSignaling(LOCAL_BOOTSTRAP_PORT)
        registerMdnsService(LOCAL_BOOTSTRAP_PORT)

        if (connectivityManager != null) {
            connectionManager.setupNetworkMonitoring(connectivityManager!!)
        }
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (!isRunning) {
            isRunning = true
            Log.i(TAG, "LanManagementService started (START_STICKY). Epoch: ${securityManager.persistentEpoch}")
        }

        // Connect remote signaling if configured
        val signalingUrl = intent?.getStringExtra(EXTRA_SIGNALING_URL)
        if (!signalingUrl.isNullOrEmpty()) {
            connectionManager.connectRemoteSignaling(signalingUrl, securityManager.getDeviceId())
        }

        return START_STICKY
    }

    // --- ConnectionManager.ConnectionListener Callbacks ---

    override fun onTransportStateChanged(state: ConnectionManager.TransportState, pathDetail: String) {
        val statusText = when (state) {
            ConnectionManager.TransportState.DIRECT_LAN -> "ACTIVE (Direct LAN)"
            ConnectionManager.TransportState.INTERNET_P2P -> "ACTIVE (Internet P2P)"
            ConnectionManager.TransportState.TURN_RELAY -> "ACTIVE (TURN Relay)"
            ConnectionManager.TransportState.CONNECTING -> "Connecting ($pathDetail)"
            ConnectionManager.TransportState.DISCONNECTED -> "Transport Disconnected"
        }
        updateNotification("Management link: $statusText")
    }

    override fun onDataChannelStateChanged(isOpen: Boolean) {
        if (isOpen) {
            // Automatically issue context-bound cryptographic challenge to newly connected peer
            scope.launch {
                val challenge = securityManager.createChallenge("pending-controller")
                connectionManager.sendDataChannelMessage(challenge)
            }
        } else {
            securityManager.terminateActiveSession()
        }
    }

    override fun onDataChannelMessage(rawJson: String) {
        scope.launch {
            try {
                val req = JSONObject(rawJson)
                val type = req.optString("type")

                when (type) {
                    "PAIR" -> {
                        val controllerId = req.optString("controller_id")
                        val pubKeyDer = req.optString("controller_pubkey")
                        val transcriptHash = req.optString("transcript_hash")
                        val nonce = req.optString("nonce")

                        val resp = JSONObject()
                        // Enforce exact pairing transcript binding
                        if (securityManager.verifyPairingTranscript(controllerId, pubKeyDer, transcriptHash, nonce)) {
                            resp.put("type", "PAIR_RESULT")
                            resp.put("status", "ok")
                            resp.put("message", "Pairing authorized via verified transcript binding")
                            resp.put("pixel_id", securityManager.getDeviceId())
                            resp.put("pixel_pubkey", securityManager.getDevicePublicKeyBase64())
                            resp.put("pixel_fingerprint", securityManager.getDeviceFingerprint())
                        } else {
                            resp.put("type", "PAIR_RESULT")
                            resp.put("status", "error")
                            resp.put("message", "Invalid pairing transcript hash, locked out, or expired PIN")
                        }
                        connectionManager.sendDataChannelMessage(resp)
                    }

                    "AUTH_RESPONSE" -> {
                        val session = securityManager.verifyChallengeResponse(req)
                        val resp = JSONObject()
                        if (session != null) {
                            resp.put("type", "AUTH_RESULT")
                            resp.put("status", "ok")
                            resp.put("protocol_context", LanSecurityManager.PROTOCOL_CONTEXT)
                            resp.put("session_id", session.sessionId)
                            resp.put("epoch", session.epoch)
                            resp.put("message", "Authenticated successfully")
                            updateNotification("Management link: Authenticated (${connectionManager.activePathType})")
                        } else {
                            resp.put("type", "AUTH_RESULT")
                            resp.put("status", "error")
                            resp.put("message", "ECDSA challenge-response verification failed or controller revoked")
                        }
                        connectionManager.sendDataChannelMessage(resp)
                    }

                    "COMMAND" -> {
                        // Reconnect-safe anti-replay, epoch check, and idempotency validation
                        when (val valResult = securityManager.validateCommand(req)) {
                            is LanSecurityManager.CommandValidationResult.Rejected -> {
                                val errResp = JSONObject().apply {
                                    put("type", "COMMAND_RESULT")
                                    put("status", "error")
                                    put("command_id", req.optString("command_id"))
                                    put("message", valResult.reason)
                                }
                                connectionManager.sendDataChannelMessage(errResp)
                            }
                            is LanSecurityManager.CommandValidationResult.Duplicate -> {
                                // Return cached idempotent response without re-executing
                                val dupResp = JSONObject(valResult.cachedResponse).apply {
                                    put("is_idempotent_duplicate", true)
                                    put("duplicate_type", valResult.duplicateType)
                                }
                                connectionManager.sendDataChannelMessage(dupResp)
                            }
                            is LanSecurityManager.CommandValidationResult.Valid -> {
                                val commandId = req.getString("command_id")
                                val seqNum = req.getLong("seq_num")
                                val timestamp = req.optLong("timestamp", System.currentTimeMillis())
                                val action = req.optString("action")
                                val params = req.optJSONObject("parameters") ?: JSONObject()

                                val resultJson = executeAction(action, params)
                                resultJson.put("type", "COMMAND_RESULT")
                                resultJson.put("command_id", commandId)
                                resultJson.put("seq_num", seqNum)

                                val finalRespStr = resultJson.toString()
                                securityManager.recordCommandResult(commandId, seqNum, timestamp, finalRespStr)
                                connectionManager.sendDataChannelMessage(resultJson)
                            }
                        }
                    }

                    else -> {
                        Log.w(TAG, "Unknown message type on DataChannel: $type")
                    }
                }
            } catch (e: Exception) {
                Log.e(TAG, "Error handling DataChannel message: ${e.message}")
            }
        }
    }

    private suspend fun executeAction(action: String, params: JSONObject): JSONObject {
        val resp = JSONObject()
        when (action) {
            "GET_TELEMETRY" -> {
                resp.put("status", "ok")
                resp.put("path", connectionManager.activePathType)
                resp.put("adb_status", "ADB TRANSPORT: UNAVAILABLE")
                resp.put("device_model", Build.MODEL)
                resp.put("battery_level", getBatteryLevel())
                resp.put("is_charging", isCharging())
                resp.put("a11y_active", RemoteAccessibilityService.isServiceActive())
                resp.put("screen_capture_status", "SCREEN CAPTURE: USER ACTION REQUIRED")
            }
            "TAP" -> {
                val x = params.optDouble("x", 0.0).toFloat()
                val y = params.optDouble("y", 0.0).toFloat()
                val res = RemoteAccessibilityService.dispatchTap(x, y)
                resp.put("status", if (res) "ok" else "error")
                resp.put("action", "TAP")
            }
            "SWIPE" -> {
                val sx = params.optDouble("sx", 0.0).toFloat()
                val sy = params.optDouble("sy", 0.0).toFloat()
                val ex = params.optDouble("ex", 0.0).toFloat()
                val ey = params.optDouble("ey", 0.0).toFloat()
                val dur = params.optLong("duration", 300L)
                val res = RemoteAccessibilityService.dispatchSwipe(sx, sy, ex, ey, dur)
                resp.put("status", if (res) "ok" else "error")
                resp.put("action", "SWIPE")
            }
            "NAV_BACK" -> {
                val res = RemoteAccessibilityService.performNavAction(AccessibilityService.GLOBAL_ACTION_BACK)
                resp.put("status", if (res) "ok" else "error")
            }
            "NAV_HOME" -> {
                val res = RemoteAccessibilityService.performNavAction(AccessibilityService.GLOBAL_ACTION_HOME)
                resp.put("status", if (res) "ok" else "error")
            }
            "NAV_RECENTS" -> {
                val res = RemoteAccessibilityService.performNavAction(AccessibilityService.GLOBAL_ACTION_RECENTS)
                resp.put("status", if (res) "ok" else "error")
            }
            "TEXT_ENTRY" -> {
                val text = params.optString("text", "")
                val res = RemoteAccessibilityService.injectText(text)
                resp.put("status", if (res) "ok" else "error")
            }
            "TAKE_SCREENSHOT" -> {
                var captured: ByteArray? = null
                val latch = java.util.concurrent.CountDownLatch(1)
                RemoteAccessibilityService.captureScreenshot { bytes ->
                    captured = bytes
                    latch.countDown()
                }
                withContext(Dispatchers.IO) {
                    latch.await(3000, java.util.concurrent.TimeUnit.MILLISECONDS)
                }
                if (captured != null) {
                    resp.put("status", "ok")
                    resp.put("image_base64", Base64.encodeToString(captured, Base64.NO_WRAP))
                } else {
                    resp.put("status", "error")
                    resp.put("message", "SCREEN CAPTURE: USER ACTION REQUIRED")
                }
            }
            else -> {
                resp.put("status", "error")
                resp.put("message", "Unknown action: $action")
            }
        }
        return resp
    }

    private fun registerMdnsService(port: Int) {
        val serviceInfo = NsdServiceInfo().apply {
            serviceName = SERVICE_NAME
            serviceType = SERVICE_TYPE
            setPort(port)
        }

        registrationListener = object : NsdManager.RegistrationListener {
            override fun onServiceRegistered(info: NsdServiceInfo?) {
                Log.i(TAG, "mDNS Service registered: ${info?.serviceName}")
            }
            override fun onRegistrationFailed(info: NsdServiceInfo?, errorCode: Int) {
                Log.w(TAG, "mDNS Registration failed: code $errorCode")
            }
            override fun onServiceUnregistered(info: NsdServiceInfo?) {
                Log.i(TAG, "mDNS Service unregistered")
            }
            override fun onUnregistrationFailed(info: NsdServiceInfo?, errorCode: Int) {
                Log.w(TAG, "mDNS Unregistration failed: code $errorCode")
            }
        }

        try {
            nsdManager?.registerService(serviceInfo, NsdManager.PROTOCOL_DNS_SD, registrationListener)
        } catch (e: Exception) {
            Log.w(TAG, "Failed to register mDNS: ${e.message}")
        }
    }

    private fun getBatteryLevel(): Int {
        val bm = getSystemService(Context.BATTERY_SERVICE) as BatteryManager
        return bm.getIntProperty(BatteryManager.BATTERY_PROPERTY_CAPACITY)
    }

    private fun isCharging(): Boolean {
        val filter = IntentFilter(Intent.ACTION_BATTERY_CHANGED)
        val status = registerReceiver(null, filter)?.getIntExtra(BatteryManager.EXTRA_STATUS, -1) ?: -1
        return status == BatteryManager.BATTERY_STATUS_CHARGING || status == BatteryManager.BATTERY_STATUS_FULL
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val chan = NotificationChannel(NOTIFICATION_CHANNEL_ID, "Management Channel", NotificationManager.IMPORTANCE_LOW)
            val nm = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
            nm.createNotificationChannel(chan)
        }
    }

    private fun buildNotification(text: String): Notification {
        val builder = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            Notification.Builder(this, NOTIFICATION_CHANNEL_ID)
        } else {
            @Suppress("DEPRECATION") Notification.Builder(this)
        }
        return builder
            .setContentTitle("Pixel Remote Management")
            .setContentText(text)
            .setSmallIcon(android.R.drawable.stat_notify_sync)
            .setOngoing(true)
            .build()
    }

    private fun updateNotification(text: String) {
        val nm = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        nm.notify(NOTIFICATION_ID, buildNotification(text))
    }

    override fun onDestroy() {
        super.onDestroy()
        instance = null
        try {
            if (registrationListener != null) {
                nsdManager?.unregisterService(registrationListener)
            }
        } catch (_: Exception) {}
        connectionManager.destroy()
        securityManager.terminateActiveSession()
        scope.cancel()
    }

    override fun onBind(intent: Intent?): IBinder? = null
}
