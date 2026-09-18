package com.pixel.lanagent

import android.app.*
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.net.nsd.NsdManager
import android.net.nsd.NsdServiceInfo
import android.os.*
import android.util.Base64
import android.util.Log
import android.view.accessibility.AccessibilityService
import kotlinx.coroutines.*
import org.json.JSONArray
import org.json.JSONObject
import org.webrtc.*
import java.io.*
import java.net.Inet4Address
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.NetworkInterface
import java.net.ServerSocket
import java.net.Socket
import java.nio.ByteBuffer
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CopyOnWriteArrayList

/**
 * Core Foreground Management Service implementing the secure Pixel <-> Controller channel.
 *
 * Transports:
 *  - WebRTC DataChannel (DTLS/SCTP) for all management commands, telemetry, and touch/gestures.
 *  - Direct LAN / Internet P2P (ICE/STUN) / TURN Relay fallback.
 *  - Ephemeral local HTTP listener strictly for out-of-band SDP/ICE candidate exchange (signaling only).
 */
class LanManagementService : Service() {

    companion object {
        private const val TAG = "LanMgmtSvc"
        private const val SERVICE_TYPE = "_pixel-remote._tcp."
        private const val SERVICE_NAME = "PixelManagedDevice"
        const val LOCAL_BOOTSTRAP_PORT = 8990
        private const val NOTIFICATION_CHANNEL_ID = "pixel_lan_channel"
        private const val NOTIFICATION_ID = 4001
        
        // Static accessor for UI
        var instance: LanManagementService? = null
            private set
    }

    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    lateinit var securityManager: LanSecurityManager
        private set
    private var nsdManager: NsdManager? = null
    private var registrationListener: NsdManager.RegistrationListener? = null
    private var connectivityManager: ConnectivityManager? = null
    private var networkCallback: ConnectivityManager.NetworkCallback? = null

    // WebRTC components
    private var peerConnectionFactory: PeerConnectionFactory? = null
    private var peerConnection: PeerConnection? = null
    private var managementDataChannel: DataChannel? = null
    private val localIceCandidates = CopyOnWriteArrayList<JSONObject>()
    private var activePathType = "DISCONNECTED"

    // Ephemeral local signaling server
    private var signalingServerSocket: ServerSocket? = null
    private var isRunning = false

    override fun onCreate() {
        super.onCreate()
        instance = this
        securityManager = LanSecurityManager(this)
        nsdManager = getSystemService(Context.NSD_SERVICE) as NsdManager
        connectivityManager = getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager

        createNotificationChannel()
        startForeground(NOTIFICATION_ID, buildNotification("Management link: Standby / Ready for connection"))

        initWebRtcFactory()
        startEphemeralSignalingServer()
        registerMdnsService(LOCAL_BOOTSTRAP_PORT)
        monitorNetworkChanges()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (!isRunning) {
            isRunning = true
            Log.i(TAG, "LanManagementService started (START_STICKY)")
        }
        return START_STICKY
    }

    // --- WebRTC Initialization ---

    private fun initWebRtcFactory() {
        try {
            val initOptions = PeerConnectionFactory.InitializationOptions.builder(this)
                .setEnableInternalTracer(false)
                .createInitializationOptions()
            PeerConnectionFactory.initialize(initOptions)

            val options = PeerConnectionFactory.Options()
            peerConnectionFactory = PeerConnectionFactory.builder()
                .setOptions(options)
                .createPeerConnectionFactory()
            Log.i(TAG, "WebRTC PeerConnectionFactory initialized successfully")
        } catch (e: Throwable) {
            Log.e(TAG, "WebRTC factory init error: ${e.message}")
        }
    }

    private fun createPeerConnection(onIceCandidateGathered: (IceCandidate) -> Unit): PeerConnection? {
        val iceServers = listOf(
            PeerConnection.IceServer.builder("stun:stun.l.google.com:19302").createIceServer(),
            PeerConnection.IceServer.builder("stun:stun1.l.google.com:19302").createIceServer()
            // Additional TURN servers can be dynamically configured via rendezvous
        )

        val rtcConfig = PeerConnection.RTCConfiguration(iceServers).apply {
            tcpCandidatePolicy = PeerConnection.TcpCandidatePolicy.ENABLED
            bundlePolicy = PeerConnection.BundlePolicy.MAXBUNDLE
            rtcpMuxPolicy = PeerConnection.RtcpMuxPolicy.REQUIRE
            continualGatheringPolicy = PeerConnection.ContinualGatheringPolicy.GATHER_CONTINUALLY
            keyType = PeerConnection.KeyType.ECDSA
        }

        val observer = object : PeerConnection.Observer {
            override fun onSignalingChange(state: PeerConnection.SignalingState?) {
                Log.d(TAG, "WebRTC SignalingState: $state")
            }

            override fun onIceConnectionChange(state: PeerConnection.IceConnectionState?) {
                Log.i(TAG, "WebRTC IceConnectionState: $state")
                when (state) {
                    PeerConnection.IceConnectionState.CONNECTED,
                    PeerConnection.IceConnectionState.COMPLETED -> {
                        updateNotification("Management link: ACTIVE ($activePathType)")
                    }
                    PeerConnection.IceConnectionState.DISCONNECTED,
                    PeerConnection.IceConnectionState.FAILED -> {
                        updateNotification("Management link: Transport Disconnected")
                        activePathType = "DISCONNECTED"
                    }
                    else -> {}
                }
            }

            override fun onIceConnectionReceivingChange(receiving: Boolean) {}
            override fun onIceGatheringChange(state: PeerConnection.IceGatheringState?) {
                Log.d(TAG, "WebRTC IceGatheringState: $state")
            }

            override fun onIceCandidate(candidate: IceCandidate?) {
                if (candidate != null) {
                    Log.d(TAG, "Gathered local ICE candidate: ${candidate.sdp}")
                    val candJson = JSONObject().apply {
                        put("sdpMid", candidate.sdpMid)
                        put("sdpMLineIndex", candidate.sdpMLineIndex)
                        put("candidate", candidate.sdp)
                    }
                    localIceCandidates.add(candJson)
                    onIceCandidateGathered(candidate)
                }
            }

            override fun onIceCandidatesRemoved(candidates: Array<out IceCandidate>?) {}
            override fun onAddStream(stream: MediaStream?) {}
            override fun onRemoveStream(stream: MediaStream?) {}
            override fun onDataChannel(dc: DataChannel?) {
                if (dc != null) {
                    Log.i(TAG, "Incoming DataChannel received: ${dc.label()}")
                    setupDataChannel(dc)
                }
            }

            override fun onRenegotiationNeeded() {
                Log.d(TAG, "WebRTC RenegotiationNeeded")
            }

            override fun onAddTrack(receiver: RtpReceiver?, mediaStreams: Array<out MediaStream>?) {}
        }

        val pc = peerConnectionFactory?.createPeerConnection(rtcConfig, observer)
        peerConnection = pc
        return pc
    }

    private fun setupDataChannel(dc: DataChannel) {
        managementDataChannel = dc
        dc.registerObserver(object : DataChannel.Observer {
            override fun onBufferedAmountChange(previousAmount: Long) {}

            override fun onStateChange() {
                Log.i(TAG, "DataChannel '${dc.label()}' state: ${dc.state()}")
                if (dc.state() == DataChannel.State.OPEN) {
                    // Automatically issue cryptographic challenge to newly connected peer
                    scope.launch {
                        val challenge = securityManager.createChallenge("pending-controller")
                        sendDataChannelMessage(challenge)
                    }
                } else if (dc.state() == DataChannel.State.CLOSED) {
                    securityManager.terminateActiveSession()
                }
            }

            override fun onMessage(buffer: DataChannel.Buffer?) {
                if (buffer != null) {
                    val bytes = ByteArray(buffer.data.remaining())
                    buffer.data.get(bytes)
                    val rawMsg = String(bytes, Charsets.UTF_8)
                    handleDataChannelMessage(rawMsg)
                }
            }
        })
    }

    // --- DataChannel Protocol & Command Dispatch (Layer 4 - Layer 6) ---

    private fun handleDataChannelMessage(rawJson: String) {
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
                        sendDataChannelMessage(resp)
                    }

                    "AUTH_RESPONSE" -> {
                        val session = securityManager.verifyChallengeResponse(req)
                        val resp = JSONObject()
                        if (session != null) {
                            resp.put("type", "AUTH_RESULT")
                            resp.put("status", "ok")
                            resp.put("session_id", session.sessionId)
                            resp.put("message", "Authenticated successfully")
                            updateNotification("Management link: Authenticated ($activePathType)")
                        } else {
                            resp.put("type", "AUTH_RESULT")
                            resp.put("status", "error")
                            resp.put("message", "ECDSA challenge-response verification failed")
                            managementDataChannel?.close()
                        }
                        sendDataChannelMessage(resp)
                    }

                    "COMMAND" -> {
                        // Reconnect-safe anti-replay and idempotency validation
                        when (val valResult = securityManager.validateCommand(req)) {
                            is LanSecurityManager.CommandValidationResult.Rejected -> {
                                val errResp = JSONObject().apply {
                                    put("type", "COMMAND_RESULT")
                                    put("status", "error")
                                    put("command_id", req.optString("command_id"))
                                    put("message", valResult.reason)
                                }
                                sendDataChannelMessage(errResp)
                            }
                            is LanSecurityManager.CommandValidationResult.Duplicate -> {
                                // Return cached idempotent response without re-executing
                                val dupResp = JSONObject(valResult.cachedResponse).apply {
                                    put("is_idempotent_duplicate", true)
                                    put("duplicate_type", valResult.duplicateType)
                                }
                                sendDataChannelMessage(dupResp)
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
                                sendDataChannelMessage(resultJson)
                            }
                        }
                    }

                    else -> {
                        Log.w(TAG, "Unknown message type on DataChannel: $type")
                    }
                }
            } catch (e: Exception) {
                Log.e(TAG, "Error parsing DataChannel message: ${e.message}")
            }
        }
    }

    private suspend fun executeAction(action: String, params: JSONObject): JSONObject {
        val resp = JSONObject()
        when (action) {
            "GET_TELEMETRY" -> {
                resp.put("status", "ok")
                resp.put("path", activePathType)
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

    private fun sendDataChannelMessage(msg: JSONObject) {
        try {
            val bytes = msg.toString().toByteArray(Charsets.UTF_8)
            val buffer = DataChannel.Buffer(ByteBuffer.wrap(bytes), false)
            managementDataChannel?.send(buffer)
        } catch (e: Exception) {
            Log.e(TAG, "Failed to send message over DataChannel: ${e.message}")
        }
    }

    // --- Ephemeral Local Signaling Server (Restricted Bind & Signaling Broker Only) ---
    // Strictly exchanges SDP and ICE candidates. NEVER carries management commands or secrets.

    private fun getPreferredLanAddress(): InetAddress {
        try {
            val interfaces = NetworkInterface.getNetworkInterfaces()
            while (interfaces.hasMoreElements()) {
                val iface = interfaces.nextElement()
                if (iface.isLoopback || !iface.isUp) continue
                val addresses = iface.inetAddresses
                while (addresses.hasMoreElements()) {
                    val addr = addresses.nextElement()
                    if (addr is Inet4Address && !addr.isLoopbackAddress && addr.isSiteLocalAddress) {
                        return addr
                    }
                }
            }
        } catch (_: Exception) {}
        return InetAddress.getByName("127.0.0.1")
    }

    private fun startEphemeralSignalingServer() {
        scope.launch {
            try {
                val bindAddr = getPreferredLanAddress()
                signalingServerSocket = ServerSocket()
                signalingServerSocket?.reuseAddress = true
                signalingServerSocket?.bind(InetSocketAddress(bindAddr, LOCAL_BOOTSTRAP_PORT))
                Log.i(TAG, "Local signaling broker listening strictly on ${bindAddr.hostAddress}:$LOCAL_BOOTSTRAP_PORT")

                while (isActive) {
                    val socket = signalingServerSocket?.accept() ?: break
                    launch { handleSignalingClient(socket) }
                }
            } catch (e: Exception) {
                if (e !is CancellationException) {
                    Log.e(TAG, "Signaling server error: ${e.message}")
                }
            }
        }
    }

    private suspend fun handleSignalingClient(socket: Socket) {
        withContext(Dispatchers.IO) {
            try {
                // Strict source address validation: drop any non-site-local, non-loopback connections
                val remoteAddr = socket.inetAddress
                if (!remoteAddr.isSiteLocalAddress && !remoteAddr.isLoopbackAddress) {
                    Log.w(TAG, "Dropping signaling connection from non-LAN address: $remoteAddr")
                    socket.close()
                    return@withContext
                }

                socket.soTimeout = 15000
                val reader = BufferedReader(InputStreamReader(socket.inputStream))
                val writer = OutputStreamWriter(socket.outputStream)

                // Simple HTTP Request Parser
                val reqLine = reader.readLine() ?: return@withContext
                val parts = reqLine.split(" ")
                if (parts.size < 2) return@withContext
                val method = parts[0]
                val path = parts[1]

                // Read HTTP Headers
                var contentLength = 0
                while (true) {
                    val headerLine = reader.readLine() ?: break
                    if (headerLine.isEmpty()) break
                    if (headerLine.startsWith("Content-Length:", ignoreCase = true)) {
                        contentLength = headerLine.substring(15).trim().toIntOrNull() ?: 0
                    }
                }

                val body = if (contentLength > 0) {
                    val charBuf = CharArray(contentLength)
                    var read = 0
                    while (read < contentLength) {
                        val count = reader.read(charBuf, read, contentLength - read)
                        if (count < 0) break
                        read += count
                    }
                    String(charBuf, 0, read)
                } else ""

                // Strict endpoint filter: only SDP and ICE candidate negotiation
                when {
                    method == "POST" && path == "/bootstrap/offer" -> {
                        val offerJson = JSONObject(body)
                        val sdp = offerJson.optString("sdp")
                        val pc = createPeerConnection { cand ->
                            // Candidates gathered asynchronously
                        }

                        if (pc != null) {
                            localIceCandidates.clear()
                            val sdpOffer = SessionDescription(SessionDescription.Type.OFFER, sdp)
                            
                            val answerLatch = java.util.concurrent.CountDownLatch(1)
                            var answerSdp: String? = null

                            pc.setRemoteDescription(object : SdpObserver {
                                override fun onSetSuccess() {
                                    pc.createAnswer(object : SdpObserver {
                                        override fun onCreateSuccess(desc: SessionDescription?) {
                                            if (desc != null) {
                                                pc.setLocalDescription(object : SdpObserver {
                                                    override fun onSetSuccess() {
                                                        answerSdp = desc.description
                                                        answerLatch.countDown()
                                                    }
                                                    override fun onSetFailure(err: String?) { answerLatch.countDown() }
                                                    override fun onCreateSuccess(p0: SessionDescription?) {}
                                                    override fun onCreateFailure(p0: String?) {}
                                                }, desc)
                                            }
                                        }
                                        override fun onCreateFailure(err: String?) { answerLatch.countDown() }
                                        override fun onSetSuccess() {}
                                        override fun onSetFailure(err: String?) {}
                                    }, MediaConstraints())
                                }
                                override fun onSetFailure(err: String?) { answerLatch.countDown() }
                                override fun onCreateSuccess(p0: SessionDescription?) {}
                                override fun onCreateFailure(p0: String?) {}
                            }, sdpOffer)

                            answerLatch.await(5000, java.util.concurrent.TimeUnit.MILLISECONDS)

                            if (answerSdp != null) {
                                activePathType = "DIRECT LAN"
                                val respObj = JSONObject().apply {
                                    put("status", "ok")
                                    put("type", "answer")
                                    put("sdp", answerSdp)
                                    put("pixel_id", securityManager.getDeviceId())
                                    put("pixel_pubkey", securityManager.getDevicePublicKeyBase64())
                                    put("pixel_fingerprint", securityManager.getDeviceFingerprint())
                                }
                                sendHttpResponse(writer, 200, respObj.toString())
                            } else {
                                sendHttpResponse(writer, 500, "{\"status\":\"error\",\"message\":\"Failed to negotiate SDP answer\"}")
                            }
                        } else {
                            sendHttpResponse(writer, 500, "{\"status\":\"error\",\"message\":\"PeerConnection creation failed\"}")
                        }
                    }

                    method == "POST" && path == "/bootstrap/ice" -> {
                        val candJson = JSONObject(body)
                        val candidate = IceCandidate(
                            candJson.optString("sdpMid"),
                            candJson.optInt("sdpMLineIndex", 0),
                            candJson.optString("candidate")
                        )
                        peerConnection?.addIceCandidate(candidate)
                        sendHttpResponse(writer, 200, "{\"status\":\"ok\"}")
                    }

                    method == "GET" && path == "/bootstrap/candidates" -> {
                        val arr = JSONArray()
                        for (c in localIceCandidates) {
                            arr.put(c)
                        }
                        val resp = JSONObject().apply {
                            put("status", "ok")
                            put("candidates", arr)
                        }
                        sendHttpResponse(writer, 200, resp.toString())
                    }

                    method == "OPTIONS" -> {
                        // CORS pre-flight support for browser controller
                        writer.write("HTTP/1.1 204 No Content\r\n")
                        writer.write("Access-Control-Allow-Origin: *\r\n")
                        writer.write("Access-Control-Allow-Methods: POST, GET, OPTIONS\r\n")
                        writer.write("Access-Control-Allow-Headers: Content-Type\r\n")
                        writer.write("\r\n")
                        writer.flush()
                    }

                    else -> {
                        // Strictly forbid management commands or unknown paths over signaling port
                        sendHttpResponse(writer, 403, "{\"status\":\"error\",\"message\":\"Signaling channel rejects management payloads\"}")
                    }
                }
            } catch (e: Exception) {
                Log.w(TAG, "Signaling client error: ${e.message}")
            } finally {
                try { socket.close() } catch (_: Exception) {}
            }
        }
    }

    private fun sendHttpResponse(writer: OutputStreamWriter, code: Int, body: String) {
        val bytes = body.toByteArray(Charsets.UTF_8)
        writer.write("HTTP/1.1 $code OK\r\n")
        writer.write("Content-Type: application/json; charset=utf-8\r\n")
        writer.write("Content-Length: ${bytes.size}\r\n")
        writer.write("Access-Control-Allow-Origin: *\r\n")
        writer.write("Connection: close\r\n")
        writer.write("\r\n")
        writer.write(body)
        writer.flush()
    }

    // --- Network Discovery & Lifecycle Monitoring ---

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

    private fun monitorNetworkChanges() {
        val req = NetworkRequest.Builder()
            .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            .build()

        networkCallback = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) {
                val caps = connectivityManager?.getNetworkCapabilities(network)
                val isWifi = caps?.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) == true
                val isCellular = caps?.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) == true
                Log.i(TAG, "Network available: Wi-Fi=$isWifi, Cellular=$isCellular")
            }

            override fun onLost(network: Network) {
                Log.i(TAG, "Network lost. Triggering transport reconnect readiness.")
            }
        }
        try {
            connectivityManager?.registerNetworkCallback(req, networkCallback!!)
        } catch (e: Exception) {
            Log.w(TAG, "Failed to register network callback: ${e.message}")
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
        try { signalingServerSocket?.close() } catch (_: Exception) {}
        try {
            if (registrationListener != null) {
                nsdManager?.unregisterService(registrationListener)
            }
        } catch (_: Exception) {}
        try {
            if (networkCallback != null) {
                connectivityManager?.unregisterNetworkCallback(networkCallback!!)
            }
        } catch (_: Exception) {}
        try {
            peerConnection?.close()
            peerConnectionFactory?.dispose()
        } catch (_: Exception) {}
        securityManager.terminateActiveSession()
        scope.cancel()
    }

    override fun onBind(intent: Intent?): IBinder? = null
}
