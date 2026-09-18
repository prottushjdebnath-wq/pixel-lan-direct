package com.pixel.lanagent

import android.content.Context
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.util.Log
import kotlinx.coroutines.*
import okhttp3.*
import org.json.JSONArray
import org.json.JSONObject
import org.webrtc.*
import java.io.BufferedReader
import java.io.InputStreamReader
import java.io.OutputStreamWriter
import java.net.Inet4Address
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.NetworkInterface
import java.net.ServerSocket
import java.net.Socket
import java.nio.ByteBuffer
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.TimeUnit

/**
 * Manages the WebRTC DataChannel transport lifecycle, separate from the logical session.
 *
 * Capabilities:
 * - Dual signaling: Local restricted LAN HTTP signaling + Outbound remote WebSocket signaling.
 * - Strict signaling filter: Only SDP, ICE candidates, and session metadata. Never carries commands.
 * - Dynamic transport classification: Direct LAN, Internet P2P (STUN), TURN Relay.
 * - Configurable STUN and TURN relay support with credential authentication.
 * - Transport recovery and ICE restart across network changes (Wi-Fi <-> Cellular, IP changes).
 *
 * MANDATORY SECURITY QUALIFICATIONS:
 * - “WebRTC provides encrypted DTLS/SCTP transport for DataChannels; exact protocol version and cipher suite are implementation dependent.”
 * - “The system is DESIGNED FOR AUTOMATIC TRANSPORT RECOVERY AND SESSION RESYNCHRONIZATION; PHYSICAL MIGRATION REMAINS UNVERIFIED.”
 */
class ConnectionManager(
    private val context: Context,
    private val listener: ConnectionListener
) {

    companion object {
        private const val TAG = "ConnectionManager"
        const val DEFAULT_LOCAL_SIGNALING_PORT = 8990
    }

    enum class TransportState {
        DISCONNECTED,
        CONNECTING,
        DIRECT_LAN,
        INTERNET_P2P,
        TURN_RELAY
    }

    data class IceServerConfig(
        val url: String,
        val username: String? = null,
        val credential: String? = null
    )

    interface ConnectionListener {
        fun onTransportStateChanged(state: TransportState, pathDetail: String)
        fun onDataChannelStateChanged(isOpen: Boolean)
        fun onDataChannelMessage(rawJson: String)
    }

    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())

    // WebRTC core objects
    private var peerConnectionFactory: PeerConnectionFactory? = null
    private var peerConnection: PeerConnection? = null
    private var managementDataChannel: DataChannel? = null
    private val localIceCandidates = CopyOnWriteArrayList<JSONObject>()

    // Current transport state
    var currentTransportState: TransportState = TransportState.DISCONNECTED
        private set
    var activePathType: String = "DISCONNECTED"
        private set

    // Configurable ICE servers (Default Google STUN + Configurable STUN/TURN relays)
    private val iceServersList = CopyOnWriteArrayList<PeerConnection.IceServer>().apply {
        add(PeerConnection.IceServer.builder("stun:stun.l.google.com:19302").createIceServer())
        add(PeerConnection.IceServer.builder("stun:stun1.l.google.com:19302").createIceServer())
    }

    // Ephemeral local signaling server
    private var localSignalingSocket: ServerSocket? = null
    private var isLocalSignalingRunning = false

    // Remote WebSocket signaling
    private val okHttpClient = OkHttpClient.Builder()
        .readTimeout(0, TimeUnit.MILLISECONDS)
        .pingInterval(25, TimeUnit.SECONDS)
        .build()
    private var remoteWebSocket: WebSocket? = null
    private var remoteSignalingUrl: String? = null
    private var registeredDeviceId: String? = null

    // Network connectivity monitoring
    private var connectivityManager: ConnectivityManager? = null
    private var networkCallback: ConnectivityManager.NetworkCallback? = null
    private var lastKnownNetworkHandle: Long = -1L

    init {
        initWebRtcFactory()
    }

    private fun initWebRtcFactory() {
        try {
            val initOptions = PeerConnectionFactory.InitializationOptions.builder(context)
                .setEnableInternalTracer(false)
                .createInitializationOptions()
            PeerConnectionFactory.initialize(initOptions)

            val options = PeerConnectionFactory.Options()
            peerConnectionFactory = PeerConnectionFactory.builder()
                .setOptions(options)
                .createPeerConnectionFactory()
            Log.i(TAG, "PeerConnectionFactory initialized")
        } catch (e: Throwable) {
            Log.e(TAG, "Error initializing PeerConnectionFactory: ${e.message}")
        }
    }

    fun setCustomIceServers(configs: List<IceServerConfig>) {
        iceServersList.clear()
        // Always include default STUN fallback
        iceServersList.add(PeerConnection.IceServer.builder("stun:stun.l.google.com:19302").createIceServer())
        for (cfg in configs) {
            val builder = PeerConnection.IceServer.builder(cfg.url)
            if (!cfg.username.isNullOrEmpty() && !cfg.credential.isNullOrEmpty()) {
                builder.setUsername(cfg.username)
                builder.setPassword(cfg.credential)
            }
            iceServersList.add(builder.createIceServer())
        }
        Log.i(TAG, "Configured ${iceServersList.size} ICE servers (STUN/TURN)")
    }

    // --- WebRTC PeerConnection Setup ---

    @Synchronized
    fun createOrResetPeerConnection(): PeerConnection? {
        peerConnection?.close()
        localIceCandidates.clear()

        val rtcConfig = PeerConnection.RTCConfiguration(iceServersList).apply {
            tcpCandidatePolicy = PeerConnection.TcpCandidatePolicy.ENABLED
            bundlePolicy = PeerConnection.BundlePolicy.MAXBUNDLE
            rtcpMuxPolicy = PeerConnection.RtcpMuxPolicy.REQUIRE
            continualGatheringPolicy = PeerConnection.ContinualGatheringPolicy.GATHER_CONTINUALLY
            keyType = PeerConnection.KeyType.ECDSA
        }

        val observer = object : PeerConnection.Observer {
            override fun onSignalingChange(state: PeerConnection.SignalingState?) {
                Log.d(TAG, "SignalingState: $state")
            }

            override fun onIceConnectionChange(state: PeerConnection.IceConnectionState?) {
                Log.i(TAG, "IceConnectionState: $state")
                when (state) {
                    PeerConnection.IceConnectionState.CONNECTED,
                    PeerConnection.IceConnectionState.COMPLETED -> {
                        inspectCandidatePairAndClassify()
                    }
                    PeerConnection.IceConnectionState.DISCONNECTED,
                    PeerConnection.IceConnectionState.FAILED -> {
                        updateTransportState(TransportState.DISCONNECTED, "Disconnected")
                        // Trigger ICE restart / recovery if disconnected
                        scope.launch {
                            delay(2000)
                            if (peerConnection?.iceConnectionState() == PeerConnection.IceConnectionState.FAILED ||
                                peerConnection?.iceConnectionState() == PeerConnection.IceConnectionState.DISCONNECTED) {
                                Log.i(TAG, "Attempting ICE restart after disconnect/failure")
                                initiateIceRestart("ICE_DISCONNECTED_OR_FAILED")
                            }
                        }
                    }
                    PeerConnection.IceConnectionState.CHECKING -> {
                        updateTransportState(TransportState.CONNECTING, "Checking ICE")
                    }
                    else -> {}
                }
            }

            override fun onIceConnectionReceivingChange(receiving: Boolean) {}
            override fun onIceGatheringChange(state: PeerConnection.IceGatheringState?) {
                Log.d(TAG, "IceGatheringState: $state")
            }

            override fun onIceCandidate(candidate: IceCandidate?) {
                if (candidate != null) {
                    val candJson = JSONObject().apply {
                        put("type", "ICE_CANDIDATE")
                        put("sdpMid", candidate.sdpMid)
                        put("sdpMLineIndex", candidate.sdpMLineIndex)
                        put("candidate", candidate.sdp)
                    }
                    localIceCandidates.add(candJson)
                    // Relay candidate via remote signaling if connected
                    sendSignalingPayload(candJson)
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
                val isOpen = dc.state() == DataChannel.State.OPEN
                listener.onDataChannelStateChanged(isOpen)
            }

            override fun onMessage(buffer: DataChannel.Buffer?) {
                if (buffer != null) {
                    val bytes = ByteArray(buffer.data.remaining())
                    buffer.data.get(bytes)
                    val rawMsg = String(bytes, Charsets.UTF_8)
                    listener.onDataChannelMessage(rawMsg)
                }
            }
        })
    }

    fun sendDataChannelMessage(msg: JSONObject): Boolean {
        return try {
            val dc = managementDataChannel
            if (dc != null && dc.state() == DataChannel.State.OPEN) {
                val bytes = msg.toString().toByteArray(Charsets.UTF_8)
                val buffer = DataChannel.Buffer(ByteBuffer.wrap(bytes), false)
                dc.send(buffer)
                true
            } else {
                Log.w(TAG, "DataChannel not open for sending")
                false
            }
        } catch (e: Exception) {
            Log.e(TAG, "Failed to send message over DataChannel: ${e.message}")
            false
        }
    }

    // --- Dynamic Transport Classification (Direct LAN, Internet P2P, TURN Relay) ---

    private fun inspectCandidatePairAndClassify() {
        val pc = peerConnection ?: return
        pc.getStats(RTCStatsCollectorCallback { report ->
            var classified = false
            if (report != null) {
                val statsMap = report.statsMap
                for ((_, stats) in statsMap) {
                    if (stats.type == "candidate-pair") {
                        val members = stats.members
                        val state = members["state"]?.toString() ?: ""
                        val nominated = members["nominated"]?.toString() ?: ""
                        if (nominated.equals("true", ignoreCase = true) || state.equals("succeeded", ignoreCase = true)) {
                            val localCandidateId = members["localCandidateId"]?.toString() ?: ""
                            val remoteCandidateId = members["remoteCandidateId"]?.toString() ?: ""
                            val localCandidateStats = statsMap[localCandidateId]
                            val remoteCandidateStats = statsMap[remoteCandidateId]

                            val localType = localCandidateStats?.members?.get("candidateType")?.toString() ?: ""
                            val remoteType = remoteCandidateStats?.members?.get("candidateType")?.toString() ?: ""

                            when {
                                localType.contains("relay", ignoreCase = true) || remoteType.contains("relay", ignoreCase = true) -> {
                                    updateTransportState(TransportState.TURN_RELAY, "TURN Relay")
                                    classified = true
                                }
                                localType.contains("host", ignoreCase = true) && remoteType.contains("host", ignoreCase = true) -> {
                                    updateTransportState(TransportState.DIRECT_LAN, "Direct LAN")
                                    classified = true
                                }
                                else -> {
                                    updateTransportState(TransportState.INTERNET_P2P, "Internet P2P (STUN)")
                                    classified = true
                                }
                            }
                            if (classified) break
                        }
                    }
                }
            }
            if (!classified) {
                updateTransportState(TransportState.DIRECT_LAN, "Direct LAN / P2P")
            }
        })
    }

    private fun updateTransportState(state: TransportState, detail: String) {
        currentTransportState = state
        activePathType = detail
        listener.onTransportStateChanged(state, detail)
    }

    // --- Negotiation (Offer/Answer) ---

    suspend fun handleRemoteOffer(offerSdp: String): String? = withContext(Dispatchers.IO) {
        val pc = peerConnection ?: createOrResetPeerConnection() ?: return@withContext null
        val sdpOffer = SessionDescription(SessionDescription.Type.OFFER, offerSdp)

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

        answerLatch.await(5000, TimeUnit.MILLISECONDS)
        answerSdp
    }

    fun handleRemoteAnswer(answerSdp: String) {
        val pc = peerConnection ?: return
        val sdpAnswer = SessionDescription(SessionDescription.Type.ANSWER, answerSdp)
        pc.setRemoteDescription(object : SdpObserver {
            override fun onSetSuccess() {
                Log.i(TAG, "Remote answer set successfully")
            }
            override fun onSetFailure(err: String?) {
                Log.w(TAG, "Failed to set remote answer: $err")
            }
            override fun onCreateSuccess(p0: SessionDescription?) {}
            override fun onCreateFailure(p0: String?) {}
        }, sdpAnswer)
    }

    fun addRemoteIceCandidate(sdpMid: String, sdpMLineIndex: Int, candidate: String) {
        val pc = peerConnection ?: return
        val iceCand = IceCandidate(sdpMid, sdpMLineIndex, candidate)
        pc.addIceCandidate(iceCand)
    }

    // --- ICE Restart (Signaled across transport migration) ---

    fun initiateIceRestart(reason: String) {
        Log.i(TAG, "Initiating ICE restart. Reason: $reason")
        // Inform peer via signaling
        sendSignalingPayload(JSONObject().apply {
            put("type", "ICE_RESTART")
            put("reason", reason)
        })

        val pc = peerConnection ?: return
        val constraints = MediaConstraints().apply {
            mandatory.add(MediaConstraints.KeyValuePair("IceRestart", "true"))
            mandatory.add(MediaConstraints.KeyValuePair("OfferToReceiveVideo", "false"))
            mandatory.add(MediaConstraints.KeyValuePair("OfferToReceiveAudio", "false"))
        }

        pc.createOffer(object : SdpObserver {
            override fun onCreateSuccess(desc: SessionDescription?) {
                if (desc != null) {
                    pc.setLocalDescription(object : SdpObserver {
                        override fun onSetSuccess() {
                            // Send offer with ICE restart over signaling
                            sendSignalingPayload(JSONObject().apply {
                                put("type", "OFFER")
                                put("sdp", desc.description)
                                put("ice_restart", true)
                            })
                        }
                        override fun onSetFailure(err: String?) {
                            Log.w(TAG, "ICE restart setLocalDescription failed: $err")
                        }
                        override fun onCreateSuccess(p0: SessionDescription?) {}
                        override fun onCreateFailure(p0: String?) {}
                    }, desc)
                }
            }
            override fun onCreateFailure(err: String?) {
                Log.w(TAG, "ICE restart createOffer failed: $err")
            }
            override fun onSetSuccess() {}
            override fun onSetFailure(err: String?) {}
        }, constraints)
    }

    // --- Outbound Remote WebSocket Signaling Client ---
    // Strictly limited to SDP, ICE, and rendezvous. NEVER carries commands.

    fun connectRemoteSignaling(signalingUrl: String, deviceId: String) {
        remoteSignalingUrl = signalingUrl
        registeredDeviceId = deviceId

        scope.launch {
            try {
                val req = Request.Builder().url(signalingUrl).build()
                remoteWebSocket = okHttpClient.newWebSocket(req, object : WebSocketListener() {
                    override fun onOpen(webSocket: WebSocket, response: Response) {
                        Log.i(TAG, "Remote WebSocket signaling connected to $signalingUrl")
                        // Register as device
                        val reg = JSONObject().apply {
                            put("type", "REGISTER")
                            put("role", "device")
                            put("device_id", deviceId)
                        }
                        webSocket.send(reg.toString())
                    }

                    override fun onMessage(webSocket: WebSocket, text: String) {
                        handleSignalingMessage(text)
                    }

                    override fun onClosed(webSocket: WebSocket, code: Int, reason: String) {
                        Log.i(TAG, "Remote signaling closed ($code: $reason). Will retry.")
                        scheduleSignalingReconnect()
                    }

                    override fun onFailure(webSocket: WebSocket, t: Throwable, response: Response?) {
                        Log.w(TAG, "Remote signaling error: ${t.message}. Will retry.")
                        scheduleSignalingReconnect()
                    }
                })
            } catch (e: Exception) {
                Log.e(TAG, "Failed to connect to remote signaling: ${e.message}")
                scheduleSignalingReconnect()
            }
        }
    }

    private fun scheduleSignalingReconnect() {
        scope.launch {
            delay(5000)
            val url = remoteSignalingUrl
            val id = registeredDeviceId
            if (url != null && id != null) {
                connectRemoteSignaling(url, id)
            }
        }
    }

    private fun sendSignalingPayload(payload: JSONObject) {
        // Enforce strict filter: never send management commands or secrets over signaling
        val type = payload.optString("type")
        if (type == "COMMAND" || type == "COMMAND_RESULT" || payload.has("image_base64") || payload.has("action")) {
            Log.e(TAG, "SECURITY VIOLATION: Attempted to send management payload over signaling! Dropped.")
            return
        }

        val ws = remoteWebSocket
        if (ws != null) {
            ws.send(payload.toString())
        }
    }

    private fun handleSignalingMessage(text: String) {
        try {
            val msg = JSONObject(text)
            val type = msg.optString("type")

            // Strictly ignore any non-signaling payloads
            when (type) {
                "OFFER" -> {
                    val sdp = msg.optString("sdp")
                    scope.launch {
                        val answerSdp = handleRemoteOffer(sdp)
                        if (answerSdp != null) {
                            val answerMsg = JSONObject().apply {
                                put("type", "ANSWER")
                                put("sdp", answerSdp)
                            }
                            sendSignalingPayload(answerMsg)
                        }
                    }
                }
                "ANSWER" -> {
                    val sdp = msg.optString("sdp")
                    handleRemoteAnswer(sdp)
                }
                "ICE_CANDIDATE" -> {
                    val sdpMid = msg.optString("sdpMid")
                    val sdpMLineIndex = msg.optInt("sdpMLineIndex", 0)
                    val cand = msg.optString("candidate")
                    addRemoteIceCandidate(sdpMid, sdpMLineIndex, cand)
                }
                "ICE_RESTART" -> {
                    val reason = msg.optString("reason", "REMOTE_REQUEST")
                    initiateIceRestart(reason)
                }
                "TURN_CONFIG" -> {
                    val arr = msg.optJSONArray("ice_servers")
                    if (arr != null) {
                        val list = mutableListOf<IceServerConfig>()
                        for (i in 0 until arr.length()) {
                            val item = arr.getJSONObject(i)
                            list.add(IceServerConfig(
                                url = item.getString("url"),
                                username = item.optString("username").ifEmpty { null },
                                credential = item.optString("credential").ifEmpty { null }
                            ))
                        }
                        setCustomIceServers(list)
                    }
                }
                "STATUS" -> {
                    Log.i(TAG, "Signaling status: ${msg.optString("status")}")
                }
            }
        } catch (e: Exception) {
            Log.w(TAG, "Error handling signaling message: ${e.message}")
        }
    }

    // --- Ephemeral Local HTTP Signaling Server (LAN Bootstrap) ---
    // Restricted to site-local & loopback addresses. Strictly exchanges SDP / ICE.

    fun startLocalSignaling(port: Int = DEFAULT_LOCAL_SIGNALING_PORT) {
        if (isLocalSignalingRunning) return
        isLocalSignalingRunning = true

        scope.launch {
            try {
                val bindAddr = getPreferredLanAddress()
                localSignalingSocket = ServerSocket().apply {
                    reuseAddress = true
                    bind(InetSocketAddress(bindAddr, port))
                }
                Log.i(TAG, "Local signaling broker listening strictly on ${bindAddr.hostAddress}:$port")

                while (isActive && isLocalSignalingRunning) {
                    val socket = localSignalingSocket?.accept() ?: break
                    launch { handleLocalSignalingClient(socket) }
                }
            } catch (e: Exception) {
                if (e !is CancellationException) {
                    Log.e(TAG, "Local signaling server error: ${e.message}")
                }
            }
        }
    }

    private suspend fun handleLocalSignalingClient(socket: Socket) = withContext(Dispatchers.IO) {
        try {
            val remoteAddr = socket.inetAddress
            if (!remoteAddr.isSiteLocalAddress && !remoteAddr.isLoopbackAddress) {
                Log.w(TAG, "Dropping signaling connection from non-LAN address: $remoteAddr")
                socket.close()
                return@withContext
            }

            socket.soTimeout = 15000
            val reader = BufferedReader(InputStreamReader(socket.inputStream))
            val writer = OutputStreamWriter(socket.outputStream)

            val reqLine = reader.readLine() ?: return@withContext
            val parts = reqLine.split(" ")
            if (parts.size < 2) return@withContext
            val method = parts[0]
            val path = parts[1]

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

            when {
                method == "POST" && path == "/bootstrap/offer" -> {
                    val offerJson = JSONObject(body)
                    val sdp = offerJson.optString("sdp")
                    val answerSdp = handleRemoteOffer(sdp)
                    if (answerSdp != null) {
                        val resp = JSONObject().apply {
                            put("status", "ok")
                            put("type", "answer")
                            put("sdp", answerSdp)
                        }
                        sendHttpResponse(writer, 200, resp.toString())
                    } else {
                        sendHttpResponse(writer, 500, "{\"status\":\"error\",\"message\":\"Failed to generate answer\"}")
                    }
                }

                method == "POST" && path == "/bootstrap/ice" -> {
                    val candJson = JSONObject(body)
                    val candidate = candJson.optString("candidate")
                    val sdpMid = candJson.optString("sdpMid")
                    val sdpMLineIndex = candJson.optInt("sdpMLineIndex", 0)
                    addRemoteIceCandidate(sdpMid, sdpMLineIndex, candidate)
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
                    writer.write("HTTP/1.1 204 No Content\r\n")
                    writer.write("Access-Control-Allow-Origin: *\r\n")
                    writer.write("Access-Control-Allow-Methods: POST, GET, OPTIONS\r\n")
                    writer.write("Access-Control-Allow-Headers: Content-Type\r\n\r\n")
                    writer.flush()
                }

                else -> {
                    sendHttpResponse(writer, 403, "{\"status\":\"error\",\"message\":\"Signaling channel rejects non-signaling payloads\"}")
                }
            }
        } catch (e: Exception) {
            Log.w(TAG, "Local signaling client error: ${e.message}")
        } finally {
            try { socket.close() } catch (_: Exception) {}
        }
    }

    private fun sendHttpResponse(writer: OutputStreamWriter, code: Int, body: String) {
        val bytes = body.toByteArray(Charsets.UTF_8)
        writer.write("HTTP/1.1 $code OK\r\n")
        writer.write("Content-Type: application/json; charset=utf-8\r\n")
        writer.write("Content-Length: ${bytes.size}\r\n")
        writer.write("Access-Control-Allow-Origin: *\r\n")
        writer.write("Connection: close\r\n\r\n")
        writer.write(body)
        writer.flush()
    }

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

    // --- Network Lifecycle Monitoring & Transport Recovery ---

    fun setupNetworkMonitoring(cm: ConnectivityManager) {
        connectivityManager = cm
        val req = NetworkRequest.Builder()
            .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            .build()

        networkCallback = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) {
                val handle = network.networkHandle
                val caps = cm.getNetworkCapabilities(network)
                val isWifi = caps?.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) == true
                val isCellular = caps?.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) == true
                Log.i(TAG, "Network available: handle=$handle, Wi-Fi=$isWifi, Cellular=$isCellular")

                if (lastKnownNetworkHandle != -1L && lastKnownNetworkHandle != handle) {
                    Log.i(TAG, "Network handle changed from $lastKnownNetworkHandle to $handle (Transport migration)")
                    // Transport recovery across Wi-Fi <-> Cellular
                    scope.launch {
                        delay(1000)
                        initiateIceRestart("NETWORK_MIGRATION")
                    }
                }
                lastKnownNetworkHandle = handle
            }

            override fun onLost(network: Network) {
                Log.i(TAG, "Network lost: ${network.networkHandle}. Preparing transport recovery.")
            }
        }

        try {
            cm.registerNetworkCallback(req, networkCallback!!)
        } catch (e: Exception) {
            Log.w(TAG, "Failed to register network callback: ${e.message}")
        }
    }

    fun destroy() {
        isLocalSignalingRunning = false
        try { localSignalingSocket?.close() } catch (_: Exception) {}
        try { remoteWebSocket?.close(1000, "Service destroyed") } catch (_: Exception) {}
        try {
            if (networkCallback != null) {
                connectivityManager?.unregisterNetworkCallback(networkCallback!!)
            }
        } catch (_: Exception) {}
        try {
            peerConnection?.close()
            peerConnectionFactory?.dispose()
        } catch (_: Exception) {}
        scope.cancel()
    }
}
