package com.pixel.lanagent

import android.app.Activity
import android.content.Context
import android.content.Intent
import android.graphics.Bitmap
import android.graphics.Color
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.os.PowerManager
import android.provider.Settings
import android.view.ViewGroup
import android.widget.*
import com.google.zxing.BarcodeFormat
import com.google.zxing.qrcode.QRCodeWriter
import org.json.JSONObject
import java.net.Inet4Address
import java.net.NetworkInterface

class MainActivity : Activity() {

    private lateinit var securityManager: LanSecurityManager

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        securityManager = LanSecurityManager(this)

        val scrollView = ScrollView(this).apply {
            layoutParams = ViewGroup.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.MATCH_PARENT
            )
        }

        val layout = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(40, 40, 40, 40)
        }
        scrollView.addView(layout)

        val title = TextView(this).apply {
            text = "Pixel Management Core"
            textSize = 22f
            setPadding(0, 0, 0, 10)
        }

        val fpView = TextView(this).apply {
            text = "Device FP: ${securityManager.getDeviceFingerprint()}"
            textSize = 12f
            setTextColor(Color.parseColor("#4CAF50"))
            setPadding(0, 0, 0, 4)
        }

        val epochView = TextView(this).apply {
            text = "Session Epoch: ${securityManager.persistentEpoch} (Monotonic persistent watermark)"
            textSize = 12f
            setTextColor(Color.parseColor("#64B5F6"))
            setPadding(0, 0, 0, 10)
        }

        val ipView = TextView(this).apply {
            val ips = getLocalIpAddresses()
            text = "Active IP(s): ${if (ips.isEmpty()) "None (Offline)" else ips.joinToString(", ")}"
            textSize = 13f
            setPadding(0, 0, 0, 10)
        }

        val a11yStatus = TextView(this).apply {
            val active = RemoteAccessibilityService.isServiceActive()
            text = "Screen Control (A11y): " + (if (active) "ACTIVE" else "DISABLED (Open settings below)")
            textSize = 13f
            setTextColor(if (active) Color.parseColor("#81C784") else Color.parseColor("#E57373"))
            setPadding(0, 0, 0, 15)
        }

        val codeDisplay = TextView(this).apply {
            text = "Pairing PIN: Tap button below"
            textSize = 16f
            setPadding(0, 0, 0, 10)
        }

        val qrImageView = ImageView(this).apply {
            layoutParams = LinearLayout.LayoutParams(500, 500).apply {
                bottomMargin = 20
            }
            visibility = ImageView.GONE
        }

        val btnGenCode = Button(this).apply {
            text = "Generate 5-Min Pairing PIN & QR"
            setOnClickListener {
                val bootstrap = securityManager.generatePairingBootstrapData()
                codeDisplay.text = "Pairing PIN: ${bootstrap.pin} (Valid 5 min, 3 attempts)"

                val primaryIp = getLocalIpAddresses().firstOrNull() ?: "127.0.0.1"
                val qrData = JSONObject().apply {
                    put("type", "PIXEL_BOOTSTRAP")
                    put("protocol_context", LanSecurityManager.PROTOCOL_CONTEXT)
                    put("pixel_id", securityManager.getDeviceId())
                    put("ip", primaryIp)
                    put("port", LanManagementService.LOCAL_BOOTSTRAP_PORT)
                    put("pin", bootstrap.pin)
                    put("nonce", bootstrap.nonce)
                    put("pubkey", securityManager.getDevicePublicKeyBase64())
                    put("fp", securityManager.getDeviceFingerprint())
                    put("epoch", securityManager.persistentEpoch)
                }.toString()

                val bitmap = generateQrBitmap(qrData, 500, 500)
                if (bitmap != null) {
                    qrImageView.setImageBitmap(bitmap)
                    qrImageView.visibility = ImageView.VISIBLE
                }
            }
        }

        // Remote WebSocket signaling configuration
        val signalingLabel = TextView(this).apply {
            text = "Remote WebSocket Signaling URL:"
            textSize = 13f
            setPadding(0, 15, 0, 4)
        }

        val signalingInput = EditText(this).apply {
            hint = "ws://<remote-host>:8991/signaling"
            textSize = 13f
        }

        val btnConnectSignaling = Button(this).apply {
            text = "Connect Remote Signaling"
            setOnClickListener {
                val url = signalingInput.text.toString().trim()
                if (url.isNotEmpty()) {
                    val intent = Intent(this@MainActivity, LanManagementService::class.java).apply {
                        putExtra(LanManagementService.EXTRA_SIGNALING_URL, url)
                    }
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                        startForegroundService(intent)
                    } else {
                        startService(intent)
                    }
                    Toast.makeText(this@MainActivity, "Connecting remote signaling...", Toast.LENGTH_SHORT).show()
                } else {
                    Toast.makeText(this@MainActivity, "Enter signaling URL", Toast.LENGTH_SHORT).show()
                }
            }
        }

        val btnA11y = Button(this).apply {
            text = "Open Accessibility Settings"
            setOnClickListener {
                startActivity(Intent(Settings.ACTION_ACCESSIBILITY_SETTINGS))
            }
        }

        val btnBattery = Button(this).apply {
            text = "Request Battery Exemption"
            setOnClickListener {
                requestBatteryExemption()
            }
        }

        val btnStartService = Button(this).apply {
            text = "Start Management Foreground Service"
            setOnClickListener {
                val intent = Intent(this@MainActivity, LanManagementService::class.java)
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                    startForegroundService(intent)
                } else {
                    startService(intent)
                }
                Toast.makeText(this@MainActivity, "Management Service Started", Toast.LENGTH_SHORT).show()
            }
        }

        val btnRevoke = Button(this).apply {
            text = "Revoke All Paired Controllers"
            setBackgroundColor(Color.parseColor("#B71C1C"))
            setTextColor(Color.WHITE)
            setOnClickListener {
                securityManager.revokeAllControllers()
                Toast.makeText(this@MainActivity, "All authorized controllers revoked", Toast.LENGTH_SHORT).show()
            }
        }

        val noticeView = TextView(this).apply {
            text = "MANDATORY SECURITY QUALIFICATIONS:\n\n" +
                    "• The Pixel core agent is PERSISTENT WHILE ANDROID PERMITS EXECUTION USING SUPPORTED LIFECYCLE MECHANISMS.\n\n" +
                    "• WebRTC provides encrypted DTLS/SCTP transport for DataChannels; exact protocol version and cipher suite are implementation dependent.\n\n" +
                    "• The system is DESIGNED FOR AUTOMATIC TRANSPORT RECOVERY AND SESSION RESYNCHRONIZATION; PHYSICAL MIGRATION REMAINS UNVERIFIED."
            textSize = 10f
            setTextColor(Color.parseColor("#9E9E9E"))
            setPadding(0, 20, 0, 10)
        }

        layout.addView(title)
        layout.addView(fpView)
        layout.addView(epochView)
        layout.addView(ipView)
        layout.addView(a11yStatus)
        layout.addView(codeDisplay)
        layout.addView(qrImageView)
        layout.addView(btnGenCode)
        layout.addView(signalingLabel)
        layout.addView(signalingInput)
        layout.addView(btnConnectSignaling)
        layout.addView(btnA11y)
        layout.addView(btnBattery)
        layout.addView(btnStartService)
        layout.addView(btnRevoke)
        layout.addView(noticeView)

        setContentView(scrollView)
    }

    private fun getLocalIpAddresses(): List<String> {
        val result = mutableListOf<String>()
        try {
            val interfaces = NetworkInterface.getNetworkInterfaces()
            while (interfaces.hasMoreElements()) {
                val iface = interfaces.nextElement()
                if (iface.isLoopback || !iface.isUp) continue
                val addresses = iface.inetAddresses
                while (addresses.hasMoreElements()) {
                    val addr = addresses.nextElement()
                    if (addr is Inet4Address && !addr.isLoopbackAddress) {
                        result.add(addr.hostAddress ?: "")
                    }
                }
            }
        } catch (_: Exception) {}
        return result.filter { it.isNotEmpty() }
    }

    private fun generateQrBitmap(content: String, width: Int, height: Int): Bitmap? {
        return try {
            val writer = QRCodeWriter()
            val bitMatrix = writer.encode(content, BarcodeFormat.QR_CODE, width, height)
            val bitmap = Bitmap.createBitmap(width, height, Bitmap.Config.RGB_565)
            for (x in 0 until width) {
                for (y in 0 until height) {
                    bitmap.setPixel(x, y, if (bitMatrix[x, y]) Color.BLACK else Color.WHITE)
                }
            }
            bitmap
        } catch (e: Exception) {
            null
        }
    }

    private fun requestBatteryExemption() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            val pm = getSystemService(Context.POWER_SERVICE) as PowerManager
            if (!pm.isIgnoringBatteryOptimizations(packageName)) {
                val intent = Intent(Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS).apply {
                    data = Uri.parse("package:$packageName")
                }
                startActivity(intent)
            }
        }
    }
}
