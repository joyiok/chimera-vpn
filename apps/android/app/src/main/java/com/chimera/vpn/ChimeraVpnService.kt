package com.chimera.vpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.content.pm.ServiceInfo
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.util.Log
import java.io.FileInputStream
import java.io.FileOutputStream
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch

class ChimeraVpnService : VpnService() {

    private var vpnHandle: Long = -1L
    private var vpnInterface: ParcelFileDescriptor? = null

    private val serviceScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private var goToTunJob: Job? = null
    private var tunToGoJob: Job? = null

    override fun onCreate() {
        super.onCreate()
        postLog("ChimeraVpnService 已创建")
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        startForegroundCompat()

        if (vpnInterface != null) {
            postLog("VPN 已在运行，忽略重复启动")
            return START_NOT_STICKY
        }

        val config = intent?.let { parseConfig(it) }
        if (config == null || config.serverAddr.isBlank() || config.seedHex.isBlank() || config.pskHex.isBlank() || config.tunIp.isBlank()) {
            postStatus("连接参数不完整")
            stopSelf()
            return START_NOT_STICKY
        }

        postStatus(getString(R.string.status_connecting))
        serviceScope.launch { startVpn(config) }
        return START_NOT_STICKY
    }

    override fun onDestroy() {
        stopVpn()
        serviceScope.cancel()
        isRunning = false
        postLog("ChimeraVpnService 已销毁")
        super.onDestroy()
    }

    private fun startForegroundCompat() {
        val notification = buildNotification()
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            startForeground(NOTIFICATION_ID, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
        } else {
            startForeground(NOTIFICATION_ID, notification)
        }
    }

    private fun buildNotification(): Notification {
        val channelId = CHANNEL_ID
        val manager = getSystemService(NotificationManager::class.java)

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                channelId,
                getString(R.string.app_name),
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = getString(R.string.notification_running)
            }
            manager.createNotificationChannel(channel)
        }

        val pendingIntent = PendingIntent.getActivity(
            this,
            0,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        return Notification.Builder(this, channelId)
            .setContentTitle(getString(R.string.app_name))
            .setContentText(getString(R.string.notification_running))
            .setSmallIcon(R.drawable.ic_stat_vpn)
            .setContentIntent(pendingIntent)
            .setOngoing(true)
            .build()
    }

    private suspend fun startVpn(config: VpnConfig) {
        try {
            postLog("正在建立 VPN 隧道：${config.serverAddr}")

            // 先完成 CHIMERA 握手，再从服务器获取自动分配的 TUN 地址；
            // 服务端未开启地址分配时，回退到界面填写的地址。
            val handle = GoBind.start(
                seedHex = config.seedHex,
                generation = config.generation,
                pskHex = config.pskHex,
                serverAddr = config.serverAddr
            )
            if (!protectUdpSocket(handle)) {
                runCatching { GoBind.stop(handle) }
                throw IllegalStateException("VpnService.protect 失败，UDP 套接字无法绕过 TUN")
            }
            val assigned = runCatching { GoBind.assignedIP(handle) }.getOrNull()
            val tunAddr = assigned ?: config.tunIp

            val builder = Builder()
                .setSession(getString(R.string.app_name))
                .setMtu(1400)
                .addAddress(tunAddr, 24)
                .addRoute("0.0.0.0", 0)
                .addDnsServer("1.1.1.1")
                .addDnsServer("8.8.8.8")

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                builder.setMetered(false)
            }
            try {
                builder.addDisallowedApplication(packageName)
            } catch (e: PackageManager.NameNotFoundException) {
                postLog("addDisallowedApplication 跳过：${e.message}")
            }

            val pfd = builder.establish()
                ?: throw IllegalStateException("VpnService.establish 返回 null（用户可能拒绝了 VPN 授权）")
            vpnInterface = pfd
            vpnHandle = handle
            isRunning = true

            postStatus(getString(R.string.status_connected))
            postLog("Go 核心已启动，handle=$handle，本地地址 $tunAddr/24${if (assigned != null) "（服务器分配）" else "（手动配置）"}")

            val input = FileInputStream(pfd.fileDescriptor)
            val output = FileOutputStream(pfd.fileDescriptor)

            goToTunJob = serviceScope.launch {
                while (isActive) {
                    try {
                        val packet = GoBind.receive(handle)
                        if (packet != null && packet.isNotEmpty()) {
                            output.write(packet)
                            output.flush()
                        } else {
                            delay(10)
                        }
                    } catch (e: Exception) {
                        if (!isActive) break
                        postLog("接收 Go 数据失败：${e.message}")
                        delay(200)
                    }
                }
            }

            tunToGoJob = serviceScope.launch {
                val buffer = ByteArray(TUN_READ_SIZE)
                while (isActive) {
                    try {
                        val n = input.read(buffer)
                        when {
                            n > 0 -> GoBind.send(handle, buffer.copyOf(n))
                            n < 0 -> {
                                postLog("TUN 文件描述符已关闭")
                                break
                            }
                            else -> delay(10)
                        }
                    } catch (e: Exception) {
                        if (!isActive) break
                        postLog("读取 TUN 数据失败：${e.message}")
                        delay(200)
                    }
                }
            }
        } catch (t: Throwable) {
            if (t is kotlinx.coroutines.CancellationException) throw t
            postStatus("连接失败：${t.message}")
            postLog("连接失败：${t.javaClass.simpleName}: ${t.message}")
            stopVpn()
            stopSelf()
        }
    }

    private fun stopVpn() {
        goToTunJob?.cancel()
        tunToGoJob?.cancel()
        goToTunJob = null
        tunToGoJob = null

        runCatching { vpnInterface?.close() }
        vpnInterface = null

        if (vpnHandle >= 0L) {
            runCatching { GoBind.stop(vpnHandle) }
                .onFailure { postLog("Go 核心停止失败：${it.message}") }
            vpnHandle = -1L
        }

        if (isRunning) {
            isRunning = false
            postStatus(getString(R.string.status_disconnected))
        }
    }

    private fun protectUdpSocket(handle: Long): Boolean {
        val fd = try {
            GoBind.socketFD(handle)
        } catch (e: Exception) {
            postLog("socketFD 失败：${e.message}")
            return false
        }
        if (fd < 0) {
            postLog("socketFD 返回无效描述符 $fd")
            return false
        }
        if (!protect(fd)) {
            postLog("protect($fd) 失败")
            return false
        }
        postLog("已 protect UDP fd=$fd，隧道套接字绕过 TUN")
        return true
    }

    private fun parseConfig(intent: Intent): VpnConfig {
        val tunIp = intent.getStringExtra(EXTRA_TUN_IP).orEmpty()
        return VpnConfig(
            serverAddr = intent.getStringExtra(EXTRA_SERVER).orEmpty(),
            seedHex = intent.getStringExtra(EXTRA_SEED).orEmpty(),
            generation = intent.getLongExtra(EXTRA_GENERATION, 0L),
            pskHex = intent.getStringExtra(EXTRA_PSK).orEmpty(),
            tunIp = tunIp.ifBlank { "10.99.0.2" }
        )
    }

    data class VpnConfig(
        val serverAddr: String,
        val seedHex: String,
        val generation: Long,
        val pskHex: String,
        val tunIp: String = "10.99.0.2"
    )

    companion object {
        private const val TAG = "ChimeraVpnService"
        private const val CHANNEL_ID = "chimera_vpn"
        private const val NOTIFICATION_ID = 42
        private const val TUN_READ_SIZE = 32767
        private const val MAX_LOG_LINES = 200

        private const val EXTRA_SERVER = "extra_server"
        private const val EXTRA_SEED = "extra_seed"
        private const val EXTRA_GENERATION = "extra_generation"
        private const val EXTRA_PSK = "extra_psk"
        private const val EXTRA_TUN_IP = "extra_tun_ip"

        @Volatile
        var isRunning = false
            private set

        private val _status = MutableStateFlow("未连接")
        val status: StateFlow<String> = _status.asStateFlow()

        private val _logLines = MutableStateFlow<List<String>>(emptyList())
        val logLines: StateFlow<List<String>> = _logLines.asStateFlow()

        fun start(context: Context, config: VpnConfig) {
            val intent = Intent(context, ChimeraVpnService::class.java).apply {
                putExtra(EXTRA_SERVER, config.serverAddr)
                putExtra(EXTRA_SEED, config.seedHex)
                putExtra(EXTRA_GENERATION, config.generation)
                putExtra(EXTRA_PSK, config.pskHex)
                putExtra(EXTRA_TUN_IP, config.tunIp)
            }
            context.startForegroundService(intent)
        }

        fun stop(context: Context) {
            context.stopService(Intent(context, ChimeraVpnService::class.java))
        }

        fun postStatus(value: String) {
            Log.i(TAG, "status: $value")
            _status.value = value
        }

        fun postLog(message: String) {
            Log.i(TAG, message)
            _logLines.update { (it + message).takeLast(MAX_LOG_LINES) }
        }
    }
}
