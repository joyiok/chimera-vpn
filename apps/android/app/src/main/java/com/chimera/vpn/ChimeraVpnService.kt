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
import java.util.concurrent.atomic.AtomicLong
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
    private var lastConfig: VpnConfig? = null
    private var tunAddr: String = ""
    private var tunIn: FileInputStream? = null
    private var tunOut: FileOutputStream? = null
    private val sessionLock = Any()
    @Volatile private var reconnecting = false

    private val serviceScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private var goToTunJob: Job? = null
    private var tunToGoJob: Job? = null
    private var watchdogJob: Job? = null
    private var trafficJob: Job? = null

    override fun onCreate() {
        super.onCreate()
        postLog("ChimeraVpnService 已创建")
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_DISCONNECT -> {
                stopVpn()
                stopSelf()
                return START_NOT_STICKY
            }
            ACTION_RECONNECT -> {
                if (isRunning) {
                    requestReconnect("notification")
                }
                return START_NOT_STICKY
            }
        }

        startForegroundCompat()

        if (vpnInterface != null) {
            postLog("VPN 已在运行，忽略重复启动")
            return START_NOT_STICKY
        }

        val config = intent?.let { parseConfig(it) } ?: ClientPrefs.load(this)
        if (config == null || config.serverAddr.isBlank() || config.seedHex.isBlank() || config.pskHex.isBlank() || config.tunIp.isBlank()) {
            postStatus("连接参数不完整")
            stopSelf()
            return START_NOT_STICKY
        }

        postStatus(getString(R.string.status_connecting))
        lastConfig = config
        ClientPrefs.save(this, config)
        bytesSent.set(0)
        bytesRecv.set(0)
        postTraffic(0, 0)
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
        val disconnectPi = PendingIntent.getService(
            this,
            1,
            Intent(this, ChimeraVpnService::class.java).setAction(ACTION_DISCONNECT),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        val reconnectPi = PendingIntent.getService(
            this,
            2,
            Intent(this, ChimeraVpnService::class.java).setAction(ACTION_RECONNECT),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        val traffic = formatBytes(bytesSent.get()) + " ↑  " + formatBytes(bytesRecv.get()) + " ↓"

        return Notification.Builder(this, channelId)
            .setContentTitle(getString(R.string.app_name))
            .setContentText(traffic)
            .setStyle(Notification.BigTextStyle().bigText(getString(R.string.notification_running) + "\n" + traffic))
            .setSmallIcon(R.drawable.ic_stat_vpn)
            .setContentIntent(pendingIntent)
            .addAction(R.drawable.ic_stat_vpn, getString(R.string.disconnect), disconnectPi)
            .addAction(R.drawable.ic_stat_vpn, getString(R.string.reconnect), reconnectPi)
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
            vpnHandle = handle
            val assigned = runCatching { GoBind.assignedIP(handle) }.getOrNull()
            val tunAddrAssigned = assigned ?: config.tunIp

            val pfd = establishTun(tunAddrAssigned)
            attachTun(pfd)
            vpnInterface = pfd
            tunAddr = tunAddrAssigned
            isRunning = true

            postStatus(getString(R.string.status_connected))
            postLog("Go 核心已启动，handle=$handle，本地地址 $tunAddrAssigned/24${if (assigned != null) "（服务器分配）" else "（手动配置）"}")

            startPumps()
            launchWatchdog()
            launchTraffic()
        } catch (t: Throwable) {
            if (t is kotlinx.coroutines.CancellationException) throw t
            postStatus("连接失败：${t.message}")
            postLog("连接失败：${t.javaClass.simpleName}: ${t.message}")
            stopVpn()
            stopSelf()
        }
    }

    private fun establishTun(address: String): ParcelFileDescriptor {
        val builder = Builder()
            .setSession(getString(R.string.app_name))
            .setMtu(1400)
            .addAddress(address, 24)
            .addRoute("0.0.0.0", 0)
            .addDnsServer("1.1.1.1")
            .addDnsServer("8.8.8.8")

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            builder.setMetered(false)
        }
        try {
            builder.addAddress("fd99::2", 64)
            builder.addRoute("::", 0)
        } catch (e: Exception) {
            postLog("IPv6 默认路由未安装：${e.message}")
        }
        try {
            builder.addDisallowedApplication(packageName)
        } catch (e: PackageManager.NameNotFoundException) {
            postLog("addDisallowedApplication 跳过：${e.message}")
        }

        return builder.establish()
            ?: throw IllegalStateException("VpnService.establish 返回 null（用户可能拒绝了 VPN 授权）")
    }

    private fun attachTun(pfd: ParcelFileDescriptor) {
        closeTunStreams()
        tunIn = FileInputStream(pfd.fileDescriptor)
        tunOut = FileOutputStream(pfd.fileDescriptor)
    }

    private fun closeTunStreams() {
        runCatching { tunIn?.close() }
        runCatching { tunOut?.close() }
        tunIn = null
        tunOut = null
    }

    private fun startPumps() {
        goToTunJob?.cancel()
        tunToGoJob?.cancel()

        goToTunJob = serviceScope.launch {
            while (isActive) {
                val handle = vpnHandle
                if (handle < 0L) {
                    delay(50)
                    continue
                }
                try {
                    val packet = GoBind.receive(handle)
                    val output = tunOut
                    if (packet != null && packet.isNotEmpty() && output != null) {
                        output.write(packet)
                        output.flush()
                        bytesRecv.addAndGet(packet.size.toLong())
                    } else {
                        delay(10)
                    }
                } catch (e: Exception) {
                    if (!isActive) break
                    postLog("接收 Go 数据失败：${e.message}")
                    if (vpnHandle == handle) {
                        requestReconnect("receive: ${e.message}")
                    }
                    delay(200)
                }
            }
        }

        tunToGoJob = serviceScope.launch {
            val buffer = ByteArray(TUN_READ_SIZE)
            while (isActive) {
                val input = tunIn
                if (input == null) {
                    delay(50)
                    continue
                }
                try {
                    val n = input.read(buffer)
                    val handle = vpnHandle
                    when {
                        n > 0 && handle >= 0L -> {
                            GoBind.send(handle, buffer.copyOf(n))
                            bytesSent.addAndGet(n.toLong())
                        }
                        n < 0 -> {
                            postLog("TUN 文件描述符已关闭")
                            delay(200)
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
    }

    private fun launchTraffic() {
        trafficJob?.cancel()
        trafficJob = serviceScope.launch {
            while (isActive) {
                val sent = bytesSent.get()
                val recv = bytesRecv.get()
                postTraffic(sent, recv)
                val nm = getSystemService(NotificationManager::class.java)
                nm.notify(NOTIFICATION_ID, buildNotification())
                delay(1000)
            }
        }
    }

    private fun launchWatchdog() {
        watchdogJob?.cancel()
        watchdogJob = serviceScope.launch {
            while (isActive) {
                delay(WATCHDOG_MS)
                if (!isRunning) continue
                val handle = vpnHandle
                if (handle < 0L) continue
                val idle = GoBind.idleMillis(handle)
                if (idle >= LINK_LOST_MS) {
                    requestReconnect("inbound silence ${idle}ms")
                }
            }
        }
    }

    private fun requestReconnect(reason: String) {
        if (!isRunning) return
        serviceScope.launch { reconnectGo(reason) }
    }

    private suspend fun reconnectGo(reason: String) {
        val config = lastConfig ?: return
        synchronized(sessionLock) {
            if (reconnecting || !isRunning) return
            reconnecting = true
        }
        try {
            postLog("正在重连：$reason")
            postStatus("重连中…")
            val newHandle = GoBind.start(
                seedHex = config.seedHex,
                generation = config.generation,
                pskHex = config.pskHex,
                serverAddr = config.serverAddr
            )
            if (!protectUdpSocket(newHandle)) {
                runCatching { GoBind.stop(newHandle) }
                throw IllegalStateException("重连 protect 失败")
            }
            val assigned = runCatching { GoBind.assignedIP(newHandle) }.getOrNull()
            val newAddr = assigned ?: config.tunIp
            if (newAddr != tunAddr) {
                val newPfd = establishTun(newAddr)
                val oldPfd = vpnInterface
                attachTun(newPfd)
                vpnInterface = newPfd
                tunAddr = newAddr
                runCatching { oldPfd?.close() }
                postLog("TUN 地址变为 $newAddr/24")
            }
            val oldHandle = vpnHandle
            vpnHandle = newHandle
            if (oldHandle >= 0L && oldHandle != newHandle) {
                runCatching { GoBind.stop(oldHandle) }
            }
            postStatus(getString(R.string.status_connected))
            postLog("重连成功，handle=$newHandle")
        } catch (t: Throwable) {
            if (t is kotlinx.coroutines.CancellationException) throw t
            postLog("重连失败：${t.message}")
            postStatus("重连失败：${t.message}")
        } finally {
            reconnecting = false
        }
    }

    private fun stopVpn() {
        watchdogJob?.cancel()
        goToTunJob?.cancel()
        tunToGoJob?.cancel()
        trafficJob?.cancel()
        watchdogJob = null
        goToTunJob = null
        tunToGoJob = null
        trafficJob = null

        closeTunStreams()
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
        private const val LINK_LOST_MS = 90_000L
        private const val WATCHDOG_MS = 5_000L

        private const val EXTRA_SERVER = "extra_server"
        private const val EXTRA_SEED = "extra_seed"
        private const val EXTRA_GENERATION = "extra_generation"
        private const val EXTRA_PSK = "extra_psk"
        private const val EXTRA_TUN_IP = "extra_tun_ip"
        const val ACTION_DISCONNECT = "com.chimera.vpn.action.DISCONNECT"
        const val ACTION_RECONNECT = "com.chimera.vpn.action.RECONNECT"

        private val bytesSent = AtomicLong(0)
        private val bytesRecv = AtomicLong(0)

        @Volatile
        var isRunning = false
            private set

        private val _status = MutableStateFlow("未连接")
        val status: StateFlow<String> = _status.asStateFlow()

        private val _logLines = MutableStateFlow<List<String>>(emptyList())
        val logLines: StateFlow<List<String>> = _logLines.asStateFlow()

        data class TrafficSnapshot(val sent: Long = 0, val recv: Long = 0)

        private val _traffic = MutableStateFlow(TrafficSnapshot())
        val traffic: StateFlow<TrafficSnapshot> = _traffic.asStateFlow()

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

        fun postTraffic(sent: Long, recv: Long) {
            _traffic.value = TrafficSnapshot(sent, recv)
        }

        fun formatBytes(n: Long): String {
            val v = if (n < 0) 0 else n
            return when {
                v < 1024 -> "$v B"
                v < 1024 * 1024 -> "%.1f KB".format(v / 1024.0)
                v < 1024L * 1024 * 1024 -> "%.2f MB".format(v / 1024.0 / 1024.0)
                else -> "%.2f GB".format(v / 1024.0 / 1024.0 / 1024.0)
            }
        }
    }
}
