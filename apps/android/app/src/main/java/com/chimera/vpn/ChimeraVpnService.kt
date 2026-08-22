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
import java.util.concurrent.atomic.AtomicBoolean
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
    // 防止 Activity/QS 磁贴双击等并发入口同时进入 startVpn，泄漏第一个 Go 会话。
    private val starting = AtomicBoolean(false)
    // 重连连续失败计数：成功归零，失败按 5s/10s/20s/40s/60s 退避重试。
    private var reconnectAttempts = 0
    private var lastNotifiedSent = -1L
    private var lastNotifiedRecv = -1L

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
                } else {
                    // 服务正在拆除时点重连：不留一个空转的实例和过期通知。
                    stopSelf()
                }
                return START_NOT_STICKY
            }
        }

        startForegroundCompat()

        if (vpnInterface != null) {
            postLog("VPN 已在运行，忽略重复启动")
            return START_NOT_STICKY
        }
        if (!starting.compareAndSet(false, true)) {
            postLog("正在建立连接，忽略重复启动")
            return START_NOT_STICKY
        }

        val config = configFrom(intent)
        if (config == null || config.serverAddr.isBlank() || config.seedHex.isBlank() || config.pskHex.isBlank() || config.tunIp.isBlank()) {
            postStatus("连接参数不完整")
            stopSelf()
            return START_NOT_STICKY
        }
        if (config.transport != "udp" && config.transport != "tcp" && config.transport != "websocket" && config.transport != "wss") {
            postStatus("传输参数无效：${config.transport}")
            stopSelf()
            return START_NOT_STICKY
        }
        if (config.portHopCount !in 1..16) {
            postStatus("端口跳跃数无效：${config.portHopCount}")
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

    override fun onRevoke() {
        postLog("系统撤销了 VPN 授权")
        stopVpn()
        stopSelf()
        super.onRevoke()
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
            postLog("正在建立 VPN 隧道：${config.serverAddr} transport=${config.transport} split=${config.splitTunnel}")

            // 先完成 CHIMERA 握手，再从服务器获取自动分配的 TUN 地址；
            // 服务端未开启地址分配时，回退到界面填写的地址。
            val handle = startGo(config)
            if (!protectUdpSocket(handle)) {
                runCatching { GoBind.stop(handle) }
                throw IllegalStateException("VpnService.protect 失败，UDP 套接字无法绕过 TUN")
            }
            vpnHandle = handle
            val assigned = runCatching { GoBind.assignedIP(handle) }.getOrNull()
            val tunAddrAssigned = assigned ?: config.tunIp

            val pfd = establishTun(tunAddrAssigned, config.splitTunnel)
            attachTun(pfd)
            vpnInterface = pfd
            tunAddr = tunAddrAssigned
            isRunning = true
            reconnectAttempts = 0

            postStatus(getString(R.string.status_connected))
            postLog("Go 核心已启动，handle=$handle，本地地址 $tunAddrAssigned/24${if (assigned != null) "（服务器分配）" else "（手动配置）"}")
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
                postLog("always-on=${isAlwaysOn} lockdown=${isLockdownEnabled}")
            }

            startPumps()
            launchWatchdog()
            launchTraffic()
        } catch (t: Throwable) {
            if (t is kotlinx.coroutines.CancellationException) throw t
            postStatus("连接失败：${t.message}")
            postLog("连接失败：${t.javaClass.simpleName}: ${t.message}")
            stopVpn()
            stopSelf()
        } finally {
            starting.set(false)
        }
    }

    private fun startGo(config: VpnConfig): Long {
        // 首选 hop 入口：它同时承载 transport 选择与端口跳跃（count<=1 即
        // 不跳跃）。websocket/wss 必须走这里，旧代码只把 "tcp" 传下去，
        // 其余传输会被静默降级成 UDP，对 wss-only 服务器必然连不上。
        return try {
            GoBind.startTransportWithHop(
                seedHex = config.seedHex,
                generation = config.generation,
                pskHex = config.pskHex,
                serverAddr = config.serverAddr,
                transport = config.transport,
                hopCount = config.portHopCount,
                hopSpread = config.portHopSpread
            )
        } catch (e: NoSuchMethodException) {
            // 旧 AAR 没有 hop 入口：尽力降级，不支持就明确报错。
            when {
                config.transport == "udp" && config.portHopCount <= 1 ->
                    GoBind.start(config.seedHex, config.generation, config.pskHex, config.serverAddr)
                config.transport == "tcp" ->
                    GoBind.startTransport(config.seedHex, config.generation, config.pskHex, config.serverAddr, "tcp")
                else -> throw IllegalStateException("当前核心库不支持 ${config.transport} 传输，请重新构建 AAR", e)
            }
        }
    }

    private fun establishTun(address: String, splitTunnel: Boolean): ParcelFileDescriptor {
        val builder = Builder()
            .setSession(getString(R.string.app_name))
            .setMtu(1400)
            .addAddress(address, 24)
            .addDnsServer("1.1.1.1")
            .addDnsServer("8.8.8.8")

        if (splitTunnel) {
            // 分流：仅把公网 IPv4 送进 VPN，私网/环回/链路本地/组播直连。
            // 路由表在 res/values/split_routes.xml，与 Windows 的绕过列表一致。
            val routes = resources.getStringArray(R.array.split_tunnel_ipv4_routes)
            var added = 0
            for (route in routes) {
                runCatching {
                    // 数组元素是 "a.b.c.d/p" 形式；部分系统版本不接受带
                    // 斜杠的 address，这里显式拆成 address + prefix。
                    val parts = route.split("/")
                    builder.addRoute(parts[0], if (parts.size > 1) parts[1].toInt() else 0)
                }
                    .onSuccess { added++ }
                    .onFailure { postLog("分流路由 ${route} 被系统拒绝：${it.message}") }
            }
            if (added == 0) {
                // 极端兜底：系统不接受白名单路由时退回全局，避免断网。
                builder.addRoute("0.0.0.0", 0)
                postLog("分流路由全部被拒绝，已退回全局模式")
            } else {
                postLog("分流模式已安装 ${added} 条公网路由，局域网/私网直连")
            }
        } else {
            builder.addRoute("0.0.0.0", 0)
            postLog("全局模式：IPv4 全部走 VPN")
        }

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            builder.setMetered(false)
        }
        try {
            builder.addAddress("fd99::2", 64)
            if (splitTunnel) {
                builder.addRoute("2000::", 3) // 仅全球单播 IPv6 走 VPN
            } else {
                builder.addRoute("::", 0)
            }
            builder.addDnsServer("2606:4700:4700::1111")
        } catch (e: Exception) {
            postLog("IPv6 路由未安装：${e.message}")
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
                // 流量数字没变化就不重建通知：每秒重建会反复唤醒通知面板。
                if (sent != lastNotifiedSent || recv != lastNotifiedRecv) {
                    val nm = getSystemService(NotificationManager::class.java)
                    nm.notify(NOTIFICATION_ID, buildNotification())
                    lastNotifiedSent = sent
                    lastNotifiedRecv = recv
                }
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
            val newHandle = startGo(config)
            if (!protectUdpSocket(newHandle)) {
                runCatching { GoBind.stop(newHandle) }
                throw IllegalStateException("重连 protect 失败")
            }
            val assigned = runCatching { GoBind.assignedIP(newHandle) }.getOrNull()
            val newAddr = assigned ?: config.tunIp
            if (newAddr != tunAddr) {
                val newPfd = establishTun(newAddr, config.splitTunnel)
                val oldPfd = vpnInterface
                attachTun(newPfd)
                vpnInterface = newPfd
                tunAddr = newAddr
                runCatching { oldPfd?.close() }
                postLog("TUN 地址变为 $newAddr/24")
            }
            val oldHandle = vpnHandle
            vpnHandle = newHandle
            // 先重启泵再停旧 handle：receive() 阻塞在旧 handle 的 JNI 调用里，
            // stop(oldHandle) 会把它错误返回，已取消的旧协程随之退出；
            // 不重启泵的话新隧道的数据没人消费。
            startPumps()
            if (oldHandle >= 0L && oldHandle != newHandle) {
                runCatching { GoBind.stop(oldHandle) }
                    .onFailure { postLog("停止旧 Go 会话失败：${it.message}") }
            }
            reconnectAttempts = 0
            postStatus(getString(R.string.status_connected))
            postLog("重连成功，handle=$newHandle")
        } catch (t: Throwable) {
            if (t is kotlinx.coroutines.CancellationException) throw t
            postLog("重连失败：${t.message}")
            postStatus("重连失败：${t.message}")
            // 有界退避重试：失败后不能只靠 watchdog 的 idleMillis（死
            // handle 上它永远返回 0，等于放弃重试）。
            reconnectAttempts++
            if (reconnectAttempts <= 5) {
                val delayMs = 5_000L shl (reconnectAttempts - 1)
                postLog("${delayMs / 1000}s 后自动重试（第 $reconnectAttempts 次）")
                serviceScope.launch {
                    delay(delayMs)
                    if (isRunning) reconnectGo("retry #$reconnectAttempts")
                }
            } else {
                postLog("连续重连失败 $reconnectAttempts 次，停止重试")
                stopVpn()
                stopSelf()
            }
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

        if (isRunning) {
            isRunning = false
            postStatus(getString(R.string.status_disconnected))
        } else {
            val current = status.value
            if (VpnState.classify(current) == ConnState.CONNECTING) {
                postStatus(getString(R.string.status_disconnected))
            }
        }

        if (vpnHandle >= 0L) {
            val handle = vpnHandle
            vpnHandle = -1L
            // 不阻塞主线程：Go 侧 Close 正常很快；若旧 AAR/内核卡住，
            // UI 状态也已经先切换到“已断开”。
            Thread {
                runCatching { GoBind.stop(handle) }
                    .onFailure { postLog("Go 核心停止失败：${it.message}") }
            }.start()
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
        postLog("已 protect transport fd=$fd，隧道套接字绕过 TUN")
        return true
    }

    private fun configFrom(intent: Intent?): VpnConfig? {
        if (intent != null && intent.action != ACTION_DISCONNECT && intent.action != ACTION_RECONNECT) {
            val fromIntent = parseConfig(intent)
            if (fromIntent.serverAddr.isNotBlank() && fromIntent.seedHex.isNotBlank() && fromIntent.pskHex.isNotBlank()) {
                return fromIntent
            }
        }
        return ClientPrefs.load(this)
    }

    private fun parseConfig(intent: Intent): VpnConfig {
        val tunIp = intent.getStringExtra(EXTRA_TUN_IP).orEmpty()
        return VpnConfig(
            serverAddr = intent.getStringExtra(EXTRA_SERVER).orEmpty(),
            seedHex = intent.getStringExtra(EXTRA_SEED).orEmpty(),
            generation = intent.getLongExtra(EXTRA_GENERATION, 0L),
            pskHex = intent.getStringExtra(EXTRA_PSK).orEmpty(),
            tunIp = tunIp.ifBlank { "10.99.0.2" },
            transport = intent.getStringExtra(EXTRA_TRANSPORT).orEmpty().ifBlank { "udp" },
            splitTunnel = intent.getBooleanExtra(EXTRA_SPLIT_TUNNEL, true),
            portHopCount = intent.getIntExtra(EXTRA_PORT_HOP_COUNT, 1),
            portHopSpread = intent.getIntExtra(EXTRA_PORT_HOP_SPREAD, 0)
        )
    }

    data class VpnConfig(
        val serverAddr: String,
        val seedHex: String,
        val generation: Long,
        val pskHex: String,
        val tunIp: String = "10.99.0.2",
        val transport: String = "udp",
        val splitTunnel: Boolean = true,
        val portHopCount: Int = 1,
        val portHopSpread: Int = 0
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
        private const val EXTRA_TRANSPORT = "extra_transport"
        private const val EXTRA_SPLIT_TUNNEL = "extra_split_tunnel"
        private const val EXTRA_PORT_HOP_COUNT = "extra_port_hop_count"
        private const val EXTRA_PORT_HOP_SPREAD = "extra_port_hop_spread"
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
                putExtra(EXTRA_TRANSPORT, config.transport)
                putExtra(EXTRA_SPLIT_TUNNEL, config.splitTunnel)
                putExtra(EXTRA_PORT_HOP_COUNT, config.portHopCount)
                putExtra(EXTRA_PORT_HOP_SPREAD, config.portHopSpread)
            }
            context.startForegroundService(intent)
        }

        /** 确定性停止：服务在跑时用 ACTION_DISCONNECT 显式触发 stopVpn+stopSelf。 */
        fun stop(context: Context) {
            val intent = Intent(context, ChimeraVpnService::class.java).setAction(ACTION_DISCONNECT)
            if (isRunning) {
                runCatching { context.startService(intent) }
                    .onSuccess { return }
            }
            context.stopService(intent)
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
