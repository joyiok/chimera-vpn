package com.chimera.vpn

import android.Manifest
import android.app.Activity
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Intent
import android.content.pm.PackageManager
import android.content.res.ColorStateList
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.os.SystemClock
import android.view.Gravity
import android.view.View
import android.widget.LinearLayout
import android.widget.TextView
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import androidx.core.content.getSystemService
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.repeatOnLifecycle
import com.google.android.material.button.MaterialButton
import com.google.android.material.materialswitch.MaterialSwitch
import com.google.android.material.textfield.TextInputEditText
import kotlinx.coroutines.launch

class MainActivity : AppCompatActivity() {

    private lateinit var inviteInput: TextInputEditText
    private lateinit var serverNameInput: TextInputEditText
    private lateinit var serverInput: TextInputEditText
    private lateinit var seedInput: TextInputEditText
    private lateinit var generationInput: TextInputEditText
    private lateinit var pskInput: TextInputEditText
    private lateinit var tunIpInput: TextInputEditText
    private lateinit var transportInput: TextInputEditText
    private lateinit var portHopCountInput: TextInputEditText
    private lateinit var portHopSpreadInput: TextInputEditText
    private lateinit var splitTunnelSwitch: MaterialSwitch
    private lateinit var connectButton: MaterialButton
    private lateinit var importButton: MaterialButton
    private lateinit var copyInviteButton: MaterialButton
    private lateinit var saveNodeButton: MaterialButton
    private lateinit var clearLogsButton: MaterialButton
    private lateinit var statusChip: LinearLayout
    private lateinit var statusDot: View
    private lateinit var statusText: TextView
    private lateinit var upTotalText: TextView
    private lateinit var upRateText: TextView
    private lateinit var downTotalText: TextView
    private lateinit var downRateText: TextView
    private lateinit var logText: TextView
    private lateinit var serverList: LinearLayout
    private lateinit var advancedPanel: View
    private lateinit var advancedToggle: TextView

    private var pendingConfig: ChimeraVpnService.VpnConfig? = null

    // Cumulative values from the previous traffic sample, used for rate display.
    private var lastTrafficSent = 0L
    private var lastTrafficRecv = 0L
    private var lastTrafficAt = 0L

    private val vpnPermissionLauncher =
        registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
            val config = pendingConfig
            pendingConfig = null
            if (result.resultCode == Activity.RESULT_OK && config != null) {
                ChimeraVpnService.start(this, config)
            } else {
                Toast.makeText(this, R.string.toast_vpn_denied, Toast.LENGTH_SHORT).show()
            }
        }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        inviteInput = findViewById(R.id.inviteInput)
        serverNameInput = findViewById(R.id.serverNameInput)
        serverInput = findViewById(R.id.serverInput)
        seedInput = findViewById(R.id.seedInput)
        generationInput = findViewById(R.id.generationInput)
        pskInput = findViewById(R.id.pskInput)
        tunIpInput = findViewById(R.id.tunIpInput)
        transportInput = findViewById(R.id.transportInput)
        portHopCountInput = findViewById(R.id.portHopCountInput)
        portHopSpreadInput = findViewById(R.id.portHopSpreadInput)
        splitTunnelSwitch = findViewById(R.id.splitTunnelSwitch)
        connectButton = findViewById(R.id.connectButton)
        importButton = findViewById(R.id.importButton)
        copyInviteButton = findViewById(R.id.copyInviteButton)
        saveNodeButton = findViewById(R.id.saveNodeButton)
        clearLogsButton = findViewById(R.id.clearLogsButton)
        statusChip = findViewById(R.id.statusChip)
        statusDot = findViewById(R.id.statusDot)
        statusText = findViewById(R.id.statusText)
        upTotalText = findViewById(R.id.upTotalText)
        upRateText = findViewById(R.id.upRateText)
        downTotalText = findViewById(R.id.downTotalText)
        downRateText = findViewById(R.id.downRateText)
        logText = findViewById(R.id.logText)
        serverList = findViewById(R.id.serverList)
        advancedPanel = findViewById(R.id.advancedPanel)
        advancedToggle = findViewById(R.id.advancedToggle)

        restoreForm()
        renderServers()
        renderStatus(ChimeraVpnService.status.value)

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
            checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED
        ) {
            requestPermissions(arrayOf(Manifest.permission.POST_NOTIFICATIONS), 0)
        }

        connectButton.setOnClickListener {
            val status = ChimeraVpnService.status.value
            val shouldStop = ChimeraVpnService.isRunning ||
                status == getString(R.string.status_connected) ||
                VpnState.classify(status) == ConnState.CONNECTING
            if (shouldStop) {
                ChimeraVpnService.stop(this)
            } else {
                connect()
            }
        }
        importButton.setOnClickListener {
            importInvite(inviteInput.text?.toString().orEmpty())
        }
        copyInviteButton.setOnClickListener { copyInvite() }
        advancedToggle.setOnClickListener {
            toggleAdvanced(advancedPanel.visibility != View.VISIBLE)
        }
        saveNodeButton.setOnClickListener {
            val addr = serverInput.text?.toString()?.trim().orEmpty()
            if (addr.isEmpty()) {
                Toast.makeText(this, R.string.toast_server_empty, Toast.LENGTH_SHORT).show()
                return@setOnClickListener
            }
            val name = serverNameInput.text?.toString()?.trim().orEmpty()
            ClientPrefs.saveServer(this, name, addr)
            renderServers()
        }
        clearLogsButton.setOnClickListener {
            logText.text = getString(R.string.log_empty)
        }

        lifecycleScope.launch {
            repeatOnLifecycle(Lifecycle.State.STARTED) {
                launch {
                    ChimeraVpnService.status.collect { status ->
                        renderStatus(status)
                    }
                }
                launch {
                    ChimeraVpnService.logLines.collect { lines ->
                        logText.text = lines.joinToString("\n").ifBlank { getString(R.string.log_empty) }
                    }
                }
                launch {
                    ChimeraVpnService.traffic.collect { snap ->
                        renderTraffic(snap.sent, snap.recv)
                    }
                }
            }
        }

        consumeInviteIntent(intent)
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        consumeInviteIntent(intent)
    }

    private fun consumeInviteIntent(intent: Intent?) {
        if (intent == null) return
        val raw = when (intent.action) {
            Intent.ACTION_VIEW -> intent.dataString
            Intent.ACTION_SEND -> intent.getStringExtra(Intent.EXTRA_TEXT)
            else -> null
        } ?: return
        inviteInput.setText(raw)
        importInvite(raw)
    }

    private fun importInvite(raw: String) {
        val invite = try {
            Invites.parse(raw)
        } catch (_: Exception) {
            Toast.makeText(this, R.string.toast_invite_bad, Toast.LENGTH_SHORT).show()
            return
        }
        applyInvite(invite)
        inviteInput.setText(raw)
        Toast.makeText(this, getString(R.string.toast_imported, invite.addr), Toast.LENGTH_SHORT).show()
    }

    private fun applyInvite(invite: Invite) {
        serverInput.setText(invite.addr)
        serverNameInput.setText(invite.name)
        seedInput.setText(invite.seedHex)
        pskInput.setText(invite.pskHex)
        generationInput.setText(invite.generation.toString())
        val tun = tunIpInput.text?.toString()?.trim().orEmpty().ifBlank { "10.99.0.2" }
        ClientPrefs.save(
            this,
            ChimeraVpnService.VpnConfig(
                serverAddr = invite.addr,
                seedHex = invite.seedHex,
                generation = invite.generation,
                pskHex = invite.pskHex,
                tunIp = tun,
                transport = transportInput.text?.toString()?.trim().orEmpty().ifBlank { "udp" },
                splitTunnel = splitTunnelSwitch.isChecked,
                portHopCount = portHopCountInput.text?.toString()?.trim()?.toIntOrNull() ?: 1,
                portHopSpread = portHopSpreadInput.text?.toString()?.trim()?.toIntOrNull() ?: 0
            )
        )
        if (invite.name.isNotEmpty()) {
            ClientPrefs.saveServer(this, invite.name, invite.addr)
        }
        renderServers()
    }

    private fun copyInvite() {
        val name = serverNameInput.text?.toString()?.trim().orEmpty()
        val server = serverInput.text?.toString()?.trim().orEmpty()
        val seed = seedInput.text?.toString()?.trim().orEmpty()
        val psk = pskInput.text?.toString()?.trim().orEmpty()
        val generation = generationInput.text?.toString()?.trim()?.toLongOrNull() ?: 0L
        if (server.isEmpty() || seed.isEmpty() || psk.isEmpty()) {
            Toast.makeText(this, R.string.toast_copy_need_fields, Toast.LENGTH_SHORT).show()
            return
        }
        val link = try {
            Invites.format(Invite(server, seed, psk, generation, name))
        } catch (_: Exception) {
            Toast.makeText(this, R.string.toast_invite_bad, Toast.LENGTH_SHORT).show()
            return
        }
        val clip = getSystemService<ClipboardManager>()
        clip?.setPrimaryClip(ClipData.newPlainText("chimera invite", link))
        Toast.makeText(this, R.string.toast_copied, Toast.LENGTH_SHORT).show()
    }

    private fun connect() {
        val server = serverInput.text?.toString()?.trim().orEmpty()
        val seed = seedInput.text?.toString()?.trim().orEmpty()
        val generationText = generationInput.text?.toString()?.trim().orEmpty()
        val psk = pskInput.text?.toString()?.trim().orEmpty()
        val tunIp = tunIpInput.text?.toString()?.trim().orEmpty().ifBlank { "10.99.0.2" }
        val transport = transportInput.text?.toString()?.trim().orEmpty().ifBlank { "udp" }
        val hopCount = portHopCountInput.text?.toString()?.trim()?.toIntOrNull() ?: 1
        val hopSpread = portHopSpreadInput.text?.toString()?.trim()?.toIntOrNull() ?: 0

        if (server.isEmpty() || seed.isEmpty() || psk.isEmpty() || generationText.isEmpty()) {
            Toast.makeText(this, R.string.toast_fill_all, Toast.LENGTH_SHORT).show()
            return
        }
        if (!isHex64(seed) || !isHex64(psk)) {
            Toast.makeText(this, R.string.toast_hex_invalid, Toast.LENGTH_SHORT).show()
            return
        }

        val generation = generationText.toLongOrNull()
        if (generation == null) {
            Toast.makeText(this, R.string.toast_generation_invalid, Toast.LENGTH_SHORT).show()
            return
        }

        val config = ChimeraVpnService.VpnConfig(
            serverAddr = server,
            seedHex = seed,
            generation = generation,
            pskHex = psk,
            tunIp = tunIp,
            transport = transport,
            splitTunnel = splitTunnelSwitch.isChecked,
            portHopCount = hopCount,
            portHopSpread = if (hopCount > 1 && hopSpread <= 0) 2048 else hopSpread
        )
        ClientPrefs.save(this, config)

        val prepareIntent = VpnService.prepare(this)
        if (prepareIntent != null) {
            pendingConfig = config
            vpnPermissionLauncher.launch(prepareIntent)
        } else {
            ChimeraVpnService.start(this, config)
        }
    }

    private fun isHex64(value: String): Boolean =
        value.length == 64 && value.all { it in '0'..'9' || it in 'a'..'f' || it in 'A'..'F' }

    private fun restoreForm() {
        val config = ClientPrefs.load(this)
        if (config != null) {
            serverInput.setText(config.serverAddr)
            seedInput.setText(config.seedHex)
            generationInput.setText(config.generation.toString())
            pskInput.setText(config.pskHex)
            tunIpInput.setText(config.tunIp)
            transportInput.setText(config.transport)
            splitTunnelSwitch.isChecked = config.splitTunnel
            portHopCountInput.setText(config.portHopCount.toString())
            portHopSpreadInput.setText(config.portHopSpread.toString())
            serverNameInput.setText(
                ClientPrefs.servers(this)
                    .firstOrNull { it.second.equals(config.serverAddr, ignoreCase = true) }
                    ?.first.orEmpty()
            )
            return
        }
        val p = getSharedPreferences(ClientPrefs.PREF, MODE_PRIVATE)
        serverInput.setText(p.getString(ClientPrefs.SERVER, ""))
        seedInput.setText(p.getString(ClientPrefs.SEED, ""))
        generationInput.setText(p.getString(ClientPrefs.GENERATION, "0"))
        pskInput.setText(p.getString(ClientPrefs.PSK, ""))
        tunIpInput.setText(p.getString(ClientPrefs.TUN_IP, "10.99.0.2"))
        transportInput.setText(p.getString(ClientPrefs.TRANSPORT, "udp"))
        splitTunnelSwitch.isChecked = p.getBoolean(ClientPrefs.SPLIT_TUNNEL, true)
        portHopCountInput.setText(p.getInt(ClientPrefs.PORT_HOP_COUNT, 1).toString())
        portHopSpreadInput.setText(p.getInt(ClientPrefs.PORT_HOP_SPREAD, 0).toString())
    }

    private fun toggleAdvanced(show: Boolean) {
        advancedPanel.visibility = if (show) View.VISIBLE else View.GONE
        advancedToggle.text = getString(if (show) R.string.advanced_open else R.string.advanced_closed)
    }

    private fun renderServers() {
        serverList.removeAllViews()
        val servers = ClientPrefs.servers(this)
        if (servers.isEmpty()) {
            serverList.addView(
                TextView(this).apply {
                    text = getString(R.string.nodes_empty)
                    setTextColor(color(R.color.muted))
                    textSize = 12f
                    gravity = Gravity.CENTER
                    setPadding(0, dp(10), 0, dp(10))
                }
            )
            return
        }

        val currentAddr = serverInput.text?.toString()?.trim().orEmpty()
        for ((name, addr) in servers) {
            val active = currentAddr.equals(addr, ignoreCase = true)
            val row = LinearLayout(this).apply {
                orientation = LinearLayout.HORIZONTAL
                gravity = Gravity.CENTER_VERTICAL
                layoutParams = LinearLayout.LayoutParams(
                    LinearLayout.LayoutParams.MATCH_PARENT,
                    LinearLayout.LayoutParams.WRAP_CONTENT
                ).apply { bottomMargin = dp(8) }
            }

            val pick = MaterialButton(
                this@MainActivity,
                null,
                com.google.android.material.R.attr.materialButtonOutlinedStyle
            ).apply {
                text = "$name\n$addr"
                isAllCaps = false
                textSize = 12f
                gravity = Gravity.START or Gravity.CENTER_VERTICAL
                minHeight = dp(52)
                setPadding(dp(12), dp(6), dp(12), dp(6))
                layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
                strokeColor = ColorStateList.valueOf(color(if (active) R.color.accent else R.color.line))
                setTextColor(color(if (active) R.color.accent else R.color.ink))
                contentDescription = "$name $addr"
                setOnClickListener {
                    serverInput.setText(addr)
                    serverNameInput.setText(name)
                    renderServers()
                }
            }

            val del = MaterialButton(
                this@MainActivity,
                null,
                com.google.android.material.R.attr.materialButtonOutlinedStyle
            ).apply {
                text = getString(R.string.delete_node)
                isAllCaps = false
                textSize = 12f
                minWidth = dp(64)
                minHeight = dp(52)
                layoutParams = LinearLayout.LayoutParams(
                    LinearLayout.LayoutParams.WRAP_CONTENT,
                    LinearLayout.LayoutParams.WRAP_CONTENT
                ).apply { marginStart = dp(8) }
                strokeColor = ColorStateList.valueOf(color(R.color.line))
                setTextColor(color(R.color.muted))
                setOnClickListener {
                    ClientPrefs.removeServer(this@MainActivity, addr)
                    renderServers()
                }
            }

            row.addView(pick)
            row.addView(del)
            serverList.addView(row)
        }
    }

    private fun renderStatus(status: String) {
        statusText.text = status

        // Centralized classification (VpnState): one set of keyword rules
        // shared by the service, this activity, and the unit tests.
        val state = VpnState.classify(status)
        val connected = state == ConnState.CONNECTED
        val connecting = state == ConnState.CONNECTING
        val failed = state == ConnState.FAILED

        val chipColor: Int
        val dotColor: Int
        val textColor: Int
        val buttonColor: Int
        val buttonTextColor: Int
        when {
            connected -> {
                chipColor = color(R.color.ok_ink)
                dotColor = color(R.color.ok)
                textColor = color(R.color.ok)
                buttonColor = color(R.color.ok)
                buttonTextColor = color(R.color.ok_ink)
            }
            connecting -> {
                chipColor = color(R.color.warn_ink)
                dotColor = color(R.color.warn)
                textColor = color(R.color.warn)
                buttonColor = color(R.color.warn)
                buttonTextColor = color(R.color.warn_ink)
            }
            failed -> {
                chipColor = color(R.color.bad_ink)
                dotColor = color(R.color.bad)
                textColor = color(R.color.bad)
                buttonColor = color(R.color.accent)
                buttonTextColor = color(R.color.accent_ink)
            }
            else -> {
                chipColor = color(R.color.surface_hi)
                dotColor = color(R.color.muted)
                textColor = color(R.color.muted)
                buttonColor = color(R.color.accent)
                buttonTextColor = color(R.color.accent_ink)
            }
        }

        statusChip.backgroundTintList = ColorStateList.valueOf(chipColor)
        statusDot.backgroundTintList = ColorStateList.valueOf(dotColor)
        statusText.setTextColor(textColor)
        connectButton.isEnabled = !connecting
        connectButton.backgroundTintList = ColorStateList.valueOf(buttonColor)
        connectButton.setTextColor(buttonTextColor)
        connectButton.text = when {
            connected -> getString(R.string.disconnect)
            connecting -> getString(R.string.connecting)
            failed -> getString(R.string.retry)
            else -> getString(R.string.connect)
        }
    }

    private fun renderTraffic(sent: Long, recv: Long) {
        val now = SystemClock.elapsedRealtime()
        val dtMillis = if (lastTrafficAt == 0L) 0L else (now - lastTrafficAt).coerceAtLeast(200L)
        val upRate = if (dtMillis > 0L) {
            ((sent - lastTrafficSent).coerceAtLeast(0L)) * 1000L / dtMillis
        } else 0L
        val downRate = if (dtMillis > 0L) {
            ((recv - lastTrafficRecv).coerceAtLeast(0L)) * 1000L / dtMillis
        } else 0L
        lastTrafficSent = sent
        lastTrafficRecv = recv
        lastTrafficAt = now

        upTotalText.text = ChimeraVpnService.formatBytes(sent)
        upRateText.text = getString(R.string.traffic_rate, ChimeraVpnService.formatBytes(upRate))
        downTotalText.text = ChimeraVpnService.formatBytes(recv)
        downRateText.text = getString(R.string.traffic_rate, ChimeraVpnService.formatBytes(downRate))
    }

    private fun color(id: Int): Int = ContextCompat.getColor(this, id)

    private fun dp(value: Int): Int =
        (value * resources.displayMetrics.density).toInt().coerceAtLeast(1)
}
