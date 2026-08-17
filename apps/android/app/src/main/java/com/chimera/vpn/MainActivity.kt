package com.chimera.vpn

import android.Manifest
import android.app.Activity
import android.content.pm.PackageManager
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.widget.LinearLayout
import android.widget.TextView
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.repeatOnLifecycle
import com.google.android.material.button.MaterialButton
import com.google.android.material.textfield.TextInputEditText
import kotlinx.coroutines.launch

class MainActivity : AppCompatActivity() {

    private lateinit var serverInput: TextInputEditText
    private lateinit var seedInput: TextInputEditText
    private lateinit var generationInput: TextInputEditText
    private lateinit var pskInput: TextInputEditText
    private lateinit var tunIpInput: TextInputEditText
    private lateinit var connectButton: MaterialButton
    private lateinit var saveNodeButton: MaterialButton
    private lateinit var statusText: TextView
    private lateinit var trafficText: TextView
    private lateinit var logText: TextView
    private lateinit var serverList: LinearLayout

    private var pendingConfig: ChimeraVpnService.VpnConfig? = null

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

        serverInput = findViewById(R.id.serverInput)
        seedInput = findViewById(R.id.seedInput)
        generationInput = findViewById(R.id.generationInput)
        pskInput = findViewById(R.id.pskInput)
        tunIpInput = findViewById(R.id.tunIpInput)
        connectButton = findViewById(R.id.connectButton)
        saveNodeButton = findViewById(R.id.saveNodeButton)
        statusText = findViewById(R.id.statusText)
        trafficText = findViewById(R.id.trafficText)
        logText = findViewById(R.id.logText)
        serverList = findViewById(R.id.serverList)
        restoreForm()
        renderServers()

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
            checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED
        ) {
            requestPermissions(arrayOf(Manifest.permission.POST_NOTIFICATIONS), 0)
        }

        connectButton.setOnClickListener {
            if (ChimeraVpnService.isRunning) {
                ChimeraVpnService.stop(this)
            } else {
                connect()
            }
        }
        saveNodeButton.setOnClickListener {
            val addr = serverInput.text?.toString()?.trim().orEmpty()
            if (addr.isEmpty()) {
                Toast.makeText(this, R.string.toast_fill_all, Toast.LENGTH_SHORT).show()
                return@setOnClickListener
            }
            ClientPrefs.saveServer(this, addr, addr)
            renderServers()
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
                        logText.text = lines.joinToString("\n")
                    }
                }
                launch {
                    ChimeraVpnService.traffic.collect { snap ->
                        trafficText.text = "↑ ${ChimeraVpnService.formatBytes(snap.sent)}    ↓ ${ChimeraVpnService.formatBytes(snap.recv)}"
                    }
                }
            }
        }
    }

    private fun connect() {
        val server = serverInput.text?.toString()?.trim().orEmpty()
        val seed = seedInput.text?.toString()?.trim().orEmpty()
        val generationText = generationInput.text?.toString()?.trim().orEmpty()
        val psk = pskInput.text?.toString()?.trim().orEmpty()
        val tunIp = tunIpInput.text?.toString()?.trim().orEmpty().ifBlank { "10.99.0.2" }

        if (server.isEmpty() || seed.isEmpty() || psk.isEmpty() || generationText.isEmpty()) {
            Toast.makeText(this, R.string.toast_fill_all, Toast.LENGTH_SHORT).show()
            return
        }
        if (seed.length != 64 || psk.length != 64) {
            Toast.makeText(this, "seed 和 PSK 都必须是 64 位十六进制", Toast.LENGTH_SHORT).show()
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
            tunIp = tunIp
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

    private fun restoreForm() {
        val config = ClientPrefs.load(this)
        if (config != null) {
            serverInput.setText(config.serverAddr)
            seedInput.setText(config.seedHex)
            generationInput.setText(config.generation.toString())
            pskInput.setText(config.pskHex)
            tunIpInput.setText(config.tunIp)
            return
        }
        val p = getSharedPreferences(ClientPrefs.PREF, MODE_PRIVATE)
        serverInput.setText(p.getString(ClientPrefs.SERVER, ""))
        seedInput.setText(p.getString(ClientPrefs.SEED, ""))
        generationInput.setText(p.getString(ClientPrefs.GENERATION, "0"))
        pskInput.setText(p.getString(ClientPrefs.PSK, ""))
        tunIpInput.setText(p.getString(ClientPrefs.TUN_IP, "10.99.0.2"))
    }

    private fun renderServers() {
        serverList.removeAllViews()
        for ((name, addr) in ClientPrefs.servers(this)) {
            val row = LinearLayout(this).apply {
                orientation = LinearLayout.HORIZONTAL
            }
            val pick = MaterialButton(this, null, com.google.android.material.R.attr.materialButtonOutlinedStyle).apply {
                text = "$name\n$addr"
                layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
                setOnClickListener { serverInput.setText(addr) }
            }
            val del = MaterialButton(this, null, com.google.android.material.R.attr.materialButtonOutlinedStyle).apply {
                text = "删除"
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
        connectButton.text = if (status == getString(R.string.status_connected)) {
            getString(R.string.disconnect)
        } else {
            getString(R.string.connect)
        }
    }
}
