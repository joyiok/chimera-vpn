package com.chimera.vpn

import android.Manifest
import android.app.Activity
import android.content.pm.PackageManager
import android.net.VpnService
import android.os.Build
import android.os.Bundle
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
    private lateinit var statusText: android.widget.TextView
    private lateinit var logText: android.widget.TextView

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
        statusText = findViewById(R.id.statusText)
        logText = findViewById(R.id.logText)
        restoreForm()

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
        saveForm(config)

        val prepareIntent = VpnService.prepare(this)
        if (prepareIntent != null) {
            pendingConfig = config
            vpnPermissionLauncher.launch(prepareIntent)
        } else {
            ChimeraVpnService.start(this, config)
        }
    }

    private fun prefs() = getSharedPreferences("chimera_client", MODE_PRIVATE)

    private fun restoreForm() {
        val p = prefs()
        serverInput.setText(p.getString(PREF_SERVER, ""))
        seedInput.setText(p.getString(PREF_SEED, ""))
        generationInput.setText(p.getString(PREF_GENERATION, "0"))
        pskInput.setText(p.getString(PREF_PSK, ""))
        tunIpInput.setText(p.getString(PREF_TUN_IP, "10.99.0.2"))
    }

    private fun saveForm(config: ChimeraVpnService.VpnConfig) {
        prefs().edit()
            .putString(PREF_SERVER, config.serverAddr)
            .putString(PREF_SEED, config.seedHex)
            .putString(PREF_GENERATION, config.generation.toString())
            .putString(PREF_PSK, config.pskHex)
            .putString(PREF_TUN_IP, config.tunIp)
            .apply()
    }

    private fun renderStatus(status: String) {
        statusText.text = status
        connectButton.text = if (status == getString(R.string.status_connected)) {
            getString(R.string.disconnect)
        } else {
            getString(R.string.connect)
        }
    }

    companion object {
        private const val PREF_SERVER = "server"
        private const val PREF_SEED = "seed"
        private const val PREF_GENERATION = "generation"
        private const val PREF_PSK = "psk"
        private const val PREF_TUN_IP = "tun_ip"
    }
}
