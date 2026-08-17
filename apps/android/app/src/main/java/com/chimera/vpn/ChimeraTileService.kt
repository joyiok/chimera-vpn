package com.chimera.vpn

import android.app.PendingIntent
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.service.quicksettings.Tile
import android.service.quicksettings.TileService

class ChimeraTileService : TileService() {

    override fun onStartListening() {
        val tile = qsTile ?: return
        tile.state = if (ChimeraVpnService.isRunning) Tile.STATE_ACTIVE else Tile.STATE_INACTIVE
        tile.label = getString(R.string.app_name)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            tile.subtitle = if (ChimeraVpnService.isRunning) {
                getString(R.string.status_connected)
            } else {
                getString(R.string.status_disconnected)
            }
        }
        tile.updateTile()
    }

    override fun onClick() {
        if (ChimeraVpnService.isRunning) {
            ChimeraVpnService.stop(this)
            onStartListening()
            return
        }
        val config = ClientPrefs.load(this) ?: return
        val prepare = VpnService.prepare(this)
        if (prepare != null) {
            val pi = PendingIntent.getActivity(
                this,
                0,
                prepare,
                PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
            )
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
                startActivityAndCollapse(pi)
            } else {
                @Suppress("DEPRECATION")
                startActivityAndCollapse(prepare)
            }
            return
        }
        ChimeraVpnService.start(this, config)
        onStartListening()
    }
}
