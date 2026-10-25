package ios.spyware.sweep

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.IBinder
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

/** Foreground service that collects + posts a snapshot on start. */
class SweepService : Service() {

    private val executor = Executors.newSingleThreadScheduledExecutor()

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        startForegroundCompat()
        val server = intent?.getStringExtra("server") ?: ""
        val token = intent?.getStringExtra("token") ?: ""
        val label = intent?.getStringExtra("label") ?: "android-device"

        if (server.isNotBlank()) {
            executor.schedule({
                val snap = Collector.snapshot(this)
                Collector.post(server, token, label, snap)
                stopSelf()
            }, 0, TimeUnit.SECONDS)
        }
        return START_NOT_STICKY
    }

    private fun startForegroundCompat() {
        val channelId = "sweep"
        val nm = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        nm.createNotificationChannel(
            NotificationChannel(channelId, "Pegasus sweep", NotificationManager.IMPORTANCE_LOW))
        val n = Notification.Builder(this, channelId)
            .setContentTitle("Pegasus-Sweep agent")
            .setContentText("Collecting device snapshot…")
            .setSmallIcon(android.R.drawable.ic_menu_view)
            .build()
        try {
            startForeground(1, n,
                ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC)
        } catch (e: Exception) {
            startForeground(1, n)
        }
    }
}