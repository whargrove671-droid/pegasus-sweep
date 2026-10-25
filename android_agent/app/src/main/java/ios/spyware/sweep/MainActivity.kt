package ios.spyware.sweep

import android.app.Activity
import android.content.Intent
import android.os.Bundle
import android.provider.Settings
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.TextView

/** Minimal launcher to set server/token and start collection. */
class MainActivity : Activity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val col = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
        val title = TextView(this).apply {
            text = "Pegasus-Sweep agent"; textSize = 20f; setPadding(16, 24, 16, 8)
        }
        val url = EditText(this).apply { setSingleLine(true); hint = "server URL (http://127.0.0.1:8097)" }
        val tok = EditText(this).apply { setSingleLine(true); hint = "API token (PSM_SWEEP_TOKEN)" }
        val btn = Button(this).apply { text = "Collect & send" }
        val usage = Button(this).apply { text = "Grant Usage Access (required)" }

        btn.setOnClickListener {
            val s = url.text.toString().trim()
            val t = tok.text.toString().trim()
            if (s.isEmpty() || t.isEmpty()) return@setOnClickListener
            val i = Intent(this, SweepService::class.java)
                .putExtra("server", s).putExtra("token", t).putExtra("label", "android-" + java.util.UUID.randomUUID().toString().take(6))
            this.startForegroundService(i)
        }
        usage.setOnClickListener {
            startActivity(Intent(Settings.ACTION_USAGE_ACCESS_SETTINGS))
        }
        col.addView(title); col.addView(url); col.addView(tok); col.addView(btn)
        col.addView(usage)
        setContentView(col)
    }
}