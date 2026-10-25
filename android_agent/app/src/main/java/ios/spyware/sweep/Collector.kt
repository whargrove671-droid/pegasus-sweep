# Pegasus-Sweep Android agent — main service
# Collects programmatically-visible surveillance-artifact signals and posts a
# snapshot to the dashboard /api/ingest endpoint.

package ios.spyware.sweep

import android.accessibilityservice.AccessibilityServiceInfo
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.provider.Settings
import android.view.accessibility.AccessibilityManager
import org.json.JSONArray
import org.json.JSONObject
import java.io.BufferedReader
import java.io.InputStreamReader
import java.net.HttpURLConnection
import java.net.URL

/** Builds the on-device JSON snapshot. */
object Collector {

    fun snapshot(ctx: Context): JSONObject {
        val out = JSONObject()
        out.put("os", "Android " + (Build.VERSION.RELEASE ?: "?"))
        out.put("device", Build.MANUFACTURER + " " + Build.MODEL)
        out.put("packages", packages(ctx))
        out.put("services_abusing", enabledAccessibility(ctx))
        out.put("processes", visibleProcesses(ctx))
        out.put("artifacts", JSONArray())   // device-owner can append {path,content}
        return out
    }

    /** Installed packages + privilege flags that matter for spyware. */
    private fun packages(ctx: Context): JSONArray {
        val arr = JSONArray()
        val pm = ctx.packageManager
        val dpm = ctx.getSystemService(android.app.admin.DevicePolicyManager::class.java)
        try {
            val apps = pm.getInstalledApplications(
                PackageManager.GET_META_DATA or PackageManager.GET_PERMISSIONS)
            for (a in apps) {
                val o = JSONObject()
                o.put("name", a.packageName)
                o.put("label", pm.getApplicationLabel(a).toString())
                o.put("flags", a.flags)
                // App can see whether IT is a device owner/admin; whether another
                // app is, is not publicly enumerable on modern Android.
                o.put("is_device_owner", dpm?.let { it.isDeviceOwnerApp(a.packageName) } ?: false)
                o.put("has_accessibility", enabledAccessibilityClass(ctx,
                    a.packageName + ".*"))
                o.put("can_overlay", Settings.canDrawOverlays(ctx))
                arr.put(o)
            }
        } catch (e: Exception) { /* app list can be restricted on some OEMs */ }
        return arr
    }

    /** AccessibilityService classes currently enabled by the user. */
    private fun enabledAccessibility(ctx: Context): JSONArray {
        val arr = JSONArray()
        try {
            val am = ctx.getSystemService(Context.ACCESSIBILITY_SERVICE) as AccessibilityManager
            val enabled = am.getEnabledAccessibilityServiceList(
                AccessibilityServiceInfo.FEEDBACK_ALL_MASK)
            for (svc in enabled) {
                val o = JSONObject()
                o.put("id", svc.id)
                o.put("class", svc.resolveInfo?.serviceInfo?.name ?: svc.id)
                o.put("pkg", svc.resolveInfo?.serviceInfo?.packageName ?: "")
                o.put("flags", svc.flags)
                arr.put(o)
            }
        } catch (e: Exception) { }
        return arr
    }

    private fun enabledAccessibilityClass(ctx: Context, pkgPattern: String): Boolean {
        val am = ctx.getSystemService(Context.ACCESSIBILITY_SERVICE) as AccessibilityManager
        return am.getEnabledAccessibilityServiceList(
            AccessibilityServiceInfo.FEEDBACK_ALL_MASK)
            .any { it.id.contains(pkgPattern) }
    }

    /** Best-effort process names. Usually sparse on Android 10+; never fatal. */
    private fun visibleProcesses(ctx: Context): JSONArray {
        val arr = JSONArray()
        try {
            val proc = Runtime.getRuntime().exec("ps -A")
            proc.inputStream.bufferedReader().useLines { lines ->
                lines.forEach { line ->
                    val parts = line.trim().split(Regex("\\s+"))
                    if (parts.size >= 4) {
                        val o = JSONObject()
                        o.put("name", parts.last())
                        o.put("cmdline", line)
                        arr.put(o)
                    }
                }
            }
        } catch (e: Exception) { }
        return arr
    }

    fun post(server: String, token: String, label: String, snapshot: JSONObject): Int {
        val body = JSONObject()
            .put("target", "android")
            .put("source_label", label)
            .put("snapshot", snapshot)
            .toString()
        val conn = URL(server.trimEnd('/') + "/api/ingest").openConnection()
                as HttpURLConnection
        return try {
            conn.requestMethod = "POST"
            conn.doOutput = true
            conn.setRequestProperty("Content-Type", "application/json")
            conn.setRequestProperty("X-Api-Key", token)
            conn.setRequestProperty("User-Agent", "pegasus-sweep-android-agent/0.1")
            conn.outputStream.use { it.write(body.toByteArray(Charsets.UTF_8)) }
            val code = conn.responseCode
            conn.inputStream.bufferedReader().use { BufferedReader(it).readText() }
            code
        } catch (e: Exception) {
            -1
        } finally {
            conn.disconnect()
        }
    }
}