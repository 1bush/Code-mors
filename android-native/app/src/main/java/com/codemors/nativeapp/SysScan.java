package com.codemors.nativeapp;

import android.app.admin.DevicePolicyManager;
import android.content.ComponentName;
import android.content.Context;
import android.os.Build;
import android.provider.Settings;
import java.io.File;
import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.InputStreamReader;
import java.util.List;

/**
 * SysScan (pjesë e CodeMors AntiSpy) — kontrolli i sistemit: root, Magisk,
 * device-admin, ADB, mock-location, SELinux permissive, test-keys.
 */
public final class SysScan {

    private static final String[] SU_PATHS = {
        "/system/bin/su", "/system/xbin/su", "/sbin/su", "/su/bin/su",
        "/data/local/xbin/su", "/data/local/bin/su", "/sbin/.magisk",
        "/data/adb/magisk", "/cache/.disable_magisk", "/debug_ramdisk/su"
    };

    public static void scan(Context ctx, AntiSpyScan.Report rep) {
        // 1. Root / Magisk binaries
        for (String p : SU_PATHS) if (new File(p).exists()) {
            rep.findings.add(new AntiSpyScan.Finding(AntiSpyScan.LEVEL_HIGH,
                    "ROOT i zbuluar",
                    "File: " + p + " — me root, çdo spyware ka akses të plotë në pajisje."));
            rep.score += 40;
        }

        // 2. ROM i modifikuar (test-keys)
        String tags = Build.TAGS;
        if (tags != null && tags.contains("test-keys")) {
            rep.findings.add(new AntiSpyScan.Finding(AntiSpyScan.LEVEL_MED,
                    "ROM i modifikuar (test-keys)", Build.TAGS));
            rep.score += 15;
        }

        // 3. SELinux permissive
        try {
            BufferedReader r = new BufferedReader(
                    new InputStreamReader(new FileInputStream("/sys/fs/selinux/enforce")));
            String line = r.readLine();
            if ("0".equals(line != null ? line.trim() : "")) {
                rep.findings.add(new AntiSpyScan.Finding(AntiSpyScan.LEVEL_MED,
                        "SELinux permissive", "Shenjë komprometimi ose ROM i modifikuar."));
                rep.score += 15;
            }
            r.close();
        } catch (Exception ignored) {}

        // 4. Device Admin aktiv (jo-sistem)
        try {
            DevicePolicyManager dpm = (DevicePolicyManager)
                    ctx.getSystemService(Context.DEVICE_POLICY_SERVICE);
            List<ComponentName> admins = dpm.getActiveAdmins();
            if (admins != null) for (ComponentName cn : admins) {
                String pkg = cn.getPackageName();
                if (!SpyDatabase.isSystemPackage(pkg) && !pkg.startsWith("com.google.")) {
                    rep.findings.add(new AntiSpyScan.Finding(AntiSpyScan.LEVEL_HIGH,
                            "Device Admin aktiv: " + pkg,
                            "Nuk fshihet lehtë — teknikë klasike stalkerware."));
                    rep.score += 35;
                }
            }
        } catch (Exception ignored) {}

        // 5. ADB
        try {
            int adb = Settings.Global.getInt(ctx.getContentResolver(), "adb_enabled", 0);
            if (adb == 1) {
                rep.findings.add(new AntiSpyScan.Finding(AntiSpyScan.LEVEL_LOW,
                        "USB Debugging aktiv",
                        "Nëse s'je dev: Settings → Developer options → USB debugging OFF."));
                rep.score += 5;
            }
        } catch (Exception ignored) {}

        // 6. Mock location
        try {
            String mock = Settings.Secure.getString(ctx.getContentResolver(),
                    Settings.Secure.ALLOW_MOCK_LOCATION);
            if ("1".equals(mock)) {
                rep.findings.add(new AntiSpyScan.Finding(AntiSpyScan.LEVEL_MED,
                        "Mock Location aktiv", "Stalkerware mund ta përdorë për të falsifikuar GPS."));
                rep.score += 12;
            }
        } catch (Exception ignored) {}
    }
}
