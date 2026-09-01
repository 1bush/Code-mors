package com.codemors.nativeapp;

import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.os.Build;
import android.os.Debug;
import java.io.BufferedReader;
import java.io.File;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;

/**
 * PRM — Pegasus Resistance Module, pjesa 1.
 * Scanner i integritetit të mjedisit: zbulon root, magisk, debug, ADB,
 * emulator, test-keys, app debuggable. Kthen risk-score (0..100) + flagje.
 *
 * Kufi i sinqertë: kjo zbulon MJEDISIN e komprometuar — nuk mund të mbrojë
 * nga një eksploatim që tashmë kontrollon OS-in. Qëllimi: refuzo veprimin
 * ose kërko fshirje në mjedis të dyshimtë, para se çelësat të ekspozohen.
 */
public final class PrmCheck {

    public static final class Result {
        public final int score;            // 0 = i pastër, 100 = komprometuar
        public final List<String> flags;
        public final boolean root, debuggable, emulator, tampered, adb;
        Result(int s, List<String> f, boolean r, boolean d, boolean e, boolean t, boolean a) {
            score=s; flags=f; root=r; debuggable=d; emulator=e; tampered=t; adb=a;
        }
    }

    private static final String[] SU_PATHS = {
        "/system/bin/su", "/system/xbin/su", "/sbin/su", "/system/su",
        "/system/bin/.ext/.su", "/system/usr/we-need-root/su",
        "/data/local/xbin/su", "/data/local/bin/su", "/data/local/su",
        "/su/bin/su", "/su/bin", "/sbin/.magisk", "/debug_ramdisk/su",
        "/system/app/Superuser.apk"
    };
    private static final String[] ROOT_APPS = {
        "com.topjohnwu.magisk", "com.koushikdutta.superuser",
        "com.noshufou.android.su", "com.thirdparty.superuser",
        "com.yellowes.su", "com.kingroot.kinguser", "com.kingo.root"
    };
    private static final String[] MAGISK_PATHS = {
        "/sbin/.magisk", "/cache/.disable_magisk", "/dev/.magisk.unblock",
        "/cache/magisk.log", "/data/adb/magisk", "/data/adb/magisk.img",
        "/data/adb/magisk.db"
    };

    public static Result scan(Context ctx) {
        List<String> flags = new ArrayList<>();
        boolean root = false, debuggable = false, emulator = false, tampered = false, adb = false;

        // 1. SU binary
        for (String p : SU_PATHS) if (exists(p)) { flags.add("ROOT_SU:"+p); root=true; break; }
        // `su -c id` probe
        try {
            Process pr = Runtime.getRuntime().exec(new String[]{"su","-c","id"});
            if (new BufferedReader(new InputStreamReader(pr.getInputStream())).readLine()!=null
                    && pr.waitFor()==0) { flags.add("ROOT_SU_EXEC"); root=true; }
        } catch (Exception ignored) {}

        // 2. Magisk
        for (String p : MAGISK_PATHS) if (exists(p)) { flags.add("MAGISK:"+p); root=true; }

        // 3. Root management apps
        for (String pkg : ROOT_APPS) {
            try { ctx.getPackageManager().getPackageInfo(pkg,0); flags.add("ROOT_APP:"+pkg); root=true; }
            catch (Exception ignored) {}
        }

        // 4. Build test-keys (custom ROM / i modifikuar)
        String tags = Build.TAGS;
        if (tags != null && tags.contains("test-keys")) { flags.add("TAMPERED:test-keys"); tampered=true; }

        // 5. App debuggable?
        if ((ctx.getApplicationInfo().flags & ApplicationInfo.FLAG_DEBUGGABLE) != 0) {
            flags.add("DEBUGGABLE_APP"); debuggable=true;
        }

        // 6. ADB enabled
        try {
            int adbEnabled = android.provider.Settings.Global.getInt(
                ctx.getContentResolver(), "adb_enabled", 0);
            if (adbEnabled==1) { flags.add("ADB_ON"); adb=true; }
        } catch (Exception ignored) {}

        // 7. Emulator / virtual device heuristics
        String fp = Build.FINGERPRINT + "|" + Build.MODEL + "|"
                 + Build.MANUFACTURER + "|" + Build.BRAND + "|" + Build.DEVICE + "|" + Build.PRODUCT;
        fp = fp.toLowerCase();
        boolean emuHints = fp.contains("generic")||fp.contains("unknown")||fp.contains("google_sdk")
                ||fp.contains("sdk")||fp.contains("emulator")||fp.contains("genymotion")
                ||fp.contains("andy")||fp.contains("x86")||fp.contains("vbox")
                ||Build.MODEL.toLowerCase().contains("sdk")
                ||Build.HARDWARE.toLowerCase().contains("goldfish")
                ||Build.HARDWARE.toLowerCase().contains("ranchu");
        if (emuHints) { flags.add("EMULATOR:"+Build.MODEL); emulator=true; }

        // 8. SELinux permissive (tregues i komprometimit)
        try {
            BufferedReader r = new BufferedReader(new InputStreamReader(
                new java.io.FileInputStream("/sys/fs/selinux/enforce")));
            String line = r.readLine();
            if ("0".equals(line!=null?line.trim():"")) { flags.add("SELINUX_PERMISSIVE"); tampered=true; }
            r.close();
        } catch (Exception ignored) {}

        int score = 0;
        if (root) score += 40;
        if (tampered) score += 20;
        if (debuggable) score += 25;
        if (adb) score += 10;
        if (emulator) score += 10;
        return new Result(Math.min(score,100), flags, root, debuggable, emulator, tampered, adb);
    }

    private static boolean exists(String path) { return new File(path).exists(); }
}