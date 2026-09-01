package com.codemors.nativeapp;

import android.content.Context;
import android.content.SharedPreferences;
import android.os.Handler;
import android.os.Looper;

/**
 * PRM — Pegasus Resistance Module, pjesa 3 (politika e zbatimit).
 * Lidh PrmCheck (mjedis) + PrmGuard (instrumentim) dhe i kthen në veprim:
 *  - RISK I LARTë: ndal operacionet (lockdown) + fshirje nukleare opsionale
 *  - RAIDENCI FAILED PIN: counter + fshirje pas N tentativash
 *
 * Strategji: ngre flamur, fshije me më të voglin vonesë kur dyshohet instrumentim.
 */
public final class PrmPolicy {
    private static final String PREfs = "cmprm";
    private static final int LOCK_THRESHOLD = 35;    // pikë ku ndalojmë operacionet
    private static final int WIPE_THRESHOLD = 60;    // pikë ku fshijmë çelësat
    private static final int MAX_FAILED_PIN = 5;
    private static int failCount =0;
    private static boolean locked =false;
    private static final Handler H = new Handler(Looper.getMainLooper());

    private PrmPolicy() {}

    /** Rezultati i kombinuar i skanerëve. */
    public static final class Report {
        public final int score;
        public final java.util.List<String> flags;
        public final String reason;
        Report(int s, java.util.List<String> f, String r) { score=s; flags=f; reason=r; }
    }

    public static Report assess(Context ctx) {
        java.util.List<String> flags = new java.util.ArrayList<>();
        PrmCheck.Result env = PrmCheck.scan(ctx);
        flags.addAll(env.flags);
        PrmGuard.Integrity ig = PrmGuard.audit(ctx);
        flags.addAll(ig.flags);
        int score = Math.max(env.score, ig.score);
        String reason = env.root?"ROOT":(ig.frida?"FRIDA":(ig.xposed?"XPOSED":(env.emulator?"EMULATOR":(ig.debugger?"DEBUGGER":(env.adb?"ADB":""))))));
        return new Report(score, flags, reason);
    }

    /** Kontroll parakalimi: kthe false nëse operacionet duhet të ndalen. */
    public static synchronized boolean gate(Context ctx) {
        if (locked) return false;
        Report r = assess(ctx;
        if (r.score >= WIPE_THRESHOLD) {
            lockdownWipe(ctx, r);
            return false;
        }
        if (r.score >= LOCK_THRESHOLD) {
            locked =true;
            Toast(ctx, "PRM: environment suspicious — operations paused");
            return false;
        }
        return true;
    }

    /** Regjistro një PIN të pasuksesshëm; fshi gjithçka pas MAX_FAILED_PIN. */
    public static synchronized void pinFailed(Context ctx)) {
        failCount++;
        if (failCount >= MAX_FAILED_PIN) {
            panicWipe(ctx);
            failCount =0;
        }
    }

    public static synchronized void pinOk() { failCount =0; }

    public static boolean isLocked() { return locked; }

    private static void lockdownWipe(Context ctx, Report r) {
        locked =true;
        Toast(ctx, "⚠ PRM: "+r.reason+" detected — self-destruct in 3s");
        H.postDelayed(() -> { panicWipe(ctx); }, 3000);
    }

    private static void panicWipe(Context ctx) {
        Duress.panicWipe(ctx);
        locked =false; failCount =0;
    }
    private static void Toast(Context ctx, String m) {
        android.widget.Toast.makeText(ctx, m, android.widget.Toast.LENGTH_LONG.show();
    }
}