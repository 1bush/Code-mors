package com.codemors.nativeapp;

import android.content.Context;
import android.content.SharedPreferences;

/**
 * CM-HARD #2 — DURESS PIN + PANIC WIPE.
 * A secondary PIN: entering it under coercion wipes every key and record
 * instantly and irreversibly. Stored only as a salted PBKDF2-SHA512 hash,
 * so the PIN itself is never recoverable from the device.
 */
public final class Duress {
    private static final String PREF = "cmduress";
    private static final int ITERS = 200_000;

    private Duress() {}

    /** Set the duress PIN (min 4 chars). Returns true on success. */
    public static boolean set(Context ctx, String pin) {
        if (pin == null || pin.length() < 4) return false;
        try {
            byte[] salt = Crypto.randomBytes(16);
            byte[] h = Crypto.pbkdf2(("CM_DURESS_V1:" + pin).toCharArray(), salt, ITERS, 256);
            String record = Crypto.bytesToHex(salt) + ":" + Crypto.bytesToHex(h);
            Crypto.zeroize(h);
            ctx.getSharedPreferences(PREF, Context.MODE_PRIVATE)
               .edit().putString("d", record).apply();
            return true;
        } catch (Exception e) { return false; }
    }

    public static boolean isSet(Context ctx) {
        return ctx.getSharedPreferences(PREF, Context.MODE_PRIVATE).getString("d", null) != null;
    }

    /** Check a PIN against the stored duress hash. */
    public static boolean matches(Context ctx, String pin) {
        String record = ctx.getSharedPreferences(PREF, Context.MODE_PRIVATE).getString("d", null);
        if (record == null || pin == null) return false;
        try {
            String[] p = record.split(":");
            byte[] salt = Crypto.hexToBytes(p[0]);
            byte[] h = Crypto.pbkdf2(("CM_DURESS_V1:" + pin).toCharArray(), salt, ITERS, 256);
            boolean ok = Crypto.bytesToHex(h).equals(p[1]);
            Crypto.zeroize(h);
            return ok;
        } catch (Exception e) { return false; }
    }

    /** PANIC WIPE: destroy every CM record on the device. Irreversible. */
    public static void panicWipe(Context ctx) {
        wipeAll(ctx, "cmdb");
        wipeAll(ctx, "cmduress");
        Store.init(ctx); // regenerate a fresh empty sealed DB so the app still runs
    }

    private static void wipeAll(Context ctx, String name) {
        SharedPreferences sp = ctx.getSharedPreferences(name, Context.MODE_PRIVATE);
        sp.edit().clear().commit(); // commit (not apply): synchronous, survives crash
    }
}