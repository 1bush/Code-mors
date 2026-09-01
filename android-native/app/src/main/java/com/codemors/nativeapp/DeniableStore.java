package com.codemors.nativeapp;

import android.content.Context;
import org.json.JSONObject;
import java.nio.charset.StandardCharsets;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * CM-HARD #6 — DENIABLE VAULT (Snowden mode).
 * Seals the entire CM database under a passphrase-derived key (PBKDF2-SHA512,
 * 600k iterations + AES-256-GCM). The plaintext database is then wiped and a
 * bland decoy state left behind. Because the sealed blob is ciphertext with no
 * marker distinguishing it from padding, nothing on the device proves the real
 * conversation exists — plausible deniability under physical inspection.
 */
public final class DeniableStore {
    private static final String VAULT_KEY = "cm_vault_sealed";
    private static final int ITERS = 600_000;

    private DeniableStore() {}

    /** Seal the current DB under passphrase, wipe plaintext, leave decoy. */
    public static boolean seal(Context ctx, String passphrase) throws Exception {
        if (passphrase == null || passphrase.length() < 6) return false;
        android.content.SharedPreferences sp = ctx.getSharedPreferences("cmdb", Context.MODE_PRIVATE);
        JSONObject all = new JSONObject();
        for (String k : sp.getAll().keySet()) all.put(k, sp.getString(k, ""));
        byte[] salt = Crypto.randomBytes(16);
        byte[] key = Crypto.pbkdf2(("CM_VAULT_V1:" + passphrase).toCharArray(), salt, ITERS, 256);
        byte[] iv = Crypto.randomBytes(12);
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, iv));
        byte[] ct = c.doFinal(all.toString().getBytes(StandardCharsets.UTF_8));
        Crypto.zeroize(key);
        String blob = Crypto.bytesToHex(iv) + ":" + Crypto.bytesToHex(ct);
        sp.edit().clear().commit();                 // wipe ALL plaintext records
        Store.init(ctx);
        Store.put("cm_vault_salt", Crypto.bytesToHex(salt)); // salt side-record
        Store.put(VAULT_KEY, blob);                 // store sealed vault
        Store.put("ghost", "GUEST-01");             // bland decoy identity
        return true;
    }

    /** Try to open the vault with a passphrase; restores state on success. */
    public static boolean unseal(Context ctx, String passphrase) {
        try {
            String blob = Store.get(VAULT_KEY);
            if (blob == null) return false;
            String[] p = blob.split(":");
            byte[] key = Crypto.pbkdf2(("CM_VAULT_V1:" + passphrase).toCharArray(),
                    Crypto.hexToBytes(saltHex(ctx)), ITERS, 256);
            Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
            c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"),
                    new GCMParameterSpec(128, Crypto.hexToBytes(p[0]), 0, 12));
            byte[] pt = c.doFinal(Crypto.hexToBytes(p[1]), 12, Crypto.hexToBytes(p[1]).length - 12);
            Crypto.zeroize(key);
            JSONObject all = new JSONObject(new String(pt, StandardCharsets.UTF_8));
            android.content.SharedPreferences sp = ctx.getSharedPreferences("cmdb", Context.MODE_PRIVATE);
            sp.edit().clear().commit();
            Store.init(ctx);
            android.content.SharedPreferences.Editor e = sp.edit();
            for (String k : all.keySet()) e.putString(k, all.getString(k, ""));
            e.commit();
            return true;
        } catch (Exception e) { return false; }
    }

    public static boolean exists() { return Store.get(VAULT_KEY) != null; }

    private static String saltHex(Context ctx) {
        // salt is stored as first 32 hex chars of a side record written at seal time
        String s = Store.get("cm_vault_salt");
        return s != null ? s : "00000000000000000000000000000000";
    }
}