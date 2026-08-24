package com.codemors.nativeapp;

import android.content.Context;
import android.content.SharedPreferences;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Base64;
import org.json.JSONArray;
import org.json.JSONObject;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

/** Encrypted local database: every record AES-256-GCM sealed with Android Keystore key. */
public final class Store {
    private static final String KS_ALIAS = "cm_native_master";
    private static SharedPreferences sp;
    private static SecretKey key;

    public static void init(Context ctx) {
        sp = ctx.getSharedPreferences("cmdb", Context.MODE_PRIVATE);
        try {
            KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
            ks.load(null);
            key = (SecretKey) ks.getKey(KS_ALIAS, null);
            if (key == null) {
                KeyGenerator kg = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");
                kg.init(new KeyGenParameterSpec.Builder(KS_ALIAS,
                        KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                        .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                        .setKeySize(256).build());
                key = kg.generateKey();
            }
        } catch (Exception e) { throw new RuntimeException(e); }
    }

    public static synchronized void put(String k, String plain) {
        try {
            Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
            c.init(Cipher.ENCRYPT_MODE, key);
            byte[] iv = c.getIV(), ct = c.doFinal(plain.getBytes(StandardCharsets.UTF_8));
            byte[] out = new byte[iv.length + ct.length];
            System.arraycopy(iv, 0, out, 0, iv.length);
            System.arraycopy(ct, 0, out, iv.length, ct.length);
            sp.edit().putString(k, Base64.encodeToString(out, Base64.NO_WRAP)).apply();
        } catch (Exception e) { throw new RuntimeException(e); }
    }

    public static String get(String k) {
        String stored = sp.getString(k, null);
        if (stored == null) return null;
        try {
            byte[] all = Base64.decode(stored, Base64.NO_WRAP);
            Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
            c.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(128, all, 0, 12));
            return new String(c.doFinal(all, 12, all.length - 12), StandardCharsets.UTF_8);
        } catch (Exception e) { return null; }
    }

    public static void del(String k) { sp.edit().remove(k).apply(); }

    public static JSONArray getContacts() {
        try { return new JSONArray(get("contacts")); } catch (Exception e) { return new JSONArray(); }
    }
    public static void putContacts(JSONArray arr) { put("contacts", arr.toString()); }
    public static JSONObject getMsgs() {
        try { return new JSONObject(get("msgs")); } catch (Exception e) { return new JSONObject(); }
    }
    public static void putMsgs(JSONObject o) { put("msgs", o.toString()); }
}
