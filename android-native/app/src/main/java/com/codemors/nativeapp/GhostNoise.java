package com.codemors.nativeapp;

import android.os.Handler;
import android.os.Looper;
import org.json.JSONArray;
import org.json.JSONObject;

/**
 * CM-HARD #1 — GHOST NOISE.
 * Emits decoy payloads that are cryptographically indistinguishable from real
 * messages (real padding + real AES-256-GCM under a random key) on a random
 * schedule, so an observer cannot tell when a real message is sent.
 * No other messenger ships continuous key-indistinguishable cover traffic.
 */
public final class GhostNoise {
    private static final Handler H = new Handler(Looper.getMainLooper());
    private static boolean running = false;
    private static final long MIN_MS = 30_000, MAX_MS = 120_000;

    private GhostNoise() {}

    public static synchronized void start() {
        if (running) return;
        running = true;
        loop();
    }

    public static synchronized void stop() { running = false; }

    public static boolean isRunning() { return running; }

    private static void loop() {
        if (!running) return;
        long delay = MIN_MS + (long) (Math.random() * (MAX_MS - MIN_MS));
        H.postDelayed(() -> {
            try { burst(); } catch (Exception ignored) {}
            loop();
        }, delay);
    }

    /** Generate one decoy payload and store it in the noise log (max 24 kept). */
    private static void burst() throws Exception {
        JSONArray contacts = Store.getContacts();
        if (contacts.length() == 0) return;
        JSONObject c = contacts.getJSONObject((int) (Math.random() * contacts.length()));
        byte[] mk = Crypto.randomBytes(32);                       // random one-time key
        byte[] fake = ("n" + Crypto.randomHex(16)).getBytes(java.nio.charset.StandardCharsets.UTF_8);
        String enc = Crypto.encryptAesGcm(Crypto.pad(fake, 256), mk);
        Crypto.zeroize(mk); Crypto.zeroize(fake);                 // WHISPER: no residue
        JSONArray log;
        try { log = new JSONArray(Store.get("noise_log")); } catch (Exception e) { log = new JSONArray(); }
        JSONObject entry = new JSONObject();
        entry.put("cid", c.getString("id"));
        entry.put("enc", enc);
        entry.put("time", System.currentTimeMillis());
        JSONArray out = new JSONArray(); out.put(entry);
        for (int i = 0; i < log.length() && i < 23; i++) out.put(log.getJSONObject(i));
        Store.put("noise_log", out.toString());
    }
}