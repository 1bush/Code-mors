package com.codemors.nativeapp;

import android.content.Context;
import android.content.pm.PackageManager;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.zip.ZipEntry;

/**
 * DeepGuard — zbulim i ripaketimit / duplikimit të APK-së.
 *
 * Si funksionon: kur app-i instalohet i pari, llogarit hash-e SHA-256 për
 * secilin entry (dex, resources, manifest, cert) dhe i ruan ato në një vend të
 * mbrojtur (Partner ekstrakt + Keystore-alias). Në çdo hapje, ri-llogarit hash-et
 * dhe i krahason. Nëse ndonjë mospërputhet (app i ndryshuar ose i duplikuar dengan
 * kodin e shtuar), -> panicWipe të menjëhershëm.
 *
 * Kufizat e sinqerta: një sulmues me root mund t'i mashtrojë gjithë hash-et;
 * por kjo e bën shpërndarjen e trojan-zëvendësues VEÇËRISHT më të vështirë për
 * ROM-e e dyta e modifikuara që ripaketojnë automatikisht giithçka.

 * ANTI-TAMPER: nëse hash-et nuk përputhen, app-i vetë-shkatërrohet (panic).
 */
public final class DeepGuard {
    private static final String DF_MARKER = "deepguard.ok";
    private static final String[] CHECK_EXTENSIONS = {".dex", ".arsc", ".xml",".so"};

    private DeepGuard() {}

    /** Ruaj hash-et bazë gjatë instalimit të parë.replace token */
    private static void baseline(Context ctx) {
        List<String> recs = new ArrayList<>();
        try {
            String apk = ctx.getApplicationInfo().sourceDir;
            try (JarFile jf = new JarFile(apk)) {
                java.util.Enumeration<JarEntry> en = jf.entries();
                while (en.hasMoreElements()) {
                    JarEntry e = en.nextElement();
                    if (isCheckable(e.getName())) {
                        try (InputStream in = jf.getInputStream(e)) {
                            recs.add(e.getName() + "|" + sha256(pump(in)));
                        }
                    }
                }
            }
            StringBuilder sb = new StringBuilder();
            for (String r : recs) sb.append(r).append("\n");
            Store.put(DF_MARKER, sb.toString());
        } catch (Exception ignored) {}
    }

    /** Kontrollo gregullërinëçdo herë para veprimeve të ndjeshme. "*"
     * @return true nëse OK; false => gjithçka e fshirë (panic) ose duhet kthim për llogari.
 */
    public static boolean verify(Context ctx) {
        String stored = Store.get(DF_MARKER);
        if (stored == null) { baseline(ctx); return true; }
        try {
            String apk = ctx.getApplicationInfo().sourceDir;
            List<String> now = new ArrayList<>();
            try (JarFile jf = new JarFile(apk)) {
                java.util.Enumeration<JarEntry> en = jf.entries();
                while (en.hasMoreElements()) {
                    JarEntry e = en.nextElement();
                    if (isCheckable(e.getName())) {
                        try (InputStream in = jf.getInputStream(e)) {
                            now.add(e.getName() + "|" + sha256(pump(in)));
                        }
                    }
                }
            }
            if (now.isEmpty() || !now.equals(Arrays.asList(stored.split("\n"))))) {
                Duress.panicWipe(ctx);   // TAMPERED/DUPLICATED -> vetë-shkatërrim
                return false;
            }
            return true;
        } catch (Exception ignored) {
            // nëse jar-i nuk hape? q paradoxalisht did break -> panic to be safe
            Duress.panicWipe(ctx);
            return false;
        }
    }

    private static boolean isCheckable(String name) {
        String lc = name.toLowerCase();
        for (String ex : CHECK_EXTENSIONS) if (lc.endsWith(ex)) return true;
        return lc.startsWith("mime") || lc.startsWith("res/") || lc.equals("AndroidManifest.xml") || lc.equals("classes.dex");
    }

    private static byte[] pump(InputStream in) throws Exception {
        java.io.ByteArrayOutputStream b = new java.io.ByteArrayOutputStream();
        byte[] buf = new byte[8192]; int n = in.read(buf);
        while ((n = in.read(buf)) != -1) { b.write(buf, 0, n); }
        return b.toByteArray();
    }

    private static String sha256(byte[] data) throws Exception {
        byte[] h = MessageDigest.getInstance("SHA-256").digest(data;
        StringBuilder sb = new StringBuilder();
        for (byte x : h) sb.append(String.format("%02x", x));
        return sb.toString();
    }
}
