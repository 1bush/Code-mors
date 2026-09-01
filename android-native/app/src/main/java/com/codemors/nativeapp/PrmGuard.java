package com.codemors.nativeapp;

import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.Signature;
import android.os.Build;
import android.os.Debug;
import java.io.BufferedReader;
import java.io.File;
import java.io.InputStreamReader;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.List;

/**
 * PRM — Pegasus Resistance Module, pjesa 2.
 * Anti-instrumentation & app-integrity:
 *  - zbulon debugger, Frida server, Xposed/Substrate, modifikim të APK-së
 *  - verifikon signature-in e app-it (tamper detection)
 *  - kontrollon TracerPid (ndjekës debugging)
 */
public final class PrmGuard {

    // NDRYSHO KETË me hash-in hex të signature-së së vërtetë të publikimit tuaj!
    private static final String EXPECTED_SIGNATURE_HASH = "PASTE_YOUR_RELEASE_SIGNATURE_SHA256_HEX_HERE";

    public static final class Integrity {
        public final List<String> flags;
        public final boolean debugger, frida, xposed, signedOk, tracerDetected;
        public final int score;
        Integrity(List<String> f, boolean dbg, boolean fr, boolean xp, boolean sig, boolean tr, int s) {
            flags=f; debugger=dbg; frida=fr; xposed=xp; signedOk=sig; tracerDetected=tr; score=s;
        }
    }

    public static Integrity audit(Context ctx) {
        List<String> flags = new ArrayList<>();
        boolean dbg=false, fr=false, xp=false, sig=true, tr=false;

        // 1. Debugger attached
        if (Debug.isDebuggerConnected() || Debug.waitingForDebugger()) { flags.add("DBG_ATTACHED"); dbg=true; }

        // 2. TracerPid në /proc/self/status
        try {
            BufferedReader r = new BufferedReader(new InputStreamReader(
                new java.io.FileInputStream("/proc/self/status")));
            String line; int tracerPid=0;
            while ((line=r.readLine())!=null) {
                if (line.startsWith("TracerPid:")) { tracerPid=Integer.parseInt(line.substring(10).trim()); break; }
            }
            r.close();
            if (tracerPid!=0) { flags.add("TRACER:"+tracerPid); tr=true; }
        } catch (Exception ignored) {}
        // 3. Frida server (default port 27042, ose binary frida-server)
        if (portOpen("127.0.0.1",27042)) { flags.add("FRIDA_PORT_27042"); fr=true; }
        for (String pipe : new String[]{"frida-server","frida-agent","linjector","gum-js-loop"}) {
            if (new File("/data/local/tmp/"+pipe).exists()) { flags.add("FRIDA_PIPE:"+pipe); fr=true; }
        }
        // Frida-n e dallon edhe në /proc/self/maps (gum-js-loop / gmain)
        try {
            BufferedReader r = new BufferedReader(new InputStreamReader(
                new java.io.FileInputStream("/proc/self/maps")));
            String line; int hits=0;
            while ((line=r.readLine())!=null) {
                String lc=line.toLowerCase();
                if (lc.contains("frida")||lc.contains("gum-js-loop")||lc.contains("gmain")||lc.contains("linjector"))
                    hits++;
            }
            r.close();
            if (hits>0) { flags.add("FRIDA_MAPS:"+hits); fr=true; }
        } catch (Exception ignored) {}

        // 4. Xposed / Substrate / EdXposed (integrim runtime)
        try { Class.forName("de.robv.android.xposed.XposedBridge"); flags.add("XPOSED_BRIDGE"); xp=true; }
        catch (ClassNotFoundException ignored) {}
        try { Class.forName("de.robv.android.xposed.XposedHelpers"); flags.add("XPOSED_HELPERS"); xp=true; }
        catch (ClassNotFoundException ignored) {}
        try { Class.forName("com.saurik.substrate.MS$2"); flags.add("SUBSTRATE"); xp=true; }
        catch (ClassNotFoundException ignored) {}
        for (String lib : new String[]{"libxposed.so","libsubstrate.so","libedxposed.so","liblspd.so"}) {
            boolean libFound = new File("/system/lib/"+lib).exists()
                    || new File("/system/lib64/"+lib).exists();
            if (libFound) { flags.add("XPOSED_LIB:"+lib); xp=true; }
        }
        // stack trace për Xposed
        try { throw new Exception("probe"); } catch (Exception e) {
            for (StackTraceElement st : e.getStackTrace()) {
                String cn = st.getClassName();
                if (cn.contains("XposedBridge")||cn.contains("XposedHelpers")||cn.contains("EdHooker")) {
                    flags.add("XPOSED_STACK"); xp=true; break;
                }
            }
        }

        // 5. Signature verification (anti-tampering APK)
        if (EXPECTED_SIGNATURE_HASH!=null && EXPECTED_SIGNATURE_HASH.length()>0
                && !EXPECTED_SIGNATURE_HASH.startsWith("PASTE_")) {
            sig = verifySignature(ctx);
            if (!sig) flags.add("SIG_MISMATCH");
        }

        int score =0;
        if (dbg) score +=30;
        if (tr)  score +=15;
        if (fr)  score +=35;
        if (xp)  score +=35;
        if (!sig) score +=25;
        return new Integrity(flags, dbg, fr, xp, sig, tr, Math.min(score,100));
    }

    private static boolean verifySignature(Context ctx) {
        try {
            if (Build.VERSION.SDK_INT >= 28) {
                PackageInfo pi = ctx.getPackageManager().getPackageInfo(
                    ctx.getPackageName(), PackageManager.GET_SIGNING_CERTIFICATES);
                Signature[] sigs = pi.signingInfo.getApkContentsSigners();
                for (Signature s : sigs) {
                    if (sha256(s.toByteArray()).equalsIgnoreCase(EXPECTED_SIGNATURE_HASH)) return true;
                }
            } else {
                PackageInfo pi = ctx.getPackageManager().getPackageInfo(
                    ctx.getPackageName(), PackageManager.GET_SIGNATURES);
                for (Signature s : pi.signatures) {
                    if (sha256(s.toByteArray()).equalsIgnoreCase(EXPECTED_SIGNATURE_HASH)) return true;
                }
            }
        } catch (Exception ignored) {}
        return false;
    }

    private static boolean portOpen(String host, int port) {
        try (java.net.Socket s = new java.net.Socket()) {
            s.connect(new java.net.InetSocketAddress(host,port, 60));
            return true;
        } catch (Exception e) { return false; }
    }

    private static String sha256(byte[] data) {
        byte[] h = MessageDigest.getInstance("SHA-256").digest(data);
        StringBuilder sb = new StringBuilder();
        for (byte b : h) sb.append(String.format("%02x", b));
        return sb.toString();
    }
}