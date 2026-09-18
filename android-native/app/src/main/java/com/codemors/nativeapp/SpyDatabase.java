package com.codemors.nativeapp;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Baza e të dhënave AntiSpy (pjesë e CodeMors native): stalkerware të njohur
 * (2024-2026) + fjalë kyçe të dyshimta. Burime: Kaspersky, Avast, ESET,
 * Coalition Against Stalkerware, Malwarebytes.
 * Kufizim: baza statistike — spyware i ri me package random kapet vetëm nga
 * heuristikat e AntiSpyScan (permission combos, hidden apps, accessibility).
 */
public final class SpyDatabase {

    /** Package names të stalkerware konfirmuar — HIGH */
    public static final Set<String> KNOWN_PACKAGES = new HashSet<>(Arrays.asList(
        // mSpy / FlexiSPY / Hoverwatch / Cerberus
        "com.mspy", "com.mspy.lite", "mspy.com", "com.mspylite",
        "com.flexispy", "com.vvt.android", "com.flx.sys", "flexispy.agent",
        "com.hoverwatch", "hoverwatch.app", "com.hv.tracker",
        "com.ap.sw", "com.cerberus",
        // TheTruthSpy / Cocospy / Spyzie / FoneMonitor / Copy9
        "com.thetruthspy", "thetruthspy.app", "com.tts.spy",
        "com.cocospy", "com.spyzie", "com.spyzie.addonservice", "com.fonemonitor",
        "com.copy9", "com.myfon.app",
        // KidsGuard (ClevGuard) / Highster / XNSPY
        "com.clev.kidsguard", "com.kidsguard", "com.clevguard.kg", "com.clevguard.wsp",
        "com.highstermobile", "com.highster", "com.ht.mobile",
        "com.xnspy", "com.xnspy.mobile", "com.xns",
        // Mobistealth / iSpyoo / SpyEra / StealthGenie
        "com.mobistealth", "com.ispyoo", "com.spyera", "com.stealthgenie",
        // Auto Forward / Easy Spy / NexSpy / Mobile Tracker Free / iKeyMonitor
        "com.autoforward", "com.easyspy", "com.af.tracker",
        "com.nexspy", "com.nexaspy",
        "com.mobiletrackerfree", "com.mtf.tracker",
        "com.ikeymonitor", "com.ikm.tracker",
        // GuestSpy / AppSpy / TheOneSpy / TrackMyPhone / Teen* / PhoneSheriff
        "com.guestspy", "com.appspy", "com.theonespy", "com.trackmyphone",
        "com.teensafe", "com.teenshield", "com.phonesheriff", "com.mamabear",
        // WebWatcher / pcTattletale / SpyX / SpyFone / TurboSpy / MaxxSpy
        "com.webwatcher", "com.awm.watcher", "com.pctattletale",
        "com.famisafe.spy", "com.spyx", "com.spyfone", "com.turbospy",
        "com.maxxspy", "com.moniterro", "com.phoenixspy",
        // ClevGuard shtesë / WhatsApp-monitors / uMobix / eyeZy
        "com.clevguard.clevmonitor", "com.clevguard.spd",
        "com.wspmon", "com.wa.monitor", "com.umobix", "com.eyezy", "com.eyezy.addon",
        // FreeAndroidSpy / RAT droppers (SpyNote, AhMyth, Hydra, BananaBot)
        "com.freeandroidspy", "com.fas.tracker",
        "com.spynote", "com.ahmyth", "com.hydra.rat", "com.bananabot"
    ));

    /** Fjalë kyçe të dyshimta (substring) — MED */
    public static final String[] SUSPICIOUS_KEYWORDS = {
        "spy", "keylogger", "stealth", "snoopza", "tispy", "silentspy",
        "spyhuman", "spyzee", "spymaster", "phonespy", "cellspy",
        "spyapp", "surveillance", "hoverwatch", "spytector"
    };

    /** Whitelist anti-false-positive */
    public static final Set<String> WHITELIST = new HashSet<>(Arrays.asList(
        "com.google.android.gms", "com.google.android.gsf", "com.google.android.webview",
        "com.android.vending", "com.google.android.inputmethod.latin",
        "com.trackerbus", "com.android.systemui"
    ));

    /** Grayware: parental-control legjitime me scope të gjerë — INFO */
    public static final Set<String> GRAYWARE = new HashSet<>(Arrays.asList(
        "com.life360.android.safetymapd", "com.qustodio.qustodioapp",
        "com.mmguardian.androidapp"
    ));

    /** Permission combos që tradhtojnë stalkerware klasik */
    public static final String[][] DANGEROUS_COMBOS = {
        {"android.permission.READ_SMS", "android.permission.RECEIVE_SMS", "android.permission.READ_CALL_LOG"},
        {"android.permission.READ_SMS", "android.permission.ACCESS_FINE_LOCATION", "android.permission.RECORD_AUDIO"},
        {"android.permission.READ_CALL_LOG", "android.permission.RECORD_AUDIO", "android.permission.CAMERA"},
        {"android.permission.RECEIVE_BOOT_COMPLETED", "android.permission.READ_SMS", "android.permission.SYSTEM_ALERT_WINDOW"}
    };

    /** Perms të ndjeshme (5+ në app jo-sistem = MED) */
    public static final Set<String> SENSITIVE_PERMS = new HashSet<>(Arrays.asList(
        "android.permission.READ_SMS", "android.permission.RECEIVE_SMS",
        "android.permission.READ_CALL_LOG", "android.permission.RECORD_AUDIO",
        "android.permission.CAMERA", "android.permission.ACCESS_FINE_LOCATION",
        "android.permission.SYSTEM_ALERT_WINDOW", "android.permission.READ_CONTACTS",
        "android.permission.RECEIVE_BOOT_COMPLETED", "android.permission.READ_PHONE_STATE",
        "android.permission.PROCESS_OUTGOING_CALLS", "android.permission.QUERY_ALL_PACKAGES",
        "android.permission.PACKAGE_USAGE_STATS"
    ));

    public static boolean isSystemPackage(String pkg) {
        if (pkg == null) return false;
        return pkg.startsWith("com.android.") || pkg.startsWith("com.google.")
            || pkg.startsWith("android.") || pkg.startsWith("com.samsung.")
            || pkg.startsWith("com.sec.") || pkg.startsWith("com.miui.")
            || pkg.startsWith("com.xiaomi.") || pkg.startsWith("org.fdroid.");
    }

    public static List<String> matchKeywords(String labelOrPkg) {
        List<String> hits = new ArrayList<>();
        if (labelOrPkg == null) return hits;
        String low = labelOrPkg.toLowerCase();
        for (String kw : SUSPICIOUS_KEYWORDS)
            if (low.contains(kw)) hits.add(kw);
        return hits;
    }
}
