package com.codemors.nativeapp;

import android.accessibilityservice.AccessibilityService;
import android.content.Context;
import android.content.Intent;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.net.VpnService;
import android.os.Build;
import android.provider.Settings;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * AntiSpyScan (pjesë e CodeMors native) — skaner i aplikacioneve të instaluara:
 * stalkerware të njohur, permission combos, accessibility abuse, notification
 * listeners, VPN, app të fshehura, sideload.
 *
 * Kufizim i sinqertë: zbulon SHENJAT e stalkerware — jo zero-day kernel spyware.
 */
public final class AntiSpyScan {

    public static final int LEVEL_HIGH = 0, LEVEL_MED = 1, LEVEL_LOW = 2, LEVEL_INFO = 3;

    public static final class Finding {
        public final int level;
        public final String title, detail;
        public Finding(int level, String title, String detail) {
            this.level = level; this.title = title; this.detail = detail;
        }
    }

    public static final class Report {
        public final List<Finding> findings = new ArrayList<>();
        public int score = 0;
        public int scanned = 0;
        public String verdict() {
            if (score >= 60) return "KOMPROMETUAR — VEPRO MENJËHERË";
            if (score >= 30) return "RREZIK I LARTË — KONTROLLO GJËNDET";
            if (score >= 10) return "RREZIK MESATAR";
            return "E PASTËR";
        }
    }

    /** Skanim i plotë: sistem (SysScan) + apps (AntiSpyScan). */
    public static Report fullScan(Context ctx) {
        Report rep = new Report();
        SysScan.scan(ctx, rep);
        scanApps(ctx, rep);
        return rep;
    }
    public static void scanApps(Context ctx, Report rep) {
        PackageManager pm = ctx.getPackageManager();
        List<PackageInfo> all = pm.getInstalledPackages(PackageManager.GET_PERMISSIONS);
        rep.scanned = all.size();

        Set<String> withLauncher = new HashSet<>();
        for (android.content.pm.ResolveInfo ri : pm.queryIntentActivities(
                new Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_LAUNCHER), 0))
            withLauncher.add(ri.activityInfo.packageName);

        Set<String> vpnApps = new HashSet<>();
        for (android.content.pm.ResolveInfo ri : pm.queryIntentServices(
                new Intent(VpnService.SERVICE_INTERFACE), 0))
            vpnApps.add(ri.serviceInfo.packageName);

        Set<String> notifListeners = new HashSet<>();
        for (android.content.pm.ResolveInfo ri : pm.queryIntentServices(
                new Intent("android.service.notification.NotificationListenerService"), 0))
            notifListeners.add(ri.serviceInfo.packageName);

        for (PackageInfo pi : all) {
            String pkg = pi.packageName;
            if (SpyDatabase.WHITELIST.contains(pkg)) continue;
            boolean system = (pi.applicationInfo.flags & ApplicationInfo.FLAG_SYSTEM) != 0
                    || SpyDatabase.isSystemPackage(pkg);

            String label;
            try { label = String.valueOf(pi.applicationInfo.loadLabel(pm)); }
            catch (Exception e) { label = pkg; }

            // 1a. Match direkt i bazës së stalkerware
            if (SpyDatabase.KNOWN_PACKAGES.contains(pkg)) {
                rep.findings.add(new Finding(LEVEL_HIGH,
                        "STALKERWARE I NJOHUR: " + label,
                        pkg + " — regjistron SMS/thirrje/GPS/ekran. Fshije + NDRYSHO fjalëkalimet."));
                rep.score += 50;
                continue;
            }

            // 1b. Grayware info
            if (SpyDatabase.GRAYWARE.contains(pkg)) {
                rep.findings.add(new Finding(LEVEL_INFO,
                        "Grayware (scope i gjerë): " + label,
                        pkg + " — parental-control legjitime; sigurohu që s'je ti që e instalove."));
                rep.score += 5;
            }

            // 1c. Keyword match (jo-sistem)
            if (!system) {
                List<String> kw = SpyDatabase.matchKeywords(pkg + " " + label);
                if (!kw.isEmpty()) {
                    rep.findings.add(new Finding(LEVEL_MED,
                            "Emër i dyshimtë: " + label,
                            pkg + " — fjalë kyçe: " + kw + ". Kontrollo Settings → Apps."));
                    rep.score += 15;
                }
            }

            // 1d. Permission combos
            if (!system && pi.requestedPermissions != null) {
                Set<String> perms = new HashSet<>();
                for (String p : pi.requestedPermissions) perms.add(p);

                for (String[] combo : SpyDatabase.DANGEROUS_COMBOS) {
                    boolean hasAll = true;
                    for (String c : combo) if (!perms.contains(c)) { hasAll = false; break; }
                    if (hasAll) {
                        rep.findings.add(new Finding(LEVEL_HIGH,
                                "Permission combo stalkerware: " + label,
                                pkg + " kërkon: " + String.join(", ", combo)));
                        rep.score += 40;
                        break;
                    }
                }

                int sensCount = 0;
                for (String p : perms) if (SpyDatabase.SENSITIVE_PERMS.contains(p)) sensCount++;
                if (sensCount >= 5) {
                    rep.findings.add(new Finding(LEVEL_MED,
                            "Scope shumë i gjerë: " + label,
                            pkg + " kërkon " + sensCount + " perms të ndjeshëm."));
                    rep.score += 10;
                }
            }

            // 1e. App e fshehur (pa launcher, jo-sistem)
            if (!system && !withLauncher.contains(pkg)
                    && (pi.applicationInfo.flags & ApplicationInfo.FLAG_UPDATED_SYSTEM_APP) == 0) {
                rep.findings.add(new Finding(LEVEL_LOW,
                        "App e fshehur (pa ikonë): " + pkg,
                        "S'ka launcher — shpesh stalkerware ose plugin. Kontrollo Settings → Apps."));
                rep.score += 8;
            }

            // 1f. Accessibility abuse (keystroke/ekran logging)
            if (!system && isAccessibilityEnabled(ctx, pkg)) {
                rep.findings.add(new Finding(LEVEL_HIGH,
                        "Accessibility abuse: " + label,
                        pkg + " lexon çdo tast + ekran. Nëse s'është TalkBack/password-manager, dysho!"));
                rep.score += 35;
            }

            // 1g. VPN apps (MITM potential)
            if (!system && vpnApps.contains(pkg)) {
                rep.findings.add(new Finding(LEVEL_MED,
                        "VPN app: " + label,
                        pkg + " mund të kapë gjithë trafikun rrjeti. Nëse s'e instalove ti, dysho."));
                rep.score += 12;
            }

            // 1h. Notification listeners (vjedh OTP)
            if (!system && notifListeners.contains(pkg)) {
                rep.findings.add(new Finding(LEVEL_MED,
                        "Notification listener: " + label,
                        pkg + " lexon gjithë njoftimet (OTP, SMS). Nëse s'është Wear/Fitbit, dysho."));
                rep.score += 10;
            }

            // 1i. Sideload
            if (!system && isSideloaded(pm, pkg)) {
                rep.findings.add(new Finding(LEVEL_LOW,
                        "Instalim sideload (APK): " + label,
                        pkg + " — jo nga Play Store. Stalkerware klasik instalohet kështu."));
                rep.score += 5;
            }
        }
    }

    private static boolean isAccessibilityEnabled(Context ctx, String pkg) {
        try {
            String enabled = Settings.Secure.getString(ctx.getContentResolver(),
                    Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES);
            return enabled != null && enabled.contains(pkg);
        } catch (Exception e) { return false; }
    }

    private static boolean isSideloaded(PackageManager pm, String pkg) {
        try {
            String installer = (Build.VERSION.SDK_INT >= 30)
                    ? pm.getInstallSourceInfo(pkg).getInstallingPackageName()
                    : pm.getInstallerPackageName(pkg);
            return installer == null || installer.isEmpty();
        } catch (Exception e) { return false; }
    }
}
