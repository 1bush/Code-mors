package com.codemors.nativeapp;

import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/** Signal-style crypto: ECDH P-256 + HMAC-SHA256 KDF chain (double ratchet) + AES-256-GCM. */
public final class Crypto {
    private static final SecureRandom RNG = new SecureRandom();

    public static byte[] randomBytes(int n) { byte[] b = new byte[n]; RNG.nextBytes(b); return b; }
    public static String randomHex(int n) { StringBuilder s=new StringBuilder(); for(byte b:randomBytes(n)) s.append(String.format("%02x",b)); return s.toString(); }

    public static KeyPair generateEcdhKeyPair() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(new ECGenParameterSpec("secp256r1"));
        return kpg.generateKeyPair();
    }

    public static String exportPublicKey(PublicKey pub) {
        return bytesToHex(pub.getEncoded());
    }

    public static PublicKey importPublicKey(String hex) throws Exception {
        byte[] der = hexToBytes(hex);
        // strip X509 wrapper if raw point provided: we always store encoded form
        return KeyFactory.getInstance("EC").generatePublic(new X509EncodedKeySpec(der));
    }

    /** ECDH shared secret -> SHA-256 -> session key material (64 hex chars). */
    public static String deriveSessionKey(PrivateKey priv, String theirPubHex) throws Exception {
        KeyAgreement ka = KeyAgreement.getInstance("ECDH");
        ka.init(priv);
        ka.doPhase(importPublicKey(theirPubHex), true);
        byte[] secret = ka.generateSecret();
        return bytesToHex(MessageDigest.getInstance("SHA-256").digest(secret));
    }

    /** KDF chain advance: ck' = HMAC-SHA256(ck, "NEXT"). */
    public static String ratchetNext(String chainHex) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(padChain(chainHex), "HmacSHA256"));
        return bytesToHex(mac.doFinal("CM_RATCHET_NEXT_V1".getBytes(StandardCharsets.UTF_8)));
    }

    /** Message key: mk = HMAC-SHA256(ck, "MSG"). */
    public static byte[] ratchetMsgKey(String chainHex) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(padChain(chainHex), "HmacSHA256"));
        return mac.doFinal("CM_RATCHET_MSG_V1".getBytes(StandardCharsets.UTF_8));
    }

    private static byte[] padChain(String chainHex) {
        byte[] h = hexToBytes(chainHex);
        byte[] out = new byte[32];
        System.arraycopy(h, 0, out, 0, Math.min(h.length, 32));
        return out;
    }

    /** SimpleX-style padding to block size. */
    public static byte[] pad(byte[] raw, int blockSize) {
        int total = Math.max(blockSize, ((raw.length + 4 + blockSize - 1) / blockSize) * blockSize);
        byte[] out = new byte[total];
        out[0] = (byte) (raw.length >> 24); out[1] = (byte) (raw.length >> 16);
        out[2] = (byte) (raw.length >> 8);  out[3] = (byte) raw.length;
        System.arraycopy(raw, 0, out, 4, raw.length);
        byte[] noise = randomBytes(total - 4 - raw.length);
        System.arraycopy(noise, 0, out, 4 + raw.length, noise.length);
        return out;
    }

    public static byte[] unpad(byte[] data) {
        int len = ((data[0] & 0xff) << 24) | ((data[1] & 0xff) << 16) | ((data[2] & 0xff) << 8) | (data[3] & 0xff);
        if (len < 0 || len > data.length - 4) throw new IllegalArgumentException("bad padding");
        byte[] out = new byte[len];
        System.arraycopy(data, 4, out, 0, len);
        return out;
    }

    public static String encryptAesGcm(byte[] plain, byte[] msgKey) throws Exception {
        byte[] iv = randomBytes(12);
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(msgKey, 0, 32, "AES"), new GCMParameterSpec(128, iv));
        byte[] ct = c.doFinal(plain);
        byte[] out = new byte[iv.length + ct.length];
        System.arraycopy(iv, 0, out, 0, iv.length);
        System.arraycopy(ct, 0, out, iv.length, ct.length);
        return bytesToHex(out);
    }

    public static byte[] decryptAesGcm(String payloadHex, byte[] msgKey) throws Exception {
        byte[] all = hexToBytes(payloadHex);
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(msgKey, 0, 32, "AES"), new GCMParameterSpec(128, all, 0, 12));
        return c.doFinal(all, 12, all.length - 12);
    }

    /** Safety number: SHA-512 of sorted combined public keys. MITM check. */
    public static String safetyNumber(String myPubHex, String theirPubHex) throws Exception {
        String combined = (myPubHex.compareTo(theirPubHex) < 0 ? myPubHex + theirPubHex : theirPubHex + myPubHex);
        byte[] h = MessageDigest.getInstance("SHA-512").digest(combined.getBytes(StandardCharsets.UTF_8));
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 12; i++) sb.append(String.format("%02X", h[i]));
        return sb.toString().replaceAll("(.{5})", "$1-").substring(0, 29);
    }

    /* ── CM-HARD v5 additions ──────────────────────────────────────────── */

    /** PBKDF2-HMAC-SHA512 key derivation (TLP / duress / vault). */
    public static byte[] pbkdf2(char[] pass, byte[] salt, int iterations, int bits) throws Exception {
        javax.crypto.spec.PBEKeySpec spec = new javax.crypto.spec.PBEKeySpec(pass, salt, iterations, bits);
        try {
            return javax.crypto.SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512").generateSecret(spec).getEncoded();
        } finally { spec.clearPassword(); }
    }

    /** SHA-512 hash (hex) used for duress PIN verification. */
    public static String sha512Hex(byte[] data) throws Exception {
        return bytesToHex(MessageDigest.getInstance("SHA-512").digest(data));
    }

    /** WHISPER: overwrite key/plaintext material so it never lingers in the heap. */
    public static void zeroize(byte[] b) { if (b != null) java.util.Arrays.fill(b, (byte) 0); }

    /** ROTATING EPOCH: HKDF-style epoch key, epochKey = HMAC-SHA256(sess, "CM_EPOCH_V1" || epoch). */
    public static String epochKey(String sessHex, int epoch) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(padChain(sessHex), "HmacSHA256"));
        String info = "CM_EPOCH_V1:" + epoch;
        return bytesToHex(mac.doFinal(info.getBytes(StandardCharsets.UTF_8)));
    }

    public static String bytesToHex(byte[] b) { StringBuilder s = new StringBuilder(); for (byte x : b) s.append(String.format("%02x", x)); return s.toString(); }
    public static byte[] hexToBytes(String h) { h = h.replace(":", ""); byte[] o = new byte[h.length() / 2]; for (int i = 0; i < o.length; i++) o[i] = (byte) Integer.parseInt(h.substring(i * 2, i * 2 + 2), 16); return o; }
}
