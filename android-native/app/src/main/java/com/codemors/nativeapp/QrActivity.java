package com.codemors.nativeapp;

import android.app.Activity;
import android.graphics.Bitmap;
import android.os.Bundle;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.TextView;
import com.google.zxing.BarcodeFormat;
import com.google.zxing.EncodeHintType;
import com.google.zxing.qrcode.QRCodeWriter;
import java.util.EnumMap;
import java.util.Map;

/** Shows my QR (ghost name + ECDH public key) for pairing. */
public class QrActivity extends Activity {
    @Override protected void onCreate(Bundle b) {
        super.onCreate(b);
        getWindow().setFlags(android.view.WindowManager.LayoutParams.FLAG_SECURE,
                android.view.WindowManager.LayoutParams.FLAG_SECURE);
        FrameLayout root = new FrameLayout(this);
        TextView label = new TextView(this);
        try {
            Store.init(this);
            String ghost = Store.get("ghost");
            String pub = Store.get("keypair").split("\\|")[1];
            String payload = new org.json.JSONObject().put("v", 1).put("n", ghost).put("k", pub).toString();
            Map<EncodeHintType, Object> hints = new EnumMap<>(EncodeHintType.class);
            hints.put(EncodeHintType.MARGIN, 1);
            com.google.zxing.common.BitMatrix mx = new QRCodeWriter().encode(payload, BarcodeFormat.QR_CODE, 900, 900, hints);
            Bitmap bm = Bitmap.createBitmap(900, 900, Bitmap.Config.RGB_565);
            for (int x = 0; x < 900; x++) for (int y = 0; y < 900; y++) bm.setPixel(x, y, mx.get(x, y) ? 0xFF000000 : 0xFFFFFFFF);
            ImageView iv = new ImageView(this);
            iv.setImageBitmap(bm);
            iv.setBackgroundColor(0xFFFFFFFF);
            FrameLayout.LayoutParams ip = new FrameLayout.LayoutParams(-2, -2);
            ip.gravity = android.view.Gravity.CENTER;
            root.addView(iv, ip);
            label.setText("SCAN THIS TO LINK WITH " + ghost);
        } catch (Exception e) {
            label.setText("QR error: " + e.getMessage());
        }
        label.setPadding(20, 30, 20, 10);
        root.addView(label, new FrameLayout.LayoutParams(-1, -2));
        setContentView(root);
    }
}
