package com.codemors.nativeapp;

import android.app.AlertDialog;
import android.content.Intent;
import android.os.Bundle;
import android.view.ViewGroup;
import android.widget.ArrayAdapter;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ListView;
import android.widget.TextView;
import android.widget.Toast;
import androidx.appcompat.app.AppCompatActivity;
import com.google.zxing.integration.android.IntentIntegrator;
import com.google.zxing.integration.android.IntentResult;
import org.json.JSONArray;
import org.json.JSONObject;

/** Contacts + ghost identity + QR pairing. Native Java. */
public class MainActivity extends AppCompatActivity {
    private ListView list;
    private TextView ghostView;
    private String ghostName, myPubHex;
    private java.security.KeyPair kp;

    @Override protected void onCreate(Bundle b) {
        super.onCreate(b);
        getWindow().setFlags(android.view.WindowManager.LayoutParams.FLAG_SECURE,
                android.view.WindowManager.LayoutParams.FLAG_SECURE); // anti screenshot/forensics
        Store.init(this);
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(24, 40, 24, 24);

        TextView logo = new TextView(this);
        logo.setText("CODE MORS — NATIVE");
        logo.setTextSize(20); logo.setLetterSpacing(0.2f);
        root.addView(logo);

        ghostView = new TextView(this);
        ghostView.setPadding(0, 16, 0, 8);
        root.addView(ghostView);

        TextView hint = new TextView(this);
        hint.setText("Tap contact to chat. Long-press = END SESSION (wipes phone+DB, keeps names)");
        hint.setTextSize(11); hint.setPadding(0, 0, 0, 12);
        root.addView(hint);

        list = new ListView(this);
        root.addView(list, new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, 0, 1));

        root.addView(btn("SCAN QR TO LINK", v -> new IntentIntegrator(this)
                .setDesiredBarcodeFormats(IntentIntegrator.QR_CODE)
                .setPrompt("Scan other user's Code Mors QR").initiateScan()));
        root.addView(btn("MY QR", v -> startActivity(new Intent(this, QrActivity.class))));
        root.addView(btn("IDENTITY", v -> editGhost()));

        setContentView(root);
        loadIdentity();
        renderContacts();
        // PRM + DeepGuard: refuzo/nuke nese mjedisi ose APK eshte i komprometuar
        if (!DeepGuard.verify(this)) return;
        if (!PrmPolicy.gate(this)) return;
    }

    private TextView btn(String label, android.view.View.OnClickListener l) {
        TextView t = new TextView(this);
        t.setText(label); t.setTextSize(14); t.setPadding(0, 20, 0, 20);
        t.setOnClickListener(l);
        return t;
    }
    private void loadIdentity() {
        ghostName = Store.get("ghost");
        if (ghostName == null) {
            String[] w = {"VOID","GHOST","RAVEN","ONYX","CIPHER","NOMAD","PHANTOM","ZERO"};
            ghostName = w[new java.util.Random().nextInt(w.length)] + "-" + Crypto.randomHex(2).toUpperCase();
            Store.put("ghost", ghostName);
        }
        try {
            String storedKp = Store.get("keypair");
            if (storedKp != null) {
                String[] parts = storedKp.split("\\|");
                kp = new java.security.KeyPair(Crypto.importPublicKey(parts[1]),
                        java.security.KeyFactory.getInstance("EC")
                                .generatePrivate(new java.security.spec.PKCS8EncodedKeySpec(Crypto.hexToBytes(parts[0]))));
            } else {
                kp = Crypto.generateEcdhKeyPair();
                Store.put("keypair", Crypto.bytesToHex(kp.getPrivate().getEncoded()) + "|" + Crypto.exportPublicKey(kp.getPublic()));
            }
            myPubHex = Crypto.exportPublicKey(kp.getPublic());
            ghostView.setText("GHOST: " + ghostName);
        } catch (Exception e) { Toast.makeText(this, "crypto init: " + e.getMessage(), Toast.LENGTH_LONG).show(); }
    }

    private void editGhost() {
        EditText in = new EditText(this); in.setText(ghostName);
        new AlertDialog.Builder(this).setTitle("Ghost identity (permanent)")
                .setView(in).setPositiveButton("SAVE", (d, w) -> {
                    String v = in.getText().toString().trim().toUpperCase();
                    if (v.length() >= 3) { ghostName = v; Store.put("ghost", v); ghostView.setText("GHOST: " + v); }
                }).setNegativeButton("CANCEL", null).show();
    }

    private void renderContacts() {
        JSONArray contacts = Store.getContacts();
        java.util.List<String> rows = new java.util.ArrayList<>();
        final java.util.List<JSONObject> objs = new java.util.ArrayList<>();
        for (int i = 0; i < contacts.length(); i++) {
            try {
                JSONObject c = contacts.getJSONObject(i);
                objs.add(c);
                rows.add(c.getString("name") + "   [mask: " + c.optString("submask") + "]");
            } catch (Exception ignored) {}
        }
        ArrayAdapter<String> ad = new ArrayAdapter<>(this, android.R.layout.simple_list_item_1, rows);
        list.setAdapter(ad);
        list.setOnItemClickListener((p, v, pos, id) -> {
            Intent it = new Intent(this, ChatActivity.class);
            // DeepGuard re-verify para hapjes se kanalit
            if (!DeepGuard.verify(this)) return;
            try { it.putExtra("cid", objs.get(pos).getString("id")); } catch (Exception ignored) {}
            // PRM gate para hapjes se kanalit
            startActivity(it);
        });
        list.setOnItemLongClickListener((p, v, pos, id) -> {
            new AlertDialog.Builder(this).setTitle("END SESSION?")
                    .setMessage("Deletes ALL messages from phone + database. Names are KEPT for reconnect.")
                    .setPositiveButton("DELETE & END", (d, w) -> {
                        try { endSession(objs.get(pos).getString("id")); } catch (Exception ignored) {}
                        Toast.makeText(this, "Session wiped - identity preserved", Toast.LENGTH_SHORT).show();
                    }).setNegativeButton("ABORT", null).show();
            return true;
        });
    }

    public static void endSession(String cid) {
        org.json.JSONObject msgs = Store.getMsgs();
        JSONArray arr = msgs.optJSONArray(cid);
        if (arr != null) for (int i = 0; i < arr.length(); i++) {
            try { Store.del("msg:" + arr.getJSONObject(i).getString("id")); } catch (Exception ignored) {}
        }
        msgs.remove(cid);
        Store.putMsgs(msgs);
    }
    @Override protected void onActivityResult(int req, int res, Intent data) {
        super.onActivityResult(req, res, data);
        IntentResult r = IntentIntegrator.parseActivityResult(req, res, data);
        if (r != null && r.getContents() != null) handleLinkData(r.getContents());
    }

    private void handleLinkData(String data) {
        try {
            JSONObject p = new JSONObject(data);
            String sess = Crypto.deriveSessionKey(kp.getPrivate(), p.getString("k"));
            JSONObject c = new JSONObject();
            c.put("id", Crypto.randomHex(8));
            c.put("name", p.optString("n", "UNKNOWN"));
            c.put("submask", "MASK_" + Crypto.randomHex(2).toUpperCase());
            c.put("sess", sess);
            c.put("pub", p.getString("k"));
            JSONArray contacts = Store.getContacts();
            contacts.put(c);
            Store.putContacts(contacts);
            renderContacts();
            Toast.makeText(this, "Linked with " + c.getString("name"), Toast.LENGTH_SHORT).show();
        } catch (Exception e) {
            Toast.makeText(this, "Invalid code: " + e.getMessage(), Toast.LENGTH_LONG).show();
        }
    }
}
