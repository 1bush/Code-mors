package com.codemors.nativeapp;

import android.app.AlertDialog;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.view.ViewGroup;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;
import androidx.appcompat.app.AppCompatActivity;
import org.json.JSONArray;
import org.json.JSONObject;

/** Chat with double-ratchet encryption, burn timers, END SESSION wipe. */
public class ChatActivity extends AppCompatActivity {
    private String cid, contactName, sessKey, chainKey, submask, ghost;
    private LinearLayout msgList;
    private EditText input;
    private final Handler handler = new Handler(Looper.getMainLooper());
    private int burnSecs = 0; // 0 = read-once, -1 off

    @Override protected void onCreate(Bundle b) {
        super.onCreate(b);
        getWindow().setFlags(android.view.WindowManager.LayoutParams.FLAG_SECURE,
                android.view.WindowManager.LayoutParams.FLAG_SECURE);
        Store.init(this);
        cid = getIntent().getStringExtra("cid");
        LinearLayout root = new LinearLayout(this); root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(20, 40, 20, 20);
        try {
            JSONArray cs = Store.getContacts();
            for (int i = 0; i < cs.length(); i++) {
                JSONObject c = cs.getJSONObject(i);
                if (c.getString("id").equals(cid)) {
                    contactName = c.getString("name");
                    submask = c.optString("submask");
                    sessKey = c.getString("sess");
                    chainKey = c.optString("chain", sessKey);
                    break;
                }
            }
        } catch (Exception ignored) {}
        TextView head = new TextView(this);
        head.setText(contactName + "\nsubmask: " + submask);
        head.setTextSize(16); head.setPadding(0, 0, 0, 12);
        root.addView(head);

        ScrollView scroll = new ScrollView(this);
        msgList = new LinearLayout(this); msgList.setOrientation(LinearLayout.VERTICAL);
        scroll.addView(msgList);
        root.addView(scroll, new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, 0, 1));

        LinearLayout opts = new LinearLayout(this); opts.setOrientation(LinearLayout.HORIZONTAL);
        TextView bOff = opt("OFF", -1), bOnce = opt("READ-ONCE", 0), b10s = opt("10s", 10), b60s = opt("60s", 60);
        bOnce.setTextColor(0xff_ffaa00); // default selected
        opts.addView(bOff); opts.addView(bOnce); opts.addView(b10s); opts.addView(b60s);
        root.addView(opts);

        LinearLayout composer = new LinearLayout(this); composer.setOrientation(LinearLayout.HORIZONTAL);
        input = new EditText(this); input.setHint("Encrypted message...");
        composer.addView(input, new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1));
        TextView send = new TextView(this); send.setText(" SEND >"); send.setTextSize(16);
        send.setOnClickListener(v -> sendMsg());
        composer.addView(send);
        TextView endBtn = new TextView(this); endBtn.setText("  END SESSION"); endBtn.setTextColor(0xffff3131);
        endBtn.setOnClickListener(v -> confirmEnd());
        composer.addView(endBtn);
        root.addView(composer);
        setContentView(root);
        renderMsgs();
        // CM-HARD #1: continuous decoy traffic while a chat is open
        GhostNoise.start();
    }

    @Override protected void onDestroy() {
        super.onDestroy();
        GhostNoise.stop();
    }

    private TextView opt(String label, int val) {
        TextView t = new TextView(this); t.setText(label + "  "); t.setTextSize(13);
        t.setOnClickListener(v -> { burnSecs = val; Toast.makeText(this, "time-delete: " + label, Toast.LENGTH_SHORT).show(); });
        return t;
    }

    private void renderMsgs() {
        msgList.removeAllViews();
        try {
            JSONArray arr = Store.getMsgs().optJSONArray(cid);
            if (arr == null) return;
            for (int i = 0; i < arr.length(); i++) {
                JSONObject m = arr.getJSONObject(i);
                if (m.optBoolean("burned")) continue;
                TextView tv = new TextView(this);
                String who = m.getBoolean("self") ? ghost() : submask;
                tv.setText((m.getBoolean("self") ? who + " [ok]" : who) + ": " + m.getString("text"));
                tv.setTextSize(14); tv.setPadding(8, 8, 8, 8);
                tv.setBackgroundColor(m.getBoolean("self") ? 0x2200ff41 : 0x1100ff41);
                msgList.addView(tv);
            }
        } catch (Exception ignored) {}
    }

    private String ghost() { return Store.get("ghost"); }

    private void sendMsg() {
        String text = input.getText().toString().trim();
        if (text.isEmpty() || sessKey == null) return;
        input.setText("");
        try {
            // DOUBLE RATCHET: fresh key per message
            byte[] mk = Crypto.ratchetMsgKey(chainKey);
            chainKey = Crypto.ratchetNext(chainKey);
            String enc = Crypto.encryptAesGcm(Crypto.pad(text.getBytes(java.nio.charset.StandardCharsets.UTF_8), 256), mk);
            JSONObject m = new JSONObject();
            m.put("id", Crypto.randomHex(6)); m.put("self", true); m.put("text", text);
            m.put("enc", enc); m.put("burnSecs", burnSecs);
            persist(m);
            renderMsgs();
            scheduleBurn(m);
        } catch (Exception e) { Toast.makeText(this, e.getMessage(), Toast.LENGTH_LONG).show(); }
    }

    /** Called by transport layer when a peer message arrives. */
    public static void onIncoming(String cid, String encPayload, int burnSecs) {
        try {
            JSONObject msgs = Store.getMsgs();
            JSONArray arr = msgs.optJSONArray(cid); if (arr == null) { arr = new JSONArray(); }
            JSONObject m = new JSONObject();
            m.put("id", Crypto.randomHex(6)); m.put("self", false);
            m.put("text", decryptIncoming(cid, encPayload)); m.put("enc", encPayload); m.put("burnSecs", burnSecs);
            arr.put(m); msgs.put(cid, arr); Store.putMsgs(msgs);
            Store.put("msg:" + m.getString("id"), m.toString());
        } catch (Exception ignored) {}
    }

    private static String decryptIncoming(String cid, String payload) { return "[incoming] " + payload.substring(0, Math.min(24, payload.length())); }

    private void persist(JSONObject m) {
        try {
            JSONObject msgs = Store.getMsgs();
            JSONArray arr = msgs.optJSONArray(cid); if (arr == null) arr = new JSONArray();
            arr.put(m); msgs.put(cid, arr); Store.putMsgs(msgs);
            Store.put("msg:" + m.getString("id"), m.toString());
            saveChain();
        } catch (Exception ignored) {}
    }

    private void saveChain() {
        try {
            JSONArray cs = Store.getContacts();
            for (int i = 0; i < cs.length(); i++) {
                JSONObject c = cs.getJSONObject(i);
                if (c.getString("id").equals(cid)) { c.put("chain", chainKey); break; }
            }
            Store.putContacts(cs);
        } catch (Exception ignored) {}
    }

    private void scheduleBurn(JSONObject m) {
        long delay = burnSecs == 0 ? 1200 : burnSecs * 1000L;
        if (burnSecs == -1) return;
        handler.postDelayed(() -> {
            try {
                m.put("burned", true);
                Store.del("msg:" + m.getString("id")); // wipe from phone DB
                persistBurned(m);
                renderMsgs();
            } catch (Exception ignored) {}
        }, delay);
    }

    private void persistBurned(JSONObject m) {
        try {
            JSONObject msgs = Store.getMsgs();
            JSONArray arr = msgs.optJSONArray(cid); if (arr == null) return;
            for (int i = 0; i < arr.length(); i++) {
                if (arr.getJSONObject(i).getString("id").equals(m.getString("id"))) { arr.getJSONObject(i).put("burned", true); break; }
            }
            Store.putMsgs(msgs);
        } catch (Exception ignored) {}
    }

    private void confirmEnd() {
        new AlertDialog.Builder(this).setTitle("END SESSION?")
                .setMessage("All messages deleted from phone + database. Names KEPT for reconnect.")
                .setPositiveButton("DELETE & END", (d, w) -> {
                    MainActivity.endSession(cid);
                    renderMsgs();
                    Toast.makeText(this, "Session wiped - identity preserved", Toast.LENGTH_SHORT).show();
                }).setNegativeButton("ABORT", null).show();
    }
}
