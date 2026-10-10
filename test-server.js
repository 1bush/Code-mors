#!/usr/bin/env node
/**
 * test-server.js — server i vetem per TESTIM (web + relay ne te njejtin port).
 *
 * Pse: aplikacioni web (mors-app.html) dhe relay-i ishin dy procese/porta te
 * ndryshme. Per testim ne telefon, nje host + nje port e ben gjithçka me te
 * thjeshte: i njejti origin sherben faqen dhe API-ne /v1/*, keshtu app-i nuk
 * ka nevoje per CORS e as per konfigurim relay-i.
 *
 * Perdorimi:
 *   node test-server.js                 # HTTPS nese ka certs/cert.pem, HTTP ndryshe
 *   node test-server.js --port 8080     # port tjeter
 *   node test-server.js --http          # detyro HTTP (pa kamera/HTTPS)
 *   node test-server.js --tunnel        # shtyp udhezimin per cloudflared/ngrok
 *
 * Kufizim: certifikata self-signed -> shfletuesi kerkon pranim manual ("Advanced").
 * Per kamera (getUserMedia) duhet HTTPS ose localhost — shih TEST-SERVER.md.
 */
'use strict';
const http = require('http');
const https = require('https');
const fs = require('fs');
const path = require('path');
const os = require('os');
const { Relay } = require('./relay/server.js');

const ROOT = __dirname;
const args = process.argv.slice(2);
const flag = (n) => args.includes(n);
const opt = (n, d) => { const i = args.indexOf(n); return i >= 0 ? args[i + 1] : d; };

const PORT = Number(opt('--port', 8443));
const FORCE_HTTP = flag('--http');
const CERT = path.join(ROOT, 'certs', 'cert.pem');
const KEY = path.join(ROOT, 'certs', 'key.pem');
const HAS_CERT = fs.existsSync(CERT) && fs.existsSync(KEY);
const USE_TLS = !FORCE_HTTP && HAS_CERT;

/* ---- static i kufizuar: nuk sherbehen skedare sensitive ---- */
const MIME = {
  '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8',
  '.mjs': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8', '.svg': 'image/svg+xml', '.png': 'image/png',
  '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg', '.ico': 'image/x-icon', '.webp': 'image/webp',
  '.woff2': 'font/woff2', '.apk': 'application/vnd.android.package-archive',
};
const BLOCKED = [/^\.git(\/|$)/i, /^node_modules(\/|$)/i, /^certs(\/|$)/i, /^android-native(\/|$)/i,
  /^tools(\/|$)/i, /\.log$/i, /_log\.txt$/i, /\.pem$/i, /\.key$/i, /\.BAK$/i, /^\.env/i,
  /\.apk$/i, /^\.expo(\/|$)/i, /^admin-dashboard(\/|$)/i];

const relay = new Relay({ logging: false });

function serveStatic(req, res) {
  const urlPath = decodeURIComponent((req.url || '/').split('?')[0]);
  let rel = urlPath === '/' ? 'mors-app.html' : urlPath.replace(/^\/+/, '');
  rel = path.posix.normalize(rel);
  if (rel.startsWith('..') || BLOCKED.some((r) => r.test(rel))) {
    res.writeHead(403, { 'content-type': 'text/plain' }); return res.end('forbidden');
  }
  const file = path.join(ROOT, rel);
  if (!file.startsWith(ROOT)) { res.writeHead(403); return res.end('forbidden'); }
  fs.readFile(file, (err, data) => {
    if (err) { res.writeHead(404, { 'content-type': 'text/plain' }); return res.end('not found'); }
    res.writeHead(200, {
      'content-type': MIME[path.extname(rel).toLowerCase()] || 'application/octet-stream',
      'cache-control': 'no-store',
      'x-content-type-options': 'nosniff',
    });
    res.end(data);
  });
}

function handler(req, res) {
  const p = (req.url || '/').split('?')[0];
  if (p.startsWith('/v1/')) return relay.handle(req, res);
  if (p === '/healthz') {
    return res.end(JSON.stringify({ ok: true, mode: USE_TLS ? 'https' : 'http', port: PORT, uptime: Math.round(process.uptime()), queues: relay.queues.size, invites: relay.invites.size }));
  }
  return serveStatic(req, res);
}

const server = USE_TLS
  ? https.createServer({ cert: fs.readFileSync(CERT), key: fs.readFileSync(KEY) }, handler)
  : http.createServer(handler);

const lanAddresses = () => {
  const out = [];
  for (const list of Object.values(os.networkInterfaces())) {
    for (const i of list || []) if (i.family === 'IPv4' && !i.internal) out.push(i.address);
  }
  return out;
};

server.listen(PORT, '0.0.0.0', () => {
  const scheme = USE_TLS ? 'https' : 'http';
  console.log('==========================================================');
  console.log(' CODE MORS — server testimi (web + relay, nje port)');
  console.log('==========================================================');
  console.log(`  Gjendja     : ${USE_TLS ? 'HTTPS (cert self-signed)' : 'HTTP (pa TLS)'}${USE_TLS ? '' : HAS_CERT ? ' [certs u injorua me --http]' : ' [certs/*.pem mungon]'}`);
  console.log(`  Vendore     : ${scheme}://localhost:${PORT}`);
  for (const ip of lanAddresses()) console.log(`  Ne telefon  : ${scheme}://${ip}:${PORT}`);
  console.log('  Ftesat      : ' + `${scheme}://<IP>:${PORT}/?relay=` + '(bosh = i njejti origin)');
  console.log('  Shendeti    : ' + `${scheme}://localhost:${PORT}/healthz`);
  console.log('  Kodi        : PIN fillestar 0000 (nese s`ka PIN te ruajtur)');
  console.log('----------------------------------------------------------');
  if (!USE_TLS) console.log('  SHENIM: pa HTTPS, kamera (skanimi QR) bllokohet nga shfletuesi.\n          Perkundrazi perdor ngjitjen manuale te linkut, ose nis me HTTPS.');
  console.log('  Fikja: Ctrl+C');
  if (flag('--tunnel')) {
    console.log('----------------------------------------------------------');
    console.log('  Tunel HTTPS pa certifikate lokale (per kamera):');
    console.log(`    cloudflared tunnel --url ${scheme}://localhost:${PORT}`);
    console.log(`    ngrok http ${PORT}`);
  }
  console.log('==========================================================');
});

process.on('SIGINT', () => { try { relay.stop(); } catch {} server.close(() => process.exit(0)); });
