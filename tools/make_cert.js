#!/usr/bin/env node
/**
 * tools/make_cert.js — gjeneron certifikate self-signed per test-server.js.
 *
 * Pse duhet: shfletuesit lejojne kamera (getUserMedia) VETEM ne "secure context"
 * (HTTPS ose localhost). Per testim ne telefon mbi LAN, kjo kerkon HTTPS.
 *
 * Perdorimi:  node tools/make_cert.js
 * Rezultati:  certs/cert.pem + certs/key.pem (SAN me localhost + te gjitha IP-te LAN)
 *
 * Kufizim i sinqertë: self-signed => shfletuesi shfaq paralajmerim; kalohet me
 * "Advanced / Proceed". Nuk eshte certifikate publike e besuar.
 */
'use strict';
const { execFileSync } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const CERT_DIR = path.join(ROOT, 'certs');

const candidates = [
  'openssl',
  'C:\\Program Files\\Git\\usr\\bin\\openssl.exe',
  'C:\\Program Files\\Git\\mingw64\\bin\\openssl.exe',
  'C:\\Program Files\\OpenSSL-Win64\\bin\\openssl.exe',
];
const findOpenssl = () => {
  for (const c of candidates) {
    try { execFileSync(c, ['version'], { stdio: 'ignore' }); return c; } catch {}
  }
  return null;
};

const lanIps = () => {
  const out = [];
  for (const list of Object.values(os.networkInterfaces())) {
    for (const i of list || []) if (i.family === 'IPv4' && !i.internal) out.push(i.address);
  }
  return out;
};

const openssl = findOpenssl();
if (!openssl) {
  console.error('openssl nuk u gjet.');
  console.error('Instalo OpenSSL ose Git for Windows (përmban openssl), pastaj provo sërish.');
  console.error('Alternativë pa certifikatë: nis serverin me --http (kamera nuk punon, por linku manual po).');
  process.exit(1);
}

fs.mkdirSync(CERT_DIR, { recursive: true });
const ips = ['127.0.0.1', ...lanIps()];
const alt = ['DNS:localhost', ...ips.map((ip) => `IP:${ip}`)].join(',');
const conf = path.join(CERT_DIR, 'openssl.cnf');
fs.writeFileSync(conf, [
  '[req]', 'prompt = no', 'distinguished_name = dn', 'x509_extensions = ext',
  '[dn]', 'CN = CodeMors-Test', 'O = CodeMors local test', 'C = AL',
  '[ext]', `subjectAltName = ${alt}`, 'basicConstraints = CA:FALSE',
  'keyUsage = digitalSignature, keyEncipherment', 'extendedKeyUsage = serverAuth',
].join('\n'));

const certPath = path.join(CERT_DIR, 'cert.pem');
const keyPath = path.join(CERT_DIR, 'key.pem');

try {
  execFileSync(openssl, ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '365',
    '-keyout', keyPath, '-out', certPath, '-config', conf, '-sha256'], { stdio: 'pipe' });
} catch (e) {
  console.error('Gjenerimi i certifikates deshtoi:', e.message);
  process.exit(1);
}

console.log('Certifikata u krijua:');
console.log('  ' + certPath);
console.log('  ' + keyPath);
console.log('  SAN: ' + alt);
console.log('  Vlefshme: 365 dite | Self-signed (shfletuesi kerkon "Advanced -> Proceed")');
console.log('\nTani: node test-server.js');