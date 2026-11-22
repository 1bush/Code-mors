// Build-i i fortifikuar: mors-app.html -> mors-app.secure.html
// Obuskon skriptin inline kryesor me javascript-obfuscator (anti reverse-engineering).
// Përdorim: node tools/build.js  →  shërbe /mors-app.secure.html
'use strict';
const fs = require('fs'), path = require('path');
const obfuscator = require('javascript-obfuscator');

const SRC = path.join(__dirname, '..', 'mors-app.html');
const OUT = path.join(__dirname, '..', 'mors-app.secure.html');
const html = fs.readFileSync(SRC, 'utf8');
const open = html.indexOf('<script>');
const close = html.indexOf('</' + 'script>', open);
if (open < 0 || close < 0) { console.error('skripti inline nuk u gjet'); process.exit(1); }
const code = html.slice(open + 8, close);

const result = obfuscator.obfuscate(code, {
  compact: true,
  controlFlowFlattening: true,
  controlFlowFlatteningThreshold: 0.6,
  deadCodeInjection: true,
  deadCodeInjectionThreshold: 0.25,
  stringArray: true,
  stringArrayThreshold: 0.85,
  stringArrayEncoding: ['base64'],
  stringArrayRotate: true,
  stringArrayShuffle: true,
  splitStrings: false,
  renameGlobals: false,          // onclick handlers + pinFn eval emra must të mbeten
  identifierNamesGenerator: 'hexadecimal',
  numbersToExpressions: false,
  simplify: true,
  selfDefending: true,
  unicodeEscapeSequence: false,
  disableConsoleOutput: false,
});

const out = html.slice(0, open + 8) + '\n' + result.getObfuscatedCode() + '\n' + html.slice(close);
fs.writeFileSync(OUT, out);
console.log('OK →', OUT, '(' + (code.length / 1024).toFixed(0) + 'KB → ' + (result.getObfuscatedCode().length / 1024).toFixed(0) + 'KB obfuscated)');
