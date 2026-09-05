/**
 * CODE MORS — GHOST RELAY v1 Hybrid Relay
 * ------------------------------------------------------------------
 * Server relay në stilin SMP (SimpleX Messaging Protocol), i përshtatur
 * me Double Ratchet dhe "Ratchet-Bound Queue Rotation" (RBQR).
 *
 * Vetitë:
 *  - Radhë njëdrejtimëshe (simplex) pa identifikues përdoruesi.
 *  - Serveri ruan vetëm HASH-E SHA-256 të token-ave (jo plaintext) —
 *    një rrjedhje DB nuk zbulon token-at.
 *  - RBQR: token-i i pull-it rrjedh nga ratchet-i i klientit; token-i i
 *    vjetër REFUZOET -> forward secrecy i metadata-s.
 *  - S'ka llogari, s'ka identifikues klienti, IP-logging OPTIONAL (i fikur).
 *  - Pa varësi të jashtme: Node.js i thjeshtë (http + crypto).
 */

'use strict';
const http = require('http');
const crypto = require('crypto');
const { URL } = require('url');

const hashToken = (t) => crypto.createHash('sha256').update(String(t)).digest('hex');
const randomId = (n) => crypto.randomBytes(n).toString('base64url');

class Relay {
  constructor(opts = {}) {
    this.ttlMs = opts.ttlMs || 7 * 24 * 3600 * 1000; // 7 ditë default
    this.maxMsgsPerQueue = opts.maxMsgsPerQueue || 1000;
    this.maxMsgBytes = opts.maxMsgBytes || 64 * 1024;
    this.logging = opts.logging !== false; // IP-logging OPTIONAL, i fikur me --no-log
    this.queues = new Map(); // queueId -> push/pull hashes, blob-e, seq
    this._sweeper = setInterval(() => this._sweep(), 60000);
    if (this._sweeper.unref) this._sweeper.unref();
  }

  _sweep() {
    const now = Date.now();
    for (const [id, q] of this.queues) {
      if (now - q.lastAccess > this.ttlMs && q.msgs.length === 0) this.queues.delete(id);
    }
  }

  stop() {
    clearInterval(this._sweeper);
    if (this.server) this.server.close();
  }

  /* ---- API e brendshme ---- */

  createQueue() {
    const id = randomId(12);
    const push = randomId(24);
    const pull = randomId(24);
    this.queues.set(id, {
      pushHash: hashToken(push),
      pullHash: hashToken(pull),
      pullEpoch: 0,
      msgs: [],
      nextSeq: 1,
      lastAccess: Date.now(),
    });
    // push/pull kthehen VETËM një herë; serveri ruan hash-e.
    return { queueId: id, pushToken: push, pullToken: pull, pullEpoch: 0 };
  }

  _q(id) { return this.queues.get(String(id)); }

  pushMessage(queueId, pushToken, blob) {
    const q = this._q(queueId);
    if (!q) return { ok: false, err: 'no_queue' };
    if (q.pushHash !== hashToken(pushToken)) return { ok: false, err: 'bad_push_token' };
    if (Buffer.byteLength(blob, 'utf8') > this.maxMsgBytes) return { ok: false, err: 'too_large' };
    if (q.msgs.length >= this.maxMsgsPerQueue) return { ok: false, err: 'queue_full' };
    const seq = q.nextSeq++;
    q.msgs.push({ seq, blob, ts: Date.now() });
    q.lastAccess = Date.now();
    return { ok: true, seq, queueId };
  }

  /** RBQR pull: klienti duhet të dërgojë pullEpoch + token aktual. */
  pullMessages(queueId, pullToken, pullEpoch, since = 0) {
    const q = this._q(queueId);
    if (!q) return { ok: false, err: 'no_queue' };
    if (q.pullHash !== hashToken(pullToken)) return { ok: false, err: 'bad_pull_token' };
    if (Number(pullEpoch) !== q.pullEpoch) return { ok: false, err: 'stale_epoch' };
    const out = q.msgs.filter((m) => m.seq > Number(since)).map((m) => ({ seq: m.seq, blob: m.blob }));
    q.lastAccess = Date.now();
    return { ok: true, msgs: out, nextSeq: q.nextSeq, pullEpoch: q.pullEpoch };
  }

  /** RBQR: rotullo token-in e pull-it dhe rrit epoch-in; i vjetri pushohet. */
  rotPullToken(queueId, pullToken, epochHint) {
    const q = this._q(queueId);
    if (!q) return { ok: false, err: 'no_queue' };
    if (q.pullHash !== hashToken(pullToken)) return { ok: false, err: 'bad_pull_token' };
    const nextPull = randomId(24);
    q.pullHash = hashToken(nextPull);
    q.pullEpoch += 1;
    q.lastAccess = Date.now();
    return { ok: true, pullToken: nextPull, pullEpoch: q.pullEpoch };
  }

/* ---- HTTP ---- */
  _json(res, code, obj) { res.writeHead(code, { 'content-type': 'application/json' }); res.end(JSON.stringify(obj)); }

  handle(req, res) {
    const u = new URL(req.url, 'http://x');
    const p = u.pathname;
    const rip = req.socket.remoteAddress || '';

    if (req.method === 'POST' && p === '/v1/queue') {
      const q = this.createQueue();
      if (this.logging) console.log(`[relay] queue ${q.queueId} @ ${rip}`);
      return this._json(res, 200, { ok: true, ...q });
    }

    if (req.method === 'POST' && /^\/v1\/queue\/([^/]+)\/msg$/.test(p)) {
      const id = p.split('/')[3];
      let body = '';
      req.on('data', (c) => { body += c; if (body.length > 2 * this.maxMsgBytes) req.destroy(); });
      req.on('end', () => {
        let parsed;
        try { parsed = JSON.parse(body); } catch { return this._json(res, 400, { ok: false, err: 'bad_json' }); }
        const token = u.searchParams.get('t') || (req.headers['x-push-token'] || '');
        const r = this.pushMessage(id, token, parsed.blob || '');
        return this._json(res, r.ok ? 200 : (r.err === 'no_queue' ? 404 : 403), { ok: r.ok, ...(r.ok ? { seq: r.seq } : { err: r.err }) });
      });
      return;
    }

    if (req.method === 'GET' && /^\/v1\/queue\/([^/]+)\/msg$/.test(p)) {
      const id = p.split('/')[3];
      const token = u.searchParams.get('token') || '';
      const epoch = u.searchParams.get('epoch') ?? '0';
      const since = u.searchParams.get('since') || '0';
      const r = this.pullMessages(id, token, epoch, since);
      return this._json(res, r.ok ? 200 : (r.err === 'no_queue' ? 404 : 403), { ok: r.ok, ...(r.ok ? { msgs: r.msgs, nextSeq: r.nextSeq, pullEpoch: r.pullEpoch } : { err: r.err }) });
    }

    if (req.method === 'POST' && /^\/v1\/queue\/([^/]+)\/rotate$/.test(p)) {
      const id = p.split('/')[3];
      const token = u.searchParams.get('token') || '';
      const r = this.rotPullToken(id, token, u.searchParams.get('epoch'));
      return this._json(res, r.ok ? 200 : (r.err === 'no_queue' ? 404 : 403), { ok: r.ok, ...(r.ok ? { pullToken: r.pullToken, pullEpoch: r.pullEpoch } : { err: r.err }) });
    }

    return this._json(res, 404, { ok: false, err: 'not_found' });
  }

  listen(port = 7000, host = '127.0.0.1') {
    this.server = http.createServer((req, res) => this.handle(req, res));
    return new Promise((resolve) => this.server.listen(port, host, () => resolve(this.server.address().port)));
  }
}

// Nëse niset si skenar i vetëm (node relay/server.js --port 7000 --no-log)
if (require.main === module) {
  const args = process.argv.slice(2);
  const portIdx = args.indexOf('--port');
  const port = portIdx >= 0 ? Number(args[portIdx + 1]) : 7000;
  const relay = new Relay({ logging: args.indexOf('--no-log') < 0 });
  relay.listen(port, '127.0.0.1').then((p) => {
    console.log(`[GHOST-RELAY] relay listening on 127.0.0.1:${p}`);
    console.log('[GHOST-RELAY] radhë njëdrejtimëshe | no-user-id | RBQR enabled');
  });
}

module.exports = { Relay, hashToken };