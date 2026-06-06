// TheAilogy — Baker onboarding. Minimal server-side auth gate.
// One internal user (Edita) + Director. Credentials + secret come from env vars.
// Content (index.html) is NEVER served statically — only after a valid session.
'use strict';

const express = require('express');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const app = express();
app.disable('x-powered-by');
app.set('trust proxy', 1); // Render terminates TLS at the proxy
app.use(express.urlencoded({ extended: false, limit: '8kb' }));

const PORT = process.env.PORT || 3000;
const USER = process.env.AIOLOGY_USER || '';
const PASS = process.env.AIOLOGY_PASS || '';
// Optional multi-user map: AIOLOGY_USERS = {"edita":"pw1","dimitry":"pw2"}
let USERS = {};
try { if (process.env.AIOLOGY_USERS) USERS = JSON.parse(process.env.AIOLOGY_USERS); }
catch (e) { console.warn('WARN: AIOLOGY_USERS is not valid JSON — ignoring.'); }
const SECRET = process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex');
const MAX_AGE_MS = 1000 * 60 * 60 * 24 * 7; // 7 days
const COOKIE = 'aiology_session';
const INDEX = path.join(__dirname, 'index.html');

// ---- session token: stateless, HMAC-signed, expiring ----
function sign(payload) {
  return crypto.createHmac('sha256', SECRET).update(payload).digest('hex');
}
function makeToken() {
  const payload = 'ok:' + (Date.now() + MAX_AGE_MS);
  return payload + '.' + sign(payload);
}
function validToken(tok) {
  if (!tok || typeof tok !== 'string') return false;
  const i = tok.lastIndexOf('.');
  if (i < 0) return false;
  const payload = tok.slice(0, i);
  const sig = tok.slice(i + 1);
  const expected = sign(payload);
  if (sig.length !== expected.length) return false;
  if (!crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected))) return false;
  const exp = parseInt(payload.split(':')[1], 10);
  return Number.isFinite(exp) && Date.now() < exp;
}
function parseCookies(req) {
  const out = {};
  const h = req.headers.cookie;
  if (!h) return out;
  h.split(';').forEach((p) => {
    const idx = p.indexOf('=');
    if (idx > -1) out[p.slice(0, idx).trim()] = decodeURIComponent(p.slice(idx + 1).trim());
  });
  return out;
}
function isAuthed(req) {
  return validToken(parseCookies(req)[COOKIE]);
}
// constant-time credential check (length-safe)
function checkCreds(u, p) {
  u = (u || '').toLowerCase();
  p = p || '';
  // multi-user map takes precedence
  if (USERS && Object.keys(USERS).length) {
    const expected = USERS[u];
    if (typeof expected === 'string' && safeEq(p, expected)) return true;
  }
  // fallback: single AIOLOGY_USER / AIOLOGY_PASS
  if (USER && PASS && safeEq(u, USER.toLowerCase()) && safeEq(p, PASS)) return true;
  return false;
}
function safeEq(a, b) {
  const ab = Buffer.from(String(a));
  const bb = Buffer.from(String(b));
  if (ab.length !== bb.length) {
    // still spend time, then fail
    crypto.timingSafeEqual(bb, bb);
    return false;
  }
  return crypto.timingSafeEqual(ab, bb);
}

// ---- login page (tech-minimal, matches the app) ----
function loginPage(error) {
  return `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>TheAilogy — Sign in</title>
<style>
  :root{--ink:#0b0d12;--muted:#5b616e;--line:#e9eaed;--canvas:#fbfbfc;--accent:#1d4ed8;--accent-weak:#eef2fe;
        --mono:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
        --sans:-apple-system,BlinkMacSystemFont,"Inter","Segoe UI",system-ui,sans-serif;}
  *{box-sizing:border-box}
  body{margin:0;min-height:100vh;display:grid;place-items:center;background:var(--canvas);
       font-family:var(--sans);color:var(--ink);letter-spacing:-0.005em;}
  .card{width:340px;max-width:92vw;background:#fff;border:1px solid var(--line);border-radius:14px;
        padding:30px 28px 26px;box-shadow:0 16px 48px rgba(11,13,18,.06);}
  .mark{width:34px;height:34px;border-radius:8px;background:var(--ink);color:#fff;display:grid;place-items:center;
        font-weight:650;font-size:17px;font-family:Georgia,serif;margin-bottom:18px;}
  h1{font-size:19px;letter-spacing:-0.02em;margin:0 0 4px;font-weight:620;}
  p.sub{font-size:13px;color:var(--muted);margin:0 0 22px;}
  label{display:block;font-size:10px;text-transform:uppercase;letter-spacing:.12em;color:var(--muted);
        font-weight:600;font-family:var(--mono);margin:14px 0 6px;}
  input{width:100%;padding:10px 12px;border:1px solid var(--line);border-radius:8px;font-size:14px;
        font-family:inherit;background:var(--canvas);color:var(--ink);}
  input:focus{outline:none;border-color:var(--accent);box-shadow:0 0 0 3px var(--accent-weak);}
  button{width:100%;margin-top:20px;padding:11px;border:none;border-radius:8px;background:var(--ink);color:#fff;
         font-size:14px;font-weight:550;font-family:inherit;cursor:pointer;letter-spacing:-0.01em;}
  button:hover{background:#23262e;}
  .err{margin-top:16px;font-size:13px;color:#b3261e;background:#fdecec;border:1px solid #f3c9c9;
       border-radius:8px;padding:9px 12px;}
  .foot{margin-top:18px;font-size:11px;color:var(--muted);font-family:var(--mono);text-align:center;}
</style></head>
<body>
  <form class="card" method="POST" action="/login" autocomplete="off">
    <div class="mark">A</div>
    <h1>Sign in to TheAilogy</h1>
    <p class="sub">Baker onboarding · internal access</p>
    <label for="u">User ID</label>
    <input id="u" name="username" type="text" autocapitalize="none" autocorrect="off" required autofocus>
    <label for="p">Password</label>
    <input id="p" name="password" type="password" required>
    <button type="submit">Continue</button>
    ${error ? `<div class="err">${error}</div>` : ''}
    <div class="foot">authorised users only</div>
  </form>
</body></html>`;
}

// ---- routes ----
app.get('/login', (req, res) => {
  if (isAuthed(req)) return res.redirect('/');
  res.set('Cache-Control', 'no-store').type('html').send(loginPage(''));
});

app.post('/login', (req, res) => {
  const { username, password } = req.body || {};
  if (checkCreds(username, password)) {
    res.cookie(COOKIE, makeToken(), {
      httpOnly: true,
      secure: true,
      sameSite: 'lax',
      maxAge: MAX_AGE_MS,
      path: '/',
    });
    return res.redirect('/');
  }
  res.status(401).set('Cache-Control', 'no-store').type('html')
     .send(loginPage('Incorrect ID or password.'));
});

app.get('/logout', (req, res) => {
  res.clearCookie(COOKIE, { path: '/' });
  res.redirect('/login');
});

app.get('/healthz', (req, res) => res.type('text').send('ok'));

// gated example pages (project-room HTML) — served only after a valid session
app.use('/rooms', (req, res, next) => {
  if (!isAuthed(req)) return res.redirect('/login');
  next();
}, express.static(path.join(__dirname, 'rooms'), { extensions: ['html'], dotfiles: 'deny', index: false }));

// everything else: gated
app.get('*', (req, res) => {
  if (!isAuthed(req)) return res.redirect('/login');
  res.set('Cache-Control', 'no-store').sendFile(INDEX);
});

app.listen(PORT, () => {
  if (!USER || !PASS) console.warn('WARN: AIOLOGY_USER / AIOLOGY_PASS not set — login will reject all.');
  console.log('TheAilogy gate listening on :' + PORT);
});
