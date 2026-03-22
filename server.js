'use strict';

const express     = require('express');
const http        = require('http');
const { WebSocketServer } = require('ws');
const bcrypt      = require('bcryptjs');
const jwt         = require('jsonwebtoken');
const webpush     = require('web-push');
const path        = require('path');
const fs          = require('fs');
const crypto      = require('crypto');
const helmet      = require('helmet');
const rateLimit   = require('express-rate-limit');
const { body, validationResult } = require('express-validator');

const app    = express();
const server = http.createServer(app);
const wss    = new WebSocketServer({ server });

// ── HELMET — header HTTP sicuri ───────────────────────────────────────────────
app.use(helmet({
  contentSecurityPolicy: false, // disabilitato perché API pura, niente HTML
  crossOriginEmbedderPolicy: false,
}));
app.use(express.json({ limit: '100kb' })); // Limita dimensione body

// ── CORS restrittivo ──────────────────────────────────────────────────────────
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || '*').split(',');
app.use((req, res, next) => {
  const origin = req.headers.origin;
  if (ALLOWED_ORIGINS.includes('*') || !origin || ALLOWED_ORIGINS.includes(origin)) {
    res.header('Access-Control-Allow-Origin', origin || '*');
  }
  res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.header('Access-Control-Allow-Methods', 'GET, POST, DELETE, OPTIONS');
  if (req.method === 'OPTIONS') return res.sendStatus(200);
  next();
});

// ── CONFIGURAZIONE ────────────────────────────────────────────────────────────
const JWT_SECRET     = process.env.JWT_SECRET;
const JWT_SECRET_ALT = process.env.JWT_SECRET_ALT || ''; // per rotazione chiavi
if (!JWT_SECRET) {
  console.error('[FATAL] JWT_SECRET non configurato! Impostalo su Render.');
  process.exit(1);
}
if (JWT_SECRET.length < 32) {
  console.error('[FATAL] JWT_SECRET troppo corto (min 32 caratteri).');
  process.exit(1);
}

const VAPID_PUBLIC  = process.env.VAPID_PUBLIC_KEY  || '';
const VAPID_PRIVATE = process.env.VAPID_PRIVATE_KEY || '';
const VAPID_EMAIL   = process.env.VAPID_EMAIL       || 'mailto:admin@scanpc.local';
const ADMIN_USER    = process.env.ADMIN_USER        || 'admin';
const ADMIN_PASS    = process.env.ADMIN_PASS;
const DATA_DIR      = process.env.DATA_DIR ||
  (process.env.RENDER ? '/opt/render/project/src/data' : path.join(__dirname, 'data'));

if (!ADMIN_PASS) {
  console.error('[FATAL] ADMIN_PASS non configurato!');
  process.exit(1);
}

if (VAPID_PUBLIC && VAPID_PRIVATE) {
  webpush.setVapidDetails(VAPID_EMAIL, VAPID_PUBLIC, VAPID_PRIVATE);
}

// ── PERSISTENZA FILE ──────────────────────────────────────────────────────────
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

const USERS_FILE    = path.join(DATA_DIR, 'users.json');
const QUEUE_FILE    = path.join(DATA_DIR, 'queue.json');
const PUSH_FILE     = path.join(DATA_DIR, 'push_subs.json');
const BLACKLIST_FILE= path.join(DATA_DIR, 'token_blacklist.json');
const AUDIT_FILE    = path.join(DATA_DIR, 'audit.log');

function loadJson(file, def) {
  try {
    if (fs.existsSync(file)) return JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch (e) { console.error('[DATA] Errore lettura', file, e.message); }
  return def;
}
function saveJson(file, data) {
  try { fs.writeFileSync(file, JSON.stringify(data, null, 2), 'utf8'); }
  catch (e) { console.error('[DATA] Errore scrittura', file, e.message); }
}

const users     = new Map(Object.entries(loadJson(USERS_FILE, {})));
const msgQueue  = new Map(Object.entries(loadJson(QUEUE_FILE, {})));
const pushSubs  = new Map(Object.entries(loadJson(PUSH_FILE,  {})));
// Token blacklist: Set di jti (JWT ID) revocati
const tokenBlacklist = new Set(loadJson(BLACKLIST_FILE, []));

function persistUsers()    { saveJson(USERS_FILE, Object.fromEntries(users)); }
function persistQueue()    { saveJson(QUEUE_FILE, Object.fromEntries(msgQueue)); }
function persistPushSubs() { saveJson(PUSH_FILE,  Object.fromEntries(pushSubs)); }
function persistBlacklist(){ saveJson(BLACKLIST_FILE, [...tokenBlacklist]); }

// ── AUDIT LOG ─────────────────────────────────────────────────────────────────
function audit(action, username, details = '', req = null) {
  const ip  = req ? (req.headers['x-forwarded-for'] || req.socket.remoteAddress || '-') : '-';
  const ts  = new Date().toISOString();
  const row = `${ts} | ${action.padEnd(20)} | ${(username||'-').padEnd(20)} | ip:${ip} | ${details}\n`;
  try { fs.appendFileSync(AUDIT_FILE, row, 'utf8'); } catch(e) { /* non bloccare */ }
  console.log(`[AUDIT] ${action} | ${username || '-'} | ${details}`);
}

// ── PULIZIA TOKEN BLACKLIST (ogni ora rimuovi i token scaduti) ─────────────────
function cleanBlacklist() {
  const now = Math.floor(Date.now() / 1000);
  let cleaned = 0;
  for (const jti of tokenBlacklist) {
    try {
      const parts = jti.split('.');
      if (parts.length === 3) {
        const payload = JSON.parse(Buffer.from(parts[1], 'base64').toString());
        if (payload.exp && payload.exp < now) { tokenBlacklist.delete(jti); cleaned++; }
      }
    } catch { tokenBlacklist.delete(jti); cleaned++; }
  }
  if (cleaned > 0) { persistBlacklist(); console.log(`[BLACKLIST] Rimossi ${cleaned} token scaduti`); }
}
setInterval(cleanBlacklist, 60 * 60 * 1000);

// ── CREAZIONE ADMIN DI DEFAULT ────────────────────────────────────────────────
(async () => {
  if (!users.has(ADMIN_USER)) {
    const hash = await bcrypt.hash(ADMIN_PASS, 12); // bcrypt rounds=12 più sicuro
    users.set(ADMIN_USER, {
      passwordHash: hash, role: 'admin',
      createdAt: new Date().toISOString(),
      failedAttempts: 0, lockedUntil: null,
    });
    persistUsers();
    audit('ADMIN_CREATED', ADMIN_USER, 'Admin creato al primo avvio');
  }
})();

// ── CODA MESSAGGI ─────────────────────────────────────────────────────────────
function enqueue(username, type, payload) {
  if (!msgQueue.has(username)) msgQueue.set(username, []);
  const q = msgQueue.get(username);
  if (q.length >= 200) q.shift();
  q.push({ id: crypto.randomUUID(), type, payload, ts: new Date().toISOString() });
  persistQueue();
}
function flushQueue(username, ws) {
  const q = msgQueue.get(username);
  if (!q || q.length === 0) return;
  console.log(`[QUEUE] Flush ${q.length} messaggi per ${username}`);
  q.forEach(item => {
    if (ws.readyState === 1)
      ws.send(JSON.stringify({ ...item.payload, _queued: true, _queuedAt: item.ts }));
  });
  msgQueue.set(username, []);
  persistQueue();
}

// ── CONNESSIONI ───────────────────────────────────────────────────────────────
const clients  = new Map(); // Map<username, Set<ws>>
const services = new Set(); // ws del servizio Java

function addClient(username, ws) {
  if (!clients.has(username)) clients.set(username, new Set());
  clients.get(username).add(ws);
}
function removeClient(username, ws) {
  const set = clients.get(username);
  if (set) { set.delete(ws); if (set.size === 0) clients.delete(username); }
  services.delete(ws);
}
function sendTo(username, msg) {
  const set = clients.get(username);
  const raw = JSON.stringify(msg);
  if (set && set.size > 0) {
    let sent = false;
    set.forEach(ws => { if (ws.readyState === 1) { ws.send(raw); sent = true; } });
    return sent;
  }
  return false;
}
function sendToServices(msg) {
  const raw = JSON.stringify(msg);
  let count = 0;
  services.forEach(ws => { if (ws.readyState === 1) { ws.send(raw); count++; } });
  return count;
}
function broadcastToDesktop(msg, excludeUsername = null) {
  let count = 0;
  users.forEach((u, username) => {
    if (['desktop', 'admin'].includes(u.role) && username !== excludeUsername)
      if (sendTo(username, msg)) count++;
  });
  return count;
}
function broadcastToScanner(msg, excludeUsername = null) {
  let count = 0;
  users.forEach((u, username) => {
    if (u.role === 'scanner' && username !== excludeUsername)
      if (sendTo(username, msg)) count++;
  });
  return count;
}
function broadcastStatus() {
  const online = [...clients.keys()];
  const msg = JSON.stringify({ type: 'user_list', online, registered: [...users.keys()] });
  clients.forEach(set => set.forEach(ws => { if (ws.readyState === 1) ws.send(msg); }));
  services.forEach(ws => { if (ws.readyState === 1) ws.send(msg); });
}

// ── PUSH ──────────────────────────────────────────────────────────────────────
async function pushToUser(username, payload) {
  if (!VAPID_PUBLIC || !VAPID_PRIVATE) return 0;
  const subs = pushSubs.get(username);
  if (!subs || !subs.length) return 0;
  const msg = JSON.stringify(payload);
  const dead = [];
  let sent = 0;
  for (const sub of subs) {
    try { await webpush.sendNotification(sub, msg); sent++; }
    catch (e) { if (e.statusCode === 410) dead.push(sub); }
  }
  dead.forEach(d => subs.splice(subs.indexOf(d), 1));
  if (dead.length) persistPushSubs();
  return sent;
}
async function pushToDesktop(payload) {
  let total = 0;
  for (const [username, u] of users)
    if (['desktop', 'admin'].includes(u.role))
      total += await pushToUser(username, payload);
  return total;
}

// ── MIDDLEWARE AUTH ───────────────────────────────────────────────────────────
function requireAuth(req, res, next) {
  const token = (req.headers.authorization || '').replace('Bearer ', '').trim();
  if (!token) return res.status(401).json({ error: 'Token mancante' });
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    // Controlla blacklist
    if (decoded.jti && tokenBlacklist.has(decoded.jti))
      return res.status(401).json({ error: 'Token revocato' });
    req.user = decoded;
    next();
  } catch (e) {
    // Prova con chiave alternativa per rotazione
    if (JWT_SECRET_ALT) {
      try {
        const decoded = jwt.verify(token, JWT_SECRET_ALT);
        if (decoded.jti && tokenBlacklist.has(decoded.jti))
          return res.status(401).json({ error: 'Token revocato' });
        req.user = decoded;
        return next();
      } catch {}
    }
    audit('AUTH_FAIL', '-', `Token non valido: ${e.message}`, req);
    res.status(401).json({ error: 'Token non valido o scaduto' });
  }
}
function requireAdmin(req, res, next) {
  requireAuth(req, res, () => {
    if (req.user.role !== 'admin') {
      audit('AUTHZ_FAIL', req.user.username, 'Accesso admin negato', req);
      return res.status(403).json({ error: 'Permessi insufficienti' });
    }
    next();
  });
}

// ── RATE LIMITING ─────────────────────────────────────────────────────────────
// Login: max 10 tentativi ogni 15 minuti per IP
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: { error: 'Troppi tentativi di login. Riprova tra 15 minuti.' },
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res, next, options) => {
    audit('RATE_LIMIT', '-', `Login bloccato per IP: ${req.ip}`, req);
    res.status(429).json(options.message);
  },
});

// API generica: max 100 req/minuto per IP
const apiLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 100,
  message: { error: 'Troppe richieste. Rallenta.' },
});
app.use('/api/', apiLimiter);

// ── ACCOUNT LOCKOUT (dopo 5 tentativi falliti, blocca 15 min) ─────────────────
const MAX_FAILED = 5;
const LOCKOUT_MS = 15 * 60 * 1000;

async function checkLockout(username) {
  const user = users.get(username);
  if (!user) return false;
  if (user.lockedUntil && Date.now() < user.lockedUntil) return true;
  if (user.lockedUntil && Date.now() >= user.lockedUntil) {
    user.failedAttempts = 0; user.lockedUntil = null; persistUsers();
  }
  return false;
}
async function recordFailedLogin(username) {
  const user = users.get(username);
  if (!user) return;
  user.failedAttempts = (user.failedAttempts || 0) + 1;
  if (user.failedAttempts >= MAX_FAILED) {
    user.lockedUntil = Date.now() + LOCKOUT_MS;
    console.warn(`[SECURITY] Account ${username} bloccato per ${LOCKOUT_MS/60000} min`);
    audit('ACCOUNT_LOCKED', username, `${MAX_FAILED} tentativi falliti`);
  }
  persistUsers();
}
async function resetFailedLogin(username) {
  const user = users.get(username);
  if (!user) return;
  user.failedAttempts = 0; user.lockedUntil = null; persistUsers();
}

// ── REST API — AUTH ───────────────────────────────────────────────────────────
app.post('/api/auth/login',
  loginLimiter,
  body('username').isString().trim().isLength({ min: 1, max: 50 }).escape(),
  body('password').isString().isLength({ min: 1, max: 128 }),
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ error: 'Input non valido' });

    const { username, password } = req.body;
    const user = users.get(username);

    if (!user) {
      // Timing attack prevention: esegui bcrypt anche se l'utente non esiste
      await bcrypt.compare(password, '$2a$12$invalidhashfortimingprotection');
      audit('LOGIN_FAIL', username, 'Utente non trovato', req);
      return res.status(401).json({ error: 'Credenziali non valide' });
    }

    // Controlla lockout
    if (await checkLockout(username)) {
      audit('LOGIN_BLOCKED', username, 'Account bloccato', req);
      return res.status(423).json({ error: 'Account temporaneamente bloccato. Riprova tra 15 minuti.' });
    }

    const ok = await bcrypt.compare(password, user.passwordHash);
    if (!ok) {
      await recordFailedLogin(username);
      audit('LOGIN_FAIL', username, `Tentativo ${user.failedAttempts}/${MAX_FAILED}`, req);
      return res.status(401).json({ error: 'Credenziali non valide' });
    }

    await resetFailedLogin(username);

    // JWT con jti univoco per poterlo revocare
    const jti   = crypto.randomUUID();
    const token = jwt.sign(
      { username, role: user.role, jti },
      JWT_SECRET,
      { expiresIn: '8h' } // 8 ore invece di 30 giorni
    );

    audit('LOGIN_OK', username, `ruolo: ${user.role}`, req);
    res.json({ token, user: { username, role: user.role } });
  }
);

app.post('/api/auth/logout', requireAuth, (req, res) => {
  // Revoca il token aggiungendolo alla blacklist
  if (req.user.jti) {
    tokenBlacklist.add(req.user.jti);
    persistBlacklist();
  }
  audit('LOGOUT', req.user.username, '', req);
  res.json({ ok: true });
});

app.post('/api/auth/register',
  requireAdmin,
  body('username').isString().trim().isLength({ min: 3, max: 30 })
    .matches(/^[a-zA-Z0-9_-]+$/).withMessage('Solo lettere, numeri, _ e -'),
  body('password').isString().isLength({ min: 8, max: 128 }),
  body('role').isIn(['admin', 'scanner', 'desktop', 'service']),
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty())
      return res.status(400).json({ error: errors.array()[0].msg });

    const { username, password, role } = req.body;
    if (users.has(username))
      return res.status(409).json({ error: 'Username già esistente' });

    // Verifica forza password
    const passStrength = checkPasswordStrength(password);
    if (!passStrength.ok)
      return res.status(400).json({ error: passStrength.reason });

    const passwordHash = await bcrypt.hash(password, 12);
    users.set(username, {
      passwordHash, role,
      createdAt: new Date().toISOString(),
      failedAttempts: 0, lockedUntil: null,
    });
    persistUsers();
    audit('USER_CREATED', req.user.username, `creato: ${username} (${role})`, req);
    broadcastStatus();
    res.status(201).json({ ok: true, username, role });
  }
);

app.get('/api/auth/users', requireAdmin, (req, res) => {
  const list = [...users.entries()].map(([username, u]) => ({
    username, role: u.role, createdAt: u.createdAt,
    online: clients.has(username),
    locked: u.lockedUntil && Date.now() < u.lockedUntil,
  }));
  res.json({ users: list });
});

app.delete('/api/auth/users/:username', requireAdmin, (req, res) => {
  const { username } = req.params;
  if (!/^[a-zA-Z0-9_-]+$/.test(username))
    return res.status(400).json({ error: 'Username non valido' });
  if (username === req.user.username)
    return res.status(400).json({ error: 'Non puoi eliminare te stesso' });
  if (!users.has(username))
    return res.status(404).json({ error: 'Utente non trovato' });

  // Revoca tutti i token dell'utente eliminato non è possibile senza session store,
  // ma possiamo forzare disconnessione WS
  const set = clients.get(username);
  if (set) set.forEach(ws => ws.close(4001, 'Account eliminato'));

  users.delete(username); pushSubs.delete(username); msgQueue.delete(username);
  persistUsers(); persistPushSubs(); persistQueue();
  audit('USER_DELETED', req.user.username, `eliminato: ${username}`, req);
  broadcastStatus();
  res.json({ ok: true });
});

app.post('/api/auth/change-password',
  requireAuth,
  body('oldPassword').isString().isLength({ min: 1, max: 128 }),
  body('newPassword').isString().isLength({ min: 8, max: 128 }),
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ error: 'Input non valido' });

    const { oldPassword, newPassword } = req.body;
    const user = users.get(req.user.username);
    if (!user) return res.status(404).json({ error: 'Utente non trovato' });

    const ok = await bcrypt.compare(oldPassword, user.passwordHash);
    if (!ok) {
      audit('PWD_CHANGE_FAIL', req.user.username, 'Password attuale errata', req);
      return res.status(401).json({ error: 'Password attuale non corretta' });
    }

    const passStrength = checkPasswordStrength(newPassword);
    if (!passStrength.ok) return res.status(400).json({ error: passStrength.reason });

    user.passwordHash = await bcrypt.hash(newPassword, 12);
    persistUsers();

    // Revoca il token corrente (deve rifare login)
    if (req.user.jti) { tokenBlacklist.add(req.user.jti); persistBlacklist(); }
    audit('PWD_CHANGED', req.user.username, '', req);
    res.json({ ok: true, message: 'Password cambiata. Effettua di nuovo il login.' });
  }
);

// Unlock account (solo admin)
app.post('/api/auth/unlock/:username', requireAdmin, (req, res) => {
  const { username } = req.params;
  const user = users.get(username);
  if (!user) return res.status(404).json({ error: 'Utente non trovato' });
  user.failedAttempts = 0; user.lockedUntil = null;
  persistUsers();
  audit('ACCOUNT_UNLOCKED', req.user.username, `sbloccato: ${username}`, req);
  res.json({ ok: true });
});

// Audit log (solo admin, ultimi N righe)
app.get('/api/audit', requireAdmin, (req, res) => {
  try {
    if (!fs.existsSync(AUDIT_FILE)) return res.json({ lines: [] });
    const lines = fs.readFileSync(AUDIT_FILE, 'utf8')
      .split('\n').filter(Boolean).slice(-200);
    res.json({ lines });
  } catch { res.json({ lines: [] }); }
});

// ── REST API — PUSH ───────────────────────────────────────────────────────────
app.get('/api/push/vapid-public-key', (req, res) => {
  res.json({ publicKey: VAPID_PUBLIC || '' });
});
app.post('/api/push/subscribe', requireAuth, (req, res) => {
  const { subscription } = req.body || {};
  if (!subscription?.endpoint) return res.status(400).json({ error: 'Subscription non valida' });
  if (!pushSubs.has(req.user.username)) pushSubs.set(req.user.username, []);
  const subs = pushSubs.get(req.user.username);
  if (!subs.find(s => s.endpoint === subscription.endpoint)) subs.push(subscription);
  persistPushSubs();
  res.json({ ok: true });
});
app.post('/api/push/unsubscribe', requireAuth, (req, res) => {
  const { endpoint } = req.body || {};
  const subs = pushSubs.get(req.user.username);
  if (subs) { const i = subs.findIndex(s => s.endpoint === endpoint); if (i >= 0) { subs.splice(i, 1); persistPushSubs(); } }
  res.json({ ok: true });
});

// ── REST API — HEALTH ─────────────────────────────────────────────────────────
app.get('/api/health', (req, res) => {
  res.json({
    ok: true, ts: new Date().toISOString(),
    users: users.size, online: clients.size,
    services: services.size,
    queued: [...msgQueue.values()].reduce((s, q) => s + q.length, 0),
  });
});

// ── VERIFICA FORZA PASSWORD ───────────────────────────────────────────────────
function checkPasswordStrength(password) {
  if (password.length < 8)
    return { ok: false, reason: 'Password troppo corta (min 8 caratteri)' };
  if (!/[A-Z]/.test(password))
    return { ok: false, reason: 'Password deve contenere almeno una lettera maiuscola' };
  if (!/[0-9]/.test(password))
    return { ok: false, reason: 'Password deve contenere almeno un numero' };
  // Lista password comuni
  const common = ['password', '12345678', 'qwerty123', 'admin123', 'password1'];
  if (common.some(c => password.toLowerCase().includes(c)))
    return { ok: false, reason: 'Password troppo comune' };
  return { ok: true };
}

// ── WEBSOCKET ─────────────────────────────────────────────────────────────────
// Rate limit WS: max 60 messaggi/minuto per connessione
const WS_RATE_WINDOW = 60 * 1000;
const WS_RATE_MAX    = 60;

// WS connection rate limit: max 10 connessioni/minuto per IP
const wsConnections = new Map(); // ip -> [{ts}]
function checkWsRateLimit(ip) {
  const now = Date.now();
  const conns = (wsConnections.get(ip) || []).filter(t => now - t < 60_000);
  conns.push(now);
  wsConnections.set(ip, conns);
  return conns.length <= 10;
}

wss.on('connection', (ws, req) => {
  const ip     = req.headers['x-forwarded-for'] || req.socket.remoteAddress || '-';
  const params = new URL(req.url, 'http://localhost').searchParams;
  const token  = params.get('token') || '';
  const clientType = params.get('clientType') || '';

  // Rate limit connessioni WS per IP
  if (!checkWsRateLimit(ip)) {
    ws.close(4029, 'Too many connections');
    audit('WS_RATE_LIMIT', '-', `IP: ${ip}`);
    return;
  }

  // Verifica token JWT
  let authUser = null;
  try {
    authUser = jwt.verify(token, JWT_SECRET);
    // Controlla blacklist
    if (authUser.jti && tokenBlacklist.has(authUser.jti)) {
      ws.close(4001, 'Token revocato');
      return;
    }
  } catch {
    // Prova chiave alternativa
    if (JWT_SECRET_ALT) {
      try { authUser = jwt.verify(token, JWT_SECRET_ALT); }
      catch {}
    }
    if (!authUser) {
      ws.close(4001, 'Token non valido');
      audit('WS_AUTH_FAIL', '-', `IP: ${ip}`);
      return;
    }
  }

  const { username, role } = authUser;

  // Verifica che l'utente esista ancora
  if (!users.has(username)) {
    ws.close(4001, 'Utente non trovato');
    return;
  }

  const isService = clientType === 'service' || role === 'service';
  ws.username  = username;
  ws.role      = role;
  ws.isService = isService;
  ws.ip        = ip;

  // Rate limiter messaggi per connessione
  ws._msgCount  = 0;
  ws._msgWindow = Date.now();

  if (isService) {
    services.add(ws);
    audit('WS_CONNECT', username, `SERVICE | ip: ${ip}`);
  } else {
    addClient(username, ws);
    audit('WS_CONNECT', username, `${role} | ip: ${ip}`);
  }

  broadcastStatus();
  flushQueue(username, ws);

  ws.send(JSON.stringify({
    type: 'status',
    online: [...clients.keys()],
    registered: [...users.keys()],
    servicesOnline: services.size,
  }));

  ws.on('message', async (data) => {
    // Rate limit messaggi
    const now = Date.now();
    if (now - ws._msgWindow > WS_RATE_WINDOW) {
      ws._msgCount = 0; ws._msgWindow = now;
    }
    ws._msgCount++;
    if (ws._msgCount > WS_RATE_MAX) {
      ws.send(JSON.stringify({ type: 'error', message: 'Troppi messaggi. Rallenta.' }));
      audit('WS_MSG_RATE', username, `${ws._msgCount} msg/min`);
      return;
    }

    // Limita dimensione messaggio
    if (data.length > 512 * 1024) { // 512KB max
      ws.send(JSON.stringify({ type: 'error', message: 'Messaggio troppo grande' }));
      return;
    }

    try {
      const msg  = JSON.parse(data.toString());
      const type = (msg.type || '').toString().slice(0, 50); // Limita lunghezza tipo

      if (type === 'ping') { ws.send(JSON.stringify({ type: 'pong' })); return; }
      if (type === 'get_user_list') { broadcastStatus(); return; }

      // ── SERVIZIO JAVA → risposta ────────────────────────────────────
      if (isService && ['search_response', 'giacenza_response'].includes(type)) {
        const to = (msg.to || msg.from || '').toString().slice(0, 50);
        if (to) {
          const delivered = sendTo(to, msg);
          if (!delivered) enqueue(to, type, msg);
        } else {
          broadcastToDesktop(msg); broadcastToScanner(msg);
        }
        return;
      }
      if (isService) {
        const to = (msg.to || msg.from || '').toString().slice(0, 50);
        if (to) sendTo(to, msg);
        else { broadcastToDesktop(msg); broadcastToScanner(msg); }
        return;
      }

      // ── SCANNER → batch/comande ─────────────────────────────────────
      if (['scan_batch', 'new_order', 'order_update'].includes(type) && role === 'scanner') {
        const enriched = { ...msg, from: username, fromRole: role };
        const delivered = broadcastToDesktop(enriched, username);
        users.forEach((u, uname) => {
          if (['desktop', 'admin'].includes(u.role) && !clients.has(uname))
            enqueue(uname, type, enriched);
        });
        await pushToDesktop({
          title: `ScanPC — ${username}`,
          body: type === 'scan_batch' ? `${msg.total || 0} codici` : `Comanda da ${username}`,
        });
        ws.send(JSON.stringify({ type: 'ack', originalType: type, delivered }));
        return;
      }

      // ── TUTTI → ricerca/giacenza/localizzazione/barcode → servizio Java ─
      if (['search_request', 'giacenza_request',
           'localization_request', 'localization_update',
           'barcode_to_codart_request'].includes(type)) {
        // Sanifica la query
        if (msg.query) msg.query = String(msg.query).slice(0, 100);
        if (msg.cod_art) msg.cod_art = String(msg.cod_art).slice(0, 50);
        const enriched = { ...msg, from: username };
        const delivered = sendToServices(enriched);
        if (delivered === 0) {
          users.forEach((u, uname) => {
            if (u.role === 'service') enqueue(uname, type, enriched);
          });
          ws.send(JSON.stringify({
            type: type === 'search_request' ? 'search_response' : 'giacenza_response',
            request_id: msg.request_id,
            error: 'Servizio offline — richiesta in coda. Ritenta tra qualche secondo.',
            results: [], queued: true,
          }));
        }
        return;
      }

      // ── DESKTOP/ADMIN → comanda specifica ──────────────────────────
      if (type === 'new_order' && ['desktop', 'admin'].includes(role)) {
        const to = (msg.destination || msg.to || '').toString().slice(0, 50);
        if (!to) { ws.send(JSON.stringify({ type: 'error', message: 'Destination mancante' })); return; }
        if (!users.has(to)) { ws.send(JSON.stringify({ type: 'error', message: 'Destinatario non trovato' })); return; }
        const enriched = { ...msg, from: username, fromRole: role };
        const delivered = sendTo(to, enriched);
        if (!delivered) enqueue(to, type, enriched);
        await pushToUser(to, { title: `Comanda da ${username}`, body: `${msg.order?.items?.length || 0} articoli` });
        ws.send(JSON.stringify({ type: 'ack', originalType: type, to, delivered }));
        return;
      }

    } catch (e) { console.error('[WS] Errore:', e.message); }
  });

  ws.on('close', (code, reason) => {
    removeClient(username, ws);
    audit('WS_DISCONNECT', username, `code: ${code} | ip: ${ip}`);
    broadcastStatus();
  });

  ws.on('error', e => console.error(`[WS] Errore (${username}):`, e.message));
});

// ── AVVIO ─────────────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`
╔══════════════════════════════════════╗
║      ScanPC Server v5.0 SECURE       ║
╚══════════════════════════════════════╝
  Porta   : ${PORT}
  DataDir : ${DATA_DIR}
  VAPID   : ${VAPID_PUBLIC ? 'OK' : '⚠ non configurato'}
  JWT     : OK (${JWT_SECRET.length} chars)
  Helmet  : ON
  RateLimit: ON
  Audit   : ON
  Lockout : ${MAX_FAILED} tentativi → ${LOCKOUT_MS/60000} min
`);
});
