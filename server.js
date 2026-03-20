'use strict';

const express  = require('express');
const http     = require('http');
const { WebSocketServer } = require('ws');
const bcrypt   = require('bcryptjs');
const jwt      = require('jsonwebtoken');
const webpush  = require('web-push');
const path     = require('path');
const fs       = require('fs');

const app    = express();
const server = http.createServer(app);
const wss    = new WebSocketServer({ server });

app.use(express.json());

// ── CORS ─────────────────────────────────────────────────────────────────────
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.header('Access-Control-Allow-Methods', 'GET, POST, DELETE, OPTIONS');
  if (req.method === 'OPTIONS') return res.sendStatus(200);
  next();
});

// ── CONFIGURAZIONE ────────────────────────────────────────────────────────────
const JWT_SECRET    = process.env.JWT_SECRET    || 'dev-secret-change-in-prod';
const VAPID_PUBLIC  = process.env.VAPID_PUBLIC_KEY  || '';
const VAPID_PRIVATE = process.env.VAPID_PRIVATE_KEY || '';
const VAPID_EMAIL   = process.env.VAPID_EMAIL       || 'mailto:admin@scanpc.local';
const DATA_DIR      = process.env.DATA_DIR          || '/tmp/scanpc_data';
const ADMIN_USER    = process.env.ADMIN_USER        || 'admin';
const ADMIN_PASS    = process.env.ADMIN_PASS        || 'admin123';

if (VAPID_PUBLIC && VAPID_PRIVATE) {
  webpush.setVapidDetails(VAPID_EMAIL, VAPID_PUBLIC, VAPID_PRIVATE);
}

// ── PERSISTENZA FILE ──────────────────────────────────────────────────────────
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

const USERS_FILE = path.join(DATA_DIR, 'users.json');
const QUEUE_FILE = path.join(DATA_DIR, 'queue.json');
const PUSH_FILE  = path.join(DATA_DIR, 'push_subs.json');

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

// ── DATABASE IN-MEMORY (con persistenza su file) ──────────────────────────────
// users: { username: { passwordHash, role, createdAt } }
const users    = new Map(Object.entries(loadJson(USERS_FILE, {})));
// queue: { username: [ { id, type, payload, ts } ] }  — messaggi offline per utente
const msgQueue = new Map(Object.entries(loadJson(QUEUE_FILE, {})));
// pushSubs: { username: [ subscriptionObj ] }
const pushSubs = new Map(Object.entries(loadJson(PUSH_FILE, {})));

function persistUsers()    { saveJson(USERS_FILE, Object.fromEntries(users)); }
function persistQueue()    { saveJson(QUEUE_FILE, Object.fromEntries(msgQueue)); }
function persistPushSubs() { saveJson(PUSH_FILE,  Object.fromEntries(pushSubs)); }

// Crea admin di default
(async () => {
  if (!users.has(ADMIN_USER)) {
    const hash = await bcrypt.hash(ADMIN_PASS, 10);
    users.set(ADMIN_USER, { passwordHash: hash, role: 'admin', createdAt: new Date().toISOString() });
    persistUsers();
    console.log(`[AUTH] Admin creato: ${ADMIN_USER}`);
  }
})();

// ── CODA MESSAGGI ─────────────────────────────────────────────────────────────
function enqueue(username, type, payload) {
  if (!msgQueue.has(username)) msgQueue.set(username, []);
  const q = msgQueue.get(username);
  // Limite 200 messaggi per utente per non esplodere
  if (q.length >= 200) q.shift();
  q.push({ id: Date.now() + Math.random().toString(36).slice(2), type, payload, ts: new Date().toISOString() });
  persistQueue();
}

function flushQueue(username, ws) {
  const q = msgQueue.get(username);
  if (!q || q.length === 0) return;
  console.log(`[QUEUE] Flush ${q.length} messaggi per ${username}`);
  q.forEach(item => {
    if (ws.readyState === 1) {
      ws.send(JSON.stringify({ ...item.payload, _queued: true, _queuedAt: item.ts }));
    }
  });
  msgQueue.set(username, []);
  persistQueue();
}

// ── CONNESSIONI WEBSOCKET ─────────────────────────────────────────────────────
// clients: Map<username, Set<ws>>  (un utente può avere più connessioni)
const clients = new Map();

function addClient(username, ws) {
  if (!clients.has(username)) clients.set(username, new Set());
  clients.get(username).add(ws);
}

function removeClient(username, ws) {
  const set = clients.get(username);
  if (set) { set.delete(ws); if (set.size === 0) clients.delete(username); }
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

function broadcastToRole(role, msg, excludeUsername = null) {
  let count = 0;
  users.forEach((u, username) => {
    if (u.role === role && username !== excludeUsername) {
      if (sendTo(username, msg)) count++;
    }
  });
  return count;
}

function broadcastStatus() {
  const online = [...clients.keys()];
  const msg = { type: 'user_list', online, registered: [...users.keys()] };
  clients.forEach((set) => {
    set.forEach(ws => { if (ws.readyState === 1) ws.send(JSON.stringify(msg)); });
  });
}

// ── MIDDLEWARE AUTH ───────────────────────────────────────────────────────────
function requireAuth(req, res, next) {
  const token = (req.headers.authorization || '').replace('Bearer ', '');
  if (!token) return res.status(401).json({ error: 'Token mancante' });
  try { req.user = jwt.verify(token, JWT_SECRET); next(); }
  catch { res.status(401).json({ error: 'Token non valido' }); }
}

function requireAdmin(req, res, next) {
  requireAuth(req, res, () => {
    if (req.user.role !== 'admin') return res.status(403).json({ error: 'Permessi insufficienti' });
    next();
  });
}

// ── REST API — AUTH ───────────────────────────────────────────────────────────
app.post('/api/auth/login', async (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: 'Credenziali mancanti' });
  const user = users.get(username);
  if (!user) return res.status(401).json({ error: 'Credenziali non valide' });
  const ok = await bcrypt.compare(password, user.passwordHash);
  if (!ok) return res.status(401).json({ error: 'Credenziali non valide' });
  const token = jwt.sign({ username, role: user.role }, JWT_SECRET, { expiresIn: '30d' });
  console.log(`[AUTH] Login: ${username} (${user.role})`);
  res.json({ token, user: { username, role: user.role } });
});

app.post('/api/auth/register', requireAdmin, async (req, res) => {
  const { username, password, role = 'scanner' } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: 'Dati mancanti' });
  if (users.has(username)) return res.status(409).json({ error: 'Username già esistente' });
  if (!['admin', 'scanner', 'desktop', 'service'].includes(role))
    return res.status(400).json({ error: 'Ruolo non valido' });
  const passwordHash = await bcrypt.hash(password, 10);
  users.set(username, { passwordHash, role, createdAt: new Date().toISOString() });
  persistUsers();
  console.log(`[AUTH] Nuovo utente: ${username} (${role})`);
  broadcastStatus();
  res.status(201).json({ ok: true, username, role });
});

app.get('/api/auth/users', requireAdmin, (req, res) => {
  const list = [...users.entries()].map(([username, u]) => ({
    username, role: u.role, createdAt: u.createdAt,
    online: clients.has(username),
  }));
  res.json({ users: list });
});

app.delete('/api/auth/users/:username', requireAdmin, (req, res) => {
  const { username } = req.params;
  if (username === req.user.username) return res.status(400).json({ error: 'Non puoi eliminare te stesso' });
  if (!users.has(username)) return res.status(404).json({ error: 'Utente non trovato' });
  users.delete(username); pushSubs.delete(username); msgQueue.delete(username);
  persistUsers(); persistPushSubs(); persistQueue();
  broadcastStatus();
  res.json({ ok: true });
});

app.post('/api/auth/change-password', requireAuth, async (req, res) => {
  const { oldPassword, newPassword } = req.body || {};
  const user = users.get(req.user.username);
  if (!user) return res.status(404).json({ error: 'Utente non trovato' });
  const ok = await bcrypt.compare(oldPassword, user.passwordHash);
  if (!ok) return res.status(401).json({ error: 'Password attuale non corretta' });
  user.passwordHash = await bcrypt.hash(newPassword, 10);
  persistUsers();
  res.json({ ok: true });
});

// ── REST API — PUSH ───────────────────────────────────────────────────────────
app.get('/api/push/vapid-public-key', (req, res) => {
  if (!VAPID_PUBLIC) return res.status(503).json({ error: 'Push non configurato' });
  res.json({ publicKey: VAPID_PUBLIC });
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
  if (subs) {
    const idx = subs.findIndex(s => s.endpoint === endpoint);
    if (idx >= 0) { subs.splice(idx, 1); persistPushSubs(); }
  }
  res.json({ ok: true });
});

// ── REST API — HEALTH ─────────────────────────────────────────────────────────
app.get('/api/health', (req, res) => {
  res.json({
    ok: true, ts: new Date().toISOString(),
    users: users.size, online: clients.size,
    queued: [...msgQueue.values()].reduce((s, q) => s + q.length, 0),
  });
});

app.get('/api/push/vapid-public-key', (req, res) => {
  res.json({ publicKey: VAPID_PUBLIC || '' });
});

// ── PUSH HELPER ───────────────────────────────────────────────────────────────
async function pushToUser(username, payload) {
  if (!VAPID_PUBLIC || !VAPID_PRIVATE) return 0;
  const subs = pushSubs.get(username);
  if (!subs || subs.length === 0) return 0;
  const msg  = JSON.stringify(payload);
  const dead = [];
  let sent = 0;
  for (const sub of subs) {
    try { await webpush.sendNotification(sub, msg); sent++; }
    catch (e) { if (e.statusCode === 410) dead.push(sub); }
  }
  if (dead.length) {
    dead.forEach(d => subs.splice(subs.indexOf(d), 1));
    persistPushSubs();
  }
  return sent;
}

async function pushToRole(role, payload, excludeUsername = null) {
  let total = 0;
  for (const [username, u] of users) {
    if (u.role === role && username !== excludeUsername) {
      total += await pushToUser(username, payload);
    }
  }
  return total;
}

// ── WEBSOCKET ─────────────────────────────────────────────────────────────────
wss.on('connection', (ws, req) => {
  const params = new URL(req.url, 'http://localhost').searchParams;
  const token  = params.get('token') || '';

  let authUser = null;
  try { authUser = jwt.verify(token, JWT_SECRET); }
  catch {
    ws.send(JSON.stringify({ type: 'error', message: 'Token non valido o mancante' }));
    ws.close(); return;
  }

  const { username, role } = authUser;
  ws.username = username;
  ws.role     = role;

  addClient(username, ws);
  console.log(`[+] ${role} connesso: ${username}`);
  broadcastStatus();

  // Flush messaggi in coda per questo utente
  flushQueue(username, ws);

  // Notifica stato iniziale
  ws.send(JSON.stringify({
    type: 'status',
    online: [...clients.keys()],
    registered: [...users.keys()],
  }));

  ws.on('message', async (data) => {
    try {
      const msg = JSON.parse(data.toString());
      const type = msg.type || '';

      // ── Ping keepalive ─────────────────────────────────────────────────
      if (type === 'ping') { ws.send(JSON.stringify({ type: 'pong' })); return; }

      // ── Richiesta lista utenti ──────────────────────────────────────────
      if (type === 'get_user_list') { broadcastStatus(); return; }

      // ── MOBILE → broadcast tutti i desktop ─────────────────────────────
      // scan_batch, new_order, order_update
      if (['scan_batch', 'new_order', 'order_update'].includes(type) && role === 'scanner') {
        const enriched = { ...msg, from: username, fromRole: role };
        let delivered = broadcastToRole('desktop', enriched, username);
        delivered    += broadcastToRole('admin',   enriched, username);

        // Metti in coda per i desktop offline
        users.forEach((u, uname) => {
          if ((u.role === 'desktop' || u.role === 'admin') && !clients.has(uname)) {
            enqueue(uname, type, enriched);
          }
        });

        // Push notification ai desktop
        await pushToRole('desktop', {
          title: `ScanPC — ${username}`,
          body:  type === 'scan_batch'
            ? `${msg.total || 0} codici scansionati`
            : `Nuova comanda da ${username}`,
        });

        // Ack allo scanner
        ws.send(JSON.stringify({ type: 'ack', originalType: type, delivered }));
        return;
      }

      // ── MOBILE → ricerca/giacenza — va al servizio Java (role: service) ─
      if (['search_request', 'giacenza_request'].includes(type) && role === 'scanner') {
        const enriched = { ...msg, from: username };
        const delivered = broadcastToRole('service', enriched);
        if (delivered === 0) {
          // Servizio offline → metti in coda
          users.forEach((u, uname) => {
            if (u.role === 'service') enqueue(uname, type, enriched);
          });
          ws.send(JSON.stringify({
            type: type === 'search_request' ? 'search_response' : 'giacenza_response',
            request_id: msg.request_id,
            error: 'Servizio offline — richiesta in coda, ritenta tra qualche secondo',
            results: [],
            queued: true,
          }));
        }
        return;
      }

      // ── DESKTOP → ricerca/giacenza — va al servizio Java ───────────────
      if (['search_request', 'giacenza_request'].includes(type) && role === 'desktop') {
        const enriched = { ...msg, from: username };
        const delivered = broadcastToRole('service', enriched);
        if (delivered === 0) {
          users.forEach((u, uname) => {
            if (u.role === 'service') enqueue(uname, type, enriched);
          });
          ws.send(JSON.stringify({
            type: type === 'search_request' ? 'search_response' : 'giacenza_response',
            request_id: msg.request_id,
            error: 'Servizio offline',
            results: [], queued: true,
          }));
        }
        return;
      }

      // ── DESKTOP → utente specifico (new_order verso mobile) ────────────
      if (type === 'new_order' && role === 'desktop') {
        const to = msg.destination || msg.to;
        if (!to) { ws.send(JSON.stringify({ type: 'error', message: 'Campo "destination" mancante' })); return; }
        const enriched = { ...msg, from: username, fromRole: role };
        const delivered = sendTo(to, enriched);
        if (!delivered) enqueue(to, type, enriched);
        // Push al destinatario mobile
        await pushToUser(to, { title: `Comanda da ${username}`, body: `${(msg.order?.items?.length || 0)} articoli` });
        ws.send(JSON.stringify({ type: 'ack', originalType: type, to, delivered }));
        return;
      }

      // ── SERVIZIO JAVA → risposta ricerca/giacenza → chi ha fatto la richiesta
      if (['search_response', 'giacenza_response'].includes(type) && role === 'service') {
        const to = msg.to || msg.from;
        if (to) {
          const delivered = sendTo(to, msg);
          if (!delivered) enqueue(to, type, msg);
        } else {
          // Broadcast a tutti scanner e desktop
          broadcastToRole('scanner', msg);
          broadcastToRole('desktop', msg);
        }
        return;
      }

      // ── SERVIZIO JAVA → batch_ack, order_update ────────────────────────
      if (role === 'service') {
        const to = msg.to || msg.from;
        if (to) sendTo(to, msg);
        else { broadcastToRole('scanner', msg); broadcastToRole('desktop', msg); }
        return;
      }

      console.log(`[WS] Messaggio non gestito: ${type} da ${username} (${role})`);

    } catch (e) { console.error('[WS] Errore:', e.message); }
  });

  ws.on('close', () => {
    removeClient(username, ws);
    console.log(`[-] ${role} disconnesso: ${username}`);
    broadcastStatus();
  });

  ws.on('error', (e) => console.error(`[WS] Errore (${username}):`, e.message));
});

// ── AVVIO ─────────────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`
╔══════════════════════════════════════╗
║      ScanPC Server v4.0              ║
╚══════════════════════════════════════╝
  Porta  : ${PORT}
  DataDir: ${DATA_DIR}
  VAPID  : ${VAPID_PUBLIC ? 'OK' : '⚠ non configurato'}
  JWT    : ${JWT_SECRET !== 'dev-secret-change-in-prod' ? 'OK' : '⚠ usa JWT_SECRET in produzione'}
`);
});
