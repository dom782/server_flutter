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
const JWT_SECRET    = process.env.JWT_SECRET        || 'dev-secret-change-in-prod';
const VAPID_PUBLIC  = process.env.VAPID_PUBLIC_KEY  || '';
const VAPID_PRIVATE = process.env.VAPID_PRIVATE_KEY || '';
const VAPID_EMAIL   = process.env.VAPID_EMAIL       || 'mailto:admin@scanpc.local';
const ADMIN_USER    = process.env.ADMIN_USER        || 'admin';
const ADMIN_PASS    = process.env.ADMIN_PASS        || 'admin123';

const DATA_DIR = process.env.DATA_DIR ||
  (process.env.RENDER ? '/opt/render/project/src/data' : path.join(__dirname, 'data'));

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

const users    = new Map(Object.entries(loadJson(USERS_FILE, {})));
const msgQueue = new Map(Object.entries(loadJson(QUEUE_FILE, {})));
const pushSubs = new Map(Object.entries(loadJson(PUSH_FILE,  {})));

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
  if (q.length >= 200) q.shift();
  q.push({ id: Date.now() + Math.random().toString(36).slice(2), type, payload, ts: new Date().toISOString() });
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
// clients:  Map<username, Set<ws>>
// services: Set<ws>  — connessioni che si sono dichiarate come servizio Java
const clients  = new Map();
const services = new Set();

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

// Invia a tutti i servizi Java connessi
function sendToServices(msg) {
  const raw = JSON.stringify(msg);
  let count = 0;
  services.forEach(ws => {
    if (ws.readyState === 1) { ws.send(raw); count++; }
  });
  return count;
}

// Invia a tutti i client con ruolo desktop o admin (escludi mittente)
function broadcastToDesktop(msg, excludeUsername = null) {
  let count = 0;
  users.forEach((u, username) => {
    if (['desktop', 'admin'].includes(u.role) && username !== excludeUsername) {
      if (sendTo(username, msg)) count++;
    }
  });
  return count;
}

// Invia a tutti i client con ruolo scanner
function broadcastToScanner(msg, excludeUsername = null) {
  let count = 0;
  users.forEach((u, username) => {
    if (u.role === 'scanner' && username !== excludeUsername) {
      if (sendTo(username, msg)) count++;
    }
  });
  return count;
}

function broadcastStatus() {
  const online = [...clients.keys()];
  const msg = JSON.stringify({ type: 'user_list', online, registered: [...users.keys()] });
  clients.forEach(set => set.forEach(ws => { if (ws.readyState === 1) ws.send(msg); }));
  // Notifica anche i service
  services.forEach(ws => { if (ws.readyState === 1) ws.send(msg); });
}

// ── PUSH HELPERS ──────────────────────────────────────────────────────────────
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
  for (const [username, u] of users) {
    if (['desktop', 'admin'].includes(u.role))
      total += await pushToUser(username, payload);
  }
  return total;
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

// ── REST API ──────────────────────────────────────────────────────────────────
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

app.get('/api/health', (req, res) => {
  res.json({
    ok: true, ts: new Date().toISOString(),
    users: users.size, online: clients.size,
    services: services.size,
    dataDir: DATA_DIR,
    queued: [...msgQueue.values()].reduce((s, q) => s + q.length, 0),
  });
});

// ── WEBSOCKET ─────────────────────────────────────────────────────────────────
wss.on('connection', (ws, req) => {
  const params     = new URL(req.url, 'http://localhost').searchParams;
  const token      = params.get('token') || '';
  // Il servizio Java può dichiararsi come 'service' tramite query param
  // indipendentemente dal ruolo dell'utente JWT
  const clientType = params.get('clientType') || '';

  let authUser = null;
  try { authUser = jwt.verify(token, JWT_SECRET); }
  catch {
    ws.send(JSON.stringify({ type: 'error', message: 'Token non valido o mancante' }));
    ws.close(); return;
  }

  const { username, role } = authUser;

  // Se il client si dichiara come servizio Java, lo trattiamo come service
  // anche se il suo ruolo JWT è admin o altro
  const isService = clientType === 'service' || role === 'service';

  ws.username  = username;
  ws.role      = role;
  ws.isService = isService;

  if (isService) {
    services.add(ws);
    console.log(`[+] SERVICE connesso: ${username} (ruolo JWT: ${role})`);
  } else {
    addClient(username, ws);
    console.log(`[+] ${role} connesso: ${username}`);
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
    try {
      const msg  = JSON.parse(data.toString());
      const type = msg.type || '';

      // Ping
      if (type === 'ping') { ws.send(JSON.stringify({ type: 'pong' })); return; }
      if (type === 'get_user_list') { broadcastStatus(); return; }

      // ── SERVIZIO JAVA → risposta ricerca/giacenza ─────────────────────
      if (isService && ['search_response', 'giacenza_response'].includes(type)) {
        const to = msg.to || msg.from;
        console.log(`[SERVICE→] ${type} per: ${to}`);
        if (to) {
          const delivered = sendTo(to, msg);
          if (!delivered) enqueue(to, type, msg);
        } else {
          broadcastToDesktop(msg);
          broadcastToScanner(msg);
        }
        return;
      }

      // ── SERVIZIO JAVA → altri messaggi ────────────────────────────────
      if (isService) {
        const to = msg.to || msg.from;
        if (to) sendTo(to, msg);
        else { broadcastToDesktop(msg); broadcastToScanner(msg); }
        return;
      }

      // ── SCANNER → batch/comande → broadcast a tutti i desktop ─────────
      if (['scan_batch', 'new_order', 'order_update'].includes(type) && role === 'scanner') {
        const enriched = { ...msg, from: username, fromRole: role };
        const delivered = broadcastToDesktop(enriched, username);

        // Coda per desktop offline
        users.forEach((u, uname) => {
          if (['desktop', 'admin'].includes(u.role) && !clients.has(uname))
            enqueue(uname, type, enriched);
        });

        await pushToDesktop({
          title: `ScanPC — ${username}`,
          body: type === 'scan_batch'
            ? `${msg.total || 0} codici scansionati`
            : `Nuova comanda da ${username}`,
        });

        ws.send(JSON.stringify({ type: 'ack', originalType: type, delivered }));
        return;
      }

      // ── SCANNER/DESKTOP/ADMIN → ricerca/giacenza → servizio Java ──────
      if (['search_request', 'giacenza_request'].includes(type)) {
        const enriched = { ...msg, from: username };
        const delivered = sendToServices(enriched);
        console.log(`[→SERVICE] ${type} da ${username} (${role}) — service connessi: ${services.size}, consegnati: ${delivered}`);

        if (delivered === 0) {
          // Nessun service connesso — metti in coda per tutti i service
          // (quando si connettono riceveranno i messaggi pendenti)
          let queued = false;
          users.forEach((u, uname) => {
            if (u.role === 'service') { enqueue(uname, type, enriched); queued = true; }
          });
          // Se non ci sono neanche utenti service registrati, rispondi con errore
          ws.send(JSON.stringify({
            type: type === 'search_request' ? 'search_response' : 'giacenza_response',
            request_id: msg.request_id,
            error: queued
              ? 'Servizio offline — richiesta in coda, ritenta tra qualche secondo'
              : 'Servizio non configurato — avvia il Servizio Java sul PC con il DB',
            results: [], queued,
          }));
        }
        return;
      }

      // ── DESKTOP/ADMIN → comanda verso utente specifico ─────────────────
      if (type === 'new_order' && ['desktop', 'admin'].includes(role)) {
        const to = msg.destination || msg.to;
        if (!to) { ws.send(JSON.stringify({ type: 'error', message: 'Campo "destination" mancante' })); return; }
        const enriched = { ...msg, from: username, fromRole: role };
        const delivered = sendTo(to, enriched);
        if (!delivered) enqueue(to, type, enriched);
        await pushToUser(to, { title: `Comanda da ${username}`, body: `${msg.order?.items?.length || 0} articoli` });
        ws.send(JSON.stringify({ type: 'ack', originalType: type, to, delivered }));
        return;
      }

      console.log(`[WS] Non gestito: ${type} da ${username} (${role})`);

    } catch (e) { console.error('[WS] Errore:', e.message); }
  });

  ws.on('close', () => {
    removeClient(username, ws);
    console.log(`[-] ${isService ? 'SERVICE' : role} disconnesso: ${username}`);
    broadcastStatus();
  });

  ws.on('error', e => console.error(`[WS] Errore (${username}):`, e.message));
});

// ── AVVIO ─────────────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`
╔══════════════════════════════════════╗
║      ScanPC Server v4.0              ║
╚══════════════════════════════════════╝
  Porta   : ${PORT}
  DataDir : ${DATA_DIR}
  VAPID   : ${VAPID_PUBLIC ? 'OK' : '⚠ non configurato'}
  JWT     : ${JWT_SECRET !== 'dev-secret-change-in-prod' ? 'OK' : '⚠ usa JWT_SECRET in produzione'}
`);
});
