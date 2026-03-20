'use strict';

const express    = require('express');
const http       = require('http');
const { WebSocketServer } = require('ws');
const bcrypt     = require('bcryptjs');
const jwt        = require('jsonwebtoken');
const webpush    = require('web-push');
const path       = require('path');

const app    = express();
const server = http.createServer(app);
const wss    = new WebSocketServer({ server });

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ─── CORS (per Flutter e web) ─────────────────────────────────────────────────
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.header('Access-Control-Allow-Methods', 'GET, POST, DELETE, OPTIONS');
  if (req.method === 'OPTIONS') return res.sendStatus(200);
  next();
});

// ─── CONFIGURAZIONE ───────────────────────────────────────────────────────────
const JWT_SECRET = process.env.JWT_SECRET || 'cambia-questa-stringa-in-produzione';

// VAPID — genera con: npx web-push generate-vapid-keys
// Poi imposta le variabili d'ambiente su Render
const VAPID_PUBLIC  = process.env.VAPID_PUBLIC_KEY  || '';
const VAPID_PRIVATE = process.env.VAPID_PRIVATE_KEY || '';
const VAPID_EMAIL   = process.env.VAPID_EMAIL       || 'mailto:admin@example.com';

if (VAPID_PUBLIC && VAPID_PRIVATE) {
  webpush.setVapidDetails(VAPID_EMAIL, VAPID_PUBLIC, VAPID_PRIVATE);
  console.log('[PUSH] VAPID configurato');
} else {
  console.warn('[PUSH] VAPID non configurato — notifiche push disabilitate');
}

// ─── DATABASE IN MEMORIA ──────────────────────────────────────────────────────
// In produzione sostituisci con un vero DB (es. MongoDB Atlas, PostgreSQL su Render)
// Per ora: semplice Map in memoria — i dati si perdono al riavvio del server
// Struttura users: Map<username, { username, passwordHash, role, createdAt }>
const users          = new Map();
const pushSubs       = new Map(); // username → Set<subscriptionObject>

// Crea utente admin di default al primo avvio
// IMPORTANTE: cambia la password nelle variabili d'ambiente
;(async () => {
  const adminUser = process.env.ADMIN_USER || 'admin';
  const adminPass = process.env.ADMIN_PASS || 'admin123';
  if (!users.has(adminUser)) {
    const hash = await bcrypt.hash(adminPass, 10);
    users.set(adminUser, {
      username:  adminUser,
      passwordHash: hash,
      role:      'admin',
      createdAt: new Date().toISOString(),
    });
    console.log(`[AUTH] Utente admin creato: ${adminUser}`);
  }
})();

// ─── MIDDLEWARE AUTH ──────────────────────────────────────────────────────────
function requireAuth(req, res, next) {
  const auth = req.headers.authorization || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'Token mancante' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Token non valido o scaduto' });
  }
}

function requireAdmin(req, res, next) {
  requireAuth(req, res, () => {
    if (req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Permessi insufficienti' });
    }
    next();
  });
}

// ─── REST API — AUTH ──────────────────────────────────────────────────────────

// POST /api/auth/login
// Body: { username, password }
app.post('/api/auth/login', async (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) {
    return res.status(400).json({ error: 'Username e password richiesti' });
  }

  const user = users.get(username);
  if (!user) return res.status(401).json({ error: 'Credenziali non valide' });

  const ok = await bcrypt.compare(password, user.passwordHash);
  if (!ok) return res.status(401).json({ error: 'Credenziali non valide' });

  const token = jwt.sign(
    { username: user.username, role: user.role },
    JWT_SECRET,
    { expiresIn: '30d' }
  );

  console.log(`[AUTH] Login: ${username}`);
  res.json({
    token,
    user: { username: user.username, role: user.role }
  });
});

// POST /api/auth/register  (solo admin può creare utenti)
// Body: { username, password, role }
app.post('/api/auth/register', requireAdmin, async (req, res) => {
  const { username, password, role = 'scanner' } = req.body || {};
  if (!username || !password) {
    return res.status(400).json({ error: 'Username e password richiesti' });
  }
  if (users.has(username)) {
    return res.status(409).json({ error: 'Username già esistente' });
  }
  if (!['admin', 'scanner', 'pc'].includes(role)) {
    return res.status(400).json({ error: 'Ruolo non valido (admin/scanner/pc)' });
  }

  const passwordHash = await bcrypt.hash(password, 10);
  users.set(username, { username, passwordHash, role, createdAt: new Date().toISOString() });

  console.log(`[AUTH] Nuovo utente: ${username} (${role})`);
  res.status(201).json({ ok: true, username, role });
});

// GET /api/auth/users  (solo admin)
app.get('/api/auth/users', requireAdmin, (req, res) => {
  const list = [...users.values()].map(u => ({
    username:  u.username,
    role:      u.role,
    createdAt: u.createdAt,
  }));
  res.json({ users: list });
});

// DELETE /api/auth/users/:username  (solo admin)
app.delete('/api/auth/users/:username', requireAdmin, (req, res) => {
  const { username } = req.params;
  if (username === req.user.username) {
    return res.status(400).json({ error: 'Non puoi eliminare te stesso' });
  }
  if (!users.has(username)) {
    return res.status(404).json({ error: 'Utente non trovato' });
  }
  users.delete(username);
  pushSubs.delete(username);
  console.log(`[AUTH] Utente eliminato: ${username}`);
  res.json({ ok: true });
});

// POST /api/auth/change-password
// Body: { oldPassword, newPassword }
app.post('/api/auth/change-password', requireAuth, async (req, res) => {
  const { oldPassword, newPassword } = req.body || {};
  if (!oldPassword || !newPassword) {
    return res.status(400).json({ error: 'Vecchia e nuova password richieste' });
  }
  const user = users.get(req.user.username);
  const ok = await bcrypt.compare(oldPassword, user.passwordHash);
  if (!ok) return res.status(401).json({ error: 'Password attuale non corretta' });

  user.passwordHash = await bcrypt.hash(newPassword, 10);
  console.log(`[AUTH] Password cambiata: ${req.user.username}`);
  res.json({ ok: true });
});

// ─── REST API — NOTIFICHE PUSH ────────────────────────────────────────────────

// GET /api/push/vapid-public-key
// Restituisce la chiave pubblica VAPID per registrare il service worker
app.get('/api/push/vapid-public-key', (req, res) => {
  if (!VAPID_PUBLIC) {
    return res.status(503).json({ error: 'Push non configurato' });
  }
  res.json({ publicKey: VAPID_PUBLIC });
});

// POST /api/push/subscribe
// Body: { subscription }  (oggetto PushSubscription dal browser/Flutter)
app.post('/api/push/subscribe', requireAuth, (req, res) => {
  const { subscription } = req.body || {};
  if (!subscription || !subscription.endpoint) {
    return res.status(400).json({ error: 'Subscription non valida' });
  }

  if (!pushSubs.has(req.user.username)) {
    pushSubs.set(req.user.username, new Set());
  }
  pushSubs.get(req.user.username).add(subscription);

  console.log(`[PUSH] Sottoscritto: ${req.user.username}`);
  res.json({ ok: true });
});

// POST /api/push/unsubscribe
// Body: { endpoint }
app.post('/api/push/unsubscribe', requireAuth, (req, res) => {
  const { endpoint } = req.body || {};
  const subs = pushSubs.get(req.user.username);
  if (subs) {
    for (const s of subs) {
      if (s.endpoint === endpoint) { subs.delete(s); break; }
    }
  }
  res.json({ ok: true });
});

// POST /api/push/send  (solo admin — invia notifica manuale)
// Body: { username, title, body }
app.post('/api/push/send', requireAdmin, async (req, res) => {
  const { username, title = 'ScanPC', body = '' } = req.body || {};
  const count = await sendPushToUser(username, { title, body });
  res.json({ ok: true, sent: count });
});

// ─── HELPER PUSH ──────────────────────────────────────────────────────────────
async function sendPushToUser(username, payload) {
  if (!VAPID_PUBLIC || !VAPID_PRIVATE) return 0;
  const subs = pushSubs.get(username);
  if (!subs || subs.size === 0) return 0;

  const msg = JSON.stringify(payload);
  let sent = 0;
  const dead = [];

  for (const sub of subs) {
    try {
      await webpush.sendNotification(sub, msg);
      sent++;
    } catch (err) {
      // 410 Gone = subscription scaduta, rimuovila
      if (err.statusCode === 410) dead.push(sub);
      else console.error('[PUSH] Errore invio:', err.message);
    }
  }
  dead.forEach(s => subs.delete(s));
  return sent;
}

// Notifica a tutti i PC registrati
async function notifyAllPCs(payload) {
  let total = 0;
  for (const [username, user] of users) {
    if (user.role === 'pc' || user.role === 'admin') {
      total += await sendPushToUser(username, payload);
    }
  }
  return total;
}

// ─── REST API — HEALTH ────────────────────────────────────────────────────────
app.get('/api/health', (req, res) => {
  res.json({
    ok:       true,
    ts:       new Date().toISOString(),
    users:    users.size,
    scanners: scannerClients.size,
    pcs:      pcClients.size,
  });
});

// ─── WEBSOCKET ────────────────────────────────────────────────────────────────
const pcClients      = new Map(); // name → ws
const scannerClients = new Set();

function broadcastStatus() {
  const status = JSON.stringify({
    type:              'status',
    pcConnected:       pcClients.size > 0,
    pcCount:           pcClients.size,
    scannersConnected: scannerClients.size,
  });
  wss.clients.forEach(client => {
    if (client.readyState === 1) client.send(status);
  });
}

wss.on('connection', (ws, req) => {
  // Autenticazione via query string: ?token=JWT&type=scanner&name=NomeDispositivo
  // Oppure senza token per retrocompatibilità (tipo scanner non autenticato)
  const params     = new URL(req.url, 'http://localhost').searchParams;
  const token      = params.get('token') || '';
  const clientType = params.get('type')  || 'scanner';
  const clientName = params.get('name')  || 'Dispositivo';

  // Verifica token se presente
  if (token) {
    try {
      ws.authUser = jwt.verify(token, JWT_SECRET);
    } catch {
      ws.send(JSON.stringify({ type: 'error', message: 'Token non valido' }));
      ws.close();
      return;
    }
  }

  ws.clientType = clientType;
  ws.clientName = clientName;

  console.log(`[+] ${clientType} connesso: ${clientName}${ws.authUser ? ` (${ws.authUser.username})` : ''}`);

  if (clientType === 'pc') {
    pcClients.set(clientName, ws);
  } else {
    scannerClients.add(ws);
  }

  broadcastStatus();

  ws.on('message', async (data) => {
    try {
      const msg = JSON.parse(data.toString());

      // ── Scanner → PC: batch di codici scansionati ──────────────────────────
      if (msg.type === 'scan_batch') {
        console.log(`[SCAN] ${clientName}: ${msg.total} codici`);

        if (pcClients.size === 0) {
          ws.send(JSON.stringify({ type: 'error', message: 'Nessun PC connesso' }));
          return;
        }

        // Inoltra a tutti i PC connessi
        pcClients.forEach(pc => {
          if (pc.readyState === 1) pc.send(JSON.stringify(msg));
        });

        // Conferma allo scanner
        ws.send(JSON.stringify({ type: 'batch_ack', count: msg.total }));

        // Notifica push ai PC che non sono connessi via WS
        await notifyAllPCs({
          title: `ScanPC — ${clientName}`,
          body:  `${msg.total} codice/i scansionati`,
        });
        return;
      }

      // ── PC → tutti gli scanner: comandi broadcast ──────────────────────────
      if (clientType === 'pc') {
        scannerClients.forEach(s => {
          if (s.readyState === 1) s.send(JSON.stringify(msg));
        });
        return;
      }

      // ── Ping keepalive ────────────────────────────────────────────────────
      if (msg.type === 'ping') {
        ws.send(JSON.stringify({ type: 'pong' }));
        return;
      }

    } catch (e) {
      console.error('[WS] Errore messaggio:', e.message);
    }
  });

  ws.on('close', () => {
    console.log(`[-] ${clientType} disconnesso: ${clientName}`);
    if (clientType === 'pc') pcClients.delete(clientName);
    else scannerClients.delete(ws);
    broadcastStatus();
  });

  ws.on('error', (err) => {
    console.error(`[WS] Errore (${clientName}):`, err.message);
  });
});

// ─── AVVIO ────────────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`
╔══════════════════════════════════╗
║     ScanPC Server v2.0           ║
╚══════════════════════════════════╝
  Porta   : ${PORT}
  JWT     : ${JWT_SECRET !== 'cambia-questa-stringa-in-produzione' ? 'OK' : '⚠ usa JWT_SECRET in produzione'}
  VAPID   : ${VAPID_PUBLIC ? 'OK' : '⚠ non configurato'}
`);
});
