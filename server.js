const express    = require('express');
const { WebSocketServer } = require('ws');
const http       = require('http');
const path       = require('path');
const admin      = require('firebase-admin');

const app    = express();
const server = http.createServer(app);
const wss    = new WebSocketServer({ server });

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ── Firebase Admin SDK ────────────────────────────────────────────────────────
let firebaseReady = false;
try {
  const serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT || '{}');
  if (serviceAccount.project_id) {
    admin.initializeApp({
      credential: admin.credential.cert(serviceAccount),
    });
    firebaseReady = true;
    console.log('[Firebase] ✓ Admin SDK inizializzato');
  } else {
    console.warn('[Firebase] FIREBASE_SERVICE_ACCOUNT non configurato — push disabilitati');
  }
} catch (e) {
  console.error('[Firebase] Errore init:', e.message);
}

// ── Coda messaggi offline ─────────────────────────────────────────────────────
// Mantiene in memoria i messaggi per utenti non connessi (max 50 per utente)
const messageQueue = new Map(); // username → [{msg, ts}]
const MAX_QUEUE    = 50;

function enqueue(username, msg) {
  if (!messageQueue.has(username)) messageQueue.set(username, []);
  const q = messageQueue.get(username);
  q.push({ msg, ts: Date.now() });
  if (q.length > MAX_QUEUE) q.shift(); // rimuovi il più vecchio
}

function flushQueue(username, ws) {
  const q = messageQueue.get(username);
  if (!q || q.length === 0) return;
  console.log(`[QUEUE] Consegna ${q.length} msg in coda a ${username}`);
  q.forEach(({ msg }) => {
    if (ws.readyState === 1) ws.send(JSON.stringify(msg));
  });
  messageQueue.delete(username);
}

// ── Stato connessioni ─────────────────────────────────────────────────────────
let serviceClient = null;               // Java service
const userClients = new Map();          // username → ws
const pendingAuth = new Map();          // request_id → {ws, username, password}
const pendingReqs = new Map();          // request_id → ws (per routing risposte Java)

function broadcast(msg, excludeWs = null) {
  const data = JSON.stringify(msg);
  wss.clients.forEach(ws => {
    if (ws !== excludeWs && ws.readyState === 1) ws.send(data);
  });
}

function broadcastStatus() {
  const msg = {
    type:           'status',
    serviceOnline:  serviceClient !== null,
    usersOnline:    [...userClients.keys()],
  };
  wss.clients.forEach(ws => {
    if (ws.readyState === 1) ws.send(JSON.stringify(msg));
  });
}

function sendToUser(username, msg) {
  const ws = userClients.get(username);
  if (ws && ws.readyState === 1) {
    ws.send(JSON.stringify(msg));
    return true;
  }
  // Utente offline → metti in coda
  enqueue(username, msg);
  return false;
}

// ── Push notification via Firebase ───────────────────────────────────────────
async function sendPush(fcmToken, title, body, data = {}) {
  if (!firebaseReady || !fcmToken) return;
  try {
    await admin.messaging().send({
      token: fcmToken,
      notification: { title, body },
      data: Object.fromEntries(
        Object.entries(data).map(([k, v]) => [k, String(v)])
      ),
      android: { priority: 'high' },
      apns: {
        payload: { aps: { sound: 'default', badge: 1 } },
        headers: { 'apns-priority': '10' },
      },
    });
    console.log(`[PUSH] ✓ Inviato a ${fcmToken.substring(0, 20)}...`);
  } catch (e) {
    console.error('[PUSH] Errore:', e.message);
  }
}

// ── WebSocket ─────────────────────────────────────────────────────────────────
wss.on('connection', (ws, req) => {
  const params     = new URL(req.url, 'http://localhost').searchParams;
  const clientType = params.get('type') || 'user';
  const clientName = params.get('name') || 'Unknown';

  ws.clientType = clientType;
  ws.clientName = clientName;
  ws.username   = null;

  console.log(`[+] ${clientType} connesso: ${clientName}`);

  // ── Java service ──────────────────────────────────────────────────────────
  if (clientType === 'service') {
    if (serviceClient) serviceClient.close();
    serviceClient = ws;
    broadcastStatus();

    ws.on('message', data => {
      try {
        const msg = JSON.parse(data.toString());

        // Auth response → rispondi al client che ha fatto login
        if (msg.type === 'auth_response') {
          const pending = pendingAuth.get(msg.request_id);
          if (pending) {
            pendingAuth.delete(msg.request_id);
            pending.ws.send(JSON.stringify(msg));
            if (msg.ok) {
              // Registra il client come autenticato
              const oldWs = userClients.get(msg.username);
              if (oldWs && oldWs !== pending.ws) oldWs.close();
              userClients.set(msg.username, pending.ws);
              pending.ws.username = msg.username;
              pending.ws.ruolo    = msg.ruolo;
              console.log(`[AUTH] ✓ ${msg.username} (${msg.ruolo})`);
              flushQueue(msg.username, pending.ws);
              broadcastStatus();
            }
          }
          return;
        }

        // Routing risposte al client che ha fatto la richiesta
        const reqId = msg.request_id;
        if (reqId && pendingReqs.has(reqId)) {
          const clientWs = pendingReqs.get(reqId);
          pendingReqs.delete(reqId);
          if (clientWs.readyState === 1) clientWs.send(JSON.stringify(msg));
          return;
        }

        // Routing per destinatario specifico
        if (msg.to) {
          sendToUser(msg.to, msg);
          return;
        }

        // Broadcast generico
        broadcast(msg, ws);

      } catch (e) {
        console.error('[SERVICE] Errore msg:', e.message);
      }
    });

    ws.on('close', () => {
      console.log('[-] Service disconnesso');
      serviceClient = null;
      broadcastStatus();
    });

    return;
  }

  // ── Client user (app Flutter) ─────────────────────────────────────────────
  ws.on('message', async data => {
    try {
      const msg  = JSON.parse(data.toString());
      const type = msg.type || '';

      // ── Login ──────────────────────────────────────────────────────────────
      if (type === 'login') {
        const reqId = `auth_${Date.now()}_${Math.random().toString(36).slice(2)}`;
        pendingAuth.set(reqId, { ws, username: msg.username, password: msg.password });

        if (serviceClient && serviceClient.readyState === 1) {
          serviceClient.send(JSON.stringify({
            type:       'auth_request',
            request_id: reqId,
            username:   msg.username,
            password:   msg.password,
            from:       clientName,
          }));
        } else {
          // Service non disponibile
          ws.send(JSON.stringify({
            type:  'auth_response',
            ok:    false,
            error: 'Servizio non disponibile. Riprova tra qualche secondo.',
          }));
          pendingAuth.delete(reqId);
        }
        return;
      }

      // ── FCM token update ───────────────────────────────────────────────────
      if (type === 'fcm_token_update') {
        ws.fcmToken = msg.fcm_token;
        if (serviceClient && serviceClient.readyState === 1) {
          serviceClient.send(JSON.stringify({
            type:      'fcm_token_update',
            username:  ws.username || msg.username,
            fcm_token: msg.fcm_token,
          }));
        }
        return;
      }

      // ── Comanda inviata da mobile/desktop ─────────────────────────────────
      if (type === 'send_order') {
        const order       = msg.order;
        const destination = order.destination || 'desktop';
        const from        = ws.username || ws.clientName;

        console.log(`[ORDER] ${from} → ${destination}: ${order.cliente || '?'}`);

        const orderMsg = { type: 'order_received', order };

        // Invia al destinatario (o metti in coda se offline)
        const delivered = sendToUser(destination, orderMsg);
        console.log(`[ORDER] ${delivered ? 'consegnato' : 'in coda per'} ${destination}`);

        // Invia push Firebase al destinatario
        const destWs = userClients.get(destination);
        const fcmToken = destWs?.fcmToken || msg.fcm_token_dest;
        if (fcmToken) {
          await sendPush(
            fcmToken,
            `Nuova comanda da ${from}`,
            `${order.cliente || '—'} — ${(order.items || []).length} articoli`,
            { type: 'order', order_id: order.order_id || '' }
          );
        }

        // Conferma al mittente
        ws.send(JSON.stringify({ type: 'order_sent', ok: true }));
        return;
      }

      // ── Richieste al Java service (search, giacenza, foto, ecc.) ──────────
      if (type.endsWith('_request') || type === 'localization_update') {
        if (!serviceClient || serviceClient.readyState !== 1) {
          ws.send(JSON.stringify({
            type:       type.replace('_request', '_response'),
            request_id: msg.request_id,
            error:      'Servizio Java non connesso',
          }));
          return;
        }
        const reqId = msg.request_id || `req_${Date.now()}`;
        pendingReqs.set(reqId, ws);
        msg.request_id = reqId;
        msg.from       = ws.username || ws.clientName;
        serviceClient.send(JSON.stringify(msg));

        // Timeout 15s
        setTimeout(() => {
          if (pendingReqs.has(reqId)) {
            pendingReqs.delete(reqId);
            if (ws.readyState === 1) ws.send(JSON.stringify({
              type:       type.replace('_request', '_response'),
              request_id: reqId,
              error:      'Timeout risposta Java',
            }));
          }
        }, 15000);
        return;
      }

      // ── Broadcast generico ─────────────────────────────────────────────────
      if (msg.to) {
        sendToUser(msg.to, msg);
      } else {
        broadcast(msg, ws);
      }

    } catch (e) {
      console.error('[USER] Errore msg:', e.message);
    }
  });

  ws.on('close', () => {
    console.log(`[-] ${ws.clientType} disconnesso: ${ws.username || ws.clientName}`);
    if (ws.username) {
      userClients.delete(ws.username);
      broadcastStatus();
    }
  });

  ws.on('error', e => console.error(`[WS Error] ${ws.clientName}:`, e.message));

  // Invia stato attuale al nuovo client
  ws.send(JSON.stringify({
    type:          'status',
    serviceOnline: serviceClient !== null,
    usersOnline:   [...userClients.keys()],
  }));
});

// ── Health check ──────────────────────────────────────────────────────────────
app.get('/api/health', (_, res) => res.json({
  ok:            true,
  serviceOnline: serviceClient !== null,
  usersOnline:   [...userClients.keys()],
  queuedUsers:   [...messageQueue.keys()],
  firebase:      firebaseReady,
  ts:            new Date().toISOString(),
}));

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => console.log(`ScanPC server v10 avviato sulla porta ${PORT}`));
