const express = require('express');
const { WebSocketServer } = require('ws');
const http = require('http');
const path = require('path');
const sql = require('mssql');

const app = express();
const server = http.createServer(app);
const wss = new WebSocketServer({ server });

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ─── CORS per Flutter ────────────────────────────────────────────────────────
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  if (req.method === 'OPTIONS') return res.sendStatus(200);
  next();
});

// ─── Configurazione SQL Server ────────────────────────────────────────────────
// Imposta queste variabili d'ambiente su Render:
//   DB_SERVER   → es. 192.168.1.10
//   DB_NAME     → nome del database
//   DB_USER     → utente SQL
//   DB_PASSWORD → password SQL
const dbConfig = {
  server:   process.env.DB_SERVER   || 'localhost',
  database: process.env.DB_NAME     || 'gestionale',
  user:     process.env.DB_USER     || 'sa',
  password: process.env.DB_PASSWORD || '',
  port:     parseInt(process.env.DB_PORT || '1433'),
  options: {
    encrypt:              false,
    trustServerCertificate: true,
    connectTimeout:       15000,
    requestTimeout:       30000,
  },
  pool: {
    max: 10, min: 0, idleTimeoutMillis: 30000
  }
};

let pool = null;

async function getPool() {
  if (!pool) {
    pool = await sql.connect(dbConfig);
    console.log('[DB] Connesso a SQL Server');
  }
  return pool;
}

// Riconnessione automatica
async function safeQuery(fn) {
  try {
    const p = await getPool();
    return await fn(p);
  } catch (err) {
    console.error('[DB] Errore, reset pool:', err.message);
    pool = null;
    throw err;
  }
}

// ─── WEBSOCKET ────────────────────────────────────────────────────────────────
let pcClients = new Map();   // name → ws
const scannerClients = new Set();

function broadcastStatus() {
  const status = JSON.stringify({
    type: 'status',
    pcConnected: pcClients.size > 0,
    pcCount: pcClients.size,
    scannersConnected: scannerClients.size
  });
  wss.clients.forEach(client => {
    if (client.readyState === 1) client.send(status);
  });
}

wss.on('connection', (ws, req) => {
  const params     = new URL(req.url, 'http://localhost').searchParams;
  const clientType = params.get('type') || 'scanner';
  const clientName = params.get('name') || 'Dispositivo';

  ws.clientType = clientType;
  ws.clientName = clientName;

  console.log(`[+] ${clientType} connesso: ${clientName}`);

  if (clientType === 'pc') {
    pcClients.set(clientName, ws);
  } else {
    scannerClients.add(ws);
  }

  broadcastStatus();

  ws.on('message', (data) => {
    try {
      const msg = JSON.parse(data.toString());

      if (msg.type === 'scan_batch') {
        console.log(`[SCAN] ${clientName}: ${msg.total} codici`);
        // Invia a tutti i PC connessi
        pcClients.forEach(pc => {
          if (pc.readyState === 1) pc.send(JSON.stringify(msg));
        });
        ws.send(JSON.stringify({ type: 'batch_ack', count: msg.total }));
        return;
      }

      if (clientType === 'pc') {
        scannerClients.forEach(s => {
          if (s.readyState === 1) s.send(JSON.stringify(msg));
        });
      }

    } catch (e) {
      console.error('Errore messaggio:', e.message);
    }
  });

  ws.on('close', () => {
    console.log(`[-] ${clientType} disconnesso: ${clientName}`);
    if (clientType === 'pc') pcClients.delete(clientName);
    else scannerClients.delete(ws);
    broadcastStatus();
  });

  ws.on('error', (err) => {
    console.error(`Errore WS (${clientName}):`, err.message);
  });
});

// ─── REST API ─────────────────────────────────────────────────────────────────

// GET /api/health — ping
app.get('/api/health', (req, res) => {
  res.json({ ok: true, ts: new Date().toISOString() });
});

// GET /api/articoli/search?q=EDILMALTA&limit=20
// Ricerca articoli per CodArt o NomeArticolo
// ⚠️  Adatta la query alla tua struttura DB
app.get('/api/articoli/search', async (req, res) => {
  const q     = (req.query.q || '').trim();
  const limit = Math.min(parseInt(req.query.limit || '30'), 100);

  if (q.length < 2) {
    return res.json({ results: [] });
  }

  try {
    const result = await safeQuery(async (p) => {
      const r = await p.request()
        .input('q', sql.NVarChar, `%${q}%`)
        .input('limit', sql.Int, limit)
        .query(`
          SELECT TOP (@limit)
            CodArticolo,
            NomeArticolo,
            UnitaMisura,
            Fornitore
          FROM Articoli
          WHERE CodArticolo LIKE @q
             OR NomeArticolo LIKE @q
          ORDER BY
            CASE WHEN CodArticolo LIKE @q THEN 0 ELSE 1 END,
            CodArticolo
        `);
      return r.recordset;
    });

    res.json({ results: result });
  } catch (err) {
    console.error('[API] search articoli:', err.message);
    // Se il DB non è configurato restituisce dati mock per sviluppo
    if (process.env.NODE_ENV !== 'production') {
      return res.json({
        results: [
          { CodArticolo: 'EDILMALTA', NomeArticolo: 'EDIMALTA DOPPIA M10 kg 25 casertana (edico)', UnitaMisura: 'NR', Fornitore: 'INDUSTRIA CALCE CASERTANA S.r.l.' },
          { CodArticolo: 'CEMENTO',  NomeArticolo: 'CEMENTO PORTLAND 325 kg 25',                 UnitaMisura: 'NR', Fornitore: 'CEMENTIROSSI S.p.A.' },
        ].filter(a => a.CodArticolo.includes(q.toUpperCase()) || a.NomeArticolo.toUpperCase().includes(q.toUpperCase()))
      });
    }
    res.status(500).json({ error: 'Errore ricerca: ' + err.message });
  }
});

// POST /api/giacenze
// Body: { CodArt: "EDILMALTA" }
// Chiama: exec sprCu_MAGArticoliSintetico_Domenico @CodARt=?, @pCodDep='SEDE', @pMinEsercizio='2026', @pDateFrom='20260101'
app.post('/api/giacenze', async (req, res) => {
  const { CodArt } = req.body;
  if (!CodArt) return res.status(400).json({ error: 'CodArt richiesto' });

  const anno      = new Date().getFullYear().toString();
  const dateFrom  = `${anno}0101`;

  try {
    const result = await safeQuery(async (p) => {
      const r = await p.request()
        .input('CodArt',        sql.NVarChar, CodArt)
        .input('pCodDep',       sql.NVarChar, process.env.COD_DEP || 'SEDE')
        .input('pMinEsercizio', sql.NVarChar, anno)
        .input('pDateFrom',     sql.NVarChar, dateFrom)
        .execute('sprCu_MAGArticoliSintetico_Domenico');
      return r.recordset;
    });

    if (!result || result.length === 0) {
      return res.json({ found: false });
    }

    const row = result[0];
    res.json({
      found: true,
      data: {
        CodArticolo:  row.CodARt    || row.CodArticolo || CodArt,
        NomeArticolo: row.NomeArticolo || row.Descrizione || '',
        UnitaMisura:  row.UnitaMisura  || row.UM || '',
        Fornitore:    row.Fornitore    || '',
        Giacenza:     row.Giacenza     ?? row.GiacenzaAttuale ?? 0,
      }
    });

  } catch (err) {
    console.error('[API] giacenze:', err.message);
    // Mock per sviluppo
    if (process.env.NODE_ENV !== 'production') {
      return res.json({
        found: true,
        data: {
          CodArticolo:  CodArt,
          NomeArticolo: 'EDIMALTA DOPPIA M10 kg 25 casertana (edico)',
          UnitaMisura:  'NR',
          Fornitore:    'INDUSTRIA CALCE CASERTANA S.r.l.',
          Giacenza:     285,
        }
      });
    }
    res.status(500).json({ error: 'Errore stored procedure: ' + err.message });
  }
});

// ─── AVVIO ────────────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`ScanPC server avviato sulla porta ${PORT}`);
  // Tenta connessione DB all'avvio (non bloccante)
  if (process.env.DB_SERVER) {
    getPool().catch(e => console.warn('[DB] Connessione iniziale fallita:', e.message));
  } else {
    console.warn('[DB] DB_SERVER non configurato — modalità mock attiva');
  }
});
