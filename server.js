/**
 * server.js — Voxa Portal Node Server
 *
 * Routes:
 *   POST /                    → proxy to GAS (user-facing actions)
 *   POST /api                 → proxy to GAS — with LOCAL LOGIN FALLBACK
 *   GET  /poller/status       → health + job stats
 *   POST /poller/force-refresh → force poll (all or one agent)
 *   POST /poller/run/:job     → run any background job
 *   POST /api/archive/leads   → get archived leads from team SS
 *   POST /api/archive/mt      → get archived MT rows from team SS
 *   POST /api/archive/manual  → get archived manual entries from team SS
 *
 * LOCAL LOGIN FALLBACK
 *   When GAS is unreachable or returns an error for a "login" action,
 *   the Node server handles login itself:
 *     1. Reads the Users sheet from the main Google Spreadsheet
 *     2. Validates the password using the same SHA-256 iteration hash as GAS
 *     3. Creates a session row in the Sessions sheet
 *     4. Returns the same { ok, session, user } shape GAS would return
 *   This means login always works as long as the Node server + Sheets API are up.
 */

const express  = require('express');
const cors     = require('cors');
const axios    = require('axios');
const path     = require('path');
const crypto   = require('crypto');

const {
  startPoller,
  pollActiveBatches,
  backfillMissingOutputs,
  repairUnassignedLeads,
  cleanupExpiredSessions,
  dedupeAllSheets,
  archiveCompletedLeads,
  archiveCompletedMT,
  archiveManualTracker,
  processCallbackQueue,
  processRetryQueue,
  getArchivedLeads,
  getArchivedMT,
  getArchivedManual,
  getStatus,
  getAllUsers,
} = require('./poller');

const { readSheet, appendRows } = require('./sheets');

const app  = express();
const PORT = process.env.PORT || 10000;
const GAS_URL        = process.env.GAS_URL;
const POLLER_TOKEN   = process.env.POLLER_TOKEN || 'voxa-bfsi-2026';
const MAIN_SS_ID     = process.env.SPREADSHEET_ID;

// GAS constants mirrored here for local login
const SESSION_TTL_HOURS = 12;
const PW_ITERATIONS     = 2000;

// Sheet column indices (0-based) matching GAS USERS_H order:
// Email, Name, Role, Team, Daily Minute Limit, Active,
// Password Hash, Password Salt, Setup Token, Setup Token Expires, Created On, Created By
const COL = {
  EMAIL:      0, NAME:  1, ROLE: 2, TEAM: 3,
  DAILY_MIN:  4, ACTIVE: 5,
  PW_HASH:    6, PW_SALT: 7,
  SETUP_TOK:  8, TOK_EXP: 9,
};

app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.static(path.join(__dirname, 'public')));

// ─── Password hashing (mirrors GAS _hashPw) ──────────────────────────────────
// GAS uses: SHA-256(salt + ':' + pw), iterated PW_ITERATIONS times, base64-encoded.
// The first iteration hashes a UTF-8 string; subsequent iterations hash the raw
// digest bytes (Uint8Array / Buffer). We replicate that exactly.

function hashPassword(password, salt) {
  // iteration 1: hash the string "salt:password"
  let buf = crypto.createHash('sha256').update(salt + ':' + password, 'utf8').digest();
  // iterations 2..PW_ITERATIONS: hash the raw buffer each time
  for (let i = 1; i < PW_ITERATIONS; i++) {
    buf = crypto.createHash('sha256').update(buf).digest();
  }
  return buf.toString('base64');
}

function verifyPassword(password, salt, hash) {
  if (!password || !salt || !hash) return false;
  const computed = hashPassword(password, salt);
  if (computed.length !== hash.length) return false;
  // constant-time compare
  let diff = 0;
  for (let i = 0; i < computed.length; i++) {
    diff |= computed.charCodeAt(i) ^ hash.charCodeAt(i);
  }
  return diff === 0;
}

// ─── Local login (used as fallback when GAS fails) ───────────────────────────

async function localLogin(email, password) {
  if (!MAIN_SS_ID) return { ok: false, error: 'SPREADSHEET_ID not configured' };

  email = String(email || '').toLowerCase().trim();
  if (!email || !password) return { ok: false, error: 'EMAIL_AND_PASSWORD_REQUIRED' };

  // 1. Read Users sheet
  let headers, rows;
  try {
    ({ headers, rows } = await readSheet(MAIN_SS_ID, 'Users'));
  } catch (e) {
    console.error('[localLogin] Cannot read Users sheet:', e.message);
    return { ok: false, error: 'CANNOT_READ_USERS_SHEET' };
  }

  if (!headers.length) return { ok: false, error: 'USERS_SHEET_EMPTY' };

  // Build column index from actual headers (robust to column order changes)
  const h = (name) => headers.indexOf(name);
  const emailCol   = h('Email');
  const nameCol    = h('Name');
  const roleCol    = h('Role');
  const teamCol    = h('Team');
  const minCol     = h('Daily Minute Limit');
  const activeCol  = h('Active');
  const hashCol    = h('Password Hash');
  const saltCol    = h('Password Salt');

  if (emailCol < 0 || hashCol < 0 || saltCol < 0) {
    return { ok: false, error: 'USERS_SHEET_MISSING_COLUMNS' };
  }

  // 2. Find the user row
  const userRow = rows.find(
    r => String(r[emailCol] || '').toLowerCase().trim() === email
  );
  if (!userRow) return { ok: false, error: 'INVALID_CREDENTIALS' };

  const active   = userRow[activeCol];
  const isActive = active === true || String(active).toUpperCase() === 'TRUE';
  if (!isActive) return { ok: false, error: 'ACCOUNT_INACTIVE' };

  const pwHash = String(userRow[hashCol] || '');
  const pwSalt = String(userRow[saltCol] || '');
  if (!pwHash) return { ok: false, error: 'PASSWORD_NOT_SET', message: 'Check your email for the setup link.' };

  // 3. Verify password
  if (!verifyPassword(password, pwSalt, pwHash)) {
    return { ok: false, error: 'INVALID_CREDENTIALS' };
  }

  // 4. Create session row in Sessions sheet
  const token = crypto.randomUUID() + '-' + crypto.randomUUID().split('-')[0];
  const now   = new Date();
  const exp   = new Date(now.getTime() + SESSION_TTL_HOURS * 3600 * 1000);

  try {
    await appendRows(MAIN_SS_ID, 'Sessions', [
      [token, email, now.toISOString(), exp.toISOString()],
    ]);
  } catch (e) {
    console.error('[localLogin] Cannot write session:', e.message);
    // Non-fatal — return login success without a persisted session
    // (the session will still work for archive endpoints that validate locally)
  }

  // 5. Build public user object (same shape as GAS _publicUser)
  const user = {
    email,
    name:             String(userRow[nameCol]  || '').trim(),
    role:             String(userRow[roleCol]  || '').trim().toLowerCase(),
    team:             String(userRow[teamCol]  || '').trim(),
    dailyMinuteLimit: Number(userRow[minCol]   || 0),
    active:           true,
    hasPassword:      true,
  };

  console.log(`[localLogin] Login OK for ${email} (GAS fallback)`);
  return { ok: true, session: token, user, _localLogin: true };
}

// ─── Auth middleware ─────────────────────────────────────────────────────────

function requirePollerToken(req, res, next) {
  const auth = req.headers['authorization'] || '';
  const token = auth.replace('Bearer ', '').trim();
  if (token !== POLLER_TOKEN) {
    return res.status(401).json({ ok: false, error: 'UNAUTHORIZED' });
  }
  next();
}

/**
 * Validate a user session token against the Sessions sheet in main SS
 * Returns { ok, user } where user = { email, role, team }
 */
async function validateSession(sessionToken) {
  if (!sessionToken) return { ok: false };
  try {
    const { headers, rows } = await readSheet(MAIN_SS_ID, 'Sessions');
    if (!headers.length) return { ok: false };
    const tokenCol   = headers.indexOf('Token');
    const emailCol   = headers.indexOf('Email');
    const expiresCol = headers.indexOf('Expires At');
    for (const row of rows) {
      if (String(row[tokenCol] || '') !== sessionToken) continue;
      const expires = new Date(row[expiresCol] || 0);
      if (expires.getTime() < Date.now()) return { ok: false, error: 'SESSION_EXPIRED' };
      const email = String(row[emailCol] || '').toLowerCase().trim();
      // Get user details
      const users = await getAllUsers();
      const user = users.find(u => u.email === email);
      if (!user || !user.active) return { ok: false };
      return { ok: true, user };
    }
    return { ok: false };
  } catch (e) {
    console.error('[auth] validateSession error:', e.message);
    return { ok: false };
  }
}

// ─── Main proxy route → GAS ──────────────────────────────────────────────────

async function proxyToGAS(req, res) {
  if (!GAS_URL) return res.json({ ok: false, error: 'GAS_URL not configured' });
  try {
    const response = await axios.post(GAS_URL, req.body, {
      headers: { 'Content-Type': 'application/json' },
      timeout: 30000,
    });
    res.json(response.data);
  } catch (err) {
    const msg = err.response?.data || err.message;
    console.error('[proxy] GAS error:', msg);
    res.status(500).json({ ok: false, error: String(msg).slice(0, 300) });
  }
}

// ─── /api route — proxy to GAS with local login fallback ─────────────────────
//
// For the "login" action specifically:
//   1. Try GAS first (if GAS_URL is set)
//   2. If GAS fails (network error, timeout, 5xx, or returns ok:false with a
//      GAS-level error), fall back to localLogin() which reads Sheets directly.
// All other actions are proxied to GAS normally.

async function proxyToGASWithLoginFallback(req, res) {
  const body   = req.body || {};
  const action = String(body.action || '').toLowerCase();

  // ── Non-login actions: just proxy normally ──
  if (action !== 'login') {
    return proxyToGAS(req, res);
  }

  // ── Login action ──
  const { email, password } = body;

  // Try GAS first (if configured)
  if (GAS_URL) {
    try {
      const response = await axios.post(GAS_URL, body, {
        headers: { 'Content-Type': 'application/json' },
        timeout: 25000,
      });
      const data = response.data;

      // GAS succeeded and login was OK → return as-is
      if (data && data.ok) {
        return res.json(data);
      }

      // GAS returned a business-logic error (wrong password, inactive, etc.)
      // These are definitive — don't fall back, just return the GAS error.
      const definitiveErrors = [
        'INVALID_CREDENTIALS',
        'ACCOUNT_INACTIVE',
        'PASSWORD_NOT_SET',
        'EMAIL_AND_PASSWORD_REQUIRED',
      ];
      if (data && data.error && definitiveErrors.includes(data.error)) {
        return res.json(data);
      }

      // GAS returned some other ok:false (e.g. sheet error, GAS crash) → fall back
      console.warn('[login] GAS returned non-definitive error, falling back:', data?.error);
    } catch (err) {
      // Network/timeout error → fall back
      console.warn('[login] GAS unreachable, falling back to local login:', err.message);
    }
  }

  // ── Local login fallback ──
  const result = await localLogin(email, password);
  return res.json(result);
}

app.post('/', proxyToGAS);                       // bare / still proxies directly
app.post('/api', proxyToGASWithLoginFallback);   // /api has the smart fallback

// ─── Poller admin endpoints ──────────────────────────────────────────────────

app.get('/poller/status', requirePollerToken, (req, res) => {
  res.json({ ok: true, ...getStatus() });
});

app.post('/poller/force-refresh', requirePollerToken, async (req, res) => {
  const { agentCode } = req.body || {};
  try {
    await pollActiveBatches(agentCode || null);
    res.json({ ok: true, message: agentCode ? `Refreshed ${agentCode}` : 'Refreshed all agents' });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

const JOB_MAP = {
  poll:        () => pollActiveBatches(),
  backfill:    () => backfillMissingOutputs(),
  repair:      () => repairUnassignedLeads(),
  sessions:    () => cleanupExpiredSessions(),
  dedupe:      () => dedupeAllSheets(),
  archLeads:   () => archiveCompletedLeads(),
  archMT:      () => archiveCompletedMT(),
  archManual:  () => archiveManualTracker(),
  callbacks:   () => processCallbackQueue(),
  retries:     () => processRetryQueue(),
};

app.post('/poller/run/:job', requirePollerToken, async (req, res) => {
  const { job } = req.params;
  const fn = JOB_MAP[job];
  if (!fn) {
    return res.status(400).json({
      ok: false,
      error: `Unknown job: ${job}`,
      available: Object.keys(JOB_MAP),
    });
  }
  try {
    const result = await fn();
    res.json({ ok: true, job, result: result || 'done' });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

// ─── Archive API endpoints ───────────────────────────────────────────────────

async function archiveAuth(req, res) {
  const sessionToken = req.body?.session || req.headers['x-session'];
  const auth = await validateSession(sessionToken);
  if (!auth.ok) {
    res.status(401).json({ ok: false, error: 'UNAUTHENTICATED' });
    return null;
  }
  return auth.user;
}

function resolveTeam(user, requestedTeam) {
  if (user.role === 'super_admin') return requestedTeam || null;
  if (user.role === 'team_lead' || user.role === 'individual_contributor') return user.team;
  return user.team;
}

app.post('/api/archive/leads', async (req, res) => {
  const user = await archiveAuth(req, res);
  if (!user) return;

  const { body } = req;
  const team = resolveTeam(user, body.team);

  try {
    let teams = [];
    if (team) {
      teams = [team];
    } else if (user.role === 'super_admin') {
      const allTeams = await (require('./poller').getAllTeams());
      teams = allTeams.map(t => t.name);
    }

    let all = [];
    for (const t of teams) {
      try {
        const rows = await getArchivedLeads(t);
        rows.forEach(r => { r._team = t; r._source = 'archive'; });
        all.push(...rows);
      } catch (e) {
        console.error(`[archive/leads] Error for team ${t}:`, e.message);
      }
    }

    if (body.agentCode) all = all.filter(r => r['_agent'] === body.agentCode || r['Agent Code'] === body.agentCode || true);

    if (user.role === 'recruiter') {
      all = all.filter(r => String(r['Assigned To Email'] || '').toLowerCase() === user.email);
    }

    if (body.filter?.search) {
      const s = String(body.filter.search).toLowerCase();
      all = all.filter(r =>
        String(r['Callee Name'] || '').toLowerCase().includes(s) ||
        String(r['Mobile Number'] || '').toLowerCase().includes(s)
      );
    }

    res.json({ ok: true, leads: all, count: all.length, source: 'archive' });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

app.post('/api/archive/mt', async (req, res) => {
  const user = await archiveAuth(req, res);
  if (!user) return;

  const team = resolveTeam(user, req.body?.team);
  if (!team) return res.json({ ok: true, rows: [], count: 0 });

  try {
    const rows = await getArchivedMT(team);
    res.json({ ok: true, rows, count: rows.length, source: 'archive' });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

app.post('/api/archive/manual', async (req, res) => {
  const user = await archiveAuth(req, res);
  if (!user) return;

  const team = resolveTeam(user, req.body?.team);
  if (!team) return res.json({ ok: true, rows: [], count: 0 });

  try {
    let rows = await getArchivedManual(team);

    if (user.role === 'recruiter') {
      rows = rows.filter(r => String(r['Added By Email'] || '').toLowerCase() === user.email);
    }

    res.json({ ok: true, rows, count: rows.length, source: 'archive' });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

// ─── Health check ─────────────────────────────────────────────────────────────

app.get('/health', (req, res) => {
  res.json({ ok: true, uptime: Math.round(process.uptime()), ts: new Date().toISOString() });
});

// ─── Catch-all: serve frontend ────────────────────────────────────────────────

app.get('*', (req, res) => {
  const indexPath = path.join(__dirname, 'public', 'index.html');
  res.sendFile(indexPath, err => {
    if (err) res.status(404).send('Not found');
  });
});

// ─── Start ────────────────────────────────────────────────────────────────────

app.listen(PORT, () => {
  console.log(`Voxa running on port ${PORT}`);
  startPoller();
});