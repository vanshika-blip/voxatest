'use strict';
/**
 * server.js
 *
 * Auth (login/logout/session) → handled by Node (auth.js) — NO GAS involved
 * Everything else             → proxy to GAS
 *
 * POST /                    → proxy to GAS (all non-auth actions)
 * POST /api/login           → Node auth (login)
 * POST /api/logout          → Node auth (logout)
 * POST /api/forcepoll       → session-auth force poll (super_admin only)
 * GET  /api/pollstatus      → session-auth poll status
 * GET  /poller/status       → Bearer token poll health
 * POST /poller/force-refresh→ Bearer token force poll
 * POST /poller/run/:job     → Bearer token run any job
 * POST /api/archive/leads   → archived leads from team SS
 * POST /api/archive/mt      → archived MT from team SS
 * POST /api/archive/manual  → archived manual from team SS
 * GET  /health              → simple health check
 */

const express = require('express');
const cors    = require('cors');
const axios   = require('axios');
const path    = require('path');

const {
  startPoller, getStatus,
  allTeams, getArchiveLeads, getArchiveMT, getArchiveManual,
  pollActiveBatches, backfillMissingOutputs, repairUnassignedLeads,
  cleanupExpiredSessions: pollerCleanupSessions, dedupeAllSheets,
  archiveCompletedLeads, archiveCompletedMT, archiveManualTracker,
  processCallbackQueue, processRetryQueue,
} = require('./poller');

const {
  login, validateSession, logout,
  cleanupExpiredSessions: authCleanupSessions,
} = require('./auth');

const app   = express();
const PORT  = process.env.PORT || 10000;
const GAS   = process.env.GAS_URL;
const TOKEN = process.env.POLLER_TOKEN || 'voxa-bfsi-2026';

app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.static(path.join(__dirname, 'public')));

// ─── Bearer token auth (admin/curl only) ─────────────────────────────────────
function auth(req, res, next) {
  const t = (req.headers['authorization'] || '').replace('Bearer ', '').trim();
  if (t !== TOKEN) return res.status(401).json({ ok: false, error: 'UNAUTHORIZED' });
  next();
}

// ─── Session auth helper ──────────────────────────────────────────────────────
async function sessionAuth(req, res) {
  const token = req.body?.session || req.headers['x-session'];
  const user  = await validateSession(token);
  if (!user) { res.status(401).json({ ok: false, error: 'UNAUTHENTICATED' }); return null; }
  return user;
}

function resolveTeam(user, requested) {
  if (user.role === 'super_admin') return requested || null;
  return user.team || null;
}

// ─────────────────────────────────────────────────────────────────────────────
// AUTH ROUTES — handled entirely by Node, never touch GAS
// ─────────────────────────────────────────────────────────────────────────────

// Login
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body || {};
  try {
    const result = await login(email, password);
    res.json(result);
  } catch (e) {
    console.error('[login]', e.message);
    res.status(500).json({ ok: false, error: 'SERVER_ERROR' });
  }
});

// Logout
app.post('/api/logout', async (req, res) => {
  const token = req.body?.session || req.headers['x-session'];
  if (token) logout(token);
  res.json({ ok: true });
});

// Me — returns current user info from session
app.post('/api/me', async (req, res) => {
  const user = await sessionAuth(req, res);
  if (!user) return;
  res.json({ ok: true, user });
});

// ─────────────────────────────────────────────────────────────────────────────
// PROXY → GAS (all non-auth actions)
// Login/logout/me are intercepted above and never reach here
// ─────────────────────────────────────────────────────────────────────────────
app.post('/', async (req, res) => {
  if (!GAS) return res.json({ ok: false, error: 'GAS_URL not configured' });

  const action = String(req.body?.action || '').toLowerCase();

  // Intercept login/logout at the root too (for frontend compatibility)
  if (action === 'login') {
    const { email, password } = req.body || {};
    try {
      const result = await login(email, password);
      return res.json(result);
    } catch (e) {
      return res.status(500).json({ ok: false, error: 'SERVER_ERROR' });
    }
  }

  if (action === 'logout') {
    const token = req.body?.session || req.headers['x-session'];
    if (token) logout(token);
    return res.json({ ok: true });
  }

  // For all other actions, validate session via Node before proxying
  // This way even if GAS is down, we don't let unauthenticated requests through
  if (action !== 'ping' && action !== 'verifytoken' && action !== 'completesetup' && action !== 'requestreset') {
    const token = req.body?.session || req.headers['x-session'];
    const sess  = await validateSession(token);
    if (!sess) return res.json({ ok: false, error: 'UNAUTHENTICATED' });
  }

  try {
    const r = await axios.post(GAS, req.body, {
      headers: { 'Content-Type': 'application/json' },
      timeout: 55000,
    });
    res.json(r.data);
  } catch (e) {
    const msg = e.response?.data || e.message;
    console.error('[proxy]', msg);
    res.status(500).json({ ok: false, error: String(msg).slice(0, 300) });
  }
});

// ─── Force poll — session auth, callable from frontend ───────────────────────
app.post('/api/forcepoll', async (req, res) => {
  const user = await sessionAuth(req, res); if (!user) return;
  if (user.role !== 'super_admin') return res.status(403).json({ ok: false, error: 'FORBIDDEN' });
  const { agentCode } = req.body || {};
  const status = getStatus();
  if (status.pollRunning) {
    return res.json({ ok: false, error: 'POLL_ALREADY_RUNNING', message: 'A poll is already running. Check back in a minute.' });
  }
  pollActiveBatches(agentCode || null).catch(e => console.error('[forcepoll]', e.message));
  res.json({ ok: true, message: agentCode ? `Poll started for ${agentCode}` : 'Poll started for all agents', note: 'Runs in background. Refresh leads in ~30 seconds.' });
});

// ─── Poll status ──────────────────────────────────────────────────────────────
app.get('/api/pollstatus', async (req, res) => {
  const token = req.headers['x-session'] || req.query.session;
  const user  = await validateSession(token);
  if (!user) return res.status(401).json({ ok: false, error: 'UNAUTHENTICATED' });
  if (user.role !== 'super_admin') return res.status(403).json({ ok: false, error: 'FORBIDDEN' });
  res.json({ ok: true, ...getStatus() });
});

// ─── Poller admin (Bearer token) ─────────────────────────────────────────────
app.get('/poller/status', auth, (req, res) => res.json({ ok: true, ...getStatus() }));

app.post('/poller/force-refresh', auth, async (req, res) => {
  const { agentCode } = req.body || {};
  const status = getStatus();
  if (status.pollRunning) return res.json({ ok: false, error: 'POLL_ALREADY_RUNNING' });
  pollActiveBatches(agentCode || null).catch(e => console.error('[force-refresh]', e.message));
  res.json({ ok: true, message: agentCode ? `Poll started for ${agentCode}` : 'Poll started for all' });
});

const JOBS = {
  poll:       () => pollActiveBatches(),
  backfill:   () => backfillMissingOutputs(),
  repair:     () => repairUnassignedLeads(),
  sessions:   () => authCleanupSessions(),
  dedupe:     () => dedupeAllSheets(),
  archLeads:  () => archiveCompletedLeads(),
  archMT:     () => archiveCompletedMT(),
  archManual: () => archiveManualTracker(),
  callbacks:  () => processCallbackQueue(),
  retries:    () => processRetryQueue(),
};

app.post('/poller/run/:job', auth, async (req, res) => {
  const fn = JOBS[req.params.job];
  if (!fn) return res.status(400).json({ ok: false, error: 'Unknown job', available: Object.keys(JOBS) });
  try { const r = await fn(); res.json({ ok: true, job: req.params.job, result: r || 'done' }); }
  catch (e) { res.status(500).json({ ok: false, error: e.message }); }
});

// ─── Archive API ──────────────────────────────────────────────────────────────
app.post('/api/archive/leads', async (req, res) => {
  const user = await sessionAuth(req, res); if (!user) return;
  const team = resolveTeam(user, req.body?.team);
  try {
    let rows = [];
    if (team) {
      rows = await getArchiveLeads(team);
    } else if (user.role === 'super_admin') {
      const teams = await allTeams();
      for (const t of teams) {
        if (!t.ssId) continue;
        const r = await getArchiveLeads(t.name);
        r.forEach(x => { x._team = t.name; });
        rows.push(...r);
      }
    }
    if (user.role === 'recruiter') rows = rows.filter(r => String(r['Assigned To Email']||'').toLowerCase() === user.email);
    if (req.body?.filter?.search) {
      const s = String(req.body.filter.search).toLowerCase();
      rows = rows.filter(r => (String(r['Callee Name']||'')+' '+String(r['Mobile Number']||'')).toLowerCase().includes(s));
    }
    res.json({ ok: true, leads: rows, count: rows.length });
  } catch (e) { res.status(500).json({ ok: false, error: e.message }); }
});

app.post('/api/archive/mt', async (req, res) => {
  const user = await sessionAuth(req, res); if (!user) return;
  const team = resolveTeam(user, req.body?.team);
  if (!team) return res.json({ ok: true, rows: [] });
  try { const rows = await getArchiveMT(team); res.json({ ok: true, rows, count: rows.length }); }
  catch (e) { res.status(500).json({ ok: false, error: e.message }); }
});

app.post('/api/archive/manual', async (req, res) => {
  const user = await sessionAuth(req, res); if (!user) return;
  const team = resolveTeam(user, req.body?.team);
  if (!team) return res.json({ ok: true, rows: [] });
  try {
    let rows = await getArchiveManual(team);
    if (user.role === 'recruiter') rows = rows.filter(r => String(r['Added By Email']||'').toLowerCase() === user.email);
    res.json({ ok: true, rows, count: rows.length });
  } catch (e) { res.status(500).json({ ok: false, error: e.message }); }
});

// ─── Health ───────────────────────────────────────────────────────────────────
app.get('/health', (req, res) => res.json({ ok: true, uptime: Math.round(process.uptime()), pollRunning: getStatus().pollRunning }));

// ─── Serve frontend ───────────────────────────────────────────────────────────
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'), err => {
    if (err) res.status(404).send('Not found');
  });
});

// ─── Start ────────────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`Voxa running on port ${PORT}`);
  startPoller();
});