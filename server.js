/**
 * xero-mcp-auth — Minimal local Xero OAuth 2.0 token server
 *
 * USAGE:
 *   1. Copy .env.example → .env and fill in your Xero credentials
 *   2. npm install
 *   3. node server.js
 *   4. Open http://localhost:3000 in your browser
 *   5. Click "Login with Xero", complete the OAuth flow
 *   6. Copy the displayed bearer token into Claude Desktop MCP config
 *
 * Tokens are stored in NeonDB (auto-initialised on first run).
 * Tokens auto-refresh when you visit the page or call /api/token.
 */

'use strict';

require('dotenv').config();
const path           = require('path');
const express        = require('express');
const axios          = require('axios');
const crypto         = require('crypto');
const fs             = require('fs');
const { spawn }      = require('child_process');
const { neon }       = require('@neondatabase/serverless');

// sql is initialised in the startup IIFE after we verify DATABASE_URL is present
let sql;

// ── Config ────────────────────────────────────────────────────────────────────

const PORT          = process.env.PORT          || 3000;
const CLIENT_ID     = process.env.XERO_CLIENT_ID;
const CLIENT_SECRET = process.env.XERO_CLIENT_SECRET;
const REDIRECT_URI  = process.env.XERO_REDIRECT_URI  || `http://localhost:${PORT}/callback`;

// Granular scopes for full Xero MCP access (Xero deprecated the broad scopes).
// offline_access is required to get a refresh_token — do not remove it.
//
// Covers:
//   invoices, payments, bank transactions, manual journals (read + write)
//   contacts + contact groups (read + write)
//   accounts, tax rates, tracking categories, items (settings)
//   balance sheet, P&L, trial balance, aged reports (read-only)
const SCOPES = process.env.XERO_SCOPES ||
  [
    'openid', 'profile', 'email',
    // Transactions (granular — replaces deprecated accounting.transactions)
    'accounting.invoices',
    'accounting.payments',
    'accounting.banktransactions',
    'accounting.manualjournals',
    // Contacts (replaces deprecated accounting.contacts)
    'accounting.contacts',
    // Settings: accounts, tax rates, tracking categories, items
    'accounting.settings',
    // Reports (granular — replaces deprecated accounting.reports.read)
    'accounting.reports.balancesheet.read',
    'accounting.reports.profitandloss.read',
    'accounting.reports.trialbalance.read',
    'accounting.reports.aged.read',
    // Required for refresh tokens
    'offline_access',
  ].join(' ');

const XERO_AUTH_URL  = 'https://login.xero.com/identity/connect/authorize';
const XERO_TOKEN_URL = 'https://identity.xero.com/connect/token';
const XERO_CONN_URL  = 'https://api.xero.com/connections';
const PUBLIC_BASE_URL = process.env.PUBLIC_BASE_URL ||
  (process.env.RAILWAY_PUBLIC_DOMAIN ? `https://${process.env.RAILWAY_PUBLIC_DOMAIN}` : null);
const MCP_MESSAGE_PATH = '/message';
const MCP_AUTH_TOKEN = process.env.MCP_AUTH_TOKEN || '';

// Streamable HTTP transport tuning. A session owns one xero-mcp-server
// subprocess, so idle sessions must be reaped or every probe from a
// connector-validation service leaks a child process.
const MCP_HTTP_IDLE_MS = Number(process.env.MCP_HTTP_IDLE_MS || 10 * 60 * 1000);
const MCP_HTTP_REQUEST_TIMEOUT_MS = Number(process.env.MCP_HTTP_REQUEST_TIMEOUT_MS || 120_000);

// ── Token storage (NeonDB) ───────────────────────────────────────────────────

/** Create table on first run if it doesn't exist yet */
async function initDb() {
  // Multi-org support: each row is one Xero org
  await sql`
    CREATE TABLE IF NOT EXISTS xero_tokens (
      id            SERIAL PRIMARY KEY,
      tenant_id     TEXT    UNIQUE NOT NULL,
      tenant_name   TEXT,
      access_token  TEXT    NOT NULL,
      refresh_token TEXT    NOT NULL,
      expires_at    BIGINT  NOT NULL,
      authorised_at TEXT,
      refreshed_at  TEXT,
      is_active     BOOLEAN DEFAULT true
    )
  `;

  // Active org tracker (single row)
  await sql`
    CREATE TABLE IF NOT EXISTS xero_active_org (
      id            INTEGER PRIMARY KEY DEFAULT 1,
      tenant_id     TEXT NOT NULL REFERENCES xero_tokens(tenant_id)
    )
  `;
}

async function loadTokens() {
  // Get the active org's tokens
  const active = await sql`SELECT tenant_id FROM xero_active_org WHERE id = 1`;
  if (!active[0]) return null;
  const rows = await sql`SELECT * FROM xero_tokens WHERE tenant_id = ${active[0].tenant_id}`;
  return rows[0] ?? null;
}

async function loadAllOrgs() {
  return await sql`SELECT tenant_id, tenant_name, authorised_at, is_active FROM xero_tokens ORDER BY authorised_at DESC`;
}

async function saveTokens(data) {
  await sql`
    INSERT INTO xero_tokens
      (tenant_id, tenant_name, access_token, refresh_token, expires_at, authorised_at, refreshed_at, is_active)
    VALUES
      (${data.tenant_id}, ${data.tenant_name}, ${data.access_token}, ${data.refresh_token},
       ${data.expires_at}, ${data.authorised_at ?? null}, ${data.refreshed_at ?? null}, true)
    ON CONFLICT (tenant_id) DO UPDATE SET
      access_token  = EXCLUDED.access_token,
      refresh_token = EXCLUDED.refresh_token,
      expires_at    = EXCLUDED.expires_at,
      tenant_name   = EXCLUDED.tenant_name,
      authorised_at = EXCLUDED.authorised_at,
      refreshed_at  = EXCLUDED.refreshed_at
  `;

  // Set as active org
  await sql`
    INSERT INTO xero_active_org (id, tenant_id) VALUES (1, ${data.tenant_id})
    ON CONFLICT (id) DO UPDATE SET tenant_id = EXCLUDED.tenant_id
  `;

  // Auto-update Claude Desktop config with fresh token
  updateClaudeDesktopConfig(data);
}

async function switchOrg(tenantId) {
  await sql`
    INSERT INTO xero_active_org (id, tenant_id) VALUES (1, ${tenantId})
    ON CONFLICT (id) DO UPDATE SET tenant_id = EXCLUDED.tenant_id
  `;
  const tokens = await loadTokens();
  if (tokens) updateClaudeDesktopConfig(tokens);
  return tokens;
}

async function clearTokens() {
  await sql`DELETE FROM xero_tokens`;
  await sql`DELETE FROM xero_active_org`;
}

function isExpired(tokens) {
  // Treat as expired 60 seconds early to avoid race conditions
  return !tokens || Date.now() >= (tokens.expires_at - 60_000);
}

// ── Claude Desktop config auto-update ────────────────────────────────────────

const CLAUDE_DESKTOP_CONFIG = process.env.CLAUDE_DESKTOP_CONFIG ||
  `${process.env.HOME}/.claude/claude_desktop_config.json`;

function updateClaudeDesktopConfig(tokens) {
  try {
    const configPath = CLAUDE_DESKTOP_CONFIG;

    // Read existing config or start fresh
    let config = {};
    if (fs.existsSync(configPath)) {
      const raw = fs.readFileSync(configPath, 'utf8').trim();
      if (raw) config = JSON.parse(raw);
    }

    // Ensure mcpServers exists
    if (!config.mcpServers) config.mcpServers = {};

    // Update xero MCP server config with fresh tokens
    config.mcpServers.xero = {
      command: 'node',
      args: [path.join(__dirname, 'xero-mcp-start.js')],
    };

    // Write back with proper formatting
    fs.writeFileSync(configPath, JSON.stringify(config, null, 2) + '\n', 'utf8');
    console.log('[xero-auth] Claude Desktop config updated:', configPath);
  } catch (err) {
    // Don't crash the server if config update fails
    console.error('[xero-auth] Failed to update Claude Desktop config:', err.message);
  }
}

// ── Token refresh ─────────────────────────────────────────────────────────────

async function refreshIfNeeded() {
  const tokens = await loadTokens();
  if (!tokens) return null;

  if (!isExpired(tokens)) {
    return tokens; // Still valid
  }

  console.log('[xero-auth] Token expired — refreshing...');
  try {
    const res = await axios.post(
      XERO_TOKEN_URL,
      new URLSearchParams({
        grant_type:    'refresh_token',
        refresh_token: tokens.refresh_token,
      }),
      {
        auth: { username: CLIENT_ID, password: CLIENT_SECRET },
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      }
    );

    const refreshed = {
      ...tokens,                                    // keep tenant info
      access_token:  res.data.access_token,
      refresh_token: res.data.refresh_token,        // Xero rotates refresh tokens
      expires_at:    Date.now() + res.data.expires_in * 1000,
      refreshed_at:  new Date().toISOString(),
    };

    await saveTokens(refreshed);
    console.log('[xero-auth] Token refreshed successfully');
    return refreshed;

  } catch (err) {
    console.error('[xero-auth] Refresh failed:', err.response?.data || err.message);
    return null; // Caller will show "re-login" message
  }
}

// ── Express app ───────────────────────────────────────────────────────────────

const app = express();
app.set('trust proxy', true);

// In-memory CSRF state (fine for local single-user app)
let oauthState = null;

// Holds already-exchanged OAuth tokens while the user chooses a Xero org.
const pendingTenantSelections = new Map();
const PENDING_TENANT_SELECTION_TTL_MS = 10 * 60 * 1000;

// Active remote MCP sessions keyed by the SSE session ID Claude receives.
const mcpSessions = new Map();

function createPendingTenantSelection(data) {
  const id = crypto.randomUUID();
  pendingTenantSelections.set(id, {
    ...data,
    created_at: Date.now(),
  });

  const timer = setTimeout(() => {
    pendingTenantSelections.delete(id);
  }, PENDING_TENANT_SELECTION_TTL_MS);

  if (typeof timer.unref === 'function') timer.unref();
  return id;
}

function getPendingTenantSelection(id) {
  const pending = pendingTenantSelections.get(id);
  if (!pending) return null;

  if (Date.now() - pending.created_at > PENDING_TENANT_SELECTION_TTL_MS) {
    pendingTenantSelections.delete(id);
    return null;
  }

  return pending;
}

async function saveSelectedTenant(selection, tenantId) {
  const tenant = selection.tenants.find(t => t.tenantId === tenantId) || selection.tenants[0];

  await saveTokens({
    access_token:  selection.access_token,
    refresh_token: selection.refresh_token,
    expires_at:    selection.expires_at,
    tenant_id:     tenant.tenantId,
    tenant_name:   tenant.tenantName,
    authorised_at: new Date().toISOString(),
    refreshed_at:  null,
  });

  console.log(`[xero-auth] Authorised: ${tenant.tenantName} (${tenant.tenantId})`);
  return tenant;
}

// ── GET / — Home: show token status ──────────────────────────────────────────

app.get('/', async (req, res) => {
  const tokens = await refreshIfNeeded();

  if (!tokens) {
    // Not authenticated yet (or refresh failed after expiry)
    return res.send(renderPage({
      title:   'Xero MCP Auth',
      content: `
        <div class="card center">
          <div class="icon">🔐</div>
          <h2>Not connected</h2>
          <p>Click the button below to authorise this app with Xero.<br>
             You only need to do this once — tokens are saved locally and auto-refreshed.</p>
          <a href="/login" class="btn">Login with Xero</a>
        </div>`,
    }));
  }

  const expiresAt     = new Date(tokens.expires_at);
  const secondsLeft   = Math.max(0, Math.round((tokens.expires_at - Date.now()) / 1000));
  const minutesLeft   = Math.floor(secondsLeft / 60);
  const expiryLabel   = minutesLeft > 1
    ? `${minutesLeft} min remaining`
    : secondsLeft > 0 ? `${secondsLeft}s remaining` : 'expired';

  const statusClass   = secondsLeft > 300 ? 'ok' : secondsLeft > 0 ? 'warn' : 'error';
  const statusIcon    = secondsLeft > 300 ? '✅' : '⏳';

  // Redact middle of token for display safety
  const token     = tokens.access_token;
  const tenantId  = tokens.tenant_id  || '';
  const orgName   = tokens.tenant_name || 'Unknown Org';
  const remoteMcpUrl = `${getPublicBaseUrl(req)}/sse${MCP_AUTH_TOKEN ? `?token=${encodeURIComponent(MCP_AUTH_TOKEN)}` : ''}`;

  // Get all connected orgs for the switcher dropdown
  const allOrgs = await loadAllOrgs();

  // Build Claude Desktop MCP config (uses launcher that auto-refreshes tokens)
  const mcpConfig = JSON.stringify({
    mcpServers: {
      xero: {
        command: 'node',
        args: [path.join(__dirname, 'xero-mcp-start.js')],
      },
    },
  }, null, 2);

  // Build org switcher dropdown HTML
  const orgSwitcherHtml = allOrgs.length > 1 ? `
    <div class="org-switcher">
      <label class="field-label">Organisation</label>
      <div class="org-select-wrap">
        <div class="org-select-box">
          <span class="org-select-icon">🏢</span>
          <select id="orgSelect" onchange="switchOrg(this.value)">
            ${allOrgs.map(o => `
              <option value="${esc(o.tenant_id)}" ${o.tenant_id === tenantId ? 'selected' : ''}>${esc(o.tenant_name || o.tenant_id)}</option>
            `).join('')}
          </select>
          <span class="org-select-chevron">▾</span>
        </div>
        <span class="switch-status" id="switchStatus"></span>
      </div>
    </div>
  ` : '';

  return res.send(renderPage({
    title:   `Token — ${orgName}`,
    content: `
      <div class="card">
        ${orgSwitcherHtml}
        <div class="org-row">
          <span class="org-name">🏢 ${esc(orgName)}</span>
          <span class="expiry ${statusClass}">${statusIcon} ${esc(expiryLabel)} · expires ${expiresAt.toLocaleTimeString()}</span>
        </div>

        <label class="field-label">Bearer Token (XERO_CLIENT_BEARER_TOKEN)</label>
        <div class="token-wrap">
          <code id="bearerToken">${esc(token)}</code>
          <button class="copy-btn" onclick="copy('bearerToken', this)">Copy</button>
        </div>

        <label class="field-label" style="margin-top:18px">Tenant ID (XERO_TENANT_ID)</label>
        <div class="token-wrap">
          <code id="tenantId">${esc(tenantId)}</code>
          <button class="copy-btn" onclick="copy('tenantId', this)">Copy</button>
        </div>

        <label class="field-label" style="margin-top:26px">Claude.ai Remote MCP URL</label>
        <div class="token-wrap">
          <code id="remoteMcpUrl">${esc(remoteMcpUrl)}</code>
          <button class="copy-btn" onclick="copy('remoteMcpUrl', this)">Copy</button>
        </div>

        <label class="field-label" style="margin-top:26px">Ready-to-paste Claude Desktop MCP Config</label>
        <div class="config-wrap">
          <pre id="mcpConfig">${esc(mcpConfig)}</pre>
          <button class="copy-btn dark" onclick="copy('mcpConfig', this)">Copy JSON</button>
        </div>

        <div class="actions">
          <a href="/refresh" class="btn outline">↻ Force Refresh Token</a>
          <a href="/login"   class="btn outline">Re-authorise Xero</a>
          <a href="/logout"  class="btn outline danger">Clear Tokens</a>
        </div>
      </div>

      <div class="info-box">
        <strong>📋 How to use:</strong>
        <strong>Claude Desktop:</strong> Config is auto-updated at <code>~/.claude/claude_desktop_config.json</code> when tokens refresh. No manual copying needed!<br>
        <strong>Claude.ai:</strong> Add the Remote MCP URL above as your custom connector URL.<br>
        Tokens expire every <strong>30 min</strong> and are auto-refreshed. Restart Claude Desktop if the MCP server shows as disconnected.
      </div>`,
  }));
});

// ── GET /login — Start OAuth flow ─────────────────────────────────────────────

app.get('/login', (req, res) => {
  if (!CLIENT_ID || !CLIENT_SECRET) {
    return res.send(renderPage({
      title: 'Setup Required',
      content: `<div class="card center">
        <div class="icon">⚠️</div>
        <h2>Missing credentials</h2>
        <p>Create a <code>.env</code> file from <code>.env.example</code> and fill in your
           <strong>XERO_CLIENT_ID</strong> and <strong>XERO_CLIENT_SECRET</strong>.</p>
        <pre style="text-align:left;background:#f5f5f5;padding:14px;border-radius:8px;font-size:12px">cp .env.example .env
# then edit .env with your Xero app credentials</pre>
      </div>`,
    }));
  }

  oauthState = crypto.randomBytes(16).toString('hex');

  const url = XERO_AUTH_URL + '?' + new URLSearchParams({
    response_type: 'code',
    client_id:     CLIENT_ID,
    redirect_uri:  REDIRECT_URI,
    scope:         SCOPES,
    state:         oauthState,
  });

  res.redirect(url);
});

// ── GET /callback — Handle Xero redirect after login ──────────────────────────

app.get('/callback', async (req, res) => {
  const { code, state, error } = req.query;

  // OAuth error from Xero (e.g. user denied access)
  if (error) {
    return res.send(renderPage({
      title: 'Auth Error',
      content: `<div class="card center">
        <div class="icon">❌</div>
        <h2>Xero returned an error</h2>
        <p>${esc(String(error))}</p>
        <a href="/login" class="btn">Try again</a>
      </div>`,
    }));
  }

  // CSRF check
  if (!state || state !== oauthState) {
    return res.status(400).send(renderPage({
      title: 'Invalid State',
      content: `<div class="card center">
        <div class="icon">🚫</div>
        <h2>Invalid state parameter</h2>
        <p>Possible CSRF or stale session. Please try again.</p>
        <a href="/login" class="btn">Retry</a>
      </div>`,
    }));
  }

  oauthState = null; // consume state

  try {
    // ── Step 1: Exchange code for tokens ──────────────────────────────────
    const tokenRes = await axios.post(
      XERO_TOKEN_URL,
      new URLSearchParams({
        grant_type:   'authorization_code',
        code,
        redirect_uri: REDIRECT_URI,
      }),
      {
        auth: { username: CLIENT_ID, password: CLIENT_SECRET },
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      }
    );

    const { access_token, refresh_token, expires_in } = tokenRes.data;
    const expires_at = Date.now() + expires_in * 1000;

    // ── Step 2: Fetch connected orgs to get tenant ID ─────────────────────
    const connRes = await axios.get(XERO_CONN_URL, {
      headers: { Authorization: `Bearer ${access_token}` },
    });

    const tenants = connRes.data;

    if (!tenants || tenants.length === 0) {
      return res.send(renderPage({
        title: 'No Orgs Found',
        content: `<div class="card center">
          <div class="icon">⚠️</div>
          <h2>No Xero organisations found</h2>
          <p>Your Xero account has no connected organisations. Please check your Xero account.</p>
          <a href="/login" class="btn">Try again</a>
        </div>`,
      }));
    }

    // If multiple orgs, show a picker
    if (tenants.length > 1 && !req.query.tenant_id) {
      const selectionId = createPendingTenantSelection({
        access_token,
        refresh_token,
        expires_at,
        tenants,
      });

      return res.send(renderPage({
        title: 'Select Organisation',
        content: `
          <div class="card">
            <h2 style="margin-bottom:16px">Select your Xero organisation</h2>
            <p style="font-size:14px;color:#666;margin-bottom:20px">
              Multiple organisations found. Choose which one to use with Claude Desktop MCP.
            </p>
            ${tenants.map(t => `
              <a href="${esc(`/select-tenant?selection=${encodeURIComponent(selectionId)}&tenant_id=${encodeURIComponent(t.tenantId)}`)}"
                 class="org-item">
                🏢 <strong>${esc(t.tenantName)}</strong>
                <span style="font-size:11px;color:#888;margin-left:8px">${esc(t.tenantId)}</span>
              </a>
            `).join('')}
          </div>`,
      }));
    }

    await saveSelectedTenant({
      access_token,
      refresh_token,
      expires_at,
      tenants,
    }, String(req.query.tenant_id || tenants[0].tenantId));

    res.redirect('/?connected=1');

  } catch (err) {
    const detail = err.response?.data
      ? JSON.stringify(err.response.data)
      : err.message;

    console.error('[xero-auth] Token exchange failed:', detail);

    return res.send(renderPage({
      title: 'Auth Failed',
      content: `<div class="card center">
        <div class="icon">❌</div>
        <h2>Token exchange failed</h2>
        <p>Xero returned an error during the code exchange. Check your credentials.</p>
        <pre style="background:#fef2f2;border:1px solid #fecaca;padding:12px;border-radius:8px;font-size:12px;text-align:left;word-break:break-all">${esc(detail)}</pre>
        <a href="/login" class="btn" style="margin-top:12px">Try again</a>
      </div>`,
    }));
  }
});

// ── GET /select-tenant — Save org chosen after OAuth callback ────────────────

app.get('/select-tenant', async (req, res) => {
  const selectionId = String(req.query.selection || '');
  const tenantId    = String(req.query.tenant_id || '');
  const selection   = getPendingTenantSelection(selectionId);

  if (!selection || !tenantId) {
    return res.status(400).send(renderPage({
      title: 'Selection Expired',
      content: `<div class="card center">
        <div class="icon">🚫</div>
        <h2>Organisation selection expired</h2>
        <p>Please re-authorise Xero and choose the organisation again.</p>
        <a href="/login" class="btn">Retry</a>
      </div>`,
    }));
  }

  const tenant = selection.tenants.find(t => t.tenantId === tenantId);
  if (!tenant) {
    return res.status(400).send(renderPage({
      title: 'Unknown Organisation',
      content: `<div class="card center">
        <div class="icon">⚠️</div>
        <h2>Unknown organisation</h2>
        <p>The selected Xero organisation was not found in this authorisation session.</p>
        <a href="/login" class="btn">Try again</a>
      </div>`,
    }));
  }

  await saveSelectedTenant(selection, tenantId);
  pendingTenantSelections.delete(selectionId);
  res.redirect('/?connected=1');
});

// ── GET /refresh — Force token refresh ───────────────────────────────────────

app.get('/refresh', async (req, res) => {
  const tokens = await loadTokens();
  if (!tokens) return res.redirect('/');

  // Force-expire so refreshIfNeeded() will refresh
  tokens.expires_at = 0;
  await saveTokens(tokens);

  await refreshIfNeeded();
  res.redirect('/');
});

// ── GET /logout — Clear saved tokens ─────────────────────────────────────────

app.get('/logout', async (req, res) => {
  await clearTokens();
  res.redirect('/');
});

// ── GET /api/orgs — List all connected Xero orgs ────────────────────────────

app.get('/api/orgs', async (req, res) => {
  res.setHeader('Content-Type', 'application/json');
  res.setHeader('Cache-Control', 'no-store');

  const orgs = await loadAllOrgs();
  const active = await loadTokens();

  return res.json({
    ok: true,
    active_tenant_id: active?.tenant_id || null,
    orgs,
  });
});

// ── POST /api/switch-org — Switch active Xero org ────────────────────────────

app.post('/api/switch-org', express.json(), async (req, res) => {
  res.setHeader('Content-Type', 'application/json');

  const { tenant_id } = req.body;
  if (!tenant_id) {
    return res.status(400).json({ ok: false, error: 'Missing tenant_id' });
  }

  // Check org exists
  const orgs = await loadAllOrgs();
  const org = orgs.find(o => o.tenant_id === tenant_id);
  if (!org) {
    return res.status(404).json({ ok: false, error: 'Org not found. Please re-authorise.' });
  }

  const tokens = await switchOrg(tenant_id);
  if (!tokens) {
    return res.status(500).json({ ok: false, error: 'Failed to load tokens for this org' });
  }

  return res.json({
    ok: true,
    tenant_id: tokens.tenant_id,
    tenant_name: tokens.tenant_name,
    message: `Switched to ${tokens.tenant_name}. Restart Claude Desktop if needed.`,
  });
});

// ── GET /api/token — JSON endpoint ───────────────────────────────────────────
//
// Returns the current valid token as JSON.
// Useful for scripts: curl http://localhost:3000/api/token
//
// Response:
//   { "ok": true, "access_token": "eyJ...", "tenant_id": "...",
//     "tenant_name": "...", "expires_at": 1234567890, "expires_in_seconds": 1234 }

app.get('/api/token', async (req, res) => {
  res.setHeader('Content-Type', 'application/json');
  res.setHeader('Cache-Control', 'no-store');

  const tokens = await refreshIfNeeded();

  if (!tokens) {
    return res.status(401).json({
      ok: false,
      error: 'not_authenticated',
      message: 'No tokens found. Visit http://localhost:' + PORT + ' and log in first.',
    });
  }

  return res.json({
    ok:              true,
    access_token:    tokens.access_token,
    tenant_id:       tokens.tenant_id,
    tenant_name:     tokens.tenant_name,
    expires_at:      Math.floor(tokens.expires_at / 1000), // Unix timestamp (seconds)
    expires_in_seconds: Math.max(0, Math.round((tokens.expires_at - Date.now()) / 1000)),
  });
});

// ── Remote MCP bridge for Claude.ai / Railway ────────────────────────────────
//
// Claude connects to GET /sse and keeps that EventSource open. The endpoint
// event tells Claude where to POST JSON-RPC messages. Each SSE connection owns
// one xero-mcp-server subprocess, and this app bridges HTTP+SSE <-> stdio.

app.get('/sse', async (req, res) => {
  if (!isMcpAuthorized(req)) {
    return res.status(401).send('Unauthorized');
  }

  const tokens = await refreshIfNeeded();
  if (!tokens) {
    return res.status(401).send('Xero is not authenticated. Visit /login first.');
  }

  let session;
  try {
    session = createMcpSession(tokens);
  } catch (err) {
    console.error('[mcp-bridge] Failed to start xero-mcp-server:', err.message);
    return res.status(500).send('Failed to start Xero MCP server');
  }

  session.res = res;
  mcpSessions.set(session.id, session);

  res.writeHead(200, {
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache, no-transform',
    Connection: 'keep-alive',
    'X-Accel-Buffering': 'no',
  });

  const endpointUrl = new URL(MCP_MESSAGE_PATH, 'http://localhost');
  endpointUrl.searchParams.set('sessionId', session.id);
  res.write(`event: endpoint\ndata: ${endpointUrl.pathname + endpointUrl.search}\n\n`);

  session.heartbeat = setInterval(() => {
    if (!session.closed && !res.writableEnded) {
      res.write(': keepalive\n\n');
    }
  }, 25_000);

  const refreshDelay = tokens.expires_at - Date.now() - 60_000;
  session.tokenExpiryTimer = setTimeout(() => {
    closeMcpSession(session, 'Xero token is nearing expiry; Claude should reconnect');
  }, Math.max(refreshDelay, 5_000));

  req.on('close', () => {
    closeMcpSession(session, 'SSE client disconnected');
  });

  console.log(`[mcp-bridge] SSE session ${session.id} started for ${tokens.tenant_name || tokens.tenant_id || 'Xero tenant'}`);
});

const mcpJsonBody = express.json({ limit: '4mb', type: 'application/json' });

app.post(MCP_MESSAGE_PATH, mcpJsonBody, handleMcpPost);
app.post('/messages', mcpJsonBody, handleMcpPost);

async function handleMcpPost(req, res) {
  const sessionId = String(req.query.sessionId || '');
  if (!sessionId) {
    return res.status(400).send('Missing sessionId parameter');
  }

  const session = mcpSessions.get(sessionId);
  if (!session || session.closed) {
    return res.status(404).send('Session not found');
  }

  const pendingIds = getJsonRpcIds(req.body);
  for (const id of pendingIds) {
    session.pendingRequestIds.add(id);
  }

  try {
    await writeJsonRpcToChild(session, req.body);
    return res.status(202).send('Accepted');
  } catch (err) {
    for (const id of pendingIds) {
      session.pendingRequestIds.delete(id);
    }
    console.error(`[mcp-bridge] Failed to forward message for session ${session.id}:`, err.message);
    return res.status(500).send('Failed to forward message to Xero MCP server');
  }
}

// ── Streamable HTTP transport (MCP 2025-03-26 / 2025-06-18) ─────────────────
//
// The legacy transport above (GET /sse + POST /message) is what Claude Desktop
// and the claude.ai chat runtime still speak. Newer clients — including the
// connector-validation service claude.ai runs when you add or sign into a
// connector — try Streamable HTTP FIRST: a plain POST of JSON-RPC to the MCP
// URL itself. Before this existed that POST 404'd, and the client read the
// 404 as "this endpoint must be behind a sign-in", walked the OAuth discovery
// chain (/.well-known/oauth-protected-resource → oauth-authorization-server →
// POST /register), found nothing, and reported "Couldn't register with this
// server's sign-in service".
//
// So POST is mounted on BOTH /mcp and /sse: /sse is the URL already sitting in
// people's connector settings, and the transport a client gets must depend on
// its HTTP method, not on which path it was handed.
//
// Auth is unchanged — the MCP_AUTH_TOKEN shared secret, as a bearer header or
// ?token=. Note the 401 below deliberately carries NO WWW-Authenticate header:
// that header is exactly what tells an MCP client to go start an OAuth flow,
// and this server has no OAuth server to send it to.

app.post('/mcp', mcpJsonBody, handleStreamableHttpPost);
app.post('/sse', mcpJsonBody, handleStreamableHttpPost);
app.delete('/mcp', handleStreamableHttpDelete);
app.delete('/sse', handleStreamableHttpDelete);

// Spec allows a server that doesn't offer a server→client stream on GET to
// refuse it. GET /sse is NOT included here — that's the legacy SSE transport
// and it keeps working exactly as before.
app.get('/mcp', (req, res) => {
  if (!isMcpAuthorized(req)) return res.status(401).send('Unauthorized');
  return res.status(405).set('Allow', 'POST, DELETE').send('Use POST for Streamable HTTP, or GET /sse for the SSE transport');
});

async function handleStreamableHttpPost(req, res) {
  if (!isMcpAuthorized(req)) {
    return res.status(401).send('Unauthorized');
  }

  const batch = Array.isArray(req.body) ? req.body : [req.body];
  if (!batch.length || batch.some(m => !m || typeof m !== 'object')) {
    return res.status(400).json(jsonRpcError(null, -32700, 'Parse error: expected a JSON-RPC message or batch'));
  }

  const wantsInit = batch.some(m => m.method === 'initialize');
  const headerSessionId = String(req.get('mcp-session-id') || '');
  let session;

  if (wantsInit) {
    const tokens = await refreshIfNeeded();
    if (!tokens) {
      return res.status(503).json(jsonRpcError(firstRequestId(batch), -32000, 'Xero is not authenticated. Visit /login first.'));
    }

    try {
      session = createMcpSession(tokens);
    } catch (err) {
      console.error('[mcp-bridge] Failed to start xero-mcp-server:', err.message);
      return res.status(500).json(jsonRpcError(firstRequestId(batch), -32000, 'Failed to start Xero MCP server'));
    }

    session.mode = 'http';
    mcpSessions.set(session.id, session);

    // Same reasoning as the SSE path: the child was handed a Xero access token
    // at spawn time and can't be re-keyed, so retire the session just before
    // that token expires. The client's next POST gets a 404 and re-initializes
    // against a child holding a fresh token.
    const refreshDelay = tokens.expires_at - Date.now() - 60_000;
    session.tokenExpiryTimer = setTimeout(() => {
      closeMcpSession(session, 'Xero token is nearing expiry; client should re-initialize');
    }, Math.max(refreshDelay, 5_000));

    res.setHeader('Mcp-Session-Id', session.id);
    console.log(`[mcp-bridge] HTTP session ${session.id} started for ${tokens.tenant_name || tokens.tenant_id || 'Xero tenant'}`);
  } else {
    session = headerSessionId ? mcpSessions.get(headerSessionId) : null;
    if (!session || session.closed || session.mode !== 'http') {
      // 404 is the spec's "your session is gone" signal — the client responds
      // by starting a new initialize handshake rather than erroring out.
      return res.status(404).json(jsonRpcError(firstRequestId(batch), -32001, 'Unknown or expired MCP session'));
    }
  }

  touchHttpSession(session);

  // Requests expect responses; notifications and responses don't. A batch of
  // only the latter is acknowledged with 202 and nothing else.
  const requestIds = batch
    .filter(m => typeof m.method === 'string' && Object.prototype.hasOwnProperty.call(m, 'id'))
    .map(m => m.id);

  if (!requestIds.length) {
    try {
      await writeJsonRpcToChild(session, req.body);
      return res.status(202).end();
    } catch (err) {
      console.error(`[mcp-bridge] Failed to forward notification for session ${session.id}:`, err.message);
      return res.status(500).json(jsonRpcError(null, -32000, 'Failed to forward message to Xero MCP server'));
    }
  }

  // Register the waiters BEFORE writing to stdin — the child can answer
  // faster than the write callback resolves.
  const waiter = waitForHttpResponses(session, requestIds);

  try {
    await writeJsonRpcToChild(session, req.body);
  } catch (err) {
    cancelHttpWaiters(session, requestIds);
    console.error(`[mcp-bridge] Failed to forward message for session ${session.id}:`, err.message);
    return res.status(500).json(jsonRpcError(requestIds[0], -32000, 'Failed to forward message to Xero MCP server'));
  }

  const responses = await waiter;
  const payload = Array.isArray(req.body) ? responses : responses[0];
  return respondJsonRpc(req, res, payload);
}

function handleStreamableHttpDelete(req, res) {
  if (!isMcpAuthorized(req)) return res.status(401).send('Unauthorized');

  const sessionId = String(req.get('mcp-session-id') || '');
  const session = sessionId ? mcpSessions.get(sessionId) : null;
  if (!session || session.mode !== 'http') return res.status(404).send('Session not found');

  closeMcpSession(session, 'client sent DELETE');
  return res.status(204).end();
}

/**
 * Park one promise per in-flight request id. Resolved by
 * `dispatchChildMessage` when the child answers, by `sendPendingErrors` when
 * the child dies, or by a timeout so a wedged subprocess can't hold the HTTP
 * response open forever.
 */
function waitForHttpResponses(session, requestIds) {
  return Promise.all(requestIds.map(id => new Promise(resolve => {
    const key = httpWaiterKey(id);
    const timer = setTimeout(() => {
      session.httpWaiters.delete(key);
      resolve(jsonRpcError(id, -32001, 'Timed out waiting for the Xero MCP server to respond'));
    }, MCP_HTTP_REQUEST_TIMEOUT_MS);
    timer.unref?.();
    session.httpWaiters.set(key, { id, resolve, timer });
  })));
}

function cancelHttpWaiters(session, requestIds) {
  for (const id of requestIds) {
    const key = httpWaiterKey(id);
    const waiter = session.httpWaiters.get(key);
    if (!waiter) continue;
    clearTimeout(waiter.timer);
    session.httpWaiters.delete(key);
  }
}

/** JSON-RPC ids may be numbers or strings; 1 and "1" are different ids. */
function httpWaiterKey(id) {
  return `${typeof id}:${String(id)}`;
}

function touchHttpSession(session) {
  if (session.mode !== 'http') return;
  if (session.idleTimer) clearTimeout(session.idleTimer);
  session.idleTimer = setTimeout(() => {
    closeMcpSession(session, `idle for ${Math.round(MCP_HTTP_IDLE_MS / 1000)}s`);
  }, MCP_HTTP_IDLE_MS);
  session.idleTimer.unref?.();
}

/**
 * Streamable HTTP lets the server answer with either a JSON body or an SSE
 * stream. JSON is preferred when the client accepts it — one response, no
 * stream teardown to get wrong. SSE is used only when that's all it accepts.
 */
function respondJsonRpc(req, res, payload) {
  const accept = String(req.get('accept') || '');
  const acceptsJson = accept === '' || accept.includes('application/json') || accept.includes('*/*');

  if (!acceptsJson && accept.includes('text/event-stream')) {
    res.writeHead(200, {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache, no-transform',
      Connection: 'keep-alive',
      'X-Accel-Buffering': 'no',
    });
    for (const message of (Array.isArray(payload) ? payload : [payload])) {
      res.write(`event: message\ndata: ${JSON.stringify(message)}\n\n`);
    }
    return res.end();
  }

  return res.status(200).json(payload);
}

function jsonRpcError(id, code, message) {
  return { jsonrpc: '2.0', id: id ?? null, error: { code, message } };
}

function firstRequestId(batch) {
  const withId = batch.find(m => m && Object.prototype.hasOwnProperty.call(m, 'id'));
  return withId ? withId.id : null;
}

function createMcpSession(tokens) {
  const id = crypto.randomUUID();
  const child = spawn(process.execPath, [require.resolve('@xeroapi/xero-mcp-server')], {
    env: {
      ...process.env,
      XERO_CLIENT_ID:           CLIENT_ID,
      XERO_CLIENT_SECRET:       CLIENT_SECRET,
      XERO_CLIENT_BEARER_TOKEN: tokens.access_token,
      XERO_TENANT_ID:           tokens.tenant_id || '',
    },
    stdio: ['pipe', 'pipe', 'pipe'],
  });

  const session = {
    id,
    child,
    // 'sse'  → legacy transport, replies stream out of session.res
    // 'http' → Streamable HTTP, replies resolve the promises in httpWaiters
    mode: 'sse',
    res: null,
    stdoutBuffer: '',
    pendingRequestIds: new Set(),
    httpWaiters: new Map(),
    heartbeat: null,
    idleTimer: null,
    tokenExpiryTimer: null,
    closed: false,
  };

  child.stdout.on('data', chunk => handleChildStdout(session, chunk));
  child.stderr.on('data', chunk => {
    const text = chunk.toString('utf8').trimEnd();
    if (text) console.error(`[xero-mcp:${id}] ${text}`);
  });
  child.on('error', err => {
    console.error(`[mcp-bridge] xero-mcp-server error for session ${id}:`, err.message);
    sendPendingErrors(session, 'Xero MCP server failed to start');
    closeMcpSession(session, 'xero-mcp-server failed', { killChild: false });
  });
  child.on('close', (code, signal) => {
    if (!session.closed) {
      console.error(`[mcp-bridge] xero-mcp-server exited for session ${id}: code=${code} signal=${signal || 'none'}`);
      sendPendingErrors(session, 'Xero MCP server exited before responding');
      closeMcpSession(session, 'xero-mcp-server exited', { killChild: false });
    }
  });

  return session;
}

function handleChildStdout(session, chunk) {
  session.stdoutBuffer += chunk.toString('utf8');

  let newlineIndex = session.stdoutBuffer.indexOf('\n');
  while (newlineIndex !== -1) {
    const line = session.stdoutBuffer.slice(0, newlineIndex).replace(/\r$/, '');
    session.stdoutBuffer = session.stdoutBuffer.slice(newlineIndex + 1);

    if (line.trim()) {
      try {
        const message = JSON.parse(line);
        for (const id of getJsonRpcIds(message)) {
          session.pendingRequestIds.delete(id);
        }
        dispatchChildMessage(session, message);
      } catch (err) {
        console.error(`[mcp-bridge] Ignoring non-JSON stdout from xero-mcp-server (${session.id}):`, line);
      }
    }

    newlineIndex = session.stdoutBuffer.indexOf('\n');
  }
}

function writeJsonRpcToChild(session, message) {
  return new Promise((resolve, reject) => {
    if (session.closed || !session.child.stdin.writable) {
      reject(new Error('xero-mcp-server stdin is closed'));
      return;
    }

    const line = JSON.stringify(message) + '\n';
    let settled = false;
    const finish = err => {
      if (settled) return;
      settled = true;
      session.child.stdin.off('error', finish);
      if (err) reject(err);
      else resolve();
    };

    session.child.stdin.once('error', finish);
    session.child.stdin.write(line, finish);
  });
}

/**
 * Route one message from the child to whichever transport is waiting for it.
 * SSE sessions stream everything down the open EventSource; HTTP sessions hand
 * each response to the POST still holding the socket open for that id.
 */
function dispatchChildMessage(session, message) {
  if (session.mode !== 'http') {
    sendSseMessage(session, message);
    return;
  }

  // The child may emit a batch on one line; each element is settled separately.
  for (const item of (Array.isArray(message) ? message : [message])) {
    if (!item || typeof item !== 'object') continue;

    // A response carries an id and no method. Anything with a method is a
    // server-initiated request or notification, which Streamable HTTP can only
    // deliver over a GET stream — this server doesn't offer one, so it's logged
    // and dropped rather than mis-delivered to an unrelated waiter.
    const isResponse = Object.prototype.hasOwnProperty.call(item, 'id') && typeof item.method !== 'string';
    const waiter = isResponse ? session.httpWaiters.get(httpWaiterKey(item.id)) : null;

    if (!waiter) {
      console.log(`[mcp-bridge] HTTP session ${session.id}: dropped unsolicited ${item.method || 'message'}`);
      continue;
    }

    clearTimeout(waiter.timer);
    session.httpWaiters.delete(httpWaiterKey(item.id));
    waiter.resolve(item);
  }
}

function sendSseMessage(session, message) {
  if (session.closed || !session.res || session.res.writableEnded) return;
  session.res.write(`event: message\ndata: ${JSON.stringify(message)}\n\n`);
}

function sendPendingErrors(session, message) {
  // HTTP mode: every waiter is an HTTP response still held open. Settle them
  // with an error object instead of leaving the client hanging until timeout.
  for (const [key, waiter] of session.httpWaiters) {
    clearTimeout(waiter.timer);
    session.httpWaiters.delete(key);
    waiter.resolve(jsonRpcError(waiter.id, -32000, message));
  }

  for (const id of session.pendingRequestIds) {
    sendSseMessage(session, {
      jsonrpc: '2.0',
      id,
      error: { code: -32000, message },
    });
  }
  session.pendingRequestIds.clear();
}

function closeMcpSession(session, reason, options = {}) {
  if (session.closed) return;
  session.closed = true;

  if (session.heartbeat) clearInterval(session.heartbeat);
  if (session.tokenExpiryTimer) clearTimeout(session.tokenExpiryTimer);
  if (session.idleTimer) clearTimeout(session.idleTimer);
  mcpSessions.delete(session.id);

  // Anything still waiting on this session gets an error rather than a hung
  // socket. No-op once sendPendingErrors has already drained the waiters.
  sendPendingErrors(session, `MCP session closed: ${reason}`);

  if (session.res && !session.res.writableEnded) {
    session.res.end();
  }

  if (options.killChild !== false && session.child.exitCode === null && !session.child.killed) {
    session.child.kill('SIGTERM');
    const forceKill = setTimeout(() => {
      if (session.child.exitCode === null && !session.child.killed) {
        session.child.kill('SIGKILL');
      }
    }, 5_000);
    forceKill.unref?.();
  }

  console.log(`[mcp-bridge] ${session.mode === 'http' ? 'HTTP' : 'SSE'} session ${session.id} closed: ${reason}`);
}

function getJsonRpcIds(message) {
  const messages = Array.isArray(message) ? message : [message];
  return messages
    .filter(item => item && typeof item === 'object' && Object.prototype.hasOwnProperty.call(item, 'id'))
    .map(item => item.id);
}

function isMcpAuthorized(req) {
  if (!MCP_AUTH_TOKEN) return true;

  const authHeader = req.get('authorization') || '';
  const bearerToken = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : '';
  const queryToken = typeof req.query.token === 'string' ? req.query.token : '';

  return timingSafeEqual(bearerToken, MCP_AUTH_TOKEN) || timingSafeEqual(queryToken, MCP_AUTH_TOKEN);
}

/** Constant-time string compare so an invalid MCP_AUTH_TOKEN guess can't be timed. */
function timingSafeEqual(a, b) {
  const bufA = Buffer.from(a);
  const bufB = Buffer.from(b);
  return bufA.length === bufB.length && crypto.timingSafeEqual(bufA, bufB);
}

function getPublicBaseUrl(req) {
  const baseUrl = PUBLIC_BASE_URL || `${req.protocol}://${req.get('host') || `localhost:${PORT}`}`;
  return baseUrl.replace(/\/+$/, '');
}

// ── HTML helpers ──────────────────────────────────────────────────────────────

/** Escape HTML special chars */
function esc(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

/** Wrap content in the shared HTML shell */
function renderPage({ title, content }) {
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>${esc(title)} — Xero MCP Auth</title>
<style>
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
    background: #f4f4f5; color: #18181b; min-height: 100vh;
  }

  /* ── Header ── */
  header {
    background: #18181b; color: #fff;
    padding: 14px 32px;
    display: flex; align-items: center; justify-content: space-between;
  }
  header h1 { font-size: 16px; font-weight: 600; letter-spacing: -.2px; }
  header nav a { color: #a1a1aa; font-size: 13px; text-decoration: none; margin-left: 16px; }
  header nav a:hover { color: #fff; }

  /* ── Layout ── */
  main { max-width: 820px; margin: 36px auto; padding: 0 20px; }

  /* ── Card ── */
  .card {
    background: #fff; border: 1px solid #e4e4e7;
    border-radius: 12px; padding: 28px 32px;
  }
  .card.center { text-align: center; padding: 48px 32px; }
  .icon { font-size: 48px; margin-bottom: 16px; }
  .card h2 { font-size: 20px; font-weight: 700; margin-bottom: 10px; }
  .card p  { font-size: 14px; color: #52525b; line-height: 1.6; margin-bottom: 20px; }

  /* ── Org row ── */
  .org-row { display: flex; align-items: center; justify-content: space-between;
             flex-wrap: wrap; gap: 8px; margin-bottom: 20px; }
  .org-name { font-size: 16px; font-weight: 600; }
  .expiry { font-size: 12px; font-weight: 600; padding: 3px 10px; border-radius: 20px; }
  .expiry.ok    { background: #dcfce7; color: #15803d; }
  .expiry.warn  { background: #fef3c7; color: #b45309; }
  .expiry.error { background: #fee2e2; color: #b91c1c; }

  /* ── Field label ── */
  .field-label {
    display: block; font-size: 11px; font-weight: 600; letter-spacing: .5px;
    text-transform: uppercase; color: #71717a; margin-bottom: 6px;
  }

  /* ── Token / code block ── */
  .token-wrap, .config-wrap {
    position: relative;
    background: #f4f4f5; border: 1px solid #d4d4d8;
    border-radius: 8px; padding: 12px 100px 12px 14px;
  }
  .config-wrap { background: #0d1117; border-color: #30363d; }

  .token-wrap code {
    font-family: 'SF Mono', Menlo, Consolas, monospace;
    font-size: 11.5px; color: #18181b; word-break: break-all; line-height: 1.6;
  }
  .config-wrap pre {
    font-family: 'SF Mono', Menlo, Consolas, monospace;
    font-size: 11.5px; color: #e6edf3; white-space: pre; line-height: 1.6;
    overflow-x: auto;
  }

  /* ── Copy button ── */
  .copy-btn {
    position: absolute; top: 10px; right: 10px;
    background: #18181b; color: #fff;
    border: none; border-radius: 6px;
    padding: 5px 14px; font-size: 12px; font-weight: 500;
    cursor: pointer; font-family: inherit; white-space: nowrap;
    transition: background .15s;
  }
  .copy-btn:hover    { background: #3f3f46; }
  .copy-btn.copied   { background: #16a34a; }
  .copy-btn.dark     { background: rgba(255,255,255,.12); border: 1px solid rgba(255,255,255,.15); }
  .copy-btn.dark:hover  { background: rgba(255,255,255,.2); }
  .copy-btn.dark.copied { background: #16a34a; border-color: #16a34a; }

  /* ── Buttons ── */
  .btn {
    display: inline-block; padding: 9px 20px;
    background: #18181b; color: #fff;
    border: 1px solid transparent;
    text-decoration: none; border-radius: 7px;
    font-size: 13px; font-weight: 500; cursor: pointer;
    font-family: inherit; transition: background .15s;
  }
  .btn:hover    { background: #3f3f46; }
  .btn.outline  { background: transparent; color: #3f3f46; border-color: #d4d4d8; }
  .btn.outline:hover { background: #f4f4f5; }
  .btn.danger   { color: #dc2626; border-color: #fecaca; }
  .btn.danger:hover { background: #fef2f2; }

  .actions { display: flex; gap: 10px; flex-wrap: wrap; margin-top: 24px; }

  /* ── Org picker items ── */
  .org-item {
    display: flex; align-items: center;
    padding: 14px 16px; border: 1px solid #e4e4e7; border-radius: 8px;
    margin-bottom: 10px; text-decoration: none; color: inherit;
    transition: background .12s;
  }
  .org-item:hover { background: #f4f4f5; }

  /* ── Info box ── */
  .info-box {
    background: #eff6ff; border: 1px solid #bfdbfe; color: #1e40af;
    border-radius: 8px; padding: 14px 16px;
    font-size: 13px; line-height: 1.6; margin-top: 20px;
  }
  .info-box code { background: rgba(0,0,0,.06); padding: 1px 5px; border-radius: 3px; font-size: 12px; }

  /* ── Org switcher ── */
  .org-switcher {
    margin-bottom: 22px; padding-bottom: 20px;
    border-bottom: 1px solid #e4e4e7;
  }
  .org-select-wrap {
    display: flex; align-items: center; gap: 12px; flex-wrap: wrap;
  }
  .org-select-box { position: relative; display: inline-block; }
  .org-select-icon {
    position: absolute; left: 13px; top: 50%; transform: translateY(-50%);
    font-size: 14px; pointer-events: none;
  }
  .org-switcher select {
    appearance: none; -webkit-appearance: none; -moz-appearance: none;
    min-width: 240px;
    padding: 10px 34px 10px 38px;
    border: 1px solid #d4d4d8; border-radius: 8px;
    font-size: 13.5px; font-weight: 500; font-family: inherit;
    background: #fafafa; color: #18181b;
    cursor: pointer;
    transition: border-color .15s, background-color .15s, box-shadow .15s;
  }
  .org-switcher select:hover  { background: #f4f4f5; border-color: #b4b4b8; }
  .org-switcher select:focus {
    outline: none; background: #fff; border-color: #18181b;
    box-shadow: 0 0 0 3px rgba(24,24,27,.08);
  }
  .org-select-chevron {
    position: absolute; right: 14px; top: 50%; transform: translateY(-50%);
    font-size: 10px; color: #71717a; pointer-events: none;
  }
  .switch-status {
    display: inline-flex; align-items: center; gap: 6px;
    font-size: 12px; font-weight: 600;
    padding: 6px 12px; border-radius: 20px;
    opacity: 0; transform: translateY(-2px);
    transition: opacity .18s, transform .18s;
  }
  .switch-status.show    { opacity: 1; transform: translateY(0); }
  .switch-status.pending { background: #f4f4f5; color: #52525b; }
  .switch-status.ok      { background: #dcfce7; color: #15803d; }
  .switch-status.error   { background: #fee2e2; color: #b91c1c; }
  .switch-spinner {
    width: 11px; height: 11px; border-radius: 50%; flex: none;
    border: 2px solid rgba(0,0,0,.15); border-top-color: currentColor;
    animation: spin .6s linear infinite;
  }
  @keyframes spin { to { transform: rotate(360deg); } }
</style>
</head>
<body>

<header>
  <h1>🔑 Xero MCP Auth</h1>
  <nav>
    <a href="/">Home</a>
    <a href="/api/token" target="_blank">JSON API</a>
    <a href="/login">Re-auth</a>
  </nav>
</header>

<main>
  ${content}
</main>

<script>
  function copy(id, btn) {
    const el = document.getElementById(id);
    const text = el.innerText || el.textContent;
    navigator.clipboard.writeText(text).then(() => {
      const orig = btn.textContent;
      btn.textContent = '✓ Copied!';
      btn.classList.add('copied');
      setTimeout(() => { btn.textContent = orig; btn.classList.remove('copied'); }, 2200);
    });
  }

  async function switchOrg(tenantId) {
    const status = document.getElementById('switchStatus');
    status.className = 'switch-status pending show';
    status.innerHTML = '<span class="switch-spinner"></span> Switching';

    try {
      const res = await fetch('/api/switch-org', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ tenant_id: tenantId }),
      });
      const data = await res.json();

      if (data.ok) {
        status.className = 'switch-status ok show';
        status.textContent = '✓ Switched';
        setTimeout(() => location.reload(), 700);
      } else {
        status.className = 'switch-status error show';
        status.textContent = '✗ ' + (data.error || 'Failed');
      }
    } catch (err) {
      status.className = 'switch-status error show';
      status.textContent = '✗ Network error';
    }
  }
</script>

</body>
</html>`;
}

// ── Start ─────────────────────────────────────────────────────────────────────

(async () => {
  // Verify DATABASE_URL is present before doing anything
  if (!process.env.DATABASE_URL) {
    console.error('[xero-auth] FATAL: DATABASE_URL environment variable is not set.');
    process.exit(1);
  }

  sql = neon(process.env.DATABASE_URL);

  // Create the DB table if it doesn't exist yet, then start the server
  await initDb();
  console.log('[xero-auth] Database ready (NeonDB)');

  app.listen(PORT, () => {
    console.log('');
    console.log('  🔑 Xero MCP Auth running at http://localhost:' + PORT);
    console.log('');
    if (!CLIENT_ID || !CLIENT_SECRET) {
      console.log('  ⚠️  No credentials found!');
      console.log('     Copy .env.example → .env and fill in XERO_CLIENT_ID + XERO_CLIENT_SECRET');
    } else {
      console.log('  → Open http://localhost:' + PORT + ' in your browser to get your token');
      console.log('  → JSON API: GET http://localhost:' + PORT + '/api/token');
      console.log('  → Remote MCP: GET http://localhost:' + PORT + '/sse, POST http://localhost:' + PORT + MCP_MESSAGE_PATH);
    }
    console.log('');
  });
})();
