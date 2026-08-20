#!/usr/bin/env node

/**
 * xero-mcp-start.js — Auto-refreshing Xero MCP launcher
 *
 * Use this as the command in your Claude Desktop MCP config INSTEAD of
 * pointing directly to xero-mcp-server with a static bearer token.
 *
 * Every time Claude Desktop starts (or restarts) the MCP server, this script:
 *   1. Loads tokens from NeonDB (saved by your one-time OAuth login via server.js)
 *   2. Refreshes the token automatically if it has expired
 *   3. Passes the fresh token as env vars to xero-mcp-server
 *   4. Hands off (exec-style) — Claude talks directly to the MCP server
 *
 * Claude Desktop config (~/.claude/claude_desktop_config.json):
 *
 *   {
 *     "mcpServers": {
 *       "xero": {
 *         "command": "node",
 *         "args": ["/FULL/PATH/TO/xero-mcp-auth/xero-mcp-start.js"]
 *       }
 *     }
 *   }
 *
 * REQUIREMENTS:
 *   - node server.js must have been run at least once (to store tokens in DB)
 *   - XERO_CLIENT_ID, XERO_CLIENT_SECRET, and DATABASE_URL must be in .env
 */

'use strict';

const fs        = require('fs');
const path      = require('path');
const https     = require('https');
const { spawn } = require('child_process');
const { neon }  = require('@neondatabase/serverless');

// ── Paths ─────────────────────────────────────────────────────────────────────

const DIR      = __dirname;
const ENV_FILE = path.join(DIR, '.env');

// Initialised in main() after loadEnv() so DATABASE_URL is available
let sql;

// ── Load .env manually (no dotenv dependency needed here) ────────────────────

function loadEnv() {
  if (!fs.existsSync(ENV_FILE)) return;
  const lines = fs.readFileSync(ENV_FILE, 'utf8').split('\n');
  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    const eq = trimmed.indexOf('=');
    if (eq === -1) continue;
    const key = trimmed.slice(0, eq).trim();
    const val = trimmed.slice(eq + 1).trim().replace(/^["']|["']$/g, '');
    if (!process.env[key]) process.env[key] = val; // don't override existing env
  }
}

// ── Token helpers (NeonDB) ────────────────────────────────────────────────────

async function loadTokens() {
  // Multi-org schema: xero_active_org points at which row in xero_tokens
  // (keyed by tenant_id, not id) is the one Claude Desktop should use.
  const active = await sql`SELECT tenant_id FROM xero_active_org WHERE id = 1`;
  if (!active[0]) return null;
  const rows = await sql`SELECT * FROM xero_tokens WHERE tenant_id = ${active[0].tenant_id}`;
  return rows[0] ?? null;
}

async function saveTokens(data) {
  await sql`
    INSERT INTO xero_tokens
      (tenant_id, tenant_name, access_token, refresh_token, expires_at, authorised_at, refreshed_at, is_active)
    VALUES
      (${data.tenant_id}, ${data.tenant_name ?? null}, ${data.access_token}, ${data.refresh_token},
       ${data.expires_at}, ${data.authorised_at ?? null}, ${data.refreshed_at ?? null}, true)
    ON CONFLICT (tenant_id) DO UPDATE SET
      access_token  = EXCLUDED.access_token,
      refresh_token = EXCLUDED.refresh_token,
      expires_at    = EXCLUDED.expires_at,
      tenant_name   = EXCLUDED.tenant_name,
      authorised_at = EXCLUDED.authorised_at,
      refreshed_at  = EXCLUDED.refreshed_at
  `;
}

function isExpired(tokens) {
  // Refresh 60 seconds early to avoid edge cases
  return Date.now() >= (tokens.expires_at - 60_000);
}

// ── HTTPS POST (no axios — keep this script dependency-free) ─────────────────

function httpsPost(url, params, auth) {
  return new Promise((resolve, reject) => {
    const body    = new URLSearchParams(params).toString();
    const parsed  = new URL(url);
    const authStr = Buffer.from(`${auth.user}:${auth.pass}`).toString('base64');

    const req = https.request({
      hostname: parsed.hostname,
      path:     parsed.pathname,
      method:   'POST',
      headers:  {
        'Content-Type':   'application/x-www-form-urlencoded',
        'Content-Length': Buffer.byteLength(body),
        'Authorization':  `Basic ${authStr}`,
      },
    }, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        try { resolve(JSON.parse(data)); }
        catch (_) { reject(new Error('Bad JSON response: ' + data)); }
      });
    });

    req.on('error', reject);
    req.write(body);
    req.end();
  });
}

// ── Refresh token ─────────────────────────────────────────────────────────────

async function refreshToken(tokens) {
  const clientId     = process.env.XERO_CLIENT_ID;
  const clientSecret = process.env.XERO_CLIENT_SECRET;

  if (!clientId || !clientSecret) {
    throw new Error('XERO_CLIENT_ID or XERO_CLIENT_SECRET missing from .env');
  }

  const res = await httpsPost(
    'https://identity.xero.com/connect/token',
    { grant_type: 'refresh_token', refresh_token: tokens.refresh_token },
    { user: clientId, pass: clientSecret }
  );

  if (!res.access_token) {
    throw new Error('Refresh failed: ' + JSON.stringify(res));
  }

  const refreshed = {
    ...tokens,
    access_token:  res.access_token,
    refresh_token: res.refresh_token, // Xero rotates refresh tokens
    expires_at:    Date.now() + res.expires_in * 1000,
    refreshed_at:  new Date().toISOString(),
  };

  await saveTokens(refreshed);
  return refreshed;
}

// ── Main ──────────────────────────────────────────────────────────────────────

async function main() {
  loadEnv();

  // Initialise NeonDB client now that DATABASE_URL is in process.env
  if (!process.env.DATABASE_URL) {
    process.stderr.write('[xero-mcp] ERROR: DATABASE_URL missing from .env\n');
    process.exit(1);
  }
  sql = neon(process.env.DATABASE_URL);

  // 1. Load stored tokens
  let tokens = await loadTokens();

  if (!tokens) {
    process.stderr.write(
      '[xero-mcp] ERROR: No tokens found in database.\n' +
      '[xero-mcp] Run "node server.js", open http://localhost:3000, and log in with Xero first.\n'
    );
    process.exit(1);
  }

  // 2. Refresh if expired
  if (isExpired(tokens)) {
    process.stderr.write('[xero-mcp] Token expired — refreshing...\n');
    try {
      tokens = await refreshToken(tokens);
      process.stderr.write('[xero-mcp] Token refreshed successfully.\n');
    } catch (err) {
      process.stderr.write(`[xero-mcp] Refresh failed: ${err.message}\n`);
      process.stderr.write('[xero-mcp] Re-authenticate at http://localhost:3000\n');
      process.exit(1);
    }
  } else {
    const mins = Math.floor((tokens.expires_at - Date.now()) / 60_000);
    process.stderr.write(`[xero-mcp] Token valid (${mins} min remaining).\n`);
  }

  // 3. Launch xero-mcp-server with the fresh token injected as env vars
  const env = {
    ...process.env,
    XERO_CLIENT_ID:           process.env.XERO_CLIENT_ID,
    XERO_CLIENT_SECRET:       process.env.XERO_CLIENT_SECRET,
    XERO_CLIENT_BEARER_TOKEN: tokens.access_token,
    XERO_TENANT_ID:           tokens.tenant_id,
  };

  process.stderr.write(`[xero-mcp] Starting xero-mcp-server for "${tokens.tenant_name}"...\n`);

  // Use npx to run the official Xero MCP server (scoped package)
  const child = spawn('npx', ['-y', '@xeroapi/xero-mcp-server'], {
    env,
    stdio: 'inherit', // pass stdin/stdout/stderr straight through to Claude
  });

  child.on('exit', (code) => process.exit(code ?? 0));
  child.on('error', (err) => {
    process.stderr.write(`[xero-mcp] Failed to start: ${err.message}\n`);
    process.exit(1);
  });

  // Forward signals so Claude Desktop can cleanly shut down the MCP server
  process.on('SIGTERM', () => child.kill('SIGTERM'));
  process.on('SIGINT',  () => child.kill('SIGINT'));
}

main().catch(err => {
  process.stderr.write(`[xero-mcp] Fatal: ${err.message}\n`);
  process.exit(1);
});
