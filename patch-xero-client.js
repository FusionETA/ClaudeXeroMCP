#!/usr/bin/env node
// Patches @xeroapi/xero-mcp-server to honour the XERO_TENANT_ID env var.
// Run automatically via postinstall. Safe to re-run (each patch is idempotent).
//
// Two fixes are applied to dist/clients/xero-client.js:
//   1. updateTenants() prefers the explicit XERO_TENANT_ID env var over the
//      /connections lookup, so SSE deployments don't depend on that API.
//   2. The constructor seeds this.tenantId from XERO_TENANT_ID immediately.
//      Upstream 0.0.14 has handlers (create-tracking-category,
//      create-tracking-option) that call xeroClient.authenticate() WITHOUT
//      awaiting it, then read xeroClient.tenantId on the next line — so it is
//      still the constructor default "" and the write goes out with an empty
//      xero-tenant-id header (403 AuthenticationUnsuccessful). Seeding tenantId
//      at construction time makes every handler correct regardless of the race.
'use strict';

const fs   = require('fs');
const path = require('path');

const target = path.join(__dirname, 'node_modules/@xeroapi/xero-mcp-server/dist/clients/xero-client.js');

if (!fs.existsSync(target)) {
  console.log('[patch] xero-client.js not found — skipping');
  process.exit(0);
}

let src = fs.readFileSync(target, 'utf8');
let changed = false;

// ── Patch 1: updateTenants prefers env var ──────────────────────────────────
const updateOriginal = `    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    async updateTenants(fullOrgDetails) {
        await super.updateTenants(fullOrgDetails);
        if (this.tenants && this.tenants.length > 0) {
            this.tenantId = this.tenants[0].tenantId;
        }
        return this.tenants;
    }`;

const updatePatched = `    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    async updateTenants(fullOrgDetails) {
        await super.updateTenants(fullOrgDetails);
        // Prefer the explicit env var so SSE deployments don't depend on the
        // connections API returning the right tenant on every call.
        const envTenantId = process.env.XERO_TENANT_ID;
        if (envTenantId) {
            this.tenantId = envTenantId;
        } else if (this.tenants && this.tenants.length > 0) {
            this.tenantId = this.tenants[0].tenantId;
        }
        return this.tenants;
    }`;

if (src.includes('const envTenantId = process.env.XERO_TENANT_ID')) {
  console.log('[patch] updateTenants already patched — skipping');
} else if (src.includes(updateOriginal)) {
  src = src.replace(updateOriginal, updatePatched);
  changed = true;
  console.log('[patch] updateTenants patched');
} else {
  console.error('[patch] ERROR: updateTenants block does not match expected content — package may have updated. Patch not applied.');
  process.exit(1);
}

// ── Patch 2: constructor seeds tenantId from env ────────────────────────────
const ctorOriginal = `        super(config);
        this.tenantId = "";
        this.shortCode = "";`;

const ctorPatched = `        super(config);
        // Seed from env so handlers that read tenantId before authenticate()
        // resolves (missing-await bug in some 0.0.14 handlers) still work.
        this.tenantId = process.env.XERO_TENANT_ID || "";
        this.shortCode = "";`;

if (src.includes('this.tenantId = process.env.XERO_TENANT_ID || "";')) {
  console.log('[patch] constructor already patched — skipping');
} else if (src.includes(ctorOriginal)) {
  src = src.replace(ctorOriginal, ctorPatched);
  changed = true;
  console.log('[patch] constructor patched');
} else {
  console.error('[patch] ERROR: constructor block does not match expected content — package may have updated. Patch not applied.');
  process.exit(1);
}

if (changed) {
  fs.writeFileSync(target, src, 'utf8');
  console.log('[patch] xero-client.js patched successfully');
} else {
  console.log('[patch] xero-client.js already fully patched — nothing to do');
}
