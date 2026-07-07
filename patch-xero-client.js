#!/usr/bin/env node
// Patches @xeroapi/xero-mcp-server to honour XERO_TENANT_ID env var.
// Run automatically via postinstall. Safe to re-run.
'use strict';

const fs   = require('fs');
const path = require('path');

const target = path.join(__dirname, 'node_modules/@xeroapi/xero-mcp-server/dist/clients/xero-client.js');

if (!fs.existsSync(target)) {
  console.log('[patch] xero-client.js not found — skipping');
  process.exit(0);
}

const original = `    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    async updateTenants(fullOrgDetails) {
        await super.updateTenants(fullOrgDetails);
        if (this.tenants && this.tenants.length > 0) {
            this.tenantId = this.tenants[0].tenantId;
        }
        return this.tenants;
    }`;

const patched = `    // eslint-disable-next-line @typescript-eslint/no-explicit-any
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

let src = fs.readFileSync(target, 'utf8');

if (src.includes('const envTenantId = process.env.XERO_TENANT_ID')) {
  console.log('[patch] xero-client.js already patched — skipping');
  process.exit(0);
}

if (!src.includes(original)) {
  console.error('[patch] ERROR: xero-client.js does not match expected content — package may have updated. Patch not applied.');
  process.exit(1);
}

fs.writeFileSync(target, src.replace(original, patched), 'utf8');
console.log('[patch] xero-client.js patched successfully');
