import { readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { guard, getCookie, COOKIE, clearCookie, addLog, clientIp } from '../lib/core.mjs';

/* app.html disimpan di folder protected/ (bukan folder publik) dan dibundel ke function lewat netlify.toml */
let HTML = null;
function loadHtml() {
  if (HTML) return HTML;
  const cands = [
    join(process.cwd(), 'protected', 'app.html'),
    process.env.LAMBDA_TASK_ROOT && join(process.env.LAMBDA_TASK_ROOT, 'protected', 'app.html'),
    fileURLToPath(new URL('../../protected/app.html', import.meta.url)),
  ].filter(Boolean);
  const p = cands.find(existsSync);
  if (!p) throw new Error('protected/app.html tidak ditemukan di function.');
  return (HTML = readFileSync(p));
}

export default async (req, ctx) => {
  const g = await guard(req);
  if (!g) {
    const had = !!getCookie(req, COOKIE);
    return new Response(null, { status: 302, headers: { location: had ? '/?r=habis' : '/', 'set-cookie': clearCookie(), 'cache-control': 'no-store' } });
  }
  await addLog({ type: 'buka', label: g.tok.label, detail: '', ip: clientIp(req, ctx) });
  return new Response(loadHtml(), { headers: { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store', 'x-robots-tag': 'noindex' } });
};
export const config = { path: ['/app', '/app.html'] };
