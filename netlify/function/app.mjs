import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { authSession, addLog, ipOf, clearCookie } from './_lib.mjs';

let HTML = null;
function loadApp() {
  if (HTML) return HTML;
  const bases = [process.env.LAMBDA_TASK_ROOT, process.cwd(), '/var/task', join(process.cwd(), '..'), join(process.cwd(), '../..')].filter(Boolean);
  for (const b of bases) { try { HTML = readFileSync(join(b, 'app.html'), 'utf8'); return HTML; } catch { /* coba berikutnya */ } }
  throw new Error('app.html tidak ditemukan di function');
}
export default async (req, ctx) => {
  const a = await authSession(req, ctx);
  if (!a) return new Response(null, { status: 302, headers: { location: '/?r=habis', 'set-cookie': clearCookie() } });
  await addLog({ type: 'buka', label: a.t.label, tokenId: a.t.id, sessionId: a.s.id, detail: 'Membuka aplikasi', ip: ipOf(req, ctx) }).catch(() => {});
  return new Response(loadApp(), { status: 200, headers: { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' } });
};
export const config = { path: '/app' };
