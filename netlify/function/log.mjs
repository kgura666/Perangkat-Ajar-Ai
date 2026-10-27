import { json, authSession, addLog, ipOf } from './_lib.mjs';
const TYPES = new Set(['generate', 'export', 'error', 'ping']);
export default async (req, ctx) => {
  if (req.method !== 'POST') return json({ error: 'Metode tidak diizinkan.' }, 405);
  const a = await authSession(req, ctx); /* ping juga memperbarui terakhir aktif */
  if (!a) return json({ error: 'Sesi berakhir.' }, 401);
  let b = {}; try { b = await req.json(); } catch { /* kosong */ }
  const type = String(b.type || '');
  if (!TYPES.has(type)) return json({ error: 'Jenis tidak valid.' }, 400);
  if (type !== 'ping') await addLog({ type, label: a.t.label, tokenId: a.t.id, sessionId: a.s.id, detail: String(b.detail || '').replace(/[\u0000-\u001f]+/g, ' ').slice(0, 300), ip: ipOf(req, ctx) });
  return json({ ok: true });
};
export const config = { path: '/api/log' };
