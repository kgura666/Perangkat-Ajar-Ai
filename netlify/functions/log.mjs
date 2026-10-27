import { guard, json, addLog, clientIp } from '../lib/core.mjs';

export default async (req, ctx) => {
  if (req.method !== 'POST') return json({ error: 'Metode tidak didukung.' }, 405);
  const g = await guard(req);               // juga memperbarui "terakhir aktif"
  if (!g) return json({ error: 'Sesi berakhir.' }, 401);
  let b = {}; try { b = await req.json(); } catch { /* kosong */ }
  const type = String(b.type || '').replace(/[^a-z_]/gi, '').slice(0, 30);
  if (type && type !== 'ping') await addLog({ type, label: g.tok.label, detail: b.detail, ip: clientIp(req, ctx) });
  return json({ ok: true });
};
export const config = { path: '/api/log' };
