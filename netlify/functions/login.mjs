import { db, json, sha256, normToken, tokenStatus, usable, newId, cookieFor, ipOf, addLog, SECRET } from './_lib.mjs';

export default async (req, ctx) => {
  if (req.method !== 'POST') return json({ error: 'Metode tidak diizinkan.' }, 405);
  if (!SECRET()) return json({ error: 'Server belum dikonfigurasi (ADMIN_PASSWORD belum diatur).' }, 500);
  const ip = ipOf(req, ctx), ua = (req.headers.get('user-agent') || '').slice(0, 300), d = db();
  /* batasi percobaan salah: 10x / 15 menit per IP */
  const rlKey = `rl/${sha256(ip || 'x')}`; const rl = (await d.get(rlKey, { type: 'json' })) || { n: 0, t: Date.now() };
  if (Date.now() - rl.t > 15 * 60 * 1000) { rl.n = 0; rl.t = Date.now(); }
  if (rl.n >= 10) return json({ error: 'Terlalu banyak percobaan. Coba lagi dalam 15 menit.' }, 429);

  let body = {}; try { body = await req.json(); } catch { /* kosong */ }
  const tok = normToken(body.token);
  const id = tok ? await d.get(`h/${sha256(tok)}`) : null;
  const t = id ? await d.get(`t/${id}`, { type: 'json' }) : null;
  if (!t || !usable(t)) {
    rl.n++; await d.setJSON(rlKey, rl);
    await addLog({ type: 'login_gagal', label: '', detail: !t ? `Token tidak dikenal (${tok.slice(0, 4)}…${tok.slice(-4)})` : `Token ${tokenStatus(t)}`, tokenId: t ? t.id : '', ip }).catch(() => {});
    return json({ error: !t ? 'Token tidak ditemukan. Periksa kembali.' : `Token ${tokenStatus(t)}. Hubungi admin.` }, 401);
  }
  if (!t.firstUsedAt) {
    t.firstUsedAt = new Date().toISOString();
    t.expiresAt = new Date(Date.now() + t.durationDays * 86400000).toISOString();
    await d.setJSON(`t/${t.id}`, t);
  }
  const sid = newId() + newId();
  const now = new Date().toISOString();
  await d.setJSON(`s/${sid}`, { id: sid, tokenId: t.id, createdAt: now, lastSeen: now, ip, ua, ended: false });
  await addLog({ type: 'login', label: t.label, tokenId: t.id, sessionId: sid, detail: 'Masuk', ip });
  const maxAge = Math.max(60, Math.floor((Date.parse(t.expiresAt) - Date.now()) / 1000));
  return json({ ok: true }, 200, { 'set-cookie': cookieFor(sid, Math.min(maxAge, 60 * 60 * 24 * 90)) });
};
export const config = { path: '/api/login' };
