import { tokens, sessions, json, clientIp, normToken, validTokenShape, tokenStatus, newSid, setCookie, addLog, blocked, fail, clearFails, SESSION_MAX_DAYS, secretOk } from '../lib/core.mjs';

export default async (req, ctx) => {
  if (req.method !== 'POST') return json({ error: 'Metode tidak didukung.' }, 405);
  if (!secretOk()) return json({ error: 'Server belum siap: SESSION_SECRET belum diatur (minimal 32 karakter) di Netlify. Hubungi admin.' }, 500);
  const ip = clientIp(req, ctx), ua = (req.headers.get('user-agent') || '').slice(0, 300);
  if (await blocked('login:' + ip)) return json({ error: 'Terlalu banyak percobaan salah. Coba lagi sekitar 10 menit.' }, 429);

  let body = {}; try { body = await req.json(); } catch { /* kosong */ }
  const token = normToken(body.token);
  const t = validTokenShape(token) ? await tokens().get(token, { type: 'json' }) : null;
  const st = t ? tokenStatus(t) : null;

  if (!t || st === 'dicabut' || st === 'kedaluwarsa') {
    await fail('login:' + ip);
    await addLog({ type: 'login_gagal', label: t ? t.label : '', detail: t ? 'Token ' + st : 'Token tidak dikenal: ' + token.slice(0, 24), ip });
    return json({ error: !t ? 'Token tidak dikenal. Periksa kembali penulisannya.' : st === 'dicabut' ? 'Token ini sudah dicabut oleh admin.' : 'Masa berlaku token sudah habis. Hubungi admin.' }, 401);
  }

  const now = Date.now();
  if (!t.firstUsedAt) { /* hitung masa berlaku mulai dari pemakaian pertama */
    t.firstUsedAt = new Date(now).toISOString();
    t.expiresAt = new Date(now + t.durationDays * 86400000).toISOString();
    await tokens().setJSON(t.id, t);
  }
  const sid = newSid(), iso = new Date(now).toISOString();
  await sessions().setJSON(sid, { id: sid, token: t.id, label: t.label, ip, ua, createdAt: iso, lastSeen: iso, ended: false, endedBy: '' });
  await clearFails('login:' + ip);
  await addLog({ type: 'login', label: t.label, detail: '', ip });

  const maxAge = Math.max(60, Math.min(SESSION_MAX_DAYS * 86400, Math.floor((Date.parse(t.expiresAt) - now) / 1000)));
  return json({ ok: true }, 200, { 'set-cookie': setCookie(sid, maxAge) });
};
export const config = { path: '/api/login' };
