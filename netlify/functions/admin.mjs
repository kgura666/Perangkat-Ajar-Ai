import { tokens, sessions, logs, json, clientIp, adminCheck, blocked, fail, newToken, tokenStatus, readAll, ONLINE_MS } from '../lib/core.mjs';

const err = (m, s = 400) => json({ error: m }, s);
const iso = () => new Date().toISOString();
const clamp = (n, a, b) => Math.max(a, Math.min(b, Math.floor(+n) || a));

export default async (req, ctx) => {
  if (req.method !== 'POST') return err('Metode tidak didukung.', 405);
  const ip = clientIp(req, ctx);
  if (await blocked('admin:' + ip)) return err('Terlalu banyak percobaan salah. Coba lagi sekitar 10 menit.', 429);
  const auth = adminCheck(req);
  if (auth === 'noenv') return err('ADMIN_PASSWORD belum diatur di Netlify (Site configuration → Environment variables).', 500);
  if (auth !== 'ok') { await fail('admin:' + ip); return err('Password admin salah.', 401); }

  let b = {}; try { b = await req.json(); } catch { /* kosong */ }
  const now = Date.now();

  switch (b.action) {
    case 'ping': return json({ ok: true });

    case 'list': {
      const [tk, ss] = await Promise.all([readAll(tokens()), readAll(sessions())]);
      const rows = tk.map(t => {
        const mine = ss.filter(s => s.token === t.id), live = mine.filter(s => !s.ended);
        const lastSeen = mine.reduce((m, s) => (s.lastSeen > m ? s.lastSeen : m), '') || null;
        return { id: t.id, label: t.label, token: t.id, status: tokenStatus(t, now), revoked: !!t.revoked, online: live.some(s => now - Date.parse(s.lastSeen) < ONLINE_MS), sessions: live.length, lastSeen, firstUsedAt: t.firstUsedAt, expiresAt: t.expiresAt, durationDays: t.durationDays, createdAt: t.createdAt };
      }).sort((a, c) => String(c.createdAt).localeCompare(String(a.createdAt)));
      return json({ rows });
    }

    case 'sessions': {
      const ss = await readAll(sessions());
      const old = ss.filter(s => s.ended && now - Date.parse(s.lastSeen) > 30 * 86400000);
      await Promise.all(old.map(s => sessions().delete(s._key)));          // bersihkan sesi lama
      const rows = ss.filter(s => !old.includes(s)).map(s => ({ id: s.id, label: s.label, token: s.token, ip: s.ip, ua: s.ua, createdAt: s.createdAt, lastSeen: s.lastSeen, online: !s.ended && now - Date.parse(s.lastSeen) < ONLINE_MS, ended: !!s.ended, endedBy: s.endedBy || '' }))
        .sort((a, c) => String(c.lastSeen).localeCompare(String(a.lastSeen)));
      return json({ rows });
    }

    case 'logs': {
      const days = clamp(b.days, 1, 90), limit = clamp(b.limit || 600, 1, 1000), keys = [];
      for (let i = 0; i < days; i++) {
        const day = new Date(now - i * 86400000).toISOString().slice(0, 10);
        const { blobs } = await logs().list({ prefix: day + '/' });
        keys.push(...blobs.map(x => x.key));
      }
      keys.sort().reverse();
      const pick = keys.slice(0, limit), rows = [];
      for (let i = 0; i < pick.length; i += 40) {
        const vals = await Promise.all(pick.slice(i, i + 40).map(k => logs().get(k, { type: 'json' })));
        rows.push(...vals.filter(Boolean));
      }
      return json({ rows });
    }

    case 'create': {
      const label = String(b.label || '').trim().slice(0, 60), count = clamp(b.count || 1, 1, 200), dur = clamp(b.durationDays || 30, 1, 3650);
      const out = [];
      for (let i = 0; i < count; i++) {
        const id = newToken();
        await tokens().setJSON(id, { id, label: count > 1 && label ? `${label} ${i + 1}` : label, durationDays: dur, createdAt: iso(), firstUsedAt: null, expiresAt: null, revoked: false });
        out.push(id);
      }
      return json({ tokens: out });
    }

    case 'extend': case 'revoke': case 'unrevoke': {
      const t = await tokens().get(String(b.id || ''), { type: 'json' });
      if (!t) return err('Token tidak ditemukan.', 404);
      if (b.action === 'extend') {
        const d = clamp(b.days, 1, 3650);
        if (t.firstUsedAt) t.expiresAt = new Date(Math.max(now, Date.parse(t.expiresAt)) + d * 86400000).toISOString(); else t.durationDays += d;
      } else if (b.action === 'revoke') {
        t.revoked = true;
        const ss = await readAll(sessions());
        await Promise.all(ss.filter(s => s.token === t.id && !s.ended).map(s => { s.ended = true; s.endedBy = 'admin'; delete s._key; return sessions().setJSON(s.id, s); }));
      } else t.revoked = false;
      await tokens().setJSON(t.id, t);
      return json({ ok: true });
    }

    case 'delete': {
      const id = String(b.id || '');
      const ss = await readAll(sessions());
      await Promise.all(ss.filter(s => s.token === id).map(s => sessions().delete(s.id)));
      await tokens().delete(id);
      return json({ ok: true });
    }

    case 'endSession': case 'endAll': {
      const ss = await readAll(sessions());
      const target = ss.filter(s => !s.ended && (b.action === 'endAll' || s.id === b.id));
      await Promise.all(target.map(s => { s.ended = true; s.endedBy = 'admin'; delete s._key; return sessions().setJSON(s.id, s); }));
      return json({ ok: true, ended: target.length });
    }

    case 'purgeLogs': {
      const keep = clamp(b.keepDays, 0, 3650), cutoff = new Date(now - keep * 86400000).toISOString().slice(0, 10);
      const { blobs } = await logs().list();
      const old = blobs.filter(x => x.key.slice(0, 10) < cutoff);
      for (let i = 0; i < old.length; i += 40) await Promise.all(old.slice(i, i + 40).map(x => logs().delete(x.key)));
      return json({ deleted: old.length });
    }

    default: return err('Aksi tidak dikenal.');
  }
};
export const config = { path: '/api/admin' };
