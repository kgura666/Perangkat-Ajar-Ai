import crypto from 'node:crypto';
import { db, json, sha256, newToken, newId, tokenStatus, ADMIN_PW, ONLINE_MS } from './_lib.mjs';

const eq = (a, b) => { const x = Buffer.from(sha256(a)), y = Buffer.from(sha256(b)); return crypto.timingSafeEqual(x, y); };
async function all(d, prefix, cap = 1000) {
  const { blobs } = await d.list({ prefix }); const keys = blobs.map((b) => b.key).slice(-cap);
  const out = []; for (let i = 0; i < keys.length; i += 25) out.push(...await Promise.all(keys.slice(i, i + 25).map((k) => d.get(k, { type: 'json' }))));
  return out.filter(Boolean);
}

export default async (req) => {
  if (req.method !== 'POST') return json({ error: 'Metode tidak diizinkan.' }, 405);
  const pw = ADMIN_PW(); if (!pw) return json({ error: 'ADMIN_PASSWORD belum diatur di Netlify.' }, 500);
  if (!eq(req.headers.get('x-admin-password') || '', pw)) return json({ error: 'Password admin salah.' }, 401);
  let b = {}; try { b = await req.json(); } catch { /* kosong */ }
  const d = db(), now = Date.now();
  const toks = async () => (await all(d, 't/', 2000));

  switch (b.action) {
    case 'ping': return json({ ok: true });

    case 'list': {
      const [T, S] = await Promise.all([toks(), all(d, 's/', 2000)]);
      const rows = T.map((t) => {
        const ss = S.filter((s) => s.tokenId === t.id);
        const last = ss.reduce((m, s) => (s.lastSeen > m ? s.lastSeen : m), '');
        return { id: t.id, label: t.label, token: t.token, hint: t.token.slice(-4), status: tokenStatus(t), revoked: !!t.revoked, durationDays: t.durationDays, createdAt: t.createdAt, firstUsedAt: t.firstUsedAt || null, expiresAt: t.expiresAt || null,
          sessions: ss.length, online: ss.some((s) => !s.ended && now - Date.parse(s.lastSeen) < ONLINE_MS), lastSeen: last || null };
      }).sort((x, y) => (y.createdAt || '').localeCompare(x.createdAt || ''));
      return json({ rows });
    }

    case 'create': {
      const count = Math.max(1, Math.min(50, Math.round(+b.count || 1))), dur = Math.max(1, Math.min(365, Math.round(+b.durationDays || 7)));
      const label = String(b.label || '').slice(0, 80), out = [];
      for (let i = 0; i < count; i++) {
        const token = newToken(), id = newId();
        await d.setJSON(`t/${id}`, { id, label, token, durationDays: dur, createdAt: new Date().toISOString(), firstUsedAt: null, expiresAt: null, revoked: false });
        await d.set(`h/${sha256(token)}`, id); out.push(token);
      }
      return json({ tokens: out });
    }

    case 'revoke': case 'unrevoke': {
      const t = await d.get(`t/${b.id}`, { type: 'json' }); if (!t) return json({ error: 'Token tidak ditemukan.' }, 404);
      t.revoked = b.action === 'revoke'; await d.setJSON(`t/${t.id}`, t);
      if (t.revoked) for (const s of await all(d, 's/', 2000)) if (s.tokenId === t.id && !s.ended) { s.ended = true; s.endedBy = 'admin'; s.endedAt = new Date().toISOString(); await d.setJSON(`s/${s.id}`, s); }
      return json({ ok: true });
    }

    case 'extend': { /* perpanjang masa berlaku (hari) */
      const t = await d.get(`t/${b.id}`, { type: 'json' }); if (!t) return json({ error: 'Token tidak ditemukan.' }, 404);
      const add = Math.max(1, Math.min(365, Math.round(+b.days || 7)));
      if (t.firstUsedAt) t.expiresAt = new Date(Math.max(now, Date.parse(t.expiresAt)) + add * 86400000).toISOString(); else t.durationDays += add;
      await d.setJSON(`t/${t.id}`, t); return json({ ok: true });
    }

    case 'delete': {
      const t = await d.get(`t/${b.id}`, { type: 'json' });
      if (t) { await d.delete(`h/${sha256(t.token)}`); await d.delete(`t/${t.id}`); }
      for (const s of await all(d, 's/', 2000)) if (s.tokenId === b.id) await d.delete(`s/${s.id}`);
      return json({ ok: true });
    }

    case 'sessions': {
      const [T, S] = await Promise.all([toks(), all(d, 's/', 2000)]); const byId = Object.fromEntries(T.map((t) => [t.id, t]));
      const rows = S.map((s) => { const t = byId[s.tokenId];
        return { id: s.id, tokenId: s.tokenId, label: t ? t.label : '(token dihapus)', token: t ? t.token : '', createdAt: s.createdAt, lastSeen: s.lastSeen, ip: s.ip, ua: s.ua, ended: !!s.ended, endedBy: s.endedBy || '', online: !s.ended && now - Date.parse(s.lastSeen) < ONLINE_MS, tokenStatus: t ? tokenStatus(t) : 'dihapus' }; })
        .sort((x, y) => y.lastSeen.localeCompare(x.lastSeen)).slice(0, 500);
      return json({ rows });
    }

    case 'endSession': { const s = await d.get(`s/${b.id}`, { type: 'json' }); if (s) { s.ended = true; s.endedBy = 'admin'; s.endedAt = new Date().toISOString(); await d.setJSON(`s/${s.id}`, s); } return json({ ok: true }); }
    case 'endAll': { for (const s of await all(d, 's/', 2000)) if (!s.ended) { s.ended = true; s.endedBy = 'admin'; s.endedAt = new Date().toISOString(); await d.setJSON(`s/${s.id}`, s); } return json({ ok: true }); }

    case 'logs': {
      const days = Math.max(1, Math.min(60, Math.round(+b.days || 3))), keys = [];
      for (let i = 0; i < days; i++) { const day = new Date(now - i * 86400000).toISOString().slice(0, 10); const { blobs } = await d.list({ prefix: `l/${day}/` }); keys.push(...blobs.map((x) => x.key).reverse()); }
      const take = keys.slice(0, Math.max(50, Math.min(1000, Math.round(+b.limit || 400)))); const rows = [];
      for (let i = 0; i < take.length; i += 25) rows.push(...await Promise.all(take.slice(i, i + 25).map((k) => d.get(k, { type: 'json' }))));
      return json({ rows: rows.filter(Boolean), total: keys.length });
    }

    case 'purgeLogs': {
      const keep = Math.max(0, Math.min(365, Math.round(+b.keepDays || 30))), cutoff = new Date(now - keep * 86400000).toISOString().slice(0, 10); let n = 0;
      const { blobs } = await d.list({ prefix: 'l/' });
      for (const x of blobs) if (x.key.split('/')[1] < cutoff) { await d.delete(x.key); n++; }
      return json({ deleted: n });
    }

    default: return json({ error: 'Aksi tidak dikenal.' }, 400);
  }
};
export const config = { path: '/api/admin' };
