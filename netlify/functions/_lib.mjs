import { getStore } from '@netlify/blobs';
import crypto from 'node:crypto';

export const db = () => getStore({ name: 'aiguru', consistency: 'strong' });
export const SECRET = () => process.env.SESSION_SECRET || process.env.ADMIN_PASSWORD || process.env.ADMIN_PASS || process.env.ADMIN_PW || '';
export const ADMIN_PW = () => process.env.ADMIN_PASSWORD || process.env.ADMIN_PASS || process.env.ADMIN_PW || '';
export const COOKIE = 'aiguru_s';
export const ONLINE_MS = 3 * 60 * 1000;

export const json = (obj, status = 200, headers = {}) =>
  new Response(JSON.stringify(obj), { status, headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store', ...headers } });
export const sha256 = (s) => crypto.createHash('sha256').update(String(s)).digest('hex');
const ALPHA = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
const rnd = (n) => Array.from(crypto.randomBytes(n), (b) => ALPHA[b % ALPHA.length]).join('');
export const newToken = () => `GURU-${rnd(4)}-${rnd(4)}-${rnd(4)}-${rnd(4)}`;
export const newId = () => crypto.randomBytes(8).toString('hex');
export const normToken = (t) => String(t || '').trim().toUpperCase().replace(/\s+/g, '');
export const ipOf = (req, ctx) => req.headers.get('x-nf-client-connection-ip') || (ctx && ctx.ip) || (req.headers.get('x-forwarded-for') || '').split(',')[0].trim() || '';

export function tokenStatus(t) {
  if (t.revoked) return 'dicabut';
  if (!t.firstUsedAt) return 'belum dipakai';
  if (t.expiresAt && Date.now() > Date.parse(t.expiresAt)) return 'kedaluwarsa';
  return 'aktif';
}
export const usable = (t) => { const s = tokenStatus(t); return s === 'aktif' || s === 'belum dipakai'; };

/* cookie sesi bertanda tangan: <sid>.<hmac> */
const sign = (sid) => crypto.createHmac('sha256', SECRET()).update(sid).digest('hex').slice(0, 32);
export const cookieFor = (sid, maxAgeSec) => `${COOKIE}=${sid}.${sign(sid)}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${maxAgeSec}`;
export const clearCookie = () => `${COOKIE}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`;
function sidFrom(req) {
  const m = (req.headers.get('cookie') || '').split(/;\s*/).find((c) => c.startsWith(COOKIE + '='));
  if (!m) return null;
  const [sid, sig] = m.slice(COOKIE.length + 1).split('.');
  if (!sid || !sig || !SECRET()) return null;
  const ok = sig.length === 32 && crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(sign(sid)));
  return ok ? sid : null;
}

/* sesi aktif + token yang masih berlaku; memperbarui "terakhir aktif" */
export async function authSession(req, ctx, touch = true) {
  const sid = sidFrom(req); if (!sid) return null;
  const d = db();
  const s = await d.get(`s/${sid}`, { type: 'json' }); if (!s || s.ended) return null;
  const t = await d.get(`t/${s.tokenId}`, { type: 'json' }); if (!t || !usable(t) || tokenStatus(t) !== 'aktif') return null;
  if (touch && Date.now() - Date.parse(s.lastSeen) > 30000) { s.lastSeen = new Date().toISOString(); await d.setJSON(`s/${sid}`, s); }
  return { s, t };
}

export async function addLog(entry) {
  const d = db(), now = new Date();
  const key = `l/${now.toISOString().slice(0, 10)}/${String(now.getTime())}-${rnd(4)}`;
  await d.setJSON(key, { ts: now.toISOString(), ...entry });
}
