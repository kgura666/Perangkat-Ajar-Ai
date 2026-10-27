import { getStore } from '@netlify/blobs';
import { createHash, createHmac, randomBytes, randomInt, timingSafeEqual } from 'node:crypto';

/* penyimpanan (Netlify Blobs, otomatis aktif di Netlify; consistency strong agar baca-setelah-tulis konsisten) */
const store = name => getStore({ name, consistency: 'strong' });
export const tokens = () => store('tokens');
export const sessions = () => store('sessions');
export const logs = () => store('logs');
const limits = () => store('limits');

export const COOKIE = 'aiguru_sid';
export const ONLINE_MS = 3 * 60 * 1000;
export const SESSION_MAX_DAYS = 30;   // batas lama cookie; masa berlaku sebenarnya mengikuti masa berlaku token

export const json = (data, status = 200, headers = {}) =>
  new Response(JSON.stringify(data), { status, headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store', ...headers } });

export const clientIp = (req, ctx) =>
  (ctx && ctx.ip) || req.headers.get('x-nf-client-connection-ip') || (req.headers.get('x-forwarded-for') || '').split(',')[0].trim() || '';

export const getCookie = (req, name) => {
  const m = (req.headers.get('cookie') || '').split(/;\s*/).find(c => c.startsWith(name + '='));
  return m ? decodeURIComponent(m.slice(name.length + 1)) : '';
};
export const setCookie = (sid, maxAge) => `${COOKIE}=${signSid(sid)}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${maxAge}`;
export const clearCookie = () => `${COOKIE}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`;

/* token */
export const normToken = t => String(t || '').trim().toUpperCase().replace(/\s+/g, '');
export const validTokenShape = t => /^[A-Z0-9-]{8,40}$/.test(t);
const ALPHA = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
export const newToken = () => {
  const grp = () => Array.from({ length: 4 }, () => ALPHA[randomInt(ALPHA.length)]).join('');
  return `GURU-${grp()}-${grp()}-${grp()}-${grp()}`;
};
export function tokenStatus(t, now = Date.now()) {
  if (t.revoked) return 'dicabut';
  if (!t.firstUsedAt) return 'belum dipakai';
  if (now > Date.parse(t.expiresAt)) return 'kedaluwarsa';
  return 'aktif';
}
export const newSid = () => randomBytes(24).toString('hex');

/* cookie sesi ditandatangani HMAC-SHA256 memakai SESSION_SECRET (environment variable Netlify) */
export const secretOk = () => (process.env.SESSION_SECRET || '').length >= 32;
const sign = sid => createHmac('sha256', process.env.SESSION_SECRET || '').update(sid).digest('base64url');
export const signSid = sid => `${sid}.${sign(sid)}`;
export function verifySid(value) {
  const [sid, sig] = String(value || '').split('.');
  if (!secretOk() || !/^[a-f0-9]{48}$/.test(sid || '') || !sig) return null;
  const a = Buffer.from(sig), b = Buffer.from(sign(sid));
  return a.length === b.length && timingSafeEqual(a, b) ? sid : null;
}

/* sesi: kembalikan {sid, sess, tok} bila valid, selain itu null */
export async function guard(req) {
  const sid = verifySid(getCookie(req, COOKIE));
  if (!sid) return null;
  const sess = await sessions().get(sid, { type: 'json' });
  if (!sess || sess.ended) return null;
  const tok = await tokens().get(sess.token, { type: 'json' });
  if (!tok || tokenStatus(tok) !== 'aktif') return null;
  const now = Date.now();
  if (now - Date.parse(sess.lastSeen) > 60000) { sess.lastSeen = new Date(now).toISOString(); await sessions().setJSON(sid, sess); }
  return { sid, sess, tok };
}

/* log */
export async function addLog({ type, label = '', detail = '', ip = '' }) {
  const ts = new Date().toISOString();
  const key = `${ts.slice(0, 10)}/${ts.replace(/[:.]/g, '')}-${randomBytes(3).toString('hex')}`;
  await logs().setJSON(key, { ts, type, label, detail: String(detail || '').slice(0, 300), ip });
}

/* pembatas percobaan salah (10 kali / 10 menit per IP) */
const rk = k => createHash('sha256').update(k).digest('hex').slice(0, 40);
export async function blocked(k, max = 10, win = 600000) {
  const r = await limits().get(rk(k), { type: 'json' });
  return !!r && Date.now() - r.first < win && r.count >= max;
}
export async function fail(k, win = 600000) {
  const key = rk(k), r = await limits().get(key, { type: 'json' }), now = Date.now();
  await limits().setJSON(key, r && now - r.first < win ? { first: r.first, count: r.count + 1 } : { first: now, count: 1 });
}
export const clearFails = k => limits().delete(rk(k));

/* password admin dari environment variable */
export function adminCheck(req) {
  const pw = process.env.ADMIN_PASSWORD;
  if (!pw) return 'noenv';
  const h = s => createHash('sha256').update(String(s)).digest();
  return timingSafeEqual(h(req.headers.get('x-admin-password') || ''), h(pw)) ? 'ok' : 'salah';
}

/* ambil semua nilai di sebuah store (paralel per 40) */
export async function readAll(st, prefix) {
  const { blobs } = await st.list(prefix ? { prefix } : {});
  const out = [];
  for (let i = 0; i < blobs.length; i += 40) {
    const vals = await Promise.all(blobs.slice(i, i + 40).map(b => st.get(b.key, { type: 'json' }).then(v => (v ? { _key: b.key, ...v } : null))));
    out.push(...vals.filter(Boolean));
  }
  return out;
}
