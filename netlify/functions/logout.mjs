import { db, json, authSession, clearCookie, addLog, ipOf } from './_lib.mjs';
export default async (req, ctx) => {
  const a = await authSession(req, ctx, false);
  if (a) { a.s.ended = true; a.s.endedBy = 'user'; a.s.endedAt = new Date().toISOString(); await db().setJSON(`s/${a.s.id}`, a.s); await addLog({ type: 'logout', label: a.t.label, tokenId: a.t.id, sessionId: a.s.id, detail: 'Keluar', ip: ipOf(req, ctx) }).catch(() => {}); }
  return new Response(null, { status: 302, headers: { location: '/', 'set-cookie': clearCookie() } });
};
export const config = { path: '/api/logout' };
