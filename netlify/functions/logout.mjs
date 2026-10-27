import { sessions, getCookie, verifySid, COOKIE, clearCookie, clientIp, addLog } from '../lib/core.mjs';

export default async (req, ctx) => {
  const sid = verifySid(getCookie(req, COOKIE));
  if (sid) {
    const s = await sessions().get(sid, { type: 'json' });
    if (s && !s.ended) {
      s.ended = true; s.endedBy = 'user'; await sessions().setJSON(sid, s);
      await addLog({ type: 'logout', label: s.label, detail: '', ip: clientIp(req, ctx) });
    }
  }
  return new Response(null, { status: 302, headers: { location: '/', 'set-cookie': clearCookie(), 'cache-control': 'no-store' } });
};
export const config = { path: '/api/logout' };
