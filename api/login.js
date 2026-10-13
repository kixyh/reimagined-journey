const crypto = require('crypto');
const { r, sha, safeEq, clientIp, readSess } = require('./_lib');

async function newToken(role) {
  const t = crypto.randomBytes(32).toString('hex');
  await r('SET', 'sess:' + t, role, 'EX', 43200);
  return t;
}

module.exports = async (req, res) => {
  const ip = clientIp(req) || 'x';
  const s = readSess(req); // verified Roblox account (or null)

  // AUTO LOGIN: verified account + same remembered IP
  if (req.method === 'GET') {
    if (!s) return res.json({ ok: false });
    const raw = await r('GET', 'trusted:' + s.id);
    if (!raw) return res.json({ ok: false });
    const t = JSON.parse(raw);
    if (t.ipHash !== sha(ip)) return res.json({ ok: false });
    return res.json({ ok: true, auto: true, token: await newToken(t.role), role: t.role, name: s.name });
  }

  if (req.method !== 'POST') return res.status(405).end();
  const body = req.body || {};

  // LOGOUT: also forgets the remembered IP
  if (body.action === 'logout') {
    const tk = (req.headers.authorization || '').replace('Bearer ', '');
    if (tk) await r('DEL', 'sess:' + tk);
    if (s) await r('DEL', 'trusted:' + s.id);
    return res.json({ ok: true });
  }

  // PASSWORD LOGIN
  const n = await r('INCR', 'rl:' + ip);
  if (n === 1) await r('EXPIRE', 'rl:' + ip, 900);
  if (n > 10) return res.status(429).json({ error: 'Too many attempts. Try later.' });

  const p = String(body.password || '');
  let role = null;
  if (process.env.OWNER_PASSWORD && safeEq(p, process.env.OWNER_PASSWORD)) role = 'owner';
  else if (process.env.MOD_PASSWORD && safeEq(p, process.env.MOD_PASSWORD)) role = 'mod';
  if (!role) return res.status(401).json({ error: 'Wrong password' });

  // remember this verified account + IP for auto-login (30 days)
  if (s) {
    await r('SET', 'trusted:' + s.id,
      JSON.stringify({ role, ipHash: sha(ip), name: s.name }), 'EX', 2592000);
  }

  res.json({ token: await newToken(role), role, name: s ? s.name : null, remembered: !!s });
};
