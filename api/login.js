const crypto = require('crypto');
const { r, safeEq, clientIp } = require('./_lib');

module.exports = async (req, res) => {
  if (req.method !== 'POST') return res.status(405).end();
  const ip = clientIp(req) || 'x';
  const n = await r('INCR', 'rl:' + ip);
  if (n === 1) await r('EXPIRE', 'rl:' + ip, 900);
  if (n > 10) return res.status(429).json({ error: 'Too many attempts. Try later.' });

  const p = String((req.body || {}).password || '');
  let role = null;
  if (process.env.OWNER_PASSWORD && safeEq(p, process.env.OWNER_PASSWORD)) role = 'owner';
  else if (process.env.MOD_PASSWORD && safeEq(p, process.env.MOD_PASSWORD)) role = 'mod';
  if (!role) return res.status(401).json({ error: 'Wrong password' });

  const token = crypto.randomBytes(32).toString('hex');
  await r('SET', 'sess:' + token, role, 'EX', 43200);
  res.json({ token, role });
};
