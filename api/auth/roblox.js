const crypto = require('crypto');
const { r, tfetch, clientIp, genPhrase } = require('../_lib');

module.exports = async (req, res) => {
  if (req.method !== 'POST') return res.status(405).end();

  const name = String((req.body || {}).username || '').trim();
  if (!/^[A-Za-z0-9_]{3,20}$/.test(name))
    return res.status(400).json({ ok: false, error: 'Invalid username' });

  const ip = clientIp(req) || 'x';
  try {
    // rate limit + Roblox lookup run at the same time (faster)
    const [n, rb] = await Promise.all([
      r('INCR', 'rb:' + ip),
      tfetch('https://users.roblox.com/v1/usernames/users', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ usernames: [name], excludeBannedUsers: true }),
      }, 6000),
    ]);
    if (n === 1) await r('EXPIRE', 'rb:' + ip, 600);
    if (n > 20) return res.status(429).json({ ok: false, error: 'Too many tries, wait a few minutes' });
    if (rb.status === 429) return res.status(429).json({ ok: false, error: 'Roblox is busy, try again in a moment' });

    const j = await rb.json();
    const u = j && j.data && j.data[0];
    if (!u) return res.status(404).json({ ok: false, error: 'Roblox user not found' });

    const token = crypto.randomBytes(24).toString('hex'); // 48 hex chars
    const phrase = genPhrase();
    await r('SET', 'pend:' + token, JSON.stringify({ id: String(u.id), name: u.name, phrase }), 'EX', 900);

    res.setHeader('Set-Cookie', `pend=${token}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=900`);
    res.json({ ok: true, name: u.name, phrase });
  } catch {
    res.status(504).json({ ok: false, error: 'Roblox took too long, try again' });
  }
};
