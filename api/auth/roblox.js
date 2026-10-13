const { r, clientIp, sessCookie } = require('../_lib');

module.exports = async (req, res) => {
  if (req.method !== 'POST') return res.status(405).end();

  const ip = clientIp(req) || 'x';
  const n = await r('INCR', 'rb:' + ip);
  if (n === 1) await r('EXPIRE', 'rb:' + ip, 600);
  if (n > 20) return res.status(429).json({ ok: false, error: 'Too many tries, wait a few minutes' });

  const name = String((req.body || {}).username || '').trim();
  if (!/^[A-Za-z0-9_]{3,20}$/.test(name))
    return res.status(400).json({ ok: false, error: 'Invalid username' });

  const u = await fetch('https://users.roblox.com/v1/usernames/users', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ usernames: [name], excludeBannedUsers: true }),
  }).then(x => x.json()).catch(() => null);

  const found = u && u.data && u.data[0];
  if (!found) return res.status(404).json({ ok: false, error: 'Roblox user not found' });

  let avatar = '';
  try {
    const t = await fetch(
      `https://thumbnails.roblox.com/v1/users/avatar-headshot?userIds=${found.id}&size=150x150&format=Png`
    ).then(x => x.json());
    const url = t && t.data && t.data[0] && t.data[0].imageUrl;
    if (/^https:\/\/[\w.-]+\.rbxcdn\.com\//.test(url || '')) avatar = url;
  } catch {}

  res.setHeader('Set-Cookie', sessCookie({ id: String(found.id), name: found.name, avatar }));
  res.json({ ok: true });
};
