const { r, tfetch, getCookie, sessCookie } = require('../_lib');

const expired = res => res.status(400).json({ ok: false, expired: true, error: 'Session expired, start again' });

module.exports = async (req, res) => {
  if (req.method !== 'POST') return res.status(405).end();

  const tok = getCookie(req, 'pend');
  if (!tok || !/^[a-f0-9]{48}$/.test(tok)) return expired(res);
  const raw = await r('GET', 'pend:' + tok);
  if (!raw) return expired(res);
  const p = JSON.parse(raw);

  const tries = await r('INCR', 'vf:' + tok);
  if (tries === 1) await r('EXPIRE', 'vf:' + tok, 900);
  if (tries > 20) return res.status(429).json({ ok: false, error: 'Too many tries, start again in a few minutes' });

  try {
    const [d, t] = await Promise.all([
      tfetch(`https://users.roblox.com/v1/users/${p.id}`, {}, 6000).then(x => (x.ok ? x.json() : null)),
      tfetch(`https://thumbnails.roblox.com/v1/users/avatar-headshot?userIds=${p.id}&size=150x150&format=Png`, {}, 4000)
        .then(x => x.json()).catch(() => null),
    ]);
    if (!d) return res.status(502).json({ ok: false, error: 'Roblox is busy, try again' });

    const norm = s => String(s || '').toLowerCase().replace(/\s+/g, ' ').trim();
    if (!norm(d.description).includes(p.phrase))
      return res.json({ ok: false, error: "Couldn't find the words in your bio. Save your bio, then try again." });

    const url = t && t.data && t.data[0] && t.data[0].imageUrl;
    const avatar = /^https:\/\/[\w.-]+\.rbxcdn\.com\//.test(url || '') ? url : '';

    await r('DEL', 'pend:' + tok);
    res.setHeader('Set-Cookie', [
      sessCookie({ id: p.id, name: p.name, avatar }),
      'pend=; Max-Age=0; Path=/; HttpOnly; Secure; SameSite=Lax',
    ]);
    res.json({ ok: true, name: p.name });
  } catch {
    res.status(504).json({ ok: false, error: 'Roblox took too long, try again' });
  }
};
