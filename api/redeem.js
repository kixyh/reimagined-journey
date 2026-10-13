const { readSess, sessCookie, clientIp, validate } = require('./_lib');

module.exports = async (req, res) => {
  const s = readSess(req);
  if (!s) return res.status(401).json({ ok: false, error: 'Enter your Roblox username first' });
  const key = String((req.body || {}).key || '').trim().toUpperCase();
  const user = { id: s.id, name: s.name, avatar: s.avatar };
  const o = await validate('redeem', key, clientIp(req), user);
  if (!o.ok) return res.status(403).json(o);
  res.setHeader('Set-Cookie', sessCookie({ ...user, key })); // survives refresh
  res.json(o);
};
