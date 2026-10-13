const { readSess, clientIp, validate } = require('./_lib');

module.exports = async (req, res) => {
  const s = readSess(req);
  if (!s || !s.key) return res.status(401).json({ error: 'locked' });
  const o = await validate('heartbeat', s.key, clientIp(req), { id: s.id, name: s.name, avatar: s.avatar });
  if (!o.ok) return res.status(403).json(o);
  res.json({ html: '<h2>Welcome 🎉</h2><p>Put your protected content here.</p>' });
};
