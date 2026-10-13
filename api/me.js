const { readSess, clientIp, validate } = require('./_lib');

module.exports = async (req, res) => {
  const s = readSess(req);
  if (!s) return res.json({ user: null });
  const user = { id: s.id, name: s.name, avatar: s.avatar };
  if (!s.key) return res.json({ user, unlocked: false });
  const o = await validate('heartbeat', s.key, clientIp(req), user);
  res.json({ user, unlocked: !!o.ok, error: o.error, expires: o.expires });
};
