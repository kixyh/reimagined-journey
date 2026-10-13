const { r, readSess, getCookie, clientIp, validate } = require('./_lib');

module.exports = async (req, res) => {
  const s = readSess(req);

  if (!s) {
    // pending bio verification survives refresh
    const tok = getCookie(req, 'pend');
    if (tok && /^[a-f0-9]{48}$/.test(tok)) {
      const raw = await r('GET', 'pend:' + tok);
      if (raw) {
        const p = JSON.parse(raw);
        return res.json({ user: null, pending: { name: p.name, phrase: p.phrase } });
      }
    }
    return res.json({ user: null });
  }

  const user = { id: s.id, name: s.name, avatar: s.avatar };
  if (!s.key) return res.json({ user, unlocked: false });
  const o = await validate('heartbeat', s.key, clientIp(req), user);
  res.json({ user, unlocked: !!o.ok, error: o.error, expires: o.expires });
};
