const { r, genKey, adminRole } = require('./_lib');
const TWO_H = 2 * 3600 * 1000;

module.exports = async (req, res) => {
  const role = await adminRole(req);
  if (!role) return res.status(401).json({ error: 'unauthorized' });

  if (req.method === 'POST') {
    const { action, key, note } = req.body || {};
    if (action === 'create') {
      const k = genKey(), now = Date.now();
      const obj = { key: k, createdAt: now, expires: now + TWO_H, createdBy: role,
                    note: String(note || '').slice(0, 80), revoked: false };
      await r('SET', 'key:' + k, JSON.stringify(obj), 'EX', 7500);
      await r('SADD', 'keys', k);
      return res.json({ ok: true, key: k });
    }
    if (action === 'revoke') {
      const raw = await r('GET', 'key:' + key);
      if (raw) {
        const o = JSON.parse(raw); o.revoked = true;
        await r('SET', 'key:' + key, JSON.stringify(o), 'KEEPTTL');
      }
      return res.json({ ok: true });
    }
    return res.status(400).json({ error: 'bad action' });
  }

  const now = Date.now();
  const ids = await r('SMEMBERS', 'keys');
  const keys = [];
  if (ids.length) {
    const vals = await r('MGET', ...ids.map(k => 'key:' + k));
    for (let i = 0; i < ids.length; i++) {
      if (!vals[i]) { await r('SREM', 'keys', ids[i]); continue; }
      const k = JSON.parse(vals[i]);
      if (k.revoked || k.expires <= now) continue;
      keys.push({
        key: k.key, createdAt: k.createdAt, expires: k.expires, note: k.note,
        status: k.ipHash ? 'locked' : 'waiting', user: k.user || null,
        ip: k.ipMask ? (role === 'owner' ? k.ipMask : 'hidden') : null, // mods never see it
      });
    }
  }

  const flat = await r('HGETALL', 'presence');
  const online = [];
  for (let i = 0; i < flat.length; i += 2) {
    const p = JSON.parse(flat[i + 1]);
    if (p.seen > now - 90000) online.push({ id: flat[i], name: p.name, avatar: p.avatar });
    else await r('HDEL', 'presence', flat[i]);
  }
  res.json({ role, keys, online });
};
