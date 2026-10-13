module.exports = async (req, res) => {
  const p = req.query.p === 'login' ? 'login' : 'panel';
  const ip = (req.headers['x-real-ip'] || (req.headers['x-forwarded-for'] || '').split(',')[0] || '').trim();
  const r = await fetch(process.env.OWNER_API + '/api/' + p, {
    method: req.method,
    headers: {
      'Content-Type': 'application/json',
      Authorization: req.headers.authorization || '',
      'x-site-secret': process.env.SITE_SECRET,
      'x-client-ip': ip,
    },
    body: req.method === 'GET' ? undefined : JSON.stringify(req.body || {}),
  });
  res.status(r.status).json(await r.json());
};
