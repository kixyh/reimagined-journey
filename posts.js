const { valid } = require("./_session");

// Runs on the server, so the Rule34 key never reaches the browser.
module.exports = async (req, res) => {
  res.setHeader("Cache-Control", "no-store");
  if (!valid(req)) return res.status(401).json({ error: "locked" });

  const key = process.env.R34_API_KEY;
  const uid = process.env.R34_USER_ID;
  if (!key || !uid) return res.status(500).json({ error: "not_configured" });

  const tags = String(req.query.tags || "").slice(0, 500);
  const pid = Math.max(0, parseInt(req.query.pid, 10) || 0);

  const params = new URLSearchParams({
    page: "dapi", s: "post", q: "index", json: "1",
    limit: "40", pid: String(pid), tags,
    api_key: key, user_id: uid
  });

  try {
    const upstream = await fetch("https://api.rule34.xxx/index.php?" + params.toString());
    const text = await upstream.text();
    res.setHeader("Content-Type", "text/plain; charset=utf-8");
    return res.status(upstream.ok ? 200 : 502).send(text);
  } catch (err) {
    return res.status(502).json({ error: "upstream_unreachable" });
  }
};
