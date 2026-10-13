const crypto = require("crypto");
const { issue, valid, cookie } = require("./_session");

// Best-effort brute-force limit: 8 wrong tries per IP per 10 minutes.
const tries = new Map();
const WINDOW = 10 * 60 * 1000;
const MAX_TRIES = 8;

function tooMany(ip) {
  const now = Date.now();
  const list = (tries.get(ip) || []).filter(t => now - t < WINDOW);
  tries.set(ip, list);
  return list.length >= MAX_TRIES;
}

const digest = s => crypto.createHash("sha256").update(String(s)).digest();

module.exports = async (req, res) => {
  res.setHeader("Cache-Control", "no-store");

  if (req.method === "GET") {
    const ok = valid(req);
    return res.status(ok ? 200 : 401).json({ ok });
  }

  if (req.method === "DELETE") {
    res.setHeader("Set-Cookie", cookie("", 0));
    return res.status(200).json({ ok: true });
  }

  if (req.method !== "POST") return res.status(405).json({ error: "Method not allowed" });

  if (!process.env.ACCESS_PASSWORD || !process.env.SESSION_SECRET) {
    return res.status(500).json({ error: "not_configured" });
  }

  const ip = String(req.headers["x-forwarded-for"] || "unknown").split(",")[0].trim();
  if (tooMany(ip)) return res.status(429).json({ error: "too_many" });

  const given = req.body && typeof req.body.password === "string" ? req.body.password : "";
  const ok = crypto.timingSafeEqual(digest(given), digest(process.env.ACCESS_PASSWORD));

  if (!ok) {
    tries.get(ip).push(Date.now());
    await new Promise(r => setTimeout(r, 600));
    return res.status(401).json({ error: "wrong_password" });
  }

  tries.delete(ip);
  res.setHeader("Set-Cookie", cookie(issue()));
  return res.status(200).json({ ok: true });
};
