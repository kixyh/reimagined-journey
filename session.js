const crypto = require("crypto");

const COOKIE = "vn_session";
const MAX_AGE = 30 * 24 * 60 * 60; // 30 days, in seconds

// The signature covers the password too, so changing ACCESS_PASSWORD
// logs everyone out and they have to get the new one from Discord.
function sign(value) {
  return crypto
    .createHmac("sha256", process.env.SESSION_SECRET || "")
    .update(value + "|" + (process.env.ACCESS_PASSWORD || ""))
    .digest("hex");
}

function issue() {
  const expires = String(Date.now() + MAX_AGE * 1000);
  return `${expires}.${sign(expires)}`;
}

function valid(req) {
  if (!process.env.SESSION_SECRET || !process.env.ACCESS_PASSWORD) return false;
  const m = (req.headers.cookie || "").match(new RegExp(`(?:^|;\\s*)${COOKIE}=([^;]+)`));
  if (!m) return false;
  const [expires, sig] = m[1].split(".");
  if (!expires || !sig) return false;
  const a = Buffer.from(sig);
  const b = Buffer.from(sign(expires));
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return false;
  return Number(expires) > Date.now();
}

function cookie(value, maxAge = MAX_AGE) {
  return `${COOKIE}=${value}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=${maxAge}`;
}

module.exports = { issue, valid, cookie };
