require('./_config');
const crypto = require('crypto');

async function r(...cmd) {
  const res = await fetch(process.env.UPSTASH_REDIS_REST_URL, {
    method: 'POST',
    headers: { Authorization: `Bearer ${process.env.UPSTASH_REDIS_REST_TOKEN}` },
    body: JSON.stringify(cmd),
  });
  const j = await res.json();
  if (j.error) throw new Error(j.error);
  return j.result;
}

const tfetch = (url, opt = {}, ms = 6000) => fetch(url, { ...opt, signal: AbortSignal.timeout(ms) });

const sha = s => crypto.createHash('sha256').update(s + process.env.IP_SALT).digest('hex');
const mask = ip => ip.slice(0, 5) + '•'.repeat(6);

function genKey() {
  const c = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  const part = () => Array.from({ length: 4 }, () => c[crypto.randomInt(c.length)]).join('');
  return [part(), part(), part(), part()].join('-');
}

const WORDS = ['apple','river','cloud','stone','maple','tiger','piano','ocean','lemon','cactus','falcon','garden','candle','rocket','pebble','meadow','harbor','copper','velvet','thunder','marble','sunset','island','whisper','canyon','feather','lantern','orchard','pepper','saddle','timber','violet','walnut','yellow','zebra','anchor','bridge','castle','dragon','ember','forest','glacier','honey','igloo','jungle','kettle','ladder','magnet','nectar','olive','parrot','quartz','raven','silver','tunnel','umbrella','valley','willow','yogurt','zephyr','acorn','badger','coral','dolphin','eagle','fossil','ginger','hammer','iris','jasmine','koala','lotus','mango','nutmeg','orchid','panda','quill','radish','sparrow','tulip','vanilla','walrus','yarrow','bamboo','cobalt','dune','fern','grove','harvest','ivory','juniper','kiwi','lagoon','mist','nimbus','prairie','reef','sage','thistle'];
const genPhrase = () => Array.from({ length: 6 }, () => WORDS[crypto.randomInt(WORDS.length)]).join(' ');

function safeEq(a, b) {
  const A = Buffer.from(a), B = Buffer.from(b);
  return A.length === B.length && crypto.timingSafeEqual(A, B);
}

const clientIp = req =>
  (req.headers['x-real-ip'] || (req.headers['x-forwarded-for'] || '').split(',')[0] || '').trim();

const getCookie = (req, name) => {
  const m = (req.headers.cookie || '').match(new RegExp('(?:^|; )' + name + '=([^;]*)'));
  return m ? m[1] : null;
};

// ---- admin sessions ----
async function adminRole(req) {
  const t = (req.headers.authorization || '').replace('Bearer ', '');
  return t ? await r('GET', 'sess:' + t) : null;
}

// ---- verified-user cookie sessions ----
const sig = v => crypto.createHmac('sha256', process.env.SESSION_SECRET).update(v).digest('base64url');

function readSess(req) {
  const c = getCookie(req, 'sess');
  if (!c) return null;
  const [v, s] = c.split('.');
  if (!v || !s) return null;
  const a = Buffer.from(s), b = Buffer.from(sig(v));
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
  try { return JSON.parse(Buffer.from(v, 'base64url').toString()); } catch { return null; }
}

function sessCookie(o) {
  const v = Buffer.from(JSON.stringify(o)).toString('base64url');
  return `sess=${v}.${sig(v)}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=604800`;
}

// ---- key validation + IP lock ----
async function validate(action, key, ip, user) {
  if (!key || !ip || !user || !user.id) return { ok: false, error: 'Bad request' };
  const raw = await r('GET', 'key:' + key);
  if (!raw) return { ok: false, error: 'Invalid or expired key' };
  const k = JSON.parse(raw);
  if (k.revoked) return { ok: false, error: 'Key was revoked' };
  const left = Math.ceil((k.expires - Date.now()) / 1000);
  if (left <= 0) return { ok: false, error: 'Key expired' };

  const id = sha(ip) + '|' + user.id;
  const set = await r('SET', 'bind:' + key, id, 'NX', 'EX', left); // atomic first-use lock
  const bound = set === 'OK' ? id : await r('GET', 'bind:' + key);
  if (bound !== id) return { ok: false, error: 'Key is locked to a different IP/account' };

  if (set === 'OK') {
    k.ipHash = sha(ip); k.ipMask = mask(ip); k.boundAt = Date.now();
    k.user = { id: user.id, name: user.name, avatar: user.avatar };
    await r('SET', 'key:' + key, JSON.stringify(k), 'KEEPTTL');
  }
  await r('HSET', 'presence', user.id,
    JSON.stringify({ name: user.name, avatar: user.avatar, seen: Date.now() }));
  return { ok: true, expires: k.expires };
}

module.exports = { r, tfetch, sha, mask, genKey, genPhrase, safeEq, clientIp, getCookie, adminRole, readSess, sessCookie, validate };
