// Versofy savings calculator: static page + small JSON API for admin settings.
// Env: PORT, DATABASE_URL (Postgres; without it settings go to ./data/settings.json),
//      ADMIN_PASSWORD (required to sign in as admin), SESSION_SECRET (keeps sign-ins across restarts),
//      SALES_PASSWORD (required: the team password that opens the calculator).
const http = require("http");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const PORT = +process.env.PORT || 3000;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "";
const SALES_PASSWORD = process.env.SALES_PASSWORD || "";
const SECRET = process.env.SESSION_SECRET || crypto.randomBytes(32).toString("hex");
const SESSION_HOURS = 12;
const PUB = path.join(__dirname, "public");
const JSPDF = require.resolve("jspdf/dist/jspdf.umd.min.js");

// ---------- storage
let store;
if (process.env.DATABASE_URL) {
  const { Pool } = require("pg");
  const ssl = /sslmode=disable|localhost|\.railway\.internal/.test(process.env.DATABASE_URL) ? false : { rejectUnauthorized: false };
  const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl });
  store = {
    async init() {
      await pool.query(`create table if not exists settings (id text primary key, data jsonb not null, at timestamptz not null, by text)`);
      await pool.query(`create table if not exists changes (id serial primary key, at timestamptz not null, by text, what text)`);
    },
    async get() {
      const r = await pool.query(`select data, at, by from settings where id='current'`);
      return r.rows[0] ? { ...r.rows[0].data, at: r.rows[0].at.toISOString(), by: r.rows[0].by } : null;
    },
    async put(data, by, what) {
      const at = new Date();
      await pool.query(`insert into settings (id,data,at,by) values ('current',$1,$2,$3) on conflict (id) do update set data=$1, at=$2, by=$3`, [data, at, by]);
      await pool.query(`insert into changes (at,by,what) values ($1,$2,$3)`, [at, by, what]);
    },
    async changes() {
      const r = await pool.query(`select at, by, what from changes order by id desc limit 10`);
      return r.rows.map(x => ({ at: x.at.toISOString(), by: x.by, what: x.what }));
    },
  };
} else {
  const file = path.join(__dirname, "data", "settings.json");
  const read = () => { try { return JSON.parse(fs.readFileSync(file, "utf8")); } catch { return { current: null, changes: [] }; } };
  const write = d => { fs.mkdirSync(path.dirname(file), { recursive: true }); fs.writeFileSync(file, JSON.stringify(d, null, 1)); };
  console.warn("DATABASE_URL not set: saving admin settings to data/settings.json (lost on redeploy).");
  store = {
    async init() {},
    async get() { return read().current; },
    async put(data, by, what) { const d = read(), at = new Date().toISOString(); d.current = { ...data, at, by }; d.changes.unshift({ at, by, what }); d.changes = d.changes.slice(0, 50); write(d); },
    async changes() { return read().changes.slice(0, 10); },
  };
}

// ---------- sessions (signed cookie)
const sign = v => crypto.createHmac("sha256", SECRET).update(v).digest("base64url");
const makeCookie = (sess, secure) => {
  const v = Buffer.from(JSON.stringify(sess)).toString("base64url");
  return `vs=${v}.${sign(v)}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${SESSION_HOURS * 3600}${secure ? "; Secure" : ""}`;
};
const readSession = req => {
  const m = /(?:^|;\s*)vs=([A-Za-z0-9_-]+)\.([A-Za-z0-9_-]+)/.exec(req.headers.cookie || "");
  if (!m) return null;
  const a = Buffer.from(sign(m[1])), b = Buffer.from(m[2]);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
  try { const s = JSON.parse(Buffer.from(m[1], "base64url").toString()); return s.exp > Date.now() ? s : null; } catch { return null; }
};
const same = (a, b) => { const x = crypto.createHash("sha256").update(String(a)).digest(), y = crypto.createHash("sha256").update(String(b)).digest(); return crypto.timingSafeEqual(x, y); };

// ---------- naive rate limit for sign-in
const tries = new Map();
const limited = ip => { const now = Date.now(), t = (tries.get(ip) || []).filter(x => now - x < 10 * 60e3); t.push(now); tries.set(ip, t); return t.length > 10; };

// ---------- helpers
const send = (res, code, body, headers = {}) => {
  const json = typeof body !== "string";
  res.writeHead(code, { "Content-Type": json ? "application/json" : "text/html; charset=utf-8", "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff", "Referrer-Policy": "same-origin", ...headers });
  res.end(json ? JSON.stringify(body) : body);
};
const body = req => new Promise((ok, bad) => {
  let n = 0; const chunks = [];
  req.on("data", c => { n += c.length; if (n > 300e3) { bad(new Error("too large")); req.destroy(); } else chunks.push(c); });
  req.on("end", () => { try { ok(JSON.parse(Buffer.concat(chunks).toString() || "{}")); } catch (e) { bad(e); } });
});
const isSecure = req => req.headers["x-forwarded-proto"] === "https";
const clean = (v, n) => String(v ?? "").replace(/[<>&"'`]/g, "").slice(0, n);

function validConfig(c) {
  if (!c || typeof c !== "object" || Array.isArray(c)) return false;
  if (!Array.isArray(c.products) || !c.products.length || c.products.length > 40) return false;
  if (c.addons && (!Array.isArray(c.addons) || c.addons.length > 30)) return false;
  if (!c.tariffs || typeof c.tariffs !== "object") return false;
  return c.products.every(p => p && typeof p.n === "string" && +p.fee > 0 && +p.kwp > 0);
}

const LOGIN_PAGE = msg => `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Versofy calculator sign-in</title>
<style>body{margin:0;min-height:100vh;display:grid;place-items:center;background:#193f2e;font:16px/1.5 system-ui,sans-serif;color:#121442}form{background:#f1e9df;padding:28px;border-radius:12px;display:grid;gap:12px;width:min(360px,90vw)}h1{margin:0;font-size:24px}input,button{font:inherit;min-height:46px;border-radius:8px;border:1px solid #dccfbf;padding:0 12px}button{background:#fdbd14;border:0;font-weight:700;border-radius:999px;cursor:pointer}p{margin:0;color:#c2413a}</style></head>
<body><form method="post" action="/login"><h1>Versofy savings calculator</h1><label>Team password<br><input type="password" name="password" required autofocus style="width:100%"></label><button>Open the calculator</button>${msg ? `<p>${msg}</p>` : ""}</form></body></html>`;

const server = http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url, "http://x");
    const sess = readSession(req);
    const ip = (req.headers["x-forwarded-for"] || req.socket.remoteAddress || "").split(",")[0].trim();
    const salesOk = !!SALES_PASSWORD && sess && (sess.role === "sales" || sess.role === "admin");

    if (url.pathname === "/health") return send(res, 200, { ok: true });

    // team password gate (optional)
    if (url.pathname === "/login" && req.method === "POST") {
      if (limited(ip)) return send(res, 429, LOGIN_PAGE("Too many tries. Wait a few minutes."));
      let raw = ""; for await (const c of req) { raw += c; if (raw.length > 2000) break; }
      const pw = new URLSearchParams(raw).get("password") || "";
      if (SALES_PASSWORD && same(pw, SALES_PASSWORD)) return send(res, 303, "", { Location: "/", "Set-Cookie": makeCookie({ role: "sales", exp: Date.now() + SESSION_HOURS * 3600e3 }, isSecure(req)) });
      return send(res, 401, LOGIN_PAGE("That password didn't work."));
    }
    if (!SALES_PASSWORD) return send(res, 503, url.pathname.startsWith("/api/") ? { error: "not configured" } : "<!DOCTYPE html><title>Not set up</title><p style='font:16px system-ui;padding:40px'>The calculator is locked until the SALES_PASSWORD variable is set in Railway.</p>");
    if (!salesOk) {
      if (url.pathname.startsWith("/api/")) return send(res, 401, { error: "sign in" });
      return send(res, 200, LOGIN_PAGE(""));
    }

    if (url.pathname === "/" || url.pathname === "/index.html") {
      res.writeHead(200, { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-cache", "X-Content-Type-Options": "nosniff" });
      return fs.createReadStream(path.join(PUB, "index.html")).pipe(res);
    }
    if (url.pathname === "/vendor/jspdf.umd.min.js") {
      res.writeHead(200, { "Content-Type": "application/javascript", "Cache-Control": "public, max-age=86400" });
      return fs.createReadStream(JSPDF).pipe(res);
    }

    if (url.pathname === "/api/config" && req.method === "GET") return send(res, 200, { config: await store.get() });
    if (url.pathname === "/api/me") return send(res, 200, { role: sess ? sess.role : null, name: sess ? sess.name || "" : "" });
    if (url.pathname === "/api/login" && req.method === "POST") {
      if (limited(ip)) return send(res, 429, { error: "too many tries" });
      const b = await body(req);
      if (!ADMIN_PASSWORD || !same(b.password || "", ADMIN_PASSWORD)) return send(res, 401, { error: "wrong password" });
      const s = { role: "admin", name: clean(b.name, 60) || "Admin", exp: Date.now() + SESSION_HOURS * 3600e3 };
      return send(res, 200, { role: s.role, name: s.name }, { "Set-Cookie": makeCookie(s, isSecure(req)) });
    }
    if (url.pathname === "/api/logout" && req.method === "POST") {
      const keep = makeCookie({ role: "sales", exp: Date.now() + SESSION_HOURS * 3600e3 }, isSecure(req));
      return send(res, 200, { ok: true }, { "Set-Cookie": keep });
    }
    if (url.pathname.startsWith("/api/") && (!sess || sess.role !== "admin")) return send(res, 401, { error: "admin only" });
    if (url.pathname === "/api/config" && req.method === "PUT") {
      // same-origin check for writes
      const origin = req.headers.origin;
      if (origin && new URL(origin).host !== req.headers.host) return send(res, 403, { error: "bad origin" });
      const b = await body(req);
      if (!validConfig(b.config)) return send(res, 400, { error: "invalid settings" });
      const { at, by, ...cfg } = b.config;
      await store.put(cfg, sess.name, clean(b.what, 1000));
      return send(res, 200, { ok: true });
    }
    if (url.pathname === "/api/changes" && req.method === "GET") return send(res, 200, { changes: await store.changes() });
    return send(res, 404, { error: "not found" });
  } catch (e) {
    console.error(e);
    if (!res.headersSent) send(res, 500, { error: "server error" });
  }
});

store.init().then(() => server.listen(PORT, () => console.log(`Versofy calculator on :${PORT}${SALES_PASSWORD ? "" : " (SALES_PASSWORD not set: calculator locked)"}${ADMIN_PASSWORD ? "" : " (ADMIN_PASSWORD not set: admin sign-in disabled)"}`)))
  .catch(e => { console.error("Storage init failed", e); process.exit(1); });
