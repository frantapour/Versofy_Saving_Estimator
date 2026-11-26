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
      await pool.query(`create table if not exists estimates (ref text primary key, at timestamptz not null, sales text, customer text, data jsonb not null, pdf bytea not null)`);
    },
    async addEst(e) { await pool.query(`insert into estimates (ref,at,sales,customer,data,pdf) values ($1,$2,$3,$4,$5,$6)`, [e.ref, e.at, e.sales, e.customer, e.data, e.pdf]); },
    async listEst(q) {
      const r = await pool.query(`select ref, at, sales, customer, data from estimates where ($1 = '' or ref ilike '%'||$1||'%' or customer ilike '%'||$1||'%' or sales ilike '%'||$1||'%') order by at desc limit 100`, [q]);
      return r.rows.map(x => ({ ref: x.ref, at: x.at.toISOString(), sales: x.sales, customer: x.customer, data: x.data }));
    },
    async getPdf(ref) { const r = await pool.query(`select pdf from estimates where ref=$1`, [ref]); return r.rows[0] ? r.rows[0].pdf : null; },
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
    async addEst(e) { const dir = path.join(__dirname, "data", "estimates"); fs.mkdirSync(dir, { recursive: true }); fs.writeFileSync(path.join(dir, e.ref + ".pdf"), e.pdf); const d = read(); d.estimates = [{ ref: e.ref, at: e.at.toISOString(), sales: e.sales, customer: e.customer, data: e.data }, ...(d.estimates || [])]; write(d); },
    async listEst(q) { const l = (read().estimates || []); const t = q.toLowerCase(); return l.filter(x => !t || [x.ref, x.customer, x.sales].some(v => String(v || "").toLowerCase().includes(t))).slice(0, 100); },
    async getPdf(ref) { try { return fs.readFileSync(path.join(__dirname, "data", "estimates", ref + ".pdf")); } catch { return null; } },
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
const body = (req, max = 300e3) => new Promise((ok, bad) => {
  let n = 0; const chunks = [];
  req.on("data", c => { n += c.length; if (n > max) { bad(new Error("too large")); req.destroy(); } else chunks.push(c); });
  req.on("end", () => { try { ok(JSON.parse(Buffer.concat(chunks).toString() || "{}")); } catch (e) { bad(e); } });
});
const isSecure = req => req.headers["x-forwarded-proto"] === "https";
// ignore spaces, quotes and backticks picked up when a password is copied and pasted
const tidy = v => String(v ?? "").trim().replace(/^[`'"]+|[`'"]+$/g, "").trim();
const clean = (v, n) => String(v ?? "").replace(/[<>&"'`]/g, "").slice(0, n);

function validConfig(c) {
  if (!c || typeof c !== "object" || Array.isArray(c)) return false;
  if (!Array.isArray(c.products) || !c.products.length || c.products.length > 40) return false;
  if (c.addons && (!Array.isArray(c.addons) || c.addons.length > 30)) return false;
  if (!c.tariffs || typeof c.tariffs !== "object") return false;
  return c.products.every(p => p && typeof p.n === "string" && +p.fee > 0 && +p.kwp > 0);
}

const LOGIN_PAGE = msg => `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Versofy savings calculator</title>
<link rel="preconnect" href="https://fonts.googleapis.com"><link href="https://fonts.googleapis.com/css2?family=Fraunces:opsz,wght@9..144,800&family=Open+Sans:wght@400;600;700&display=swap" rel="stylesheet">
<style>
*{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;padding:24px;background:#193f2e radial-gradient(ellipse at 80% -10%,#2b5c47 0,transparent 60%);font:16px/1.5 "Open Sans",system-ui,sans-serif;color:#121442}
.card{width:min(400px,100%);background:#f1e9df;border-radius:16px;padding:32px 28px;box-shadow:0 20px 50px rgba(0,0,0,.25)}
.sun{width:44px;height:44px;border-radius:50%;background:#fdbd14;box-shadow:0 0 0 8px rgba(253,189,20,.25);margin-bottom:18px}
h1{font:800 28px/1.1 Fraunces,Georgia,serif;margin:0 0 6px}p.sub{margin:0 0 22px;color:#4d5a52;font-size:15px}
label{display:block;font-weight:600;font-size:15px;margin-bottom:6px}
.pw{position:relative}.pw input{width:100%;min-height:48px;border:1px solid #dccfbf;border-radius:10px;padding:0 64px 0 14px;font:16px "Open Sans",sans-serif;background:#fff;color:#121442}
.pw button{position:absolute;right:6px;top:6px;bottom:6px;border:0;background:none;color:#193f2e;font:600 14px "Open Sans",sans-serif;cursor:pointer;padding:0 10px;border-radius:8px}
input:focus-visible,button:focus-visible{outline:3px solid #faa21b;outline-offset:2px}
.go{width:100%;min-height:48px;margin-top:16px;border:0;border-radius:999px;background:#fdbd14;color:#121442;font:700 16px "Open Sans",sans-serif;cursor:pointer}.go:hover{background:#faa21b}
.err{margin:14px 0 0;color:#c2413a;font-weight:600;font-size:15px}.foot{margin:18px 0 0;font-size:13px;color:#4d5a52}
</style></head>
<body><form class="card" method="post" action="/login"><div class="sun" aria-hidden="true"></div><h1>Versofy savings calculator</h1><p class="sub">For the Versofy sales team. Enter the team password to start a quote.</p>
<label for="pw">Team password</label><div class="pw"><input id="pw" type="password" name="password" required autofocus autocapitalize="off" autocorrect="off" spellcheck="false" autocomplete="current-password"><button type="button" onclick="const i=document.getElementById('pw');i.type=i.type==='password'?'text':'password';this.textContent=i.type==='password'?'Show':'Hide'">Show</button></div>
<button class="go">Open the calculator</button>${msg ? `<p class="err" role="alert">${msg}</p>` : ""}<p class="foot">Don't have the password? Ask your sales manager.</p></form></body></html>`;

const server = http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url, "http://x");
    const sess = readSession(req);
    const ip = (req.headers["x-forwarded-for"] || req.socket.remoteAddress || "").split(",")[0].trim();
    const salesOk = !!SALES_PASSWORD && sess && (sess.role === "sales" || sess.role === "admin");

    if (url.pathname === "/health") return send(res, 200, { ok: true });

    // team password gate (optional)
    if (url.pathname === "/logout") return send(res, 303, "", { Location: "/", "Set-Cookie": "vs=; Path=/; Max-Age=0" });
    if (url.pathname === "/login" && req.method === "POST") {
      if (limited(ip)) return send(res, 429, LOGIN_PAGE("Too many tries. Wait a few minutes."));
      let raw = ""; for await (const c of req) { raw += c; if (raw.length > 2000) break; }
      const pw = tidy(new URLSearchParams(raw).get("password"));
      const role = SALES_PASSWORD && same(pw, tidy(SALES_PASSWORD)) ? "sales" : ADMIN_PASSWORD && same(pw, tidy(ADMIN_PASSWORD)) ? "admin" : null;
      if (role) return send(res, 303, "", { Location: "/", "Set-Cookie": makeCookie({ role, name: role === "admin" ? "Admin" : "", exp: Date.now() + SESSION_HOURS * 3600e3 }, isSecure(req)) });
      console.warn(`Team sign-in failed (typed ${pw.length} characters, expected ${tidy(SALES_PASSWORD).length})`);
      return send(res, 401, LOGIN_PAGE("That password didn't work. Passwords are case-sensitive."));
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
    if (url.pathname === "/api/estimates" && req.method === "POST") {
      const origin = req.headers.origin;
      if (origin && new URL(origin).host !== req.headers.host) return send(res, 403, { error: "bad origin" });
      const b = await body(req, 3e6);
      const ref = String(b.ref || "");
      if (!/^VS-\d{8}-[A-Z0-9]{3,8}$/.test(ref)) return send(res, 400, { error: "bad ref" });
      const pdf = Buffer.from(String(b.pdf || ""), "base64");
      if (pdf.length < 500 || pdf.slice(0, 5).toString() !== "%PDF-") return send(res, 400, { error: "bad pdf" });
      const data = b.data && typeof b.data === "object" && !Array.isArray(b.data) ? b.data : {};
      if (JSON.stringify(data).length > 20000) return send(res, 400, { error: "too large" });
      await store.addEst({ ref, at: new Date(), sales: clean(b.sales, 60) || (sess.role === "admin" ? clean(sess.name, 60) : ""), customer: clean(b.customer, 60), data, pdf });
      return send(res, 201, { ok: true, ref });
    }
    if (url.pathname === "/api/me") return send(res, 200, { role: sess ? sess.role : null, name: sess ? sess.name || "" : "" });
    if (url.pathname === "/api/login" && req.method === "POST") {
      if (limited(ip)) return send(res, 429, { error: "too many tries" });
      const b = await body(req);
      if (!ADMIN_PASSWORD || !same(tidy(b.password), tidy(ADMIN_PASSWORD))) return send(res, 401, { error: "wrong password" });
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
    if (url.pathname === "/api/estimates" && req.method === "GET") return send(res, 200, { estimates: await store.listEst(clean(url.searchParams.get("q"), 60).trim()) });
    if (url.pathname.startsWith("/api/estimates/") && req.method === "GET") {
      const ref = decodeURIComponent(url.pathname.slice(15)).replace(/\.pdf$/, "");
      if (!/^VS-\d{8}-[A-Z0-9]{3,8}$/.test(ref)) return send(res, 400, { error: "bad ref" });
      const pdf = await store.getPdf(ref);
      if (!pdf) return send(res, 404, { error: "not found" });
      res.writeHead(200, { "Content-Type": "application/pdf", "Content-Disposition": `attachment; filename="${ref}.pdf"`, "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff" });
      return res.end(pdf);
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
