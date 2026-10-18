"use strict";
const express = require("express");
const Database = require("better-sqlite3");
const crypto = require("crypto");
const path = require("path");
const fs = require("fs");

const PORT = +process.env.PORT || 3000;
const DB_PATH = process.env.DB_PATH || path.join(__dirname, "data", "tracker.db");
const ADMINS = (process.env.ADMIN_NAMES || "").split(",").map(s => s.trim().toLowerCase()).filter(Boolean);
const TTL = 60 * 24 * 3600 * 1000; // session lifetime: 60 days

fs.mkdirSync(path.dirname(DB_PATH), { recursive: true });
const db = new Database(DB_PATH);
db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");
db.exec(`
CREATE TABLE IF NOT EXISTS users(
  id INTEGER PRIMARY KEY, name TEXT NOT NULL UNIQUE COLLATE NOCASE,
  salt TEXT NOT NULL, hash TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'user', created INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS progress(
  user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE, data TEXT NOT NULL, updated INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS announcements(
  id INTEGER PRIMARY KEY, text TEXT NOT NULL, by TEXT, ts INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY, v TEXT NOT NULL);
`);

// ---- session secret (env var, or generated once and kept in the db)
let SECRET = process.env.SESSION_SECRET;
if (!SECRET) {
  const r = db.prepare("SELECT v FROM meta WHERE k='secret'").get();
  SECRET = r ? r.v : crypto.randomBytes(32).toString("hex");
  if (!r) db.prepare("INSERT INTO meta(k,v) VALUES('secret',?)").run(SECRET);
}

// ---- passwords (scrypt) and signed session cookie
const scrypt = (pw, salt) => new Promise((res, rej) => crypto.scrypt(pw, salt, 64, (e, k) => (e ? rej(e) : res(k))));
async function hashPw(pw) {
  const salt = crypto.randomBytes(16).toString("hex");
  return { salt, hash: (await scrypt(pw, salt)).toString("hex") };
}
async function checkPw(pw, salt, hash) {
  const k = await scrypt(pw, salt), h = Buffer.from(hash, "hex");
  return k.length === h.length && crypto.timingSafeEqual(k, h);
}
const sign = s => crypto.createHmac("sha256", SECRET).update(s).digest("base64url");
const makeToken = id => { const p = id + "." + (Date.now() + TTL); return p + "." + sign(p); };
function readToken(t) {
  if (!t) return null;
  const a = t.split(".");
  if (a.length !== 3) return null;
  const s = sign(a[0] + "." + a[1]);
  if (s.length !== a[2].length || !crypto.timingSafeEqual(Buffer.from(s), Buffer.from(a[2]))) return null;
  return +a[1] > Date.now() ? +a[0] : null;
}
const getCookie = (req, n) => {
  const m = (req.headers.cookie || "").split(/;\s*/).find(c => c.startsWith(n + "="));
  return m ? decodeURIComponent(m.slice(n.length + 1)) : null;
};
const setSession = (req, res, id) =>
  res.setHeader("Set-Cookie", `sid=${makeToken(id)}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${TTL / 1000 | 0}${req.secure ? "; Secure" : ""}`);
const pub = u => ({ id: u.id, name: u.name, admin: u.role === "admin" });

// ---- tiny per-IP rate limit for login/register
const hits = new Map();
const limit = (req, res, next) => {
  const now = Date.now(), h = (hits.get(req.ip) || []).filter(t => now - t < 15 * 60 * 1000);
  if (h.length >= 30) return res.status(429).json({ error: "Too many attempts, try again later" });
  h.push(now); hits.set(req.ip, h); next();
};
setInterval(() => { const n = Date.now(); for (const [k, v] of hits) if (!v.some(t => n - t < 9e5)) hits.delete(k); }, 36e5).unref();

const app = express();
app.set("trust proxy", 1);
app.disable("x-powered-by");
app.use(express.json({ limit: "300kb" }));
app.use((req, res, next) => {
  const id = readToken(getCookie(req, "sid"));
  req.user = id ? db.prepare("SELECT id,name,role FROM users WHERE id=?").get(id) : null;
  next();
});
const need = (req, res, next) => (req.user ? next() : res.status(401).json({ error: "Not logged in" }));
const admin = (req, res, next) => (req.user && req.user.role === "admin" ? next() : res.status(403).json({ error: "Admins only" }));

app.get("/healthz", (req, res) => res.json({ ok: true }));

app.post("/api/register", limit, async (req, res, next) => {
  try {
    const name = String((req.body || {}).name || "").trim(), pw = String((req.body || {}).password || "");
    if (!/^[\w .-]{2,30}$/.test(name)) return res.status(400).json({ error: "Name: 2-30 letters, numbers, space . _ -" });
    if (pw.length < 4 || pw.length > 100) return res.status(400).json({ error: "Password must be 4-100 characters" });
    if (db.prepare("SELECT 1 FROM users WHERE name=?").get(name)) return res.status(409).json({ error: "Name already taken" });
    const first = db.prepare("SELECT COUNT(*) c FROM users").get().c === 0;
    const role = first || ADMINS.includes(name.toLowerCase()) ? "admin" : "user";
    const { salt, hash } = await hashPw(pw);
    const id = db.prepare("INSERT INTO users(name,salt,hash,role,created) VALUES(?,?,?,?,?)").run(name, salt, hash, role, Date.now()).lastInsertRowid;
    setSession(req, res, +id);
    res.json({ user: pub({ id: +id, name, role }) });
  } catch (e) { next(e); }
});

app.post("/api/login", limit, async (req, res, next) => {
  try {
    const name = String((req.body || {}).name || "").trim(), pw = String((req.body || {}).password || "");
    const u = db.prepare("SELECT * FROM users WHERE name=?").get(name);
    if (!u || !(await checkPw(pw, u.salt, u.hash))) return res.status(401).json({ error: "Wrong name or password" });
    if (u.role !== "admin" && ADMINS.includes(u.name.toLowerCase())) {
      db.prepare("UPDATE users SET role='admin' WHERE id=?").run(u.id); u.role = "admin";
    }
    setSession(req, res, u.id);
    res.json({ user: pub(u) });
  } catch (e) { next(e); }
});

app.post("/api/logout", (req, res) => {
  res.setHeader("Set-Cookie", "sid=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0");
  res.json({ ok: true });
});
app.get("/api/me", need, (req, res) => res.json({ user: pub(req.user) }));

app.get("/api/progress", need, (req, res) => {
  const r = db.prepare("SELECT data FROM progress WHERE user_id=?").get(req.user.id);
  res.json(r ? JSON.parse(r.data) : {});
});
app.put("/api/progress", need, (req, res) => {
  const { p, c, x } = req.body || {};
  if (!p || typeof p !== "object" || Array.isArray(p) || !Array.isArray(c) || typeof x !== "string")
    return res.status(400).json({ error: "Bad data" });
  const data = JSON.stringify({ p, c, x });
  if (data.length > 250000) return res.status(413).json({ error: "Too much data" });
  db.prepare("INSERT INTO progress(user_id,data,updated) VALUES(?,?,?) ON CONFLICT(user_id) DO UPDATE SET data=excluded.data, updated=excluded.updated")
    .run(req.user.id, data, Date.now());
  res.json({ ok: true });
});

app.get("/api/announcements", need, (req, res) => {
  const items = db.prepare("SELECT id, text AS t, by, ts FROM announcements ORDER BY ts DESC LIMIT 10").all();
  res.json({ items });
});
app.post("/api/announcements", need, admin, (req, res) => {
  const t = String((req.body || {}).t || "").trim().slice(0, 500);
  if (!t) return res.status(400).json({ error: "Empty announcement" });
  db.prepare("INSERT INTO announcements(text,by,ts) VALUES(?,?,?)").run(t, req.user.name, Date.now());
  res.json({ ok: true });
});
app.delete("/api/announcements/:id", need, admin, (req, res) => {
  db.prepare("DELETE FROM announcements WHERE id=?").run(+req.params.id);
  res.json({ ok: true });
});

app.use(express.static(path.join(__dirname, "public")));
app.use((err, req, res, next) => {
  const s = err.status || 500;
  if (s >= 500) console.error(err);
  res.status(s).json({ error: s >= 500 ? "Server error" : "Bad request" });
});

const server = app.listen(PORT, () => console.log("CSE 2027 TRACKER running on port " + PORT));
for (const sig of ["SIGINT", "SIGTERM"]) process.on(sig, () => { server.close(() => { db.close(); process.exit(0); }); });
