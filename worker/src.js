// AgroPulse — Cloudflare Worker: serves the app page and a small document API on D1.
// Bindings: DB (D1 database). Secret: APP_PASSWORD.
const COLS = new Set(["fields", "ops", "machines", "implements", "people", "products", "tasks", "service", "parcels", "leases", "owners", "payments", "settings", "warehouses", "whdocs", "invoices", "whrequests", "pricelists", "units", "mplans", "norms", "fuelstations", "fuelings", "harvests", "waybills", "elevators", "scoutreports", "scouttasks", "notes", "plantthreats", "agroplans", "recommendations", "costs", "aofields", "aowaybills", "aolzk", "aoitems"]);
const ID_RE = /^[A-Za-z0-9._-]{1,64}$/;
const COOKIE = "klg_session";
let schemaReady = false;
const ROLES = {
  admin: { name: "Адміністратор", write: "*" },
  agronomist: { name: "Агроном", write: ["fields", "ops", "scoutreports", "scouttasks", "notes", "plantthreats", "agroplans", "recommendations", "products", "whrequests", "settings"] },
  mechanic: { name: "Механік / диспетчер", write: ["machines", "implements", "people", "tasks", "service", "mplans", "norms", "fuelstations", "fuelings", "harvests", "waybills", "elevators", "whrequests"] },
  storekeeper: { name: "Комірник", write: ["warehouses", "whdocs", "invoices", "whrequests", "pricelists", "units", "products", "fuelstations", "fuelings"] },
  land: { name: "Земельник", write: ["parcels", "leases", "owners", "payments", "settings"] },
  accountant: { name: "Бухгалтер", write: ["payments", "invoices", "pricelists", "owners", "settings", "costs"] },
  viewer: { name: "Лише перегляд", write: [] },
};
const canWriteCol = (u, col) => !!u && ROLES[u.role] && (ROLES[u.role].write === "*" || ROLES[u.role].write.includes(col));
const enc = new TextEncoder();
const hex = (buf) => [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
async function hmacHex(secret, msg) { const key = await crypto.subtle.importKey("raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]); return hex(await crypto.subtle.sign("HMAC", key, enc.encode(msg))); }
async function hashPassword(pw, saltHex) {
  const salt = saltHex ? new Uint8Array(saltHex.match(/../g).map((h) => parseInt(h, 16))) : crypto.getRandomValues(new Uint8Array(16));
  const key = await crypto.subtle.importKey("raw", enc.encode(pw), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt, iterations: 100000 }, key, 256);
  return { hash: hex(bits), salt: hex(salt) };
}
const b64e = (o) => btoa(String.fromCharCode(...enc.encode(JSON.stringify(o)))).replace(/=+$/, "");
const b64d = (s) => JSON.parse(new TextDecoder().decode(Uint8Array.from(atob(s), (c) => c.charCodeAt(0))));
async function makeToken(env, uid) { const body = b64e({ u: uid, e: Date.now() + 365 * 864e5 }); return "v2." + body + "." + (await hmacHex(env.APP_PASSWORD, "v2." + body)); }
const ADMIN = { id: "admin", name: "Адміністратор", role: "admin", builtin: true };
async function readSession(req, env) {
  const raw = ((req.headers.get("cookie") || "").split(/;\s*/).find((c) => c.startsWith(COOKIE + "=")) || "").slice(COOKIE.length + 1);
  if (!raw) return null;
  if (!raw.startsWith("v2.")) return (await safeEqual(raw, await sessionToken(env.APP_PASSWORD))) ? ADMIN : null;
  const [, body, sig] = raw.split(".");
  if (!body || !sig || !(await safeEqual(sig, await hmacHex(env.APP_PASSWORD, "v2." + body)))) return null;
  let p; try { p = b64d(body); } catch (e) { return null; }
  if (!p.e || p.e < Date.now()) return null;
  if (p.u === "admin") return ADMIN;
  await ensureSchema(env.DB);
  const u = await env.DB.prepare("SELECT id, login, name, role, active FROM users WHERE id = ?").bind(p.u).first();
  return u && u.active ? { id: u.id, login: u.login, name: u.name, role: ROLES[u.role] ? u.role : "viewer" } : null;
}
let cdseCache = null;
async function cdseToken(env) {
  if (cdseCache && cdseCache.exp > Date.now() + 60000) return cdseCache.token;
  const r = await fetch("https://identity.dataspace.copernicus.eu/auth/realms/CDSE/protocol/openid-connect/token", { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ grant_type: "client_credentials", client_id: env.CDSE_CLIENT_ID, client_secret: env.CDSE_CLIENT_SECRET }) });
  if (!r.ok) throw new Error("Copernicus login failed: " + r.status);
  const j = await r.json(); cdseCache = { token: j.access_token, exp: Date.now() + (j.expires_in || 600) * 1000 }; return cdseCache.token;
}
const cookieHeader = (v, age) => `${COOKIE}=${v}; Path=/; Max-Age=${age}; HttpOnly; Secure; SameSite=Lax`;

export default {
  async scheduled(event, env, ctx) {
    if (!env.DB) return;
    await ensureSchema(env.DB);
    if (event.cron === "7 5 * * *") { if (env.TELEGRAM_BOT_TOKEN) ctx.waitUntil(sendDigests(env)); }
    else ctx.waitUntil(makeBackup(env, "auto"));
  },
  async fetch(req, env) {
    const url = new URL(req.url);
    if (url.pathname.startsWith("/tg/hook/") && req.method === "POST" && env.TELEGRAM_BOT_TOKEN && env.APP_PASSWORD && url.pathname === (await tgHookPath(env))) { try { return await handleTgHook(req, env); } catch (e) { return new Response("ok"); } }
    if (env.DB && env.APP_PASSWORD && (url.pathname.startsWith("/.well-known/") || url.pathname.startsWith("/oauth/"))) return handleOAuth(req, env, url);
    if (url.pathname === "/mcp" && env.DB && env.APP_PASSWORD) {
      if (req.method === "OPTIONS") return oaJson({}, 204);
      await ensureSchema(env.DB);
      if (!(await mcpBearerOk(req, env))) return oaJson({ error: "unauthorized" }, 401, { "www-authenticate": `Bearer resource_metadata="${url.origin}/.well-known/oauth-protected-resource"` });
      return handleMcp(req, env);
    }
    if (!url.pathname.startsWith("/api/")) {
      return new Response(HTML, { headers: { "content-type": "text/html; charset=utf-8", "cache-control": "no-cache", "x-frame-options": "DENY", "referrer-policy": "same-origin" } });
    }
    try {
      return await handleApi(req, env, url);
    } catch (e) {
      return json({ error: String((e && e.message) || e) }, 500);
    }
  },
};

async function handleApi(req, env, url) {
  if (!env.APP_PASSWORD) return json({ error: "APP_PASSWORD is not set" }, 503);
  const path = url.pathname;

  if (path === "/api/login" && req.method === "POST") {
    const body = await req.json().catch(() => ({}));
    const login = String(body.login || "admin").trim().toLowerCase(), pw = String(body.password || "");
    const fail = async () => { await new Promise((r) => setTimeout(r, 700)); return json({ error: "bad login" }, 401); };
    if (!pw) return fail();
    if (login === "admin" && (await safeEqual(pw, env.APP_PASSWORD))) return json({ ok: true }, 200, { "set-cookie": cookieHeader(await makeToken(env, "admin"), 31536000) });
    if (!env.DB) return fail();
    await ensureSchema(env.DB);
    const u = await env.DB.prepare("SELECT id, hash, salt, active FROM users WHERE login = ?").bind(login).first();
    if (!u || !u.active) return fail();
    const h = await hashPassword(pw, u.salt);
    if (!(await safeEqual(h.hash, u.hash))) return fail();
    await env.DB.prepare("UPDATE users SET last_login = ? WHERE id = ?").bind(new Date().toISOString(), u.id).run();
    return json({ ok: true }, 200, { "set-cookie": cookieHeader(await makeToken(env, u.id), 31536000) });
  }
  if (path === "/api/logout" && req.method === "POST") {
    return json({ ok: true }, 200, { "set-cookie": cookieHeader("", 0) });
  }

  if (!env.DB) return json({ error: "D1 binding DB is missing" }, 500);
  const user = await readSession(req, env);
  if (!user) return json({ error: "auth" }, 401);
  await ensureSchema(env.DB);
  const forbid = () => json({ error: "forbidden", role: user.role }, 403);

  if (path === "/api/me" && req.method === "GET") return json({ id: user.id, name: user.name, login: user.login || "admin", role: user.role, builtin: !!user.builtin, write: ROLES[user.role].write, roles: Object.fromEntries(Object.entries(ROLES).map(([k, v]) => [k, v.name])) });
  if (path === "/api/password" && req.method === "POST") {
    if (user.builtin) return json({ error: "Пароль адміністратора admin змінюється в Cloudflare (APP_PASSWORD)" }, 400);
    const b = await req.json().catch(() => ({}));
    const u = await env.DB.prepare("SELECT hash, salt FROM users WHERE id = ?").bind(user.id).first();
    if (!u || !(await safeEqual((await hashPassword(String(b.old || ""), u.salt)).hash, u.hash))) return json({ error: "Невірний поточний пароль" }, 400);
    if (String(b.new || "").length < 8) return json({ error: "Новий пароль має бути щонайменше 8 символів" }, 400);
    const h = await hashPassword(String(b.new));
    await env.DB.prepare("UPDATE users SET hash = ?, salt = ? WHERE id = ?").bind(h.hash, h.salt, user.id).run();
    return json({ ok: true });
  }
  if (path === "/api/users" && req.method === "GET") {
    if (user.role !== "admin") return forbid();
    const { results } = await env.DB.prepare("SELECT id, login, name, role, active, created, last_login FROM users ORDER BY name").all();
    return json({ users: results });
  }
  if (path === "/api/users" && req.method === "POST") {
    if (user.role !== "admin") return forbid();
    const b = await req.json().catch(() => ({}));
    const login = String(b.login || "").trim().toLowerCase(), name = String(b.name || "").trim().slice(0, 100), role = ROLES[b.role] ? b.role : "viewer", active = b.active === false ? 0 : 1;
    if (!/^[a-z0-9._-]{3,40}$/.test(login) || login === "admin") return json({ error: "Логін: 3–40 латинських літер, цифр, . _ - (не admin)" }, 400);
    if (!name) return json({ error: "Вкажіть ім’я" }, 400);
    const clash = await env.DB.prepare("SELECT id FROM users WHERE login = ?").bind(login).first();
    if (clash && clash.id !== b.id) return json({ error: "Такий логін уже є" }, 400);
    if (b.id) {
      await env.DB.prepare("UPDATE users SET login = ?, name = ?, role = ?, active = ? WHERE id = ?").bind(login, name, role, active, b.id).run();
      if (b.password) { if (String(b.password).length < 8) return json({ error: "Пароль щонайменше 8 символів" }, 400); const h = await hashPassword(String(b.password)); await env.DB.prepare("UPDATE users SET hash = ?, salt = ? WHERE id = ?").bind(h.hash, h.salt, b.id).run(); }
      return json({ ok: true, id: b.id });
    }
    if (String(b.password || "").length < 8) return json({ error: "Пароль щонайменше 8 символів" }, 400);
    const h = await hashPassword(String(b.password)); const id = crypto.randomUUID();
    await env.DB.prepare("INSERT INTO users (id, login, name, role, hash, salt, active, created) VALUES (?, ?, ?, ?, ?, ?, ?, ?)").bind(id, login, name, role, h.hash, h.salt, active, new Date().toISOString()).run();
    return json({ ok: true, id });
  }
  const um = path.match(/^\/api\/users\/([0-9a-f-]{36})$/);
  if (um && req.method === "DELETE") { if (user.role !== "admin") return forbid(); await env.DB.prepare("DELETE FROM users WHERE id = ?").bind(um[1]).run(); return json({ ok: true }); }

  if (path === "/api/all" && req.method === "GET") {
    const now = new Date().toISOString();
    const { results } = await env.DB.prepare("SELECT col, id, data, updated, deleted FROM docs WHERE deleted = 0").all();
    return json({ now, docs: results.map(rowOut) });
  }
  if (path === "/api/changes" && req.method === "GET") {
    const now = new Date().toISOString();
    const since = url.searchParams.get("since") || "1970-01-01T00:00:00.000Z";
    const { results } = await env.DB.prepare("SELECT col, id, data, updated, deleted FROM docs WHERE updated > ?").bind(since).all();
    return json({ now, docs: results.map(rowOut) });
  }
  if (path === "/api/files" && req.method === "GET") {
    const col = url.searchParams.get("col") || "", id = url.searchParams.get("id") || "";
    const { results } = await env.DB.prepare("SELECT id, name, type, size, created FROM files WHERE col = ? AND doc = ? ORDER BY created").bind(col, id).all();
    return json({ files: results });
  }
  if (path === "/api/files" && req.method === "POST") {
    const col = url.searchParams.get("col") || "", id = url.searchParams.get("id") || "";
    const name = (url.searchParams.get("name") || "file").slice(0, 200);
    if (!COLS.has(col) || !ID_RE.test(id)) return json({ error: "bad target" }, 400);
    if (!canWriteCol(user, col)) return forbid();
    const buf = new Uint8Array(await req.arrayBuffer());
    if (!buf.length) return json({ error: "empty file" }, 400);
    if (buf.length > 20 * 1024 * 1024) return json({ error: "file larger than 20 MB" }, 413);
    const fid = crypto.randomUUID();
    const type = (req.headers.get("content-type") || "application/octet-stream").slice(0, 100);
    const created = new Date().toISOString();
    const CH = 512 * 1024; const stmts = [env.DB.prepare("INSERT INTO files (id, col, doc, name, type, size, created) VALUES (?, ?, ?, ?, ?, ?, ?)").bind(fid, col, id, name, type, buf.length, created)];
    for (let i = 0, n = 0; i < buf.length; i += CH, n++) stmts.push(env.DB.prepare("INSERT INTO file_chunks (file_id, idx, data) VALUES (?, ?, ?)").bind(fid, n, buf.slice(i, i + CH).buffer));
    for (let i = 0; i < stmts.length; i += 10) await env.DB.batch(stmts.slice(i, i + 10));
    return json({ ok: true, file: { id: fid, name, type, size: buf.length, created } });
  }
  const fm = path.match(/^\/api\/files\/([0-9a-f-]{36})$/);
  if (fm && req.method === "GET") {
    const f = await env.DB.prepare("SELECT name, type, size FROM files WHERE id = ?").bind(fm[1]).first();
    if (!f) return json({ error: "not found" }, 404);
    const { results } = await env.DB.prepare("SELECT data FROM file_chunks WHERE file_id = ? ORDER BY idx").bind(fm[1]).all();
    const parts = results.map((r) => new Uint8Array(r.data));
    const out = new Uint8Array(parts.reduce((t, p) => t + p.length, 0)); let o = 0; for (const p of parts) { out.set(p, o); o += p.length; }
    const dl = url.searchParams.get("download") ? "attachment" : "inline";
    return new Response(out, { headers: { "content-type": f.type, "content-length": String(out.length), "cache-control": "private, max-age=3600", "content-disposition": dl + "; filename*=UTF-8''" + encodeURIComponent(f.name), "x-content-type-options": "nosniff" } });
  }
  if (fm && req.method === "DELETE") {
    const fr = await env.DB.prepare("SELECT col FROM files WHERE id = ?").bind(fm[1]).first();
    if (fr && !canWriteCol(user, fr.col)) return forbid();
    await env.DB.batch([env.DB.prepare("DELETE FROM file_chunks WHERE file_id = ?").bind(fm[1]), env.DB.prepare("DELETE FROM files WHERE id = ?").bind(fm[1])]);
    return json({ ok: true });
  }
  if (path === "/api/ao/info" && req.method === "GET") {
    if (user.role !== "admin") return forbid();
    return json(Object.assign({ url: url.origin + "/mcp" }, await aoStatus(env)));
  }
  if (path === "/api/tg/info" && req.method === "GET") {
    if (!env.TELEGRAM_BOT_TOKEN) return json({ configured: false });
    const me = await TG(env, "getMe"); const linked = await env.DB.prepare("SELECT COUNT(*) AS n FROM tg_links WHERE user_id = ?").bind(user.id).first();
    let hook = null; if (user.role === "admin") { const w = await TG(env, "getWebhookInfo"); hook = w.ok ? { url: !!w.result.url, ok: (w.result.url || "").endsWith(await tgHookPath(env)), error: w.result.last_error_message || "" } : null; }
    const all = user.role === "admin" ? (await tgLinks(env)).map((l) => ({ name: l.name, role: l.role })) : null;
    return json({ configured: true, bot: me.ok ? me.result.username : null, linked: (linked || {}).n || 0, hook, all });
  }
  if (path === "/api/tg/setup" && req.method === "POST") {
    if (user.role !== "admin") return forbid();
    if (!env.TELEGRAM_BOT_TOKEN) return json({ error: "TELEGRAM_BOT_TOKEN не задано" }, 400);
    const r = await TG(env, "setWebhook", { url: url.origin + (await tgHookPath(env)), secret_token: (await hmacHex(env.APP_PASSWORD, "tg-secret")).slice(0, 48), allowed_updates: ["message"], drop_pending_updates: true });
    await TG(env, "setMyCommands", { commands: [{ command: "digest", description: "Зведення зараз" }, { command: "stop", description: "Вимкнути сповіщення" }] });
    return json({ ok: !!r.ok, description: r.description || "" });
  }
  if (path === "/api/tg/code" && req.method === "POST") {
    if (!env.TELEGRAM_BOT_TOKEN) return json({ error: "not configured" }, 400);
    const code = [...crypto.getRandomValues(new Uint8Array(8))].map((b) => "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"[b % 32]).join("");
    await env.DB.prepare("INSERT INTO tg_codes (code, user_id, name, role, exp) VALUES (?, ?, ?, ?, ?)").bind(code, user.id, user.name, user.role, Date.now() + 15 * 60e3).run();
    const me = await TG(env, "getMe");
    return json({ code, bot: me.ok ? me.result.username : null });
  }
  if (path === "/api/tg/unlink" && req.method === "POST") { await env.DB.prepare("DELETE FROM tg_links WHERE user_id = ?").bind(user.id).run(); return json({ ok: true }); }
  if (path === "/api/tg/test" && req.method === "POST") { if (!env.TELEGRAM_BOT_TOKEN) return json({ error: "not configured" }, 400);
    const ls = (await tgLinks(env)).filter((l) => l.user_id === user.id); let n = 0; for (const l of ls) n += await sendDigests(env, l.chat_id); return json({ sent: n }); }
  if (path === "/api/backups" && req.method === "GET") {
    if (user.role !== "admin") return forbid();
    const { results } = await env.DB.prepare("SELECT id, created, kind, docs, size, author FROM backups ORDER BY created DESC").all();
    return json({ backups: results });
  }
  if (path === "/api/backups" && req.method === "POST") {
    if (user.role !== "admin") return forbid();
    return json(await makeBackup(env, "manual", user.name));
  }
  const bm = path.match(/^\/api\/backups\/([0-9a-f-]{36})$/);
  if (bm && req.method === "GET") {
    if (user.role !== "admin") return forbid();
    const b = await env.DB.prepare("SELECT created FROM backups WHERE id = ?").bind(bm[1]).first();
    if (!b) return json({ error: "not found" }, 404);
    const { results } = await env.DB.prepare("SELECT data FROM backup_chunks WHERE backup_id = ? ORDER BY idx").bind(bm[1]).all();
    const parts = results.map((r) => new Uint8Array(r.data)); const out = new Uint8Array(parts.reduce((t, p) => t + p.length, 0)); let o = 0; for (const p of parts) { out.set(p, o); o += p.length; }
    return new Response(out, { headers: { "content-type": "application/gzip", "content-disposition": "attachment; filename=klg-agro-backup-" + b.created.slice(0, 16).replace(/[:T]/g, "-") + ".json.gz", "cache-control": "no-store" } });
  }
  if (bm && req.method === "DELETE") {
    if (user.role !== "admin") return forbid();
    await env.DB.batch([env.DB.prepare("DELETE FROM backup_chunks WHERE backup_id = ?").bind(bm[1]), env.DB.prepare("DELETE FROM backups WHERE id = ?").bind(bm[1])]);
    return json({ ok: true });
  }
  if (path === "/api/export" && req.method === "GET") {
    if (user.role !== "admin") return forbid();
    return new Response(JSON.stringify(await snapshot(env)), { headers: { "content-type": "application/json; charset=utf-8", "content-disposition": "attachment; filename=klg-agro-export-" + new Date().toISOString().slice(0, 10) + ".json", "cache-control": "no-store" } });
  }
  if (path === "/api/import" && req.method === "POST") {
    if (user.role !== "admin") return forbid();
    const mode = url.searchParams.get("mode") === "replace" ? "replace" : "merge";
    let snap; try { snap = await req.json(); } catch (e) { return json({ error: "Файл не є резервною копією" }, 400); }
    if (!snap || snap.app !== "klg-agro-pole" || !Array.isArray(snap.docs)) return json({ error: "Файл не є резервною копією AgroPulse" }, 400);
    await makeBackup(env, "before-restore", user.name);
    const updated = new Date().toISOString(); const stmts = []; const keep = new Set();
    for (const d of snap.docs) { if (!COLS.has(d.col) || !ID_RE.test(String(d.id || "")) || !d.data || typeof d.data !== "object") continue; keep.add(d.col + "|" + d.id);
      stmts.push(env.DB.prepare("INSERT INTO docs (col, id, data, updated, deleted) VALUES (?, ?, ?, ?, 0) ON CONFLICT(col, id) DO UPDATE SET data = excluded.data, updated = excluded.updated, deleted = 0").bind(d.col, d.id, JSON.stringify(d.data), updated)); }
    let removed = 0;
    if (mode === "replace") { const { results } = await env.DB.prepare("SELECT col, id FROM docs WHERE deleted = 0").all(); for (const r of results) if (!keep.has(r.col + "|" + r.id)) { removed++; stmts.push(env.DB.prepare("UPDATE docs SET data = '{}', deleted = 1, updated = ? WHERE col = ? AND id = ?").bind(updated, r.col, r.id)); } }
    for (let i = 0; i < stmts.length; i += 50) await env.DB.batch(stmts.slice(i, i + 50));
    return json({ ok: true, restored: keep.size, removed, mode });
  }
  if (path.startsWith("/api/ndvi/") && req.method === "POST") {
    if (!env.CDSE_CLIENT_ID || !env.CDSE_CLIENT_SECRET) return json({ error: "ndvi_not_configured" }, 503);
    const b = await req.json().catch(() => ({}));
    const g = b.geometry;
    if (!g || !["Polygon", "MultiPolygon"].includes(g.type) || JSON.stringify(g).length > 200000) return json({ error: "bad geometry" }, 400);
    const kind = path === "/api/ndvi/stats" ? "stats" : path === "/api/ndvi/image" ? "image" : "";
    if (!kind) return json({ error: "not found" }, 404);
    const okDate = (d) => /^\d{4}-\d{2}-\d{2}$/.test(d || "");
    const cacheKey = new Request("https://cache.klg/ndvi/" + kind + "/" + (await hmacHex("k", JSON.stringify([g, b.from, b.to, b.date, b.width]))));
    let cached = null; try { cached = await caches.default.match(cacheKey); } catch (e) {} if (cached) return cached;
    const token = await cdseToken(env);
    const shPost = async (paths, body) => { for (const pth of paths) { const r = await fetch("https://sh.dataspace.copernicus.eu" + pth, { method: "POST", headers: { authorization: "Bearer " + token, "content-type": "application/json", accept: kind === "image" ? "image/png" : "application/json" }, body: JSON.stringify(body) }); if (r.status !== 404) return r; } return null; };
    const bounds = { geometry: g, properties: { crs: "http://www.opengis.net/def/crs/EPSG/0/4326" } };
    let resp;
    if (kind === "stats") {
      if (!okDate(b.from) || !okDate(b.to)) return json({ error: "bad dates" }, 400);
      const evalscript = `//VERSION=3
function setup(){return{input:[{bands:["B04","B08","SCL","dataMask"]}],output:[{id:"ndvi",bands:1,sampleType:"FLOAT32"},{id:"dataMask",bands:1}]};}
function evaluatePixel(s){const bad=[0,1,3,8,9,10,11].indexOf(s.SCL)>=0;const v=(s.B08-s.B04)/(s.B08+s.B04+1e-6);return{ndvi:[v],dataMask:[s.dataMask&&!bad?1:0]};}`;
      const r = await shPost(["/statistics/v1", "/api/v1/statistics"], { input: { bounds, data: [{ type: "sentinel-2-l2a", dataFilter: { maxCloudCoverage: 70 } }] }, aggregation: { timeRange: { from: b.from + "T00:00:00Z", to: b.to + "T23:59:59Z" }, aggregationInterval: { of: "P1D" }, evalscript, resx: 0.0001, resy: 0.0001 }, calculations: { default: {} } });
      if (!r || !r.ok) return json({ error: "cdse " + (r ? r.status : "no response"), detail: r ? (await r.text()).slice(0, 300) : "" }, 502);
      const j = await r.json();
      const pts = (j.data || []).map((d) => { const st = (((d.outputs || {}).ndvi || {}).bands || {}).B0 || {}; const s2 = st.stats || {}; const total = (s2.sampleCount || 0); const valid = total - (s2.noDataCount || 0);
        return { date: (d.interval || {}).from ? d.interval.from.slice(0, 10) : "", mean: s2.mean, min: s2.min, max: s2.max, p: total ? valid / total : 0 }; }).filter((x) => x.date && x.p >= 0.5 && Number.isFinite(x.mean));
      resp = json({ points: pts });
    } else {
      if (!okDate(b.date)) return json({ error: "bad date" }, 400);
      const w = Math.max(64, Math.min(1400, Math.round(Number(b.width) || 512))), h = Math.max(64, Math.min(1400, Math.round(Number(b.height) || 512)));
      const evalscript = `//VERSION=3
function setup(){return{input:[{bands:["B04","B08","SCL","dataMask"]}],output:{bands:4}};}
const ramp=[[-1,[0.55,0.35,0.2]],[0,[0.75,0.6,0.4]],[0.2,[0.93,0.86,0.45]],[0.35,[0.75,0.87,0.35]],[0.5,[0.45,0.75,0.25]],[0.65,[0.2,0.6,0.15]],[0.8,[0.05,0.4,0.08]]];
function col(v){for(let i=ramp.length-1;i>=0;i--){if(v>=ramp[i][0]){if(i==ramp.length-1)return ramp[i][1];const a=ramp[i],b=ramp[i+1],t=(v-a[0])/(b[0]-a[0]);return [0,1,2].map(k=>a[1][k]+(b[1][k]-a[1][k])*t);}}return ramp[0][1];}
function evaluatePixel(s){const bad=[0,1,3,8,9,10,11].indexOf(s.SCL)>=0;if(!s.dataMask)return[0,0,0,0];if(bad)return[0.85,0.85,0.85,0.75];const v=(s.B08-s.B04)/(s.B08+s.B04+1e-6);const c=col(v);return[c[0],c[1],c[2],1];}`;
      const r = await shPost(["/process/v1", "/api/v1/process"], { input: { bounds, data: [{ type: "sentinel-2-l2a", dataFilter: { timeRange: { from: b.date + "T00:00:00Z", to: b.date + "T23:59:59Z" }, mosaickingOrder: "leastCC" } }] }, output: { width: w, height: h, responses: [{ identifier: "default", format: { type: "image/png" } }] }, evalscript });
      if (!r || !r.ok) return json({ error: "cdse " + (r ? r.status : "no response"), detail: r ? (await r.text()).slice(0, 300) : "" }, 502);
      resp = new Response(await r.arrayBuffer(), { headers: { "content-type": "image/png" } });
    }
    const toCache = new Response(resp.clone().body, { headers: { "content-type": resp.headers.get("content-type"), "cache-control": "max-age=43200" } });
    try { await caches.default.put(cacheKey, toCache); } catch (e) {}
    return resp;
  }
  if (path === "/api/weather" && req.method === "GET") {
    const lat = Number(url.searchParams.get("lat")), lon = Number(url.searchParams.get("lon"));
    if (!(lat > 40 && lat < 55 && lon > 20 && lon < 45)) return json({ error: "bad coordinates" }, 400);
    const from = url.searchParams.get("from") || "";
    const q = "latitude=" + lat.toFixed(4) + "&longitude=" + lon.toFixed(4) + "&timezone=Europe%2FKyiv";
    const get = async (u) => { const r = await fetch(u, { cf: { cacheTtl: 1800, cacheEverything: true } }); return r.ok ? r.json() : null; };
    const forecast = await get("https://api.open-meteo.com/v1/forecast?" + q + "&current=temperature_2m,weather_code,wind_speed_10m&daily=temperature_2m_max,temperature_2m_min,precipitation_sum,wind_speed_10m_max,weather_code&past_days=31&forecast_days=8");
    let history = null;
    if (/^\d{4}-\d{2}-\d{2}$/.test(from)) {
      const end = new Date(Date.now() - 5 * 864e5).toISOString().slice(0, 10);
      const start = from > end ? end : from;
      if ((new Date(end) - new Date(start)) / 864e5 < 450) history = await get("https://archive-api.open-meteo.com/v1/archive?" + q + "&start_date=" + start + "&end_date=" + end + "&daily=temperature_2m_max,temperature_2m_min,precipitation_sum");
    }
    return json({ forecast, history });
  }
  if (path === "/api/wms" && req.method === "GET") {
    const bbox = url.searchParams.get("bbox") || "";
    if (!/^-?\d+(\.\d+)?(,-?\d+(\.\d+)?){3}$/.test(bbox)) return json({ error: "bad bbox" }, 400);
    const layer = url.searchParams.get("layer") === "ikk" ? "ikk" : "kadastr";
    const src = "https://map.land.gov.ua/geowebcache/service/wms?SERVICE=WMS&VERSION=1.1.1&REQUEST=GetMap&LAYERS=" + layer + "&STYLES=&FORMAT=image/png&TRANSPARENT=TRUE&SRS=EPSG:900913&WIDTH=256&HEIGHT=256&BBOX=" + bbox;
    try {
      const r = await fetch(src, { cf: { cacheTtl: 86400, cacheEverything: true }, headers: { "user-agent": "Mozilla/5.0 KLG-Agro-Pole" } });
      if (!r.ok) return new Response("", { status: 204 });
      return new Response(r.body, { headers: { "content-type": r.headers.get("content-type") || "image/png", "cache-control": "private, max-age=86400" } });
    } catch (e) { return new Response("", { status: 204 }); }
  }
  const m = path.match(/^\/api\/doc\/([a-z]+)\/([^/]+)$/);
  if (m) {
    const col = m[1], id = decodeURIComponent(m[2]);
    if (!COLS.has(col) || !ID_RE.test(id)) return json({ error: "bad path" }, 400);
    if (req.method !== "GET" && !canWriteCol(user, col)) return forbid();
    const updated = new Date().toISOString();
    if (req.method === "PUT") {
      const text = await req.text();
      if (text.length > 900000) return json({ error: "document too large" }, 413);
      let data;
      try { data = JSON.parse(text); } catch (e) { return json({ error: "bad json" }, 400); }
      if (!data || typeof data !== "object" || Array.isArray(data)) return json({ error: "body must be an object" }, 400);
      data.updatedBy = user.name;
      if (col === "scoutreports" && env.TELEGRAM_BOT_TOKEN) { const sev = Math.max(0, ...(data.threats || []).map((t) => Number(t.severity) || 0)); const prev = await env.DB.prepare("SELECT data FROM docs WHERE col = ? AND id = ?").bind(col, id).first();
        const prevSev = prev ? Math.max(0, ...((JSON.parse(prev.data).threats) || []).map((t) => Number(t.severity) || 0)) : 0;
        if (sev >= 30 && prevSev < 30) { const f = await env.DB.prepare("SELECT data FROM docs WHERE col = 'fields' AND id = ?").bind(data.fieldId || "").first(); const fname = f ? JSON.parse(f.data).name : "";
          await tgNotifyRoles(env, ["admin", "agronomist"], `🚨 <b>Огляд поля ${tgEsc(fname)}</b>: ураження до ${sev}%\n${tgEsc(data.note || "")}\nАвтор: ${tgEsc(user.name)}`).catch(() => {}); } }
      await env.DB.prepare("INSERT INTO docs (col, id, data, updated, deleted) VALUES (?, ?, ?, ?, 0) ON CONFLICT(col, id) DO UPDATE SET data = excluded.data, updated = excluded.updated, deleted = 0")
        .bind(col, id, JSON.stringify(data), updated).run();
      return json({ ok: true, updated });
    }
    if (req.method === "DELETE") {
      await env.DB.prepare("INSERT INTO docs (col, id, data, updated, deleted) VALUES (?, ?, '{}', ?, 1) ON CONFLICT(col, id) DO UPDATE SET data = '{}', updated = excluded.updated, deleted = 1")
        .bind(col, id, updated).run();
      return json({ ok: true, updated });
    }
  }
  return json({ error: "not found" }, 404);
}

async function snapshot(env) {
  const { results } = await env.DB.prepare("SELECT col, id, data FROM docs WHERE deleted = 0").all();
  const { results: files } = await env.DB.prepare("SELECT id, col, doc, name, type, size, created FROM files").all();
  return { app: "klg-agro-pole", version: 1, created: new Date().toISOString(), docs: results.map((r) => ({ col: r.col, id: r.id, data: JSON.parse(r.data) })), files };
}
async function makeBackup(env, kind, author) {
  const snap = await snapshot(env);
  const gz = new Uint8Array(await new Response(new Blob([JSON.stringify(snap)]).stream().pipeThrough(new CompressionStream("gzip"))).arrayBuffer());
  const id = crypto.randomUUID(); const CH = 512 * 1024;
  const stmts = [env.DB.prepare("INSERT INTO backups (id, created, kind, docs, size, author) VALUES (?, ?, ?, ?, ?, ?)").bind(id, snap.created, kind, snap.docs.length, gz.length, author || "")];
  for (let i = 0, n = 0; i < gz.length; i += CH, n++) stmts.push(env.DB.prepare("INSERT INTO backup_chunks (backup_id, idx, data) VALUES (?, ?, ?)").bind(id, n, gz.slice(i, i + CH).buffer));
  for (let i = 0; i < stmts.length; i += 10) await env.DB.batch(stmts.slice(i, i + 10));
  const { results: old } = await env.DB.prepare("SELECT id FROM backups WHERE kind = 'auto' ORDER BY created DESC LIMIT -1 OFFSET 30").all();
  for (const o of old) await env.DB.batch([env.DB.prepare("DELETE FROM backup_chunks WHERE backup_id = ?").bind(o.id), env.DB.prepare("DELETE FROM backups WHERE id = ?").bind(o.id)]);
  return { ok: true, id, docs: snap.docs.length, size: gz.length, created: snap.created };
}
async function ensureSchema(db) {
  if (schemaReady) return;
  await db.prepare("CREATE TABLE IF NOT EXISTS docs (col TEXT NOT NULL, id TEXT NOT NULL, data TEXT NOT NULL, updated TEXT NOT NULL, deleted INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (col, id))").run();
  await db.prepare("CREATE INDEX IF NOT EXISTS docs_updated ON docs (updated)").run();
  await db.prepare("CREATE TABLE IF NOT EXISTS users (id TEXT PRIMARY KEY, login TEXT UNIQUE NOT NULL, name TEXT, role TEXT, hash TEXT, salt TEXT, active INTEGER DEFAULT 1, created TEXT, last_login TEXT)").run();
  await db.prepare("CREATE TABLE IF NOT EXISTS tg_links (chat_id TEXT PRIMARY KEY, user_id TEXT, name TEXT, role TEXT, created TEXT)").run();
  await db.prepare("CREATE TABLE IF NOT EXISTS tg_codes (code TEXT PRIMARY KEY, user_id TEXT, name TEXT, role TEXT, exp INTEGER)").run();
  await db.prepare("CREATE TABLE IF NOT EXISTS backups (id TEXT PRIMARY KEY, created TEXT, kind TEXT, docs INTEGER, size INTEGER, author TEXT)").run();
  await db.prepare("CREATE TABLE IF NOT EXISTS backup_chunks (backup_id TEXT NOT NULL, idx INTEGER NOT NULL, data BLOB NOT NULL, PRIMARY KEY (backup_id, idx))").run();
  await db.prepare("CREATE TABLE IF NOT EXISTS files (id TEXT PRIMARY KEY, col TEXT NOT NULL, doc TEXT NOT NULL, name TEXT NOT NULL, type TEXT, size INTEGER, created TEXT)").run();
  await db.prepare("CREATE INDEX IF NOT EXISTS files_doc ON files (col, doc)").run();
  await db.prepare("CREATE TABLE IF NOT EXISTS file_chunks (file_id TEXT NOT NULL, idx INTEGER NOT NULL, data BLOB NOT NULL, PRIMARY KEY (file_id, idx))").run();
  schemaReady = true;
}
function rowOut(r) {
  return { col: r.col, id: r.id, updated: r.updated, deleted: r.deleted ? 1 : 0, data: r.deleted ? {} : JSON.parse(r.data) };
}
function json(obj, status = 200, extra = {}) {
  return new Response(JSON.stringify(obj), { status, headers: Object.assign({ "content-type": "application/json; charset=utf-8", "cache-control": "no-store" }, extra) });
}
async function sessionToken(secret) {
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode("klg-agro-session-v1"));
  return [...new Uint8Array(sig)].map((b) => b.toString(16).padStart(2, "0")).join("");
}
async function safeEqual(a, b) {
  const enc = new TextEncoder();
  const [ha, hb] = await Promise.all([crypto.subtle.digest("SHA-256", enc.encode(a)), crypto.subtle.digest("SHA-256", enc.encode(b))]);
  const x = new Uint8Array(ha), y = new Uint8Array(hb);
  let d = 0; for (let i = 0; i < x.length; i++) d |= x[i] ^ y[i];
  return d === 0;
}

/* ---------- Telegram notifications ---------- */
const TG = (env, method, body) => fetch("https://api.telegram.org/bot" + env.TELEGRAM_BOT_TOKEN + "/" + method, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body || {}) }).then((r) => r.json()).catch(() => ({ ok: false }));
const tgEsc = (s) => String(s ?? "").replace(/[&<>]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;" }[c]));
async function tgHookPath(env) { return "/tg/hook/" + (await hmacHex(env.APP_PASSWORD, "tg-hook")).slice(0, 32); }
async function tgSend(env, chatId, text) { return TG(env, "sendMessage", { chat_id: chatId, text, parse_mode: "HTML", disable_web_page_preview: true }); }
async function tgLinks(env) { const { results } = await env.DB.prepare("SELECT chat_id, user_id, name, role FROM tg_links").all(); return results; }
async function loadAll(env) { const { results } = await env.DB.prepare("SELECT col, id, data FROM docs WHERE deleted = 0").all(); const S = {}; for (const r of results) (S[r.col] ||= []).push(Object.assign({ id: r.id }, JSON.parse(r.data))); return S; }
const nn = (v) => { const x = parseFloat(String(v ?? "").replace(",", ".")); return Number.isFinite(x) ? x : 0; };
const kyivToday = () => new Date(Date.now() + 2 * 3600e3).toISOString().slice(0, 10);
const fd = (s) => (s ? s.slice(8, 10) + "." + s.slice(5, 7) : "—");
function digestSections(S, origin) {
  const td = kyivToday(), g = (c) => S[c] || [], by = (c, id) => g(c).find((x) => x.id === id) || {};
  const out = {};
  // leases ending within 30 days or ended in the last 30 days without auto-renewal
  const lim = new Date(Date.now() + 30 * 864e5).toISOString().slice(0, 10), past = new Date(Date.now() - 30 * 864e5).toISOString().slice(0, 10);
  const ls = g("leases").filter((l) => !l.archived && !l.autoRenew && l.status !== "розірваний").filter((l) => !l.factEnd).map((l) => ({ l, end: l.dateTo })).filter((x) => x.end && x.end <= lim && x.end >= past).sort((a, b) => a.end.localeCompare(b.end));
  if (ls.length) out.land = "📄 <b>Договори оренди, що закінчуються</b>\n" + ls.slice(0, 12).map((x) => `• ${tgEsc(x.l.number || "#")} — ${tgEsc(by("owners", x.l.ownerId).name || "")}, до ${fd(x.end)}${x.end < td ? " ❗ закінчився" : ""}`).join("\n") + (ls.length > 12 ? `\n…ще ${ls.length - 12}` : "");
  // maintenance due by plans
  const reading = (mid) => { let km = 0, mh = 0; g("fuelings").filter((f) => f.machineId === mid).forEach((f) => { km = Math.max(km, nn(f.odometer)); mh = Math.max(mh, nn(f.motohours)); }); g("service").filter((s) => s.machineId === mid && s.status === "done").forEach((s) => { km = Math.max(km, nn(s.km)); mh = Math.max(mh, nn(s.mh)); }); return { km, mh }; };
  const late = [];
  g("mplans").filter((p) => !p.archived).forEach((p) => g("machines").filter((x) => ((p.machineIds || []).length ? p.machineIds.includes(x.id) : (!p.subtype || p.subtype === x.subtype) && (!p.type || p.type === (x.type || "Агро")))).forEach((x) => {
    const last = g("service").filter((s) => s.machineId === x.id && s.status === "done" && (s.planId === p.id || s.kind === p.name)).sort((a, b) => (b.date || "").localeCompare(a.date || ""))[0]; if (!last) return;
    const r = reading(x.id); const why = [];
    if (nn(p.everyKm) && r.km - nn(last.km) >= nn(p.everyKm)) why.push("пробіг");
    if (nn(p.everyMh) && r.mh - nn(last.mh) >= nn(p.everyMh)) why.push("мотогодини");
    if (nn(p.everyDays) && last.date && (new Date(td) - new Date(last.date)) / 864e5 >= nn(p.everyDays)) why.push("строк");
    if (why.length) late.push(`• ${tgEsc(x.name)} — ${tgEsc(p.name)} (${why.join(", ")})`);
  }));
  const planned = g("service").filter((s) => s.status !== "done" && s.date && s.date <= td).map((s) => `• ${tgEsc(by("machines", s.machineId).name || "")} — ${tgEsc(s.kind || "ТО")}, план на ${fd(s.date)}`);
  if (late.length || planned.length) out.mech = "🔧 <b>Обслуговування техніки</b>\n" + [...late, ...planned].slice(0, 15).join("\n");
  // fuel stations below 15% of capacity (quantity replay)
  const qty = {}; const key = (w, p) => w + "|" + p; const add = (w, p, q) => { qty[key(w, p)] = (qty[key(w, p)] || 0) + q; };
  const fuelD = g("fuelings").map((f) => { const st = by("fuelstations", f.stationId); return st.warehouseId && f.productId ? { kind: "issue", status: "posted", date: f.date, createdAt: (f.date || "") + (f.time || ""), from: st.warehouseId, lines: [{ productId: f.productId, qty: f.liters }] } : null; }).filter(Boolean);
  [...g("whdocs"), ...fuelD].filter((d) => d.status === "posted").sort((a, b) => ((a.date || "") + (a.createdAt || "")).localeCompare((b.date || "") + (b.createdAt || ""))).forEach((d) => {
    const L = d.lines || [];
    if (d.kind === "receipt") L.forEach((l) => add(d.to, l.productId, nn(l.qty)));
    if (d.kind === "issue") L.forEach((l) => add(d.from, l.productId, -nn(l.qty)));
    if (d.kind === "transfer") L.forEach((l) => { add(d.from, l.productId, -nn(l.qty)); add(d.to, l.productId, nn(l.qty)); });
    if (d.kind === "inventory") L.forEach((l) => { qty[key(d.to, l.productId)] = nn(l.fact); });
    if (d.kind === "production") { (d.inputs || []).forEach((l) => add(d.from, l.productId, -nn(l.qty))); L.forEach((l) => add(d.to, l.productId, nn(l.qty))); }
  });
  const low = g("fuelstations").filter((s) => s.warehouseId && s.productId && nn(s.capacity)).map((s) => ({ s, q: qty[key(s.warehouseId, s.productId)] || 0 })).filter((x) => x.q < nn(x.s.capacity) * 0.15);
  const neg = Object.entries(qty).filter(([, q]) => q < -1e-6).map(([k, q]) => { const [w, p] = k.split("|"); return `• ${tgEsc(by("products", p).name || "?")} на «${tgEsc(by("warehouses", w).name || "?")}»: ${q.toFixed(1)}`; });
  if (low.length || neg.length) out.store = "⛽ <b>Склад і пальне</b>\n" + [...low.map((x) => `• АЗС «${tgEsc(x.s.name)}»: залишок ${Math.round(x.q)} л з ${Math.round(nn(x.s.capacity))}`), ...neg.map((s) => s + " (від’ємний залишок)")].join("\n");
  // agronomy: overdue operations and fresh scouting with high damage
  const overdue = g("ops").filter((o) => (o.status || "planned") !== "done" && o.status !== "cancel" && o.plannedTo && o.plannedTo < td);
  const today = g("ops").filter((o) => (o.status || "planned") === "planned" && o.plannedFrom === td);
  const yest = new Date(Date.now() - 864e5).toISOString().slice(0, 10);
  const hot = g("scoutreports").filter((r) => (r.date || "") >= yest && Math.max(0, ...(r.threats || []).map((t) => nn(t.severity))) >= 20);
  const agro = [];
  if (today.length) agro.push(`Заплановано на сьогодні: ${today.length}\n` + today.slice(0, 8).map((o) => `• ${tgEsc(o.workType)} — ${tgEsc(by("fields", o.fieldId).name || "")}`).join("\n"));
  if (overdue.length) agro.push(`Прострочені агрооперації: ${overdue.length}\n` + overdue.slice(0, 8).map((o) => `• ${tgEsc(o.workType)} — ${tgEsc(by("fields", o.fieldId).name || "")}, план до ${fd(o.plannedTo)}`).join("\n"));
  if (hot.length) agro.push("Огляди з високим ураженням:\n" + hot.slice(0, 8).map((r) => `• ${tgEsc(by("fields", r.fieldId).name || "")}: ` + (r.threats || []).map((t) => `${tgEsc(by("plantthreats", t.threatId).name || "")} ${nn(t.severity)}%`).join(", ")).join("\n"));
  if (agro.length) out.agro = "🌱 <b>Агрономія</b>\n" + agro.join("\n\n");
  return out;
}
const ROLE_SECTIONS = { admin: ["agro", "mech", "store", "land", "wx"], agronomist: ["agro", "wx"], mechanic: ["mech", "store"], storekeeper: ["store"], land: ["land"], accountant: ["land"], viewer: [] };
async function sprayWeather(S) {
  const fs = (S.fields || []).filter((f) => !f.archived && f.contours && f.contours.length); if (!fs.length) return "";
  let x = 0, y = 0, n = 0; fs.forEach((f) => f.contours.forEach((r) => r.forEach((p) => { x += p[0]; y += p[1]; n++; })));
  const r = await fetch(`https://api.open-meteo.com/v1/forecast?latitude=${(y / n).toFixed(3)}&longitude=${(x / n).toFixed(3)}&timezone=Europe%2FKyiv&daily=temperature_2m_max,temperature_2m_min,precipitation_sum,wind_speed_10m_max&forecast_days=2`).then((r) => r.json()).catch(() => null);
  if (!r || !r.daily) return "";
  const d = r.daily; const line = (i, lbl) => { const w = d.wind_speed_10m_max[i] / 3.6, p = d.precipitation_sum[i], t = d.temperature_2m_max[i]; const ok = w <= 5 && p < 1 && t <= 25; return `${lbl}: ${Math.round(d.temperature_2m_min[i])}…${Math.round(t)}°, вітер до ${w.toFixed(1)} м/с, опади ${p.toFixed(1)} мм — ${ok ? "✅ можна обприскувати" : "⚠️ обприскування обмежене"}`; };
  return "🌦 <b>Погода по господарству</b>\n" + line(0, "Сьогодні") + "\n" + line(1, "Завтра");
}
async function sendDigests(env, onlyChat) {
  await ensureSchema(env.DB);
  const links = (await tgLinks(env)).filter((l) => !onlyChat || String(l.chat_id) === String(onlyChat)); if (!links.length) return 0;
  const S = await loadAll(env); const sec = digestSections(S); const wx = links.some((l) => (ROLE_SECTIONS[l.role] || []).includes("wx")) ? await sprayWeather(S) : "";
  let sent = 0;
  for (const l of links) {
    const parts = (ROLE_SECTIONS[l.role] || []).map((k) => (k === "wx" ? wx : sec[k])).filter(Boolean);
    const text = `<b>AgroPulse · ${fd(kyivToday())}</b>\n\n` + (parts.length ? parts.join("\n\n") : "Усе спокійно: термінових подій немає ✅");
    const r = await tgSend(env, l.chat_id, text.slice(0, 4000)); if (r.ok) sent++;
  }
  return sent;
}
async function tgNotifyRoles(env, roles, text) { if (!env.TELEGRAM_BOT_TOKEN) return; await ensureSchema(env.DB); for (const l of await tgLinks(env)) if (roles.includes(l.role)) await tgSend(env, l.chat_id, text); }
async function handleTgHook(req, env) {
  if (req.headers.get("x-telegram-bot-api-secret-token") !== (await hmacHex(env.APP_PASSWORD, "tg-secret")).slice(0, 48)) return new Response("forbidden", { status: 403 });
  const up = await req.json().catch(() => ({})); const msg = up.message || {}; const chat = (msg.chat || {}).id; const text = String(msg.text || "").trim();
  if (!chat) return new Response("ok");
  await ensureSchema(env.DB);
  const m = text.match(/^\/start\s+([A-Z0-9]{6,12})$/i);
  if (m) {
    const c = await env.DB.prepare("SELECT user_id, name, role, exp FROM tg_codes WHERE code = ?").bind(m[1].toUpperCase()).first();
    if (!c || c.exp < Date.now()) { await tgSend(env, chat, "Код недійсний або застарів. Отримайте новий у програмі: меню внизу → «Telegram»."); return new Response("ok"); }
    await env.DB.batch([env.DB.prepare("INSERT INTO tg_links (chat_id, user_id, name, role, created) VALUES (?, ?, ?, ?, ?) ON CONFLICT(chat_id) DO UPDATE SET user_id = excluded.user_id, name = excluded.name, role = excluded.role").bind(String(chat), c.user_id, c.name, c.role, new Date().toISOString()), env.DB.prepare("DELETE FROM tg_codes WHERE code = ?").bind(m[1].toUpperCase())]);
    await tgSend(env, chat, `Готово, ${tgEsc(c.name)}! Щоранку о 7:00 надсилатиму зведення для ролі «${tgEsc((ROLES[c.role] || {}).name || c.role)}».\n\n/digest — зведення зараз\n/stop — відписатися`);
  } else if (/^\/stop/.test(text)) { await env.DB.prepare("DELETE FROM tg_links WHERE chat_id = ?").bind(String(chat)).run(); await tgSend(env, chat, "Сповіщення вимкнено. Підключитися знову можна з програми."); }
  else if (/^\/digest/.test(text)) { const n = await sendDigests(env, chat); if (!n) await tgSend(env, chat, "Цей чат ще не підключено. Отримайте код у програмі: меню внизу → «Telegram»."); }
  else await tgSend(env, chat, "Щоб підключити сповіщення, відкрийте програму AgroPulse → меню внизу → «Telegram» і натисніть посилання з кодом.\n\n/digest — зведення зараз\n/stop — відписатися");
  return new Response("ok");
}

/* ---------- АгроОблік: приймання даних через конектор (MCP) ---------- */
const AO_COLS = { fields: "aofields", waybills: "aowaybills", lzk: "aolzk", items: "aoitems" };
async function aoMcpPath(env) { return "/mcp/" + (await hmacHex(env.APP_PASSWORD, "agrooblik-mcp")).slice(0, 40); }
async function aoStatus(env) {
  await ensureSchema(env.DB); const out = {};
  for (const [k, col] of Object.entries(AO_COLS)) {
    const r = await env.DB.prepare("SELECT COUNT(*) AS n, MAX(CAST(json_extract(data, '$.ts') AS REAL)) AS ts, MAX(updated) AS up FROM docs WHERE col = ? AND deleted = 0").bind(col).first();
    out[k] = { count: (r && r.n) || 0, max_ts: (r && r.ts) || 0, last_received: (r && r.up) || null };
  }
  const s = await env.DB.prepare("SELECT data FROM docs WHERE col = 'settings' AND id = 'agrooblik'").first();
  return { collections: out, last_sync: s ? JSON.parse(s.data).lastSync || null : null };
}
async function aoPush(env, a) {
  const col = AO_COLS[a.collection]; if (!col) throw new Error("collection має бути одним із: " + Object.keys(AO_COLS).join(", "));
  const recs = Array.isArray(a.records) ? a.records : []; if (recs.length > 1000) throw new Error("не більше 1000 записів за виклик");
  const updated = new Date().toISOString(); const st = []; let bad = 0; const ids = new Set();
  for (const r0 of recs) {
    if (!r0 || typeof r0 !== "object") { bad++; continue; }
    const r = r0.data && typeof r0.data === "object" && r0.id ? Object.assign({}, r0.data) : Object.assign({}, r0); const id = String(r0.id || r.id || ""); delete r.id;
    if (!ID_RE.test(id)) { bad++; continue; } ids.add(id);
    st.push(env.DB.prepare("INSERT INTO docs (col, id, data, updated, deleted) VALUES (?, ?, ?, ?, 0) ON CONFLICT(col, id) DO UPDATE SET data = excluded.data, updated = excluded.updated, deleted = 0 WHERE docs.data <> excluded.data OR docs.deleted = 1").bind(col, id, JSON.stringify(r), updated));
  }
  for (let i = 0; i < st.length; i += 100) await env.DB.batch(st.slice(i, i + 100));
  let removed = 0;
  if (a.replace_all) {
    const { results } = await env.DB.prepare("SELECT id FROM docs WHERE col = ? AND deleted = 0").bind(col).all();
    const del = results.map((x) => x.id).filter((id) => !ids.has(id)); removed = del.length;
    for (let i = 0; i < del.length; i += 100) await env.DB.batch(del.slice(i, i + 100).map((id) => env.DB.prepare("UPDATE docs SET data = '{}', deleted = 1, updated = ? WHERE col = ? AND id = ?").bind(updated, col, id)));
  }
  if (Array.isArray(a.all_ids)) {
    const keep = new Set(a.all_ids.map(String)); recs.forEach((r) => keep.add(String(r.id || (r.data && r.data.id) || "")));
    const { results } = await env.DB.prepare("SELECT id FROM docs WHERE col = ? AND deleted = 0").bind(col).all();
    const del = results.map((x) => x.id).filter((id) => !keep.has(id)); removed += del.length;
    for (let i = 0; i < del.length; i += 100) await env.DB.batch(del.slice(i, i + 100).map((id) => env.DB.prepare("UPDATE docs SET data = '{}', deleted = 1, updated = ? WHERE col = ? AND id = ?").bind(updated, col, id)));
  }
  if (Array.isArray(a.deleted_ids) && a.deleted_ids.length) { const del = a.deleted_ids.map(String).filter((id) => ID_RE.test(id)); removed += del.length;
    for (let i = 0; i < del.length; i += 100) await env.DB.batch(del.slice(i, i + 100).map((id) => env.DB.prepare("UPDATE docs SET data = '{}', deleted = 1, updated = ? WHERE col = ? AND id = ?").bind(updated, col, id))); }
  await env.DB.prepare("INSERT INTO docs (col, id, data, updated, deleted) VALUES ('settings', 'agrooblik', ?, ?, 0) ON CONFLICT(col, id) DO UPDATE SET data = json_set(docs.data, '$.lastSync', ?), updated = excluded.updated, deleted = 0").bind(JSON.stringify({ lastSync: updated }), updated, updated).run();
  return { collection: a.collection, received: recs.length, saved: st.length, skipped: bad, removed };
}
const AO_TOOLS = [
  { name: "agrooblik_status", description: "Стан даних АгроОбліку в програмі AgroPulse: скільки записів кожної колекції вже отримано і найбільше значення поля ts (для інкрементальної синхронізації: надсилайте записи з ts більшим за max_ts).", inputSchema: { type: "object", properties: {} } },
  { name: "agrooblik_push", description: "Записати в AgroPulse записи з бази артефакту АгроОблік. collection: fields | waybills | lzk | items. records: масив документів у тому вигляді, як їх повертає база артефакту ({id, data:{...}}) або плоскі об'єкти з полем id. Повторне надсилання того самого запису його оновлює, дублікатів не буде. replace_all=true означає, що надіслано ПОВНИЙ список колекції, і записи, яких у ньому немає, буде позначено видаленими (використовуйте тільки коли надсилаєте всю колекцію одним викликом). deleted_ids: id записів, видалених в АгроОбліку. all_ids: повний список id колекції в АгроОбліку (можна надіслати з порожнім records окремим викликом після всіх частин) — усе, чого в ньому немає, буде позначено видаленим. Надсилайте не більше 500 записів за виклик.", inputSchema: { type: "object", properties: { collection: { type: "string", enum: Object.keys(AO_COLS) }, records: { type: "array", items: { type: "object" } }, replace_all: { type: "boolean" }, deleted_ids: { type: "array", items: { type: "string" } }, all_ids: { type: "array", items: { type: "string" } } }, required: ["collection", "records"] } },
];
async function handleMcp(req, env) {
  if (req.method === "GET") return new Response("Method not allowed", { status: 405, headers: { allow: "POST" } });
  if (req.method === "DELETE") return new Response(null, { status: 204 });
  const msg = await req.json().catch(() => null); if (!msg) return json({ jsonrpc: "2.0", id: null, error: { code: -32700, message: "Parse error" } }, 400);
  const one = async (m) => {
    if (m.id === undefined || m.id === null) return null;
    const ok = (result) => ({ jsonrpc: "2.0", id: m.id, result }), err = (code, message) => ({ jsonrpc: "2.0", id: m.id, error: { code, message } });
    if (m.method === "initialize") return ok({ protocolVersion: (m.params && m.params.protocolVersion) || "2025-06-18", capabilities: { tools: { listChanged: false } }, serverInfo: { name: "klg-agro-pole", title: "AgroPulse", version: "1.0.0" }, instructions: "Конектор програми AgroPulse. Приймає дані з артефакту АгроОблік (шляхові листи, лімітно-забірні карти, поля, номенклатура), щоб вони автоматично з'являлися на полях." });
    if (m.method === "ping") return ok({});
    if (m.method === "tools/list") return ok({ tools: AO_TOOLS });
    if (m.method === "tools/call") {
      const name = m.params && m.params.name, a = (m.params && m.params.arguments) || {};
      try {
        let r; if (name === "agrooblik_status") r = await aoStatus(env); else if (name === "agrooblik_push") r = await aoPush(env, a); else return err(-32602, "Unknown tool: " + name);
        return ok({ content: [{ type: "text", text: JSON.stringify(r) }], structuredContent: r });
      } catch (e) { return ok({ content: [{ type: "text", text: "Помилка: " + (e.message || e) }], isError: true }); }
    }
    return err(-32601, "Method not found");
  };
  if (Array.isArray(msg)) { const out = (await Promise.all(msg.map(one))).filter(Boolean); return out.length ? json(out) : new Response(null, { status: 202 }); }
  const r = await one(msg); return r ? json(r) : new Response(null, { status: 202 });
}

/* ---------- OAuth 2.1 для конектора Claude (вхід адміністратора) ---------- */
const sha256hex = async (s) => hex(await crypto.subtle.digest("SHA-256", enc.encode(s)));
const randTok = (n = 32) => [...crypto.getRandomValues(new Uint8Array(n))].map((b) => b.toString(16).padStart(2, "0")).join("");
const b64url = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
async function oauthSchema(db) {
  await db.prepare("CREATE TABLE IF NOT EXISTS oauth_clients (id TEXT PRIMARY KEY, redirect_uris TEXT, name TEXT, created TEXT)").run();
  await db.prepare("CREATE TABLE IF NOT EXISTS oauth_codes (code TEXT PRIMARY KEY, client_id TEXT, redirect_uri TEXT, challenge TEXT, user_id TEXT, exp INTEGER)").run();
  await db.prepare("CREATE TABLE IF NOT EXISTS oauth_tokens (hash TEXT PRIMARY KEY, kind TEXT, client_id TEXT, user_id TEXT, exp INTEGER)").run();
}
async function checkLogin(env, login, pw) {
  login = String(login || "admin").trim().toLowerCase(); pw = String(pw || "");
  if (!pw) return null;
  if (login === "admin" && (await safeEqual(pw, env.APP_PASSWORD))) return ADMIN;
  const u = await env.DB.prepare("SELECT id, login, name, role, hash, salt, active FROM users WHERE login = ?").bind(login).first();
  if (!u || !u.active) return null;
  const h = await hashPassword(pw, u.salt);
  return (await safeEqual(h.hash, u.hash)) ? { id: u.id, login: u.login, name: u.name, role: u.role } : null;
}
const oaJson = (o, status = 200, extra = {}) => new Response(status === 204 ? null : JSON.stringify(o), { status, headers: Object.assign({ "content-type": "application/json", "cache-control": "no-store", "access-control-allow-origin": "*", "access-control-allow-headers": "authorization, content-type, mcp-protocol-version" }, extra) });
function oaPage(title, body) {
  return new Response(`<!doctype html><html lang="uk"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${title}</title><style>body{font:15px system-ui,sans-serif;background:#f3f5f0;color:#1d2419;display:grid;place-items:center;min-height:100vh;margin:0}form,.c{background:#fff;border:1px solid #d3dacb;border-radius:12px;padding:24px;width:min(380px,92vw);display:grid;gap:12px}h1{font-size:19px;margin:0}input{font:inherit;padding:9px 10px;border:1px solid #c9d1c1;border-radius:8px}button{font:inherit;padding:10px;border:0;border-radius:8px;background:#2f6b3a;color:#fff;cursor:pointer}.e{color:#b3402e}.n{color:#5d6857;font-size:13px}</style></head><body>${body}</body></html>`, { headers: { "content-type": "text/html; charset=utf-8", "cache-control": "no-store", "x-frame-options": "DENY" } });
}
async function handleOAuth(req, env, url) {
  const o = url.origin, p = url.pathname;
  if (req.method === "OPTIONS") return oaJson({}, 204);
  if (p.startsWith("/.well-known/oauth-protected-resource")) return oaJson({ resource: o + "/mcp", authorization_servers: [o], bearer_methods_supported: ["header"], resource_name: "AgroPulse" });
  if (p.startsWith("/.well-known/oauth-authorization-server") || p.startsWith("/.well-known/openid-configuration"))
    return oaJson({ issuer: o, authorization_endpoint: o + "/oauth/authorize", token_endpoint: o + "/oauth/token", registration_endpoint: o + "/oauth/register", response_types_supported: ["code"], grant_types_supported: ["authorization_code", "refresh_token"], code_challenge_methods_supported: ["S256"], token_endpoint_auth_methods_supported: ["none"], scopes_supported: ["agrooblik"] });
  if (p.startsWith("/.well-known/")) return oaJson({ error: "not_found" }, 404);
  await ensureSchema(env.DB); await oauthSchema(env.DB);
  if (p === "/oauth/register" && req.method === "POST") {
    const b = await req.json().catch(() => ({})); const uris = Array.isArray(b.redirect_uris) ? b.redirect_uris.map(String).filter((u) => /^https:\/\//.test(u) || /^http:\/\/(localhost|127\.0\.0\.1)/.test(u)) : [];
    if (!uris.length) return oaJson({ error: "invalid_redirect_uri" }, 400);
    const id = "c_" + randTok(16);
    await env.DB.prepare("INSERT INTO oauth_clients (id, redirect_uris, name, created) VALUES (?, ?, ?, ?)").bind(id, JSON.stringify(uris), String(b.client_name || "").slice(0, 100), new Date().toISOString()).run();
    return oaJson({ client_id: id, client_id_issued_at: Math.floor(Date.now() / 1000), redirect_uris: uris, client_name: b.client_name || "", grant_types: ["authorization_code", "refresh_token"], response_types: ["code"], token_endpoint_auth_method: "none" }, 201);
  }
  if (p === "/oauth/authorize") {
    const q = req.method === "POST" ? new URLSearchParams(await req.text()) : url.searchParams;
    const cid = q.get("client_id") || "", ru = q.get("redirect_uri") || "", ch = q.get("code_challenge") || "", st = q.get("state") || "";
    const c = await env.DB.prepare("SELECT redirect_uris, name FROM oauth_clients WHERE id = ?").bind(cid).first();
    if (!c || !JSON.parse(c.redirect_uris).includes(ru)) return oaPage("Помилка", `<div class="c"><h1>Невідомий застосунок</h1><p class="n">Спробуйте додати конектор у Claude ще раз.</p></div>`);
    if ((q.get("response_type") || "code") !== "code" || !ch || (q.get("code_challenge_method") || "S256") !== "S256") return oaPage("Помилка", `<div class="c"><h1>Непідтримуваний запит</h1></div>`);
    const hidden = ["client_id", "redirect_uri", "code_challenge", "code_challenge_method", "state", "scope", "response_type", "resource"].map((k) => q.get(k) != null ? `<input type="hidden" name="${k}" value="${String(q.get(k)).replace(/[&<>"]/g, (x) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[x]))}">` : "").join("");
    let err = "";
    if (req.method === "POST") {
      const u = await checkLogin(env, q.get("login"), q.get("password"));
      if (!u) { await new Promise((r) => setTimeout(r, 700)); err = "Неправильний логін або пароль."; }
      else if (u.role !== "admin") err = "Підключати конектор може лише адміністратор.";
      else {
        const code = randTok(24);
        await env.DB.prepare("INSERT INTO oauth_codes (code, client_id, redirect_uri, challenge, user_id, exp) VALUES (?, ?, ?, ?, ?, ?)").bind(code, cid, ru, ch, u.id, Date.now() + 10 * 60e3).run();
        const back = new URL(ru); back.searchParams.set("code", code); if (st) back.searchParams.set("state", st);
        return new Response(null, { status: 302, headers: { location: back.toString(), "cache-control": "no-store" } });
      }
    }
    return oaPage("Підключення Claude", `<form method="post" action="/oauth/authorize">${hidden}<h1>AgroPulse</h1><p class="n">Claude просить дозвіл записувати в програму дані з АгроОбліку (шляхові листи, лімітно-забірні карти, поля, номенклатуру). Увійдіть як адміністратор, щоб дозволити.</p>${err ? `<div class="e">${err}</div>` : ""}<input name="login" placeholder="Логін" value="admin" autocomplete="username"><input name="password" type="password" placeholder="Пароль" autocomplete="current-password" autofocus><button type="submit">Дозволити</button></form>`);
  }
  if (p === "/oauth/token" && req.method === "POST") {
    const ct = req.headers.get("content-type") || ""; const q = ct.includes("json") ? new URLSearchParams(Object.entries(await req.json().catch(() => ({})))) : new URLSearchParams(await req.text());
    const gt = q.get("grant_type"); let uid, cid;
    if (gt === "authorization_code") {
      const c = await env.DB.prepare("SELECT * FROM oauth_codes WHERE code = ?").bind(q.get("code") || "").first();
      await env.DB.prepare("DELETE FROM oauth_codes WHERE code = ?").bind(q.get("code") || "").run();
      if (!c || c.exp < Date.now() || c.client_id !== q.get("client_id") || c.redirect_uri !== q.get("redirect_uri")) return oaJson({ error: "invalid_grant" }, 400);
      const v = q.get("code_verifier") || ""; if (!v || b64url(await crypto.subtle.digest("SHA-256", enc.encode(v))) !== c.challenge) return oaJson({ error: "invalid_grant", error_description: "PKCE" }, 400);
      uid = c.user_id; cid = c.client_id;
    } else if (gt === "refresh_token") {
      const h = await sha256hex(q.get("refresh_token") || ""); const t = await env.DB.prepare("SELECT * FROM oauth_tokens WHERE hash = ? AND kind = 'refresh'").bind(h).first();
      if (!t || t.exp < Date.now()) return oaJson({ error: "invalid_grant" }, 400);
      await env.DB.prepare("DELETE FROM oauth_tokens WHERE hash = ?").bind(h).run(); uid = t.user_id; cid = t.client_id;
    } else return oaJson({ error: "unsupported_grant_type" }, 400);
    const at = randTok(32), rt = randTok(32), life = 30 * 864e2;
    await env.DB.batch([env.DB.prepare("INSERT INTO oauth_tokens (hash, kind, client_id, user_id, exp) VALUES (?, 'access', ?, ?, ?)").bind(await sha256hex(at), cid, uid, Date.now() + life * 1000),
      env.DB.prepare("INSERT INTO oauth_tokens (hash, kind, client_id, user_id, exp) VALUES (?, 'refresh', ?, ?, ?)").bind(await sha256hex(rt), cid, uid, Date.now() + 365 * 864e5),
      env.DB.prepare("DELETE FROM oauth_tokens WHERE exp < ?").bind(Date.now())]);
    return oaJson({ access_token: at, token_type: "Bearer", expires_in: life, refresh_token: rt, scope: "agrooblik" });
  }
  return oaJson({ error: "not_found" }, 404);
}
async function mcpBearerOk(req, env) {
  const m = (req.headers.get("authorization") || "").match(/^Bearer\s+(\S+)$/i); if (!m) return false;
  await oauthSchema(env.DB); const t = await env.DB.prepare("SELECT exp FROM oauth_tokens WHERE hash = ? AND kind = 'access'").bind(await sha256hex(m[1])).first();
  return !!(t && t.exp > Date.now());
}

const HTML = __HTML__;
