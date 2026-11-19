// КЛГ Агро Поле — Cloudflare Worker: serves the app page and a small document API on D1.
// Bindings: DB (D1 database). Secret: APP_PASSWORD.
const COLS = new Set(["fields", "ops", "machines", "implements", "people", "products", "tasks", "service", "parcels", "leases", "owners", "payments", "settings", "warehouses", "whdocs", "invoices", "whrequests", "pricelists", "units", "mplans", "norms", "fuelstations", "fuelings", "harvests", "waybills", "elevators", "scoutreports", "scouttasks", "notes", "plantthreats", "agroplans", "recommendations", "costs"]);
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
    ctx.waitUntil(makeBackup(env, "auto"));
  },
  async fetch(req, env) {
    const url = new URL(req.url);
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
    if (!snap || snap.app !== "klg-agro-pole" || !Array.isArray(snap.docs)) return json({ error: "Файл не є резервною копією КЛГ Агро Поле" }, 400);
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

const HTML = __HTML__;
