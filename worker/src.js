// КЛГ Агро Поле — Cloudflare Worker: serves the app page and a small document API on D1.
// Bindings: DB (D1 database). Secret: APP_PASSWORD.
const COLS = new Set(["fields", "ops", "machines", "implements", "people", "products", "tasks", "service", "parcels", "leases", "owners", "payments", "settings", "warehouses", "whdocs", "invoices", "whrequests", "pricelists", "units"]);
const ID_RE = /^[A-Za-z0-9._-]{1,64}$/;
const COOKIE = "klg_session";
let schemaReady = false;

export default {
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
  const token = await sessionToken(env.APP_PASSWORD);
  const path = url.pathname;

  if (path === "/api/login" && req.method === "POST") {
    const body = await req.json().catch(() => ({}));
    if (!body.password || !(await safeEqual(String(body.password), env.APP_PASSWORD))) {
      await new Promise((r) => setTimeout(r, 600));
      return json({ error: "bad password" }, 401);
    }
    return json({ ok: true }, 200, { "set-cookie": `${COOKIE}=${token}; Path=/; Max-Age=31536000; HttpOnly; Secure; SameSite=Lax` });
  }
  if (path === "/api/logout" && req.method === "POST") {
    return json({ ok: true }, 200, { "set-cookie": `${COOKIE}=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax` });
  }

  const cookie = (req.headers.get("cookie") || "").split(/;\s*/).find((c) => c.startsWith(COOKIE + "="));
  if (!cookie || !(await safeEqual(cookie.slice(COOKIE.length + 1), token))) return json({ error: "auth" }, 401);

  if (!env.DB) return json({ error: "D1 binding DB is missing" }, 500);
  await ensureSchema(env.DB);

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
    const updated = new Date().toISOString();
    if (req.method === "PUT") {
      const text = await req.text();
      if (text.length > 900000) return json({ error: "document too large" }, 413);
      let data;
      try { data = JSON.parse(text); } catch (e) { return json({ error: "bad json" }, 400); }
      if (!data || typeof data !== "object" || Array.isArray(data)) return json({ error: "body must be an object" }, 400);
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

async function ensureSchema(db) {
  if (schemaReady) return;
  await db.prepare("CREATE TABLE IF NOT EXISTS docs (col TEXT NOT NULL, id TEXT NOT NULL, data TEXT NOT NULL, updated TEXT NOT NULL, deleted INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (col, id))").run();
  await db.prepare("CREATE INDEX IF NOT EXISTS docs_updated ON docs (updated)").run();
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
