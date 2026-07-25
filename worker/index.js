/**
 * 802universe.com — edge worker
 *
 *  GET  /api/content            public, returns the live site content
 *  GET  /admin/api/me           who am I (verified Access identity)
 *  GET  /admin/api/content      content for the editor
 *  PUT  /admin/api/content      save content
 *  GET  /admin/api/revisions    list recent revisions
 *  GET  /admin/api/revisions/:id  fetch one revision
 *  everything else              static files from /public
 *
 * Cloudflare Access sits in front of /admin, so unauthenticated requests
 * never arrive. We verify the signed token here anyway — the gate and the
 * lock should not be the same thing.
 */

const KEY = "site";
const REVS = "revs";
const MAX_REVS = 10;
const MAX_BYTES = 512 * 1024;
const JSON_HEADERS = { "content-type": "application/json; charset=utf-8" };

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname.replace(/\/+$/, "") || "/";

    try {
      if (path === "/api/content") return await publicContent(request, env);
      if (path.startsWith("/admin/api")) return await adminApi(path, request, env, ctx);
    } catch (err) {
      return json({ error: "server error", detail: String(err && err.message) }, 500);
    }

    return env.ASSETS.fetch(request);
  }
};

/* ---------------------------------------------------------------- public */

async function publicContent(request, env) {
  if (request.method !== "GET") return json({ error: "method not allowed" }, 405);
  const body = await currentContent(request, env);
  return new Response(body, {
    headers: { ...JSON_HEADERS, "cache-control": "public, max-age=30" }
  });
}

/* ----------------------------------------------------------------- admin */

async function adminApi(path, request, env, ctx) {
  const auth = await verifyAccess(request, env);
  if (!auth.ok) return json({ error: "not authorised", reason: auth.reason }, 403);

  if (path === "/admin/api/me" && request.method === "GET") {
    return json({ email: auth.email });
  }

  if (path === "/admin/api/content") {
    if (request.method === "GET") {
      return new Response(await currentContent(request, env), { headers: JSON_HEADERS });
    }
    if (request.method === "PUT") {
      const raw = await request.text();
      if (raw.length > MAX_BYTES) return json({ error: "content is too large" }, 413);

      let data;
      try { data = JSON.parse(raw); }
      catch { return json({ error: "body is not valid JSON" }, 400); }

      const problem = validate(data);
      if (problem) return json({ error: problem }, 400);

      const previous = await env.CONTENT.get(KEY);
      data.updated = new Date().toISOString();
      data.updatedBy = auth.email;

      await env.CONTENT.put(KEY, JSON.stringify(data));
      if (previous) ctx.waitUntil(saveRevision(env, previous));

      return json({ ok: true, updated: data.updated });
    }
    return json({ error: "method not allowed" }, 405);
  }

  if (path === "/admin/api/revisions" && request.method === "GET") {
    return json({ revisions: JSON.parse((await env.CONTENT.get(REVS)) || "[]") });
  }

  if (path.startsWith("/admin/api/revisions/") && request.method === "GET") {
    const id = decodeURIComponent(path.slice("/admin/api/revisions/".length));
    const body = await env.CONTENT.get("rev:" + id);
    return body
      ? new Response(body, { headers: JSON_HEADERS })
      : json({ error: "revision not found" }, 404);
  }

  return json({ error: "no such endpoint" }, 404);
}

async function saveRevision(env, previousJson) {
  const stamp = new Date().toISOString();
  await env.CONTENT.put("rev:" + stamp, previousJson, { expirationTtl: 60 * 60 * 24 * 180 });

  const list = JSON.parse((await env.CONTENT.get(REVS)) || "[]");
  list.unshift(stamp);
  for (const old of list.slice(MAX_REVS)) await env.CONTENT.delete("rev:" + old);
  await env.CONTENT.put(REVS, JSON.stringify(list.slice(0, MAX_REVS)));
}

/* Falls back to the checked-in defaults the first time, before anything
   has ever been saved. One source of truth, versioned in git. */
async function currentContent(request, env) {
  const stored = await env.CONTENT.get(KEY);
  if (stored) return stored;
  const seed = new URL("/content.default.json", request.url);
  const res = await env.ASSETS.fetch(new Request(seed, { method: "GET" }));
  return res.ok ? await res.text() : "null";
}

/* Shape check. Not a security boundary — only you can write — but it stops
   a bad save from taking the front page down. */
function validate(d) {
  if (!d || typeof d !== "object" || Array.isArray(d)) return "content must be an object";
  if (!d.hero || typeof d.hero.title !== "string") return "hero.title is required";
  if (!Array.isArray(d.projects)) return "projects must be a list";
  for (const [i, p] of d.projects.entries()) {
    if (typeof p.title !== "string" || !p.title.trim()) return `project ${i + 1} needs a title`;
    if (typeof p.href !== "string") return `project ${i + 1} needs a link`;
    if (p.tags && !Array.isArray(p.tags)) return `project ${i + 1}: tags must be a list`;
  }
  return null;
}

/* ------------------------------------------------- Cloudflare Access JWT */

let jwksCache = { keys: null, expires: 0 };

async function verifyAccess(request, env) {
  if (!env.TEAM_DOMAIN || !env.POLICY_AUD) {
    return { ok: false, reason: "TEAM_DOMAIN or POLICY_AUD is not configured" };
  }

  const token =
    request.headers.get("cf-access-jwt-assertion") || cookie(request, "CF_Authorization");
  if (!token) return { ok: false, reason: "no Access token on this request" };

  try {
    const [h, p, s] = token.split(".");
    if (!h || !p || !s) return { ok: false, reason: "malformed token" };

    const header = JSON.parse(decode(b64url(h)));
    if (header.alg !== "RS256") return { ok: false, reason: "unexpected signing algorithm" };

    const keys = await accessKeys(env);
    const jwk = keys.find((k) => k.kid === header.kid);
    if (!jwk) return { ok: false, reason: "signing key not recognised" };

    const key = await crypto.subtle.importKey(
      "jwk",
      { kty: jwk.kty, n: jwk.n, e: jwk.e, alg: "RS256", ext: true },
      { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
      false,
      ["verify"]
    );

    const valid = await crypto.subtle.verify(
      "RSASSA-PKCS1-v1_5",
      key,
      b64url(s),
      new TextEncoder().encode(h + "." + p)
    );
    if (!valid) return { ok: false, reason: "signature does not match" };

    const c = JSON.parse(decode(b64url(p)));
    const now = Math.floor(Date.now() / 1000);
    if (c.exp && c.exp < now) return { ok: false, reason: "token has expired" };
    if (c.nbf && c.nbf > now + 60) return { ok: false, reason: "token is not yet valid" };
    if (c.iss !== env.TEAM_DOMAIN) return { ok: false, reason: "wrong issuer" };

    const aud = Array.isArray(c.aud) ? c.aud : [c.aud];
    if (!aud.includes(env.POLICY_AUD)) return { ok: false, reason: "wrong audience" };

    return { ok: true, email: c.email || c.common_name || "authenticated user" };
  } catch {
    return { ok: false, reason: "token could not be verified" };
  }
}

async function accessKeys(env) {
  const now = Date.now();
  if (jwksCache.keys && jwksCache.expires > now) return jwksCache.keys;
  const res = await fetch(env.TEAM_DOMAIN + "/cdn-cgi/access/certs");
  if (!res.ok) throw new Error("could not reach the Access certificate endpoint");
  const data = await res.json();
  jwksCache = { keys: data.keys || [], expires: now + 60 * 60 * 1000 };
  return jwksCache.keys;
}

/* ----------------------------------------------------------------- utils */

function cookie(request, name) {
  const jar = request.headers.get("cookie") || "";
  for (const part of jar.split(";")) {
    const [k, ...v] = part.trim().split("=");
    if (k === name) return v.join("=");
  }
  return null;
}

function b64url(s) {
  s = s.replace(/-/g, "+").replace(/_/g, "/");
  const pad = s.length % 4 ? 4 - (s.length % 4) : 0;
  const bin = atob(s + "=".repeat(pad));
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

const decode = (bytes) => new TextDecoder().decode(bytes);

function json(obj, status = 200) {
  return new Response(JSON.stringify(obj), { status, headers: JSON_HEADERS });
}
