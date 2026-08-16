import { hasValidSession } from "../_shared/auth.js";

const OBJECT_KEY = "vault/data.json";
const MAX_BODY_BYTES = 5 * 1024 * 1024;

const json = (body, status = 200, extraHeaders = {}) => new Response(JSON.stringify(body), {
  status,
  headers: {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff",
    ...extraHeaders
  }
});

function isVaultData(value) {
  return Boolean(
    value &&
    Array.isArray(value.items) &&
    value.items.length <= 10000 &&
    typeof value.updatedAt === "string"
  );
}

export async function onRequestGet({ request, env }) {
  if (!await hasValidSession(request, env.SESSION_SECRET)) return json({ error: "Unauthorized" }, 401);
  if (!env.VAULT_BUCKET) return json({ error: "R2 binding VAULT_BUCKET is missing" }, 503);
  const object = await env.VAULT_BUCKET.get(OBJECT_KEY);
  if (!object) return json({ error: "Vault not found" }, 404);
  return new Response(object.body, {
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store",
      "ETag": object.httpEtag,
      "X-Content-Type-Options": "nosniff"
    }
  });
}

export async function onRequestPut({ request, env }) {
  if (!await hasValidSession(request, env.SESSION_SECRET)) return json({ error: "Unauthorized" }, 401);
  if (!env.VAULT_BUCKET) return json({ error: "R2 binding VAULT_BUCKET is missing" }, 503);
  const contentLength = Number(request.headers.get("Content-Length") || 0);
  if (contentLength > MAX_BODY_BYTES) return json({ error: "Vault is too large" }, 413);

  let raw;
  let value;
  try {
    raw = await request.text();
    if (new TextEncoder().encode(raw).byteLength > MAX_BODY_BYTES) return json({ error: "Vault is too large" }, 413);
    value = JSON.parse(raw);
  } catch {
    return json({ error: "Invalid JSON" }, 400);
  }
  if (!isVaultData(value)) return json({ error: "Invalid vault data" }, 400);

  await env.VAULT_BUCKET.put(OBJECT_KEY, JSON.stringify(value), {
    httpMetadata: { contentType: "application/json; charset=utf-8", cacheControl: "no-store" },
    customMetadata: { updatedAt: value.updatedAt }
  });
  return json({ ok: true, updatedAt: value.updatedAt });
}
