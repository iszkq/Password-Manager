import { clearSessionCookie, makeSessionCookie, safeEqual } from "../_shared/auth.js";

const reply = (body, status = 200, cookie = null) => {
  const headers = new Headers({
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff"
  });
  if (cookie) headers.set("Set-Cookie", cookie);
  return new Response(JSON.stringify(body), { status, headers });
};

export async function onRequestPost({ request, env }) {
  if (!env.VAULT_PASSWORD || !env.SESSION_SECRET) {
    return reply({ error: "VAULT_PASSWORD or SESSION_SECRET is missing" }, 503);
  }
  let password = "";
  try {
    const body = await request.json();
    password = typeof body.password === "string" ? body.password : "";
  } catch {
    return reply({ error: "Invalid JSON" }, 400);
  }
  if (!await safeEqual(password, env.VAULT_PASSWORD)) return reply({ error: "Invalid password" }, 401);
  return reply({ ok: true }, 200, await makeSessionCookie(env.SESSION_SECRET));
}

export async function onRequestDelete() {
  return reply({ ok: true }, 200, clearSessionCookie());
}
