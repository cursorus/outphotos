import { serve } from "https://deno.land/std@0.178.0/http/server.ts";
import { verifyJWT } from "https://esm.sh/@supabase/gotrue-js";
import { createClient } from "https://esm.sh/@supabase/supabase-js";

const SUPA_URL       = Deno.env.get("PROJECT_URL")!;
const SERVICE_KEY    = Deno.env.get("SERVICE_ROLE_KEY")!;
const supa           = createClient(SUPA_URL, SERVICE_KEY);
const GITHUB_RAW     = "https://raw.githubusercontent.com/" + Deno.env.get("GITHUB_REPO") + "/main/";
const REPO_PREFIX    = "encrypted/";

// Подготовка AES-GCM ключа
tconst keyRaw   = Uint8Array.from(atob(Deno.env.get("ENCRYPTION_KEY")!), c=>c.charCodeAt(0));
const cryptoKey = await crypto.subtle.importKey("raw", keyRaw, "AES-GCM", false, ["decrypt"]);

serve(async (req) => {
  if (req.method === "OPTIONS") {
    return new Response(null, { headers: {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET,OPTIONS",
      "Access-Control-Allow-Headers": "Authorization"
    }});
  }

  const token = req.headers.get("Authorization")?.split(" ")[1];
  if (!token) return new Response("No auth", { status: 401 });

  let user;
  try {
    user = await verifyJWT(token, { url: SUPA_URL, key: SERVICE_KEY });
  } catch {
    return new Response("Invalid token", { status: 403 });
  }

  // Проверяем approved
  const { data: prof } = await supa.from("profiles").select("approved").eq("id", user.sub).single();
  if (!prof?.approved) return new Response("Not approved", { status: 403 });

  const url  = new URL(req.url);
  const path = url.searchParams.get("path");
  if (!path?.startsWith(REPO_PREFIX)) return new Response("Bad path", { status: 400 });

  const resp = await fetch(GITHUB_RAW + encodeURIComponent(path));
  if (!resp.ok) return new Response("Not found", { status: 404 });

  const bytes = new Uint8Array(await resp.arrayBuffer());
  const iv    = bytes.slice(0,12), ct = bytes.slice(12);
  let plain;
  try {
    plain = await crypto.subtle.decrypt({ name:"AES-GCM", iv }, cryptoKey, ct);
  } catch {
    return new Response("Decrypt failed", { status: 500 });
  }

  return new Response(plain, {
    status: 200,
    headers: {
      "Content-Type": "video/mp4",
      "Access-Control-Allow-Origin": "*"
    }
  });
});
