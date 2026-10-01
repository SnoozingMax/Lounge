// Supabase Edge Function: push
// Sends web push notifications. Called by the database when a message is sent.
import webpush from "npm:web-push@3.6.7";

const HOOK_SECRET = "PASTE_HOOK_SECRET";
const VAPID_PUBLIC = "BD6ZQnKpJte395o8SjKQyuOe4gYr8356df4mF0xXhBHv4Gfs8mkFfnM-HniZu02erQLNxng29U1JNQajxAYqAnw";
const VAPID_PRIVATE = "PASTE_VAPID_PRIVATE_KEY";

webpush.setVapidDetails("https://snoozingmax.github.io/Lounge/", VAPID_PUBLIC, VAPID_PRIVATE);

type Sub = { endpoint: string; p256dh: string; auth: string };

Deno.serve(async (req) => {
  if (req.headers.get("x-hook-secret") !== HOOK_SECRET) return new Response("nope", { status: 401 });
  const { subs = [], ...msg } = await req.json();
  const payload = JSON.stringify(msg);
  const dead: string[] = [];
  let sent = 0;

  await Promise.all((subs as Sub[]).map(async (s) => {
    try {
      await webpush.sendNotification(
        { endpoint: s.endpoint, keys: { p256dh: s.p256dh, auth: s.auth } },
        payload,
        { TTL: 3600, urgency: "high" },
      );
      sent++;
    } catch (e) {
      const code = (e as { statusCode?: number }).statusCode;
      if (code === 404 || code === 410) dead.push(s.endpoint);
      else console.error("push failed", code, (e as Error).message);
    }
  }));

  // forget devices that unsubscribed
  const url = Deno.env.get("SUPABASE_URL"), key = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");
  if (dead.length && url && key) {
    const list = dead.map((d) => `"${d.replace(/"/g, '\\"')}"`).join(",");
    await fetch(`${url}/rest/v1/push_subs?endpoint=in.(${encodeURIComponent(list)})`, {
      method: "DELETE",
      headers: { apikey: key, Authorization: `Bearer ${key}` },
    }).catch(() => {});
  }

  return new Response(JSON.stringify({ sent, dead: dead.length }), {
    headers: { "Content-Type": "application/json" },
  });
});
