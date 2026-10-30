import { createFileRoute } from "@tanstack/react-router";
import { supabaseAdmin } from "@/integrations/supabase/client.server";
import { scoreBeacon, type BeaconSignals } from "@/lib/fingerprint";
import { ensureChaffIndex, indexEvent } from "@/lib/es-chaff.server";
import { readBeacon } from "@/lib/beacon-input";

const cors = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type",
};

export const Route = createFileRoute("/api/public/beacon")({
  server: {
    handlers: {
      OPTIONS: async () => new Response(null, { status: 204, headers: cors }),
      POST: async ({ request }) => {
        let body: BeaconSignals;
        try {
          body = await readBeacon(request);
        } catch {
          return new Response(JSON.stringify({ error: "invalid json" }), {
            status: 400,
            headers: { ...cors, "Content-Type": "application/json" },
          });
        }

        const ip =
          request.headers.get("cf-connecting-ip") ||
          request.headers.get("x-forwarded-for")?.split(",")[0]?.trim() ||
          request.headers.get("x-real-ip") ||
          "0.0.0.0";
        const country = request.headers.get("cf-ipcountry") || null;

        // Identify owner: slug → honeypot owner (any hit is a bot). If no slug,
        // path may match `/trap/{slug}`. Otherwise reject — beacon must be tied to a tenant.
        let slug = body.slug || null;
        if (!slug && typeof body.path === "string") {
          const m = body.path.match(/^\/trap\/([a-z0-9]{6,32})/);
          if (m) slug = m[1];
        }
        if (!slug) {
          return new Response(JSON.stringify({ error: "missing slug" }), {
            status: 400,
            headers: { ...cors, "Content-Type": "application/json" },
          });
        }
        const { data: hp, error: hpErr } = await supabaseAdmin
          .from("honeypot_keys")
          .select("id,user_id,slug")
          .eq("slug", slug)
          .maybeSingle();
        if (hpErr || !hp) {
          return new Response(JSON.stringify({ error: "unknown slug" }), {
            status: 404,
            headers: { ...cors, "Content-Type": "application/json" },
          });
        }

        // A beacon hit is a "honeypot hit" only when it lands on a /trap/{slug} URL.
        // Beacons embedded on the customer's normal pages are scored on their signals alone.
        const isTrapPath =
          typeof body.path === "string" && /^\/trap\/[a-z0-9]{6,32}/.test(body.path);
        const result = scoreBeacon(body, { honeypot: isTrapPath });

        if (isTrapPath) {
          const { data: cur } = await supabaseAdmin
            .from("honeypot_keys")
            .select("hit_count")
            .eq("id", hp.id)
            .maybeSingle();
          await supabaseAdmin
            .from("honeypot_keys")
            .update({ hit_count: (Number(cur?.hit_count) || 0) + 1 })
            .eq("id", hp.id);
        }

        // Pull this user's ES connection and index the event
        const { data: conn } = await supabaseAdmin
          .from("es_connections")
          .select("endpoint,api_key,is_active")
          .eq("user_id", hp.user_id)
          .eq("is_active", true)
          .limit(1)
          .maybeSingle();

        let indexed = false;
        let indexError: string | null = null;
        if (conn) {
          const auth = { endpoint: conn.endpoint as string, apiKey: conn.api_key as string };
          try {
            await ensureChaffIndex(auth, hp.user_id);
            const isIp = /^\d{1,3}(\.\d{1,3}){3}$/.test(ip);
            await indexEvent(auth, hp.user_id, {
              "@timestamp": new Date().toISOString(),
              verdict: result.verdict,
              score: result.score,
              reasons: result.reasons,
              signature_hash: result.signature_hash,
              ua_family: result.ua_family,
              slug,
              is_honeypot_hit: isTrapPath,
              ...(isIp ? { ip } : {}),
              ip_str: ip,
              country,
              path: body.path,
              origin: body.origin,
              referrer: body.referrer,
              dwell_ms: body.dwell_ms,
              ua: body.navigator?.ua,
              canvas_hash: body.canvas_hash,
              webgl_vendor: body.webgl_vendor,
              webgl_renderer: body.webgl_renderer,
              hardware_concurrency: body.navigator?.hardwareConcurrency,
              device_memory: body.navigator?.deviceMemory,
              screen_w: body.screen?.w,
              screen_h: body.screen?.h,
              mouse_moves: body.behavior?.mouse_moves,
              mouse_entropy: body.behavior?.mouse_entropy,
              scrolls: body.behavior?.scrolls,
              clicks: body.behavior?.clicks,
              raw: body,
            });
            indexed = true;
          } catch (e: any) {
            console.error("[beacon] ES index failed:", e?.message ?? e);
            indexError = "es_write_failed";
          }
        }

        // Do NOT expose verdict/score/reasons/signature_hash to clients —
        // an adversary could iterate on payloads to evade detection.
        // Full result is logged server-side via the ES index above.
        void indexed;
        void indexError;
        return new Response(JSON.stringify({ ok: true }), {
          status: 200,
          headers: { ...cors, "Content-Type": "application/json" },
        });
      },
    },
  },
});
