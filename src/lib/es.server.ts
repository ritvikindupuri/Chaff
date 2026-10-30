// Server-only Elasticsearch client. Uses fetch + ApiKey auth. Cloudflare Workers compatible.

export type EsAuth = {
  endpoint: string;
  apiKey: string;
};

function normalizeEndpoint(ep: string) {
  return ep.replace(/\/+$/, "");
}

// SSRF guard: reject non-https schemes and hostnames that resolve to (or
// literally are) private / loopback / link-local addresses. We can't do DNS
// resolution in a Worker, so we block by literal IP and known internal names.
function isBlockedHostname(host: string): boolean {
  const h = host.toLowerCase().replace(/^\[|\]$/g, "");
  if (
    h === "localhost" ||
    h.endsWith(".localhost") ||
    h.endsWith(".internal") ||
    h.endsWith(".local")
  )
    return true;
  if (h === "::1" || h.startsWith("::ffff:") || h === "0:0:0:0:0:0:0:1") return true;
  // IPv6 unique-local / link-local
  if (/^f[cd][0-9a-f]{2}:/i.test(h) || /^fe80:/i.test(h)) return true;
  // IPv4
  const m = h.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (m) {
    const [a, b] = [parseInt(m[1], 10), parseInt(m[2], 10)];
    if (a === 10) return true;
    if (a === 127) return true;
    if (a === 0) return true;
    if (a === 169 && b === 254) return true; // link-local / cloud metadata
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 192 && b === 168) return true;
    if (a === 100 && b >= 64 && b <= 127) return true; // CGNAT
    if (a >= 224) return true; // multicast / reserved
  }
  return false;
}

export function assertSafeEsEndpoint(endpoint: string): void {
  let u: URL;
  try {
    u = new URL(endpoint);
  } catch {
    throw new Error("Invalid Elasticsearch endpoint URL");
  }
  if (u.protocol !== "https:") throw new Error("Elasticsearch endpoint must use https://");
  if (!u.hostname) throw new Error("Invalid Elasticsearch endpoint host");
  if (u.username || u.password || u.search || u.hash)
    throw new Error("Elasticsearch endpoint must not contain credentials, query, or fragment");
  if (isBlockedHostname(u.hostname)) throw new Error("Elasticsearch endpoint host is not allowed");
}

export async function esRequest<T = unknown>(
  auth: EsAuth,
  path: string,
  init?: { method?: string; body?: unknown },
): Promise<T> {
  assertSafeEsEndpoint(auth.endpoint);
  const url = `${normalizeEndpoint(auth.endpoint)}${path.startsWith("/") ? "" : "/"}${path}`;
  const res = await fetch(url, {
    // Do not follow a public endpoint's redirect to an internal service or leak its API key.
    redirect: "error",
    signal: AbortSignal.timeout(15_000),
    method: init?.method ?? (init?.body ? "POST" : "GET"),
    headers: {
      "Content-Type": "application/json",
      Authorization: `ApiKey ${auth.apiKey}`,
      Accept: "application/json",
    },
    body: init?.body ? JSON.stringify(init.body) : undefined,
  });
  const text = await res.text();
  let parsed: unknown = null;
  try {
    parsed = text ? JSON.parse(text) : null;
  } catch {
    parsed = text;
  }
  if (!res.ok) {
    const msg =
      typeof parsed === "object" && parsed && "error" in (parsed as any)
        ? JSON.stringify((parsed as any).error)
        : text || res.statusText;
    throw new Error(`Elasticsearch ${res.status}: ${msg.slice(0, 400)}`);
  }
  return parsed as T;
}

export async function esPing(
  auth: EsAuth,
): Promise<{ name?: string; version?: { number?: string } }> {
  return esRequest(auth, "/");
}

export async function esSearch<T = any>(auth: EsAuth, index: string, body: unknown): Promise<T> {
  return esRequest<T>(auth, `/${encodeURIComponent(index)}/_search`, { method: "POST", body });
}
