# Local security assessment — 2026-10-30

Scope: Chaff source and the local development server. No production services,
real tenant data, paid APIs, or hosted Supabase security policies were exercised.
This is a bounded assessment, not a claim that the application is vulnerability-free.

## Remediation

- Public beacon JSON previously flowed directly into scoring and privileged
  database operations without runtime shape validation or a body size limit.
  Validate nested fields and tenant slug shape, bound collections and strings,
  strip unknown properties, and cap the streamed body at 32 KiB before processing.
  Malformed input receives a generic 400 without database access.
- Elasticsearch requests previously followed redirects after validating only the
  initial endpoint. Reject redirects, credential/query/fragment-bearing endpoint
  URLs, and abort upstream requests after 15 seconds. Existing private-address
  checks remain in place.
- Apply anti-framing, MIME-sniffing, referrer, restricted browser permission, and
  limited CSP headers to normal and error responses from the SSR entry point.
  The CSP is intentionally limited; it is not a complete script execution policy.

## Verification

- Production client and SSR build: passed.
- TypeScript `tsc --noEmit`: passed.
- `node --test tests/security.test.mjs`: three regression tests passed.
- Twelve local HTTP probes returned expected statuses: missing/forged rescan
  credentials 403; unauthenticated MCP tools/list 401; unsupported MCP GET 405;
  malformed JSON, null/object/nested-type payloads, 40 KiB payload, and missing
  beacon slug 400; homepage 200. No database lookup is needed for these probes.
- Browser navigation to protected dashboard redirected to login. This proves
  the UI guard only; server authorization needs separate authenticated testing.
- Live homepage confirmed CSP, X-Frame-Options, X-Content-Type-Options,
  Referrer-Policy, and Permissions-Policy headers after remediation.
- Repository-wide lint fails on existing formatting and typing violations.
  After formatting changed files, four existing no-explicit-any errors remain
  in es.server.ts and beacon.ts. New validation and tests have no lint errors.

## Remaining work — ACTION REQUIRED

- Test authorization and RLS with two isolated local tenants, including MCP
  token revocation, object ownership, and all mutating server functions.
- Private-address hostname checks do not provide DNS pinning. Enforce an egress
  allowlist/network policy against DNS rebinding and private DNS resolution.
- Public beacons can still be replayed or forged by someone knowing a slug.
  Add edge rate limits, abuse budgets and concurrency-safe hit counters.
- Assess onboarding fetch destinations and AI tool execution with local mocks.
- Review dependency advisories separately; this patch does not claim to resolve
  all transitive dependency findings.
- Verify headers at the deployed edge and ensure deployment applies the source
  changes. Merging this PR does not prove deployed backend policy changes.
