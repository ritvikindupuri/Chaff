import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import ts from "typescript";

async function loadTs(path) {
  const source = ts.transpileModule(fs.readFileSync(new URL(path, import.meta.url), "utf8"), {
    compilerOptions: { module: ts.ModuleKind.ESNext, target: ts.ScriptTarget.ES2022 },
  }).outputText;
  // A file adjacent to the source resolves installed packages normally.
  const temporary = new URL(`../.security-test-${crypto.randomUUID()}.mjs`, import.meta.url);
  fs.writeFileSync(temporary, source);
  try {
    return await import(temporary.href);
  } finally {
    fs.unlinkSync(temporary);
  }
}
const { readBeacon } = await loadTs("../src/lib/beacon-input.ts");
const { assertSafeEsEndpoint, esRequest } = await loadTs("../src/lib/es.server.ts");
const request = (body) =>
  new Request("http://localhost/beacon", { method: "POST", body: JSON.stringify(body) });

test("beacon rejects malformed JSON types and excessive input before database access", async () => {
  for (const body of [
    null,
    [],
    { navigator: { ua: {} } },
    { slug: { id: 1 } },
    { behavior: { key_intervals: Array(513).fill(1) } },
  ]) {
    await assert.rejects(readBeacon(request(body)));
  }
  await assert.rejects(readBeacon(request({ path: "x".repeat(40_000) })), /Body too large/);
  const valid = await readBeacon(
    request({ slug: "abc123", path: "/trap/abc123", navigator: { ua: "Firefox/130" } }),
  );
  assert.equal(valid.slug, "abc123");
});

test("Elasticsearch rejects internal and credential-bearing endpoints", () => {
  for (const endpoint of [
    "http://example.com",
    "https://127.0.0.1",
    "https://169.254.169.254",
    "https://[::1]",
    "https://user:pass@example.com",
    "https://example.com/?secret=1",
  ]) {
    assert.throws(() => assertSafeEsEndpoint(endpoint));
  }
  assert.doesNotThrow(() => assertSafeEsEndpoint("https://cluster.example.com:9243"));
});

test("Elasticsearch disables redirects and bounds upstream time", async () => {
  const original = globalThis.fetch;
  globalThis.fetch = async (url, init) => {
    assert.equal(init.redirect, "error");
    assert.ok(init.signal instanceof AbortSignal);
    return Response.json({ ok: true });
  };
  try {
    assert.deepEqual(
      await esRequest({ endpoint: "https://cluster.example.com", apiKey: "test" }, "/"),
      { ok: true },
    );
  } finally {
    globalThis.fetch = original;
  }
});
