import { z } from "zod";

const text = z.string().max(2048);
const count = z.number().finite().nonnegative().max(1e9);
export const beaconSchema = z.object({
  slug: z
    .string()
    .regex(/^[a-z0-9]{6,32}$/)
    .nullish(),
  origin: text.optional(),
  path: text.optional(),
  referrer: text.nullish(),
  dwell_ms: count.optional(),
  reason: text.optional(),
  navigator: z
    .object({
      ua: text.optional(),
      platform: text.optional(),
      languages: z.array(z.string().max(64)).max(32).optional(),
      hardwareConcurrency: count.optional(),
      deviceMemory: count.optional(),
      webdriver: z.boolean().optional(),
      plugins: count.optional(),
      pdfViewerEnabled: z.boolean().optional(),
      hasChrome: z.boolean().optional(),
    })
    .optional(),
  screen: z
    .object({
      w: count.optional(),
      h: count.optional(),
      avail_w: count.optional(),
      avail_h: count.optional(),
      dpr: count.optional(),
      color_depth: count.optional(),
    })
    .optional(),
  tz: z
    .object({ name: text.optional(), offset: z.number().finite().min(-1440).max(1440).optional() })
    .optional(),
  canvas_hash: text.optional(),
  webgl_vendor: text.optional(),
  webgl_renderer: text.optional(),
  behavior: z
    .object({
      mouse_moves: count.optional(),
      mouse_entropy: count.optional(),
      clicks: count.optional(),
      scrolls: count.optional(),
      max_scroll: count.optional(),
      key_count: count.optional(),
      key_intervals: z.array(count).max(512).optional(),
    })
    .optional(),
});

// Limit bytes while streaming: Content-Length alone is attacker-controlled.
export async function readBeacon(request: Request) {
  const reader = request.body?.getReader();
  if (!reader) throw new Error("Missing body");
  const chunks: Uint8Array[] = [];
  let size = 0;
  try {
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > 32_768) {
        await reader.cancel();
        throw new Error("Body too large");
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }
  const bytes = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.length;
  }
  return beaconSchema.parse(JSON.parse(new TextDecoder().decode(bytes)));
}
