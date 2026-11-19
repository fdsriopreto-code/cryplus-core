import { createHash } from "node:crypto";

/**
 * A cache key for a value that must not appear in the cache in clear text (API keys, tokens, CPF...).
 * Never use a secret itself as a cache or Map key: Redis keys show up in MONITOR, SCAN and dumps.
 * SHA-256 is the right tool for HIGH-ENTROPY random secrets (API keys, tokens). For low-entropy values (CPF, phone) use
 * `$cryplus.index(...)` instead, which is keyed per tenant and cannot be brute-forced from a dump.
 */
export function cacheKey(namespace: string, secret: string): string {
  return `${namespace}:${createHash("sha256").update(secret).digest("hex")}`;
}
