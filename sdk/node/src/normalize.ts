/**
 * Value normalizers applied before a blind index is computed (on write AND on every filter value), so that
 * "(11) 91234-5678", "11912345678" and "+55 11 91234-5678" can be made to match.
 * `trim` is always applied first.
 */
export type Normalizer = "trim" | "lowercase" | "digits" | "fold" | "email-lower" | "br-phone-canonical";

export const NORMALIZER_NAMES: readonly Normalizer[] = ["trim", "lowercase", "digits", "fold", "email-lower", "br-phone-canonical"];

/** Lowercase and strip accents: "João Çaña" -> "joao cana". Same effect as translate(lower(x), 'áàãâéêíóôõúüç', 'aaaaeeiooouuc'). */
export function fold(s: string): string {
  return s.normalize("NFD").replace(/\p{M}+/gu, "").toLowerCase();
}

/**
 * Canonical Brazilian phone number, for equality and suffix matching:
 *  1. keep digits only;
 *  2. drop the country code 55 when the number is long enough to carry it (12 or 13 digits);
 *  3. for a mobile number with 11 digits (DDD + 9 + 8 digits) drop the extra leading 9 of the subscriber part,
 *     so "(11) 91234-5678" and the old "(11) 1234-5678" compare equal.
 * Numbers that do not fit these shapes are returned as digits only.
 * NOTE: this is a specification of the rule as described, check it against the SQL it replaces before relying on it.
 */
export function brPhoneCanonical(s: string): string {
  let d = s.replace(/\D+/g, "");
  if ((d.length === 12 || d.length === 13) && d.startsWith("55")) d = d.slice(2);
  if (d.length === 11 && d[2] === "9") d = d.slice(0, 2) + d.slice(3);
  return d;
}

const fns: Record<Normalizer, (s: string) => string> = {
  trim: (s) => s.trim(),
  lowercase: (s) => s.toLowerCase(),
  digits: (s) => s.replace(/\D+/g, ""),
  fold,
  "email-lower": (s) => s.trim().toLowerCase(),
  "br-phone-canonical": brPhoneCanonical,
};

export function applyNormalizers(v: string, ops: readonly Normalizer[]): string {
  let out = v.trim();
  for (const o of ops) out = fns[o](out);
  return out;
}
