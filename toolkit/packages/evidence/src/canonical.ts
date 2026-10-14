// RFC 8785-style canonical JSON, behaviour-compatible with REA's `digestCanonicalValue`
// (src/domain/canonicalDigest.ts in morluto/rea): keys sorted by UTF-16 code unit,
// undefined/symbol properties dropped, undefined/symbol array items become null, scalars via JSON.stringify.
import { createHash } from "node:crypto";

export type Json = null | boolean | number | string | Json[] | { [key: string]: Json };

export function canonicalJson(value: unknown): string {
  const ancestors = new Set<object>();
  const emit = (v: unknown): string => {
    if (typeof v === "number" && !Number.isFinite(v)) throw new Error(Number.isNaN(v) ? "NaN is not allowed" : "Infinity is not allowed");
    if (v === null || typeof v !== "object") {
      const s = JSON.stringify(v);
      if (s === undefined) throw new TypeError("value cannot be canonicalized");
      return s;
    }
    if (ancestors.has(v)) throw new Error("Circular reference detected");
    ancestors.add(v);
    try {
      const withToJson = v as { toJSON?: () => unknown };
      if (typeof withToJson.toJSON === "function") return emit(withToJson.toJSON());
      if (Array.isArray(v)) {
        return "[" + v.map((item) => emit(item === undefined || typeof item === "symbol" ? null : item)).join(",") + "]";
      }
      const parts: string[] = [];
      for (const key of Object.keys(v).sort()) {
        const item = (v as Record<string, unknown>)[key];
        if (item === undefined || typeof item === "symbol") continue;
        parts.push(JSON.stringify(key) + ":" + emit(item));
      }
      return "{" + parts.join(",") + "}";
    } finally {
      ancestors.delete(v);
    }
  };
  return emit(value);
}

export const sha256Hex = (data: string | Uint8Array): string => createHash("sha256").update(data).digest("hex");
export const canonicalDigest = (value: unknown): string => sha256Hex(canonicalJson(value));
