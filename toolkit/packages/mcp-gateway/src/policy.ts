// Enforcing policy: tool verdicts (from @rtk/effects) and argument path confinement.
import { existsSync, realpathSync } from "node:fs";
import { basename, dirname, isAbsolute, join, normalize, resolve, sep } from "node:path";
import { PROFILES, decide, type Decision, type EffectsTable, type PolicyProfile, type Verdict } from "@rtk/effects";

export function resolveProfile(p: string | PolicyProfile): PolicyProfile {
  if (typeof p !== "string") return p;
  const prof = PROFILES[p]; if (!prof) throw new Error(`unknown policy profile ${JSON.stringify(p)} (known: ${Object.keys(PROFILES).join(", ")})`);
  return prof;
}
export interface ToolVerdict { verdict: Verdict; known: boolean; tier: string | null; reasons: string[]; decision: Decision | null }
/** Fail closed: a tool without an effects record is denied no matter what upstream annotations claim. */
export function decideTool(name: string, table: EffectsTable, profile: PolicyProfile): ToolVerdict {
  const rec = table[name];
  if (!rec) return { verdict: "deny", known: false, tier: null, reasons: ["tool has no audited effects record (fail closed)"], decision: null };
  const d = decide(name, rec.effects, profile);
  return { verdict: d.verdict, known: true, tier: d.tier, reasons: d.reasons, decision: d };
}

/** Resolve symlinks and `..`; for paths that do not exist yet, resolve the deepest existing ancestor and append the rest. */
export function realpathLoose(p: string): string {
  const abs = normalize(resolve(p)); const tail: string[] = []; let cur = abs;
  while (!existsSync(cur)) { const parent = dirname(cur); if (parent === cur) break; tail.unshift(basename(cur)); cur = parent; }
  let real: string; try { real = realpathSync(cur); } catch { real = cur; }
  return tail.length ? join(real, ...tail) : real;
}
export const isUnder = (child: string, root: string): boolean => child === root || child.startsWith(root.endsWith(sep) ? root : root + sep);

export interface PathPolicy { allowedRoots: string[]; writeRoots?: string[]; baseDir?: string }
export interface Violation { key: string; value: string; reason: string }
export interface ArgCheck { ok: boolean; violations: Violation[]; checked: number }

// Keys that look like host paths. Device-side / debugger-internal paths are explicitly not host filesystem paths.
const NOT_HOST_PATH = new Set(["device_path", "unit_path", "parent_unit_path", "remote_path", "target_path_on_device"]);
const PATH_KEY = /(^|_)(path|paths|dir|dirs|directory|directories|root|roots|file|files|executable|cwd)$/u;
const WRITE_KEY = /(^|_)(output|out|destination|dest|save|export)(_[a-z]+)*$/u;
const RELATIVE_KEYS = new Set(["source_paths"]);
const URL_KEY = /(^|_)(url|uri)$/u;
export type PathKind = "read" | "write" | "relative" | "url" | null;
export function classifyKey(key: string): PathKind {
  const k = key.toLowerCase();
  if (NOT_HOST_PATH.has(k)) return null;
  if (URL_KEY.test(k)) return "url";
  if (RELATIVE_KEYS.has(k)) return "relative";
  if (!PATH_KEY.test(k) && k !== "executable" && k !== "program") return null;
  return WRITE_KEY.test(k) && k !== "output_path_hint" ? "write" : "read";
}

export function checkArguments(args: unknown, policy: PathPolicy): ArgCheck {
  const violations: Violation[] = []; let checked = 0;
  const base = policy.baseDir ?? process.cwd();
  const readRoots = policy.allowedRoots.map(realpathLoose); const writeRoots = (policy.writeRoots ?? policy.allowedRoots).map(realpathLoose);
  const checkValue = (key: string, kind: Exclude<PathKind, null>, value: string) => {
    checked++;
    const bad = (reason: string) => violations.push({ key, value: value.slice(0, 300), reason });
    if (value.includes("\0")) return bad("NUL byte in path");
    if (kind === "relative") { if (isAbsolute(value) || value.split(/[\\/]/u).includes("..")) bad("must be a relative path without '..' segments"); return; }
    let p = value;
    if (kind === "url") {
      if (!/^file:/iu.test(value)) return; // non-file URLs are not filesystem paths; network egress is the upstream/tool-tier policy's concern
      try { p = decodeURIComponent(new URL(value).pathname); } catch { return bad("malformed file: URL"); }
    }
    const roots = kind === "write" ? writeRoots : readRoots;
    if (roots.length === 0) return bad("no allowed roots configured");
    const real = realpathLoose(isAbsolute(p) ? p : join(base, p));
    if (!roots.some((r) => isUnder(real, r))) bad(`resolves to ${real}, outside allowed ${kind} roots`);
  };
  const walk = (v: unknown, key: string | null, kind: PathKind, depth: number) => {
    if (depth > 12) { violations.push({ key: key ?? "$", value: "", reason: "argument nesting too deep" }); return; }
    if (typeof v === "string") { if (kind) checkValue(key ?? "$", kind, v); return; }
    if (Array.isArray(v)) { for (const x of v) walk(x, key, kind, depth + 1); return; }
    if (v && typeof v === "object") for (const [k, x] of Object.entries(v as Record<string, unknown>)) walk(x, k, classifyKey(k) ?? (kind && typeof x !== "string" ? kind : null), depth + 1);
  };
  walk(args ?? {}, null, null, 0);
  return { ok: violations.length === 0, violations, checked };
}
