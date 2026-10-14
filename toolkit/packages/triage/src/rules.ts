import { readFileSync } from "node:fs";
import type { Facts } from "./facts.ts";

export type Severity = "info" | "low" | "medium" | "high";
export type Cond =
  | { api_any: string[] } | { api_all: string[] } | { permission_any: string[] } | { tag_any: string[] } | { anomaly_any: string[] } | { yara_any: string[] }
  | { ioc: { kinds?: string[]; classification_not?: string[]; value_regex?: string; decoded?: boolean } }
  | { sink: { kind: string; taint_source?: string } } | { feature: { max_section_entropy_gt?: number; overlay_bytes_gt?: number; hardening_weak?: boolean } }
  | { electron: { window_nodeIntegration?: boolean; window_contextIsolation?: boolean; ipc_without_sender_validation?: boolean } }
  | { all: Cond[] } | { any: Cond[] } | { not: Cond };
export interface Rule { id: string; title: string; tactic: string; attack: string[]; severity: Severity; when: Cond; description?: string }
export interface RuleSet { version: number; note?: string; rules: Rule[] }
export interface Match { matched: boolean; evidence_ids: string[]; detail: string[] }
export interface Finding { rule_id: string; title: string; tactic: string; attack: string[]; severity: Severity; detail: string[]; evidence_ids: string[]; basis: "static-indicator-match (not a verdict)" }

export const loadRules = (path = new URL("../rules/default.json", import.meta.url).pathname): RuleSet => validateRules(JSON.parse(readFileSync(path, "utf8")));
const SEV = new Set(["info", "low", "medium", "high"]);
export function validateRules(x: unknown): RuleSet {
  const rs = x as RuleSet; if (!rs || !Array.isArray(rs.rules)) throw new Error("rule set must have a rules array"); const seen = new Set<string>();
  for (const r of rs.rules) { if (!r.id || seen.has(r.id)) throw new Error(`duplicate or missing rule id ${r.id}`); seen.add(r.id); if (!SEV.has(r.severity)) throw new Error(`rule ${r.id}: bad severity`); if (!r.when || typeof r.when !== "object") throw new Error(`rule ${r.id}: missing when`); checkCond(r.when, r.id); }
  return rs;
}
const COND_KEYS = ["api_any", "api_all", "permission_any", "tag_any", "anomaly_any", "yara_any", "ioc", "sink", "feature", "electron", "all", "any", "not"];
function checkCond(c: Cond, id: string): void { const keys = Object.keys(c); if (keys.length !== 1 || !COND_KEYS.includes(keys[0]!)) throw new Error(`rule ${id}: invalid condition ${JSON.stringify(c).slice(0, 80)}`); const k = keys[0] as keyof typeof c; if (k === "all" || k === "any") for (const s of (c as { all: Cond[] }).all ?? (c as { any: Cond[] }).any) checkCond(s, id); if (k === "not") checkCond((c as { not: Cond }).not, id); }

const none: Match = { matched: false, evidence_ids: [], detail: [] };
const union = (...xs: string[][]) => [...new Set(xs.flat())];
const rx = (s: string): RegExp => new RegExp(s.replace(/^\(\?i\)/u, ""), s.startsWith("(?i)") ? "iu" : "u");

export function evaluate(c: Cond, f: Facts): Match {
  if ("api_any" in c) { const hit = c.api_any.filter((a) => f.apis.has(a)); return hit.length ? { matched: true, evidence_ids: union(...hit.map((a) => [...f.apis.get(a)!])), detail: hit } : none; }
  if ("api_all" in c) return c.api_all.every((a) => f.apis.has(a)) ? { matched: true, evidence_ids: union(...c.api_all.map((a) => [...f.apis.get(a)!])), detail: c.api_all } : none;
  if ("permission_any" in c) { const hit = c.permission_any.filter((p) => f.permissions.has(p)); return hit.length ? { matched: true, evidence_ids: union(...hit.map((p) => [...f.permissions.get(p)!])), detail: hit } : none; }
  if ("tag_any" in c) { const hit = c.tag_any.filter((t) => f.tags.has(t)); return hit.length ? { matched: true, evidence_ids: union(...hit.map((t) => [...f.tags.get(t)!])), detail: hit } : none; }
  if ("anomaly_any" in c) { const hit = f.anomalies.filter((a) => c.anomaly_any.includes(a.kind)); return hit.length ? { matched: true, evidence_ids: union(hit.map((a) => a.evidence_id)), detail: hit.map((a) => `${a.kind}: ${a.detail}`) } : none; }
  if ("yara_any" in c) { const hit = f.yara.filter((y) => c.yara_any.includes("*") || c.yara_any.includes(y.rule)); return hit.length ? { matched: true, evidence_ids: union(hit.map((y) => y.evidence_id)), detail: hit.map((y) => `${y.rule} on ${y.target}`) } : none; }
  if ("ioc" in c) {
    const q = c.ioc; const re = q.value_regex ? rx(q.value_regex) : null;
    const hit = f.iocs.all().filter((i) => (!q.kinds || q.kinds.includes(i.kind)) && (!q.classification_not || !q.classification_not.includes(i.classification)) && (!re || re.test(i.value)) && (q.decoded === undefined || (i.decoded_from !== undefined) === q.decoded));
    return hit.length ? { matched: true, evidence_ids: union(...hit.map((i) => i.evidence_ids)), detail: hit.map((i) => `${i.kind}:${i.value}`) } : none;
  }
  if ("sink" in c) { const hit = f.sinks.filter((s) => s.kind === c.sink.kind && (!c.sink.taint_source || s.taint === c.sink.taint_source)); return hit.length ? { matched: true, evidence_ids: union(hit.map((s) => s.evidence_id)), detail: hit.map((s) => `${s.kind} ${s.api}${s.where ? " @ " + s.where : ""}${s.taint ? " (taint: " + s.taint + ")" : ""}`) } : none; }
  if ("feature" in c) {
    const q = c.feature; const ok = (q.max_section_entropy_gt === undefined || (f.features.maxSectionEntropy ?? 0) > q.max_section_entropy_gt) && (q.overlay_bytes_gt === undefined || (f.features.overlayBytes ?? 0) > q.overlay_bytes_gt) && (q.hardening_weak === undefined || (f.features.hardeningWeak ?? false) === q.hardening_weak);
    return ok ? { matched: true, evidence_ids: [...f.tags.get("feature-source") ?? []], detail: Object.entries(q).map(([k, v]) => `${k}=${String(v)}`) } : none;
  }
  if ("electron" in c) {
    const q = c.electron; const detail: string[] = []; const ids: string[] = [];
    if (q.window_nodeIntegration !== undefined) for (const w of f.electron.windows) if (w.nodeIntegration === q.window_nodeIntegration) { detail.push(`window nodeIntegration=${String(w.nodeIntegration)} ${w.where ?? ""}`); ids.push(w.evidence_id); }
    if (q.window_contextIsolation !== undefined) for (const w of f.electron.windows) if (w.contextIsolation === q.window_contextIsolation) { detail.push(`window contextIsolation=${String(w.contextIsolation)} ${w.where ?? ""}`); ids.push(w.evidence_id); }
    if (q.ipc_without_sender_validation) for (const i of f.electron.ipc) if (i.senderValidation === false) { detail.push(`ipc ${i.channel} has no sender validation`); ids.push(i.evidence_id); }
    return detail.length ? { matched: true, evidence_ids: union(ids), detail } : none;
  }
  if ("all" in c) { const ms = c.all.map((s) => evaluate(s, f)); return ms.every((m) => m.matched) ? { matched: true, evidence_ids: union(...ms.map((m) => m.evidence_ids)), detail: ms.flatMap((m) => m.detail) } : none; }
  if ("any" in c) { const ms = c.any.map((s) => evaluate(s, f)).filter((m) => m.matched); return ms.length ? { matched: true, evidence_ids: union(...ms.map((m) => m.evidence_ids)), detail: ms.flatMap((m) => m.detail) } : none; }
  return evaluate(c.not, f).matched ? none : { matched: true, evidence_ids: [], detail: ["negated condition holds"] };
}

export function applyRules(rs: RuleSet, f: Facts): Finding[] {
  const out: Finding[] = [];
  for (const r of rs.rules) { const m = evaluate(r.when, f); if (m.matched) out.push({ rule_id: r.id, title: r.title, tactic: r.tactic, attack: r.attack, severity: r.severity, detail: m.detail.slice(0, 12), evidence_ids: m.evidence_ids, basis: "static-indicator-match (not a verdict)" }); }
  return out;
}

export const SEVERITY_WEIGHT: Record<Severity, number> = { info: 0, low: 1, medium: 3, high: 6 };
export type Band = "no-suspicious-indicators-observed" | "some-indicators" | "suspicious" | "highly-suspicious";
/** Triage score: sum of severity weights with diminishing returns per tactic (each further finding in a tactic counts half). NOT a verdict. */
export function score(findings: Finding[]): { score: number; band: Band; by_tactic: Record<string, number>; note: string } {
  const byTactic: Record<string, Finding[]> = {}; for (const f of findings) (byTactic[f.tactic] ??= []).push(f);
  const by_tactic: Record<string, number> = {}; let total = 0;
  for (const [t, fs] of Object.entries(byTactic)) { const w = fs.map((f) => SEVERITY_WEIGHT[f.severity]).sort((a, b) => b - a); let s = 0; w.forEach((x, i) => { s += i === 0 ? x : x / 2; }); by_tactic[t] = Math.round(s * 10) / 10; total += s; }
  total = Math.round(total * 10) / 10;
  const band: Band = total < 3 ? "no-suspicious-indicators-observed" : total < 8 ? "some-indicators" : total < 16 ? "suspicious" : "highly-suspicious";
  return { score: total, band, by_tactic, note: "Heuristic triage score from static indicators; it is not a malware verdict and absence of findings does not establish safety." };
}
