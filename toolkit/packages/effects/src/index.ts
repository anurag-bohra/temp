// @rtk/effects — audited tool effects, derived MCP annotations, risk tiers and an ENFORCING policy engine.
// The ToolEffects model and annotation derivation mirror REA (src/contracts/toolEffects.ts); REA only advertises
// effects, it never enforces them — `decide()` is the enforcement point a gateway or agent host should call.
import { readFileSync } from "node:fs";

export interface ToolEffects {
  readonly mutatesTarget: boolean;
  readonly mutatesSession: boolean;
  readonly writesFilesystem: boolean;
  readonly launchesProcess: boolean;
  readonly accessesNetwork: boolean;
  readonly changesUiState: boolean;
  readonly mayDiscardData: boolean;
  readonly executesForeignCode: boolean;
  readonly mutatesDevice: boolean;
  readonly idempotent: boolean;
}
export interface DerivedToolAnnotations { readonly readOnlyHint: boolean; readonly destructiveHint: boolean; readonly idempotentHint: boolean; readonly openWorldHint: boolean }

export const EFFECT_FLAGS = ["mutatesTarget", "mutatesSession", "writesFilesystem", "launchesProcess", "accessesNetwork", "changesUiState", "mayDiscardData", "executesForeignCode", "mutatesDevice"] as const;

/** Same derivation rule as REA's `annotationsFromEffects` (no tool-name heuristics). */
export const deriveAnnotations = (v: ToolEffects): DerivedToolAnnotations => ({
  readOnlyHint: !EFFECT_FLAGS.some((f) => v[f]),
  destructiveHint: v.mayDiscardData || v.executesForeignCode || v.mutatesDevice,
  idempotentHint: v.idempotent,
  openWorldHint: v.launchesProcess || v.accessesNetwork,
});

export type Tier = "A" | "B" | "C" | "D" | "E";
export const TIER_MEANING: Record<Tier, string> = {
  A: "parse/inspect only (no process launch, network, filesystem write, target or device mutation, foreign code)",
  B: "writes files, launches helper processes or touches the network",
  C: "mutates the target database / analysis target",
  D: "executes foreign code (detonation class)",
  E: "mutates an attached device",
};
export const tierOf = (e: ToolEffects): Tier =>
  e.executesForeignCode ? "D" : e.mutatesDevice ? "E" : e.mutatesTarget ? "C" : e.writesFilesystem || e.launchesProcess || e.accessesNetwork ? "B" : "A";

export interface ToolRecord { kind: string; requiresSession: boolean; effects: ToolEffects; annotations: DerivedToolAnnotations }
export type EffectsTable = Record<string, ToolRecord>;

export const loadReaEffects = (): EffectsTable =>
  (JSON.parse(readFileSync(new URL("../data/rea-tool-effects.json", import.meta.url), "utf8")) as { tools: EffectsTable }).tools;

/** Verified audit gaps (REA f75b1a4, chapter 21): tools whose real behaviour exceeds their declared effects. */
export const KNOWN_AUDIT_GAPS: Record<string, { patch: Partial<ToolEffects>; why: string }> = {
  close_frida_session: { patch: { executesForeignCode: true }, why: "resumes a paused spawned target on close" },
  start_frida_session: { patch: { executesForeignCode: true }, why: "a failed start also resumes the paused spawn; attach/spawn precede script execution" },
  observe_web_execution: { patch: { executesForeignCode: true }, why: "drives a live page; classified by wording only in REA" },
  install_adb_package: { patch: { executesForeignCode: true }, why: "installs code onto a device (flagged mutatesDevice only)" },
  start_adb_app: { patch: { executesForeignCode: true }, why: "starts an app on the device" },
  start_adb_activity: { patch: { executesForeignCode: true }, why: "starts an activity on the device" },
};
/** Declared effects with the verified gap overlay applied (conservative). */
export const effectiveEffects = (name: string, declared: ToolEffects): ToolEffects =>
  KNOWN_AUDIT_GAPS[name] ? { ...declared, ...KNOWN_AUDIT_GAPS[name]!.patch } : declared;

export type Verdict = "allow" | "ask" | "deny";
export interface PolicyProfile { name: string; description: string; tiers: Record<Tier, Verdict>; allowTools?: string[]; denyTools?: string[] }
export const PROFILES: Record<string, PolicyProfile> = {
  locked: { name: "locked", description: "Tier A only", tiers: { A: "allow", B: "deny", C: "deny", D: "deny", E: "deny" } },
  "static-analysis": { name: "static-analysis", description: "Hostile samples on an analysis host: inspect + helper engines; target DB edits need approval; no execution", tiers: { A: "allow", B: "allow", C: "ask", D: "deny", E: "deny" } },
  "lab-vm": { name: "lab-vm", description: "Disposable detonation VM with egress control: execution needs approval; device mutation denied", tiers: { A: "allow", B: "allow", C: "allow", D: "ask", E: "deny" } },
  "device-lab": { name: "device-lab", description: "Dedicated analysis emulator/device", tiers: { A: "allow", B: "allow", C: "allow", D: "ask", E: "ask" } },
};
export interface Decision { verdict: Verdict; tier: Tier; reasons: string[]; effects: ToolEffects }

export function decide(tool: string, declared: ToolEffects, profile: PolicyProfile): Decision {
  const effects = effectiveEffects(tool, declared); const tier = tierOf(effects); const reasons: string[] = [];
  if (effects !== declared) reasons.push(`audit-gap overlay: ${KNOWN_AUDIT_GAPS[tool]!.why}`);
  if (profile.denyTools?.includes(tool)) return { verdict: "deny", tier, reasons: [...reasons, "tool explicitly denied by profile"], effects };
  if (profile.allowTools?.includes(tool)) return { verdict: "allow", tier, reasons: [...reasons, "tool explicitly allowed by profile"], effects };
  reasons.push(`tier ${tier}: ${TIER_MEANING[tier]}`);
  return { verdict: profile.tiers[tier], tier, reasons, effects };
}

export interface AuditProblem { tool: string; problem: string }
/** Consistency audit: advertised annotations must equal annotations derived from effects. */
export function auditAnnotations(table: EffectsTable): AuditProblem[] {
  const out: AuditProblem[] = [];
  for (const [tool, rec] of Object.entries(table)) {
    const d = deriveAnnotations(rec.effects);
    for (const k of Object.keys(d) as (keyof DerivedToolAnnotations)[]) if (d[k] !== rec.annotations[k]) out.push({ tool, problem: `${k}: advertised ${rec.annotations[k]} but derived ${d[k]}` });
  }
  return out;
}
export function tierSummary(table: EffectsTable, overlay = true): Record<Tier, string[]> {
  const s: Record<Tier, string[]> = { A: [], B: [], C: [], D: [], E: [] };
  for (const [tool, rec] of Object.entries(table)) s[tierOf(overlay ? effectiveEffects(tool, rec.effects) : rec.effects)].push(tool);
  return s;
}
