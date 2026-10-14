import { mkdirSync, writeFileSync, mkdtempSync, rmSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, basename } from "node:path";
import { createEvidence, buildBundle, serializeBundle, sha256Hex, type Evidence } from "@rtk/evidence";
import { decide, PROFILES, type PolicyProfile, type ToolEffects } from "@rtk/effects";
import { identify, type Identity } from "./identify.ts";
import { staticFeatures } from "./static.ts";
import { addEvidence, newFacts, type Facts } from "./facts.ts";
import { applyRules, loadRules, score, type Finding, type RuleSet } from "./rules.ts";
import { yaraScan } from "./yara.ts";
import { toCsv, toMarkdown, toMisp, toStix, type ReportInput } from "./exporters/index.ts";
import { CaseStore } from "./store.ts";
import type { Ioc } from "./ioc.ts";

export interface TriageOptions {
  profile?: string | PolicyProfile; approve?: string[]; rules?: RuleSet; yaraRules?: string; allowDomains?: string[];
  depth?: number; maxChildren?: number; scratchDir?: string; keepScratch?: boolean; store?: CaseStore; deep?: boolean; detonate?: boolean; reaCommand?: string[];
  maxAnalyzerMs?: number; now?: () => Date;
}
export interface AnalyzerContext { path: string; identity: Identity; opts: TriageOptions; depth: number; scratch: () => string; recurse: (path: string) => Promise<TriageResult> }
export interface Analyzer { id: string; description: string; effects: ToolEffects; handles: (id: Identity, ctx: { opts: TriageOptions }) => boolean; run: (ctx: AnalyzerContext) => Promise<Evidence[]> }
const E = (o: Partial<ToolEffects>): ToolEffects => ({ mutatesTarget: false, mutatesSession: false, writesFilesystem: false, launchesProcess: false, accessesNetwork: false, changesUiState: false, mayDiscardData: false, executesForeignCode: false, mutatesDevice: false, idempotent: true, ...o });
export const effectsFor = E;

const analyzers: Analyzer[] = [];
export const registerAnalyzer = (a: Analyzer): void => { const i = analyzers.findIndex((x) => x.id === a.id); if (i >= 0) analyzers[i] = a; else analyzers.push(a); };
export const registeredAnalyzers = (): string[] => analyzers.map((a) => a.id);

registerAnalyzer({ id: "static-features", description: "Identity, strings, ELF/PE structure (built-in)", effects: E({}), handles: (id) => id.size > 0, run: async ({ identity }) => [staticFeatures(identity)] });
registerAnalyzer({ id: "yara", description: "YARA command-line scan with caller-supplied rules", effects: E({ launchesProcess: true }), handles: (id, { opts }) => !!opts.yaraRules && id.type !== "directory" && id.type !== "js-application" && id.size > 0, run: async ({ identity, opts }) => [await yaraScan(identity.path, opts.yaraRules!, identity.sha256)] });

export interface TriageResult {
  identity: Identity; evidence: Evidence[]; facts: Facts; findings: Finding[]; score: ReturnType<typeof score>; iocs: Ioc[]; skipped: { analyzer: string; reason: string }[]; ran: string[];
  children: { path: string; result: TriageResult }[]; triageEvidence: Evidence; report: ReportInput; bundle: { text: string; sha256: string };
}

const profileOf = (p: TriageOptions["profile"]): PolicyProfile => (typeof p === "object" ? p : PROFILES[p ?? "static-analysis"] ?? (() => { throw new Error(`unknown policy profile ${String(p)}`); })());

export async function triageSample(path: string, opts: TriageOptions = {}): Promise<TriageResult> { return triageInternal(path, opts, 0); }

async function triageInternal(path: string, opts: TriageOptions, depth: number): Promise<TriageResult> {
  const identity = identify(path); const profile = profileOf(opts.profile); const rules = opts.rules ?? loadRules(); const now = (opts.now ?? (() => new Date()))().toISOString();
  const facts = newFacts(opts.allowDomains ?? []); const evidence: Evidence[] = []; const skipped: TriageResult["skipped"] = []; const ran: string[] = []; const children: TriageResult["children"] = [];
  let scratchDir: string | null = null; const scratch = () => (scratchDir ??= opts.scratchDir ? (mkdirSync(opts.scratchDir, { recursive: true }), mkdtempSync(join(opts.scratchDir, "rtk-"))) : mkdtempSync(join(tmpdir(), "rtk-triage-")));
  const recurse = async (p: string) => triageInternal(p, { ...opts, store: undefined }, depth + 1);
  try {
    for (const a of analyzers) {
      let applies = false; try { applies = a.handles(identity, { opts }); } catch (e) { skipped.push({ analyzer: a.id, reason: `handles() failed: ${(e as Error).message}` }); continue; }
      if (!applies) continue;
      const d = decide(`analyzer:${a.id}`, a.effects, profile);
      if (d.verdict === "deny") { skipped.push({ analyzer: a.id, reason: `policy ${profile.name}: denied (tier ${d.tier})` }); continue; }
      if (d.verdict === "ask" && !(opts.approve ?? []).includes(a.id)) { skipped.push({ analyzer: a.id, reason: `policy ${profile.name}: needs approval (tier ${d.tier}); pass approve:[\"${a.id}\"]` }); continue; }
      try { const evs = await withTimeout(a.run({ path, identity, opts, depth, scratch, recurse }), opts.maxAnalyzerMs ?? 300000, a.id); evidence.push(...evs); ran.push(a.id); }
      catch (e) { skipped.push({ analyzer: a.id, reason: `failed: ${String((e as Error).message).slice(0, 300)}` }); }
    }
    for (const e of evidence) addEvidence(facts, e);
    const findings = applyRules(rules, facts); const sc = score(findings); const iocs = facts.iocs.all();
    const limitations = [...new Set(evidence.flatMap((e) => e.limitations))];
    const triageEvidence = createEvidence({
      subject: identity.sha256 ? { name: basename(path), digest: { sha256: identity.sha256 }, local_path: path, format: identity.type, architecture: null } : null,
      provider: { id: "rtk-triage", name: "rea-toolkit triage pipeline", version: "1" }, predicate_type: "rtk.triage", operation: "triage_sample",
      parameters: { profile: profile.name, analyzers_ran: ran, analyzers_skipped: skipped, rules_version: rules.version }, normalized_result: { score: sc, findings, ioc_count: iocs.length, evidence_count: evidence.length },
      confidence: "inferred", authority: "analyst-inference", limitations: ["Rule findings are heuristics over analyzer Evidence, not malware verdicts.", ...limitations.slice(0, 20)],
      evidence_links: evidence.map((e) => ({ evidence_id: e.evidence_id, operation: e.operation })),
    });
    const all = [...evidence, triageEvidence]; const bundleObj = buildBundle({ records: all }); const bundleText = serializeBundle(bundleObj);
    const report: ReportInput = { sample: { name: basename(path), sha256: identity.sha256, sha1: identity.sha1, md5: identity.md5, size: identity.size, type: identity.type }, iocs, findings, score: { score: sc.score, band: sc.band, note: sc.note, by_tactic: sc.by_tactic }, generatedAt: now, evidenceBundleSha256: sha256Hex(bundleText), limitations };
    const result: TriageResult = { identity, evidence: all, facts, findings, score: sc, iocs, skipped, ran, children, triageEvidence, report, bundle: { text: bundleText, sha256: sha256Hex(bundleText) } };
    if (opts.store && identity.sha256) { opts.store.upsertSample({ sha256: identity.sha256, name: basename(path), type: identity.type, size: identity.size, md5: identity.md5, sha1: identity.sha1 }, { score: sc.score, band: sc.band }); for (const e of all) opts.store.addEvidence(identity.sha256, e); opts.store.saveFindings(identity.sha256, now, findings); opts.store.saveIocs(identity.sha256, iocs); }
    return result;
  } finally { if (scratchDir && !opts.keepScratch) rmSync(scratchDir, { recursive: true, force: true }); }
}
const withTimeout = <T>(p: Promise<T>, ms: number, id: string): Promise<T> => new Promise((res, rej) => { const t = setTimeout(() => rej(new Error(`analyzer ${id} exceeded ${ms} ms`)), ms); p.then((v) => { clearTimeout(t); res(v); }, (e) => { clearTimeout(t); rej(e); }); });

export interface WrittenCase { dir: string; files: Record<string, string> }
/** Write the case directory: report.md/json, stix.json, misp.json, iocs.csv, evidence-bundle.json, manifest.json (with output hashes). */
export function writeCase(r: TriageResult, outDir: string): WrittenCase {
  mkdirSync(outDir, { recursive: true }); const files: Record<string, string> = {};
  const put = (n: string, content: string) => { writeFileSync(join(outDir, n), content, { mode: 0o640 }); files[n] = sha256Hex(content); };
  put("report.md", toMarkdown(r.report)); put("report.json", JSON.stringify({ sample: r.report.sample, score: r.score, findings: r.findings, iocs: r.iocs, ran: r.ran, skipped: r.skipped, evidence_ids: r.evidence.map((e) => e.evidence_id) }, null, 1));
  put("stix.json", JSON.stringify(toStix(r.report), null, 1)); put("misp.json", JSON.stringify(toMisp(r.report), null, 1)); put("iocs.csv", toCsv(r.iocs)); put("evidence-bundle.json", r.bundle.text);
  put("manifest.json", JSON.stringify({ generated: r.report.generatedAt, sample_sha256: r.identity.sha256, evidence_bundle_sha256: r.bundle.sha256, files: { ...files } }, null, 1));
  return { dir: outDir, files };
}
export const existsCase = (dir: string): boolean => existsSync(join(dir, "manifest.json"));
