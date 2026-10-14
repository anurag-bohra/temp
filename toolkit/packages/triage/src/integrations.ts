// Wires the toolkit analyzer packages into the triage pipeline: analyzers (what runs, under which effects/policy)
// and Evidence-to-Facts adapters for their output shapes.
import { mkdirSync } from "node:fs";
import { join } from "node:path";
import { createEvidence, type Evidence } from "@rtk/evidence";
import { analyzeJavaScriptApplication } from "@rtk/js-analyzer";
import { inspectManagedAssembly } from "@rtk/dotnet-analyzer";
import { extractArchive, inspectArchive } from "@rtk/artifacts";
import { addApi, addPermission, addTag, registerFactsAdapter, scan, type Facts } from "./facts.ts";
import { extractIocs } from "./ioc.ts";
import { effectsFor, registerAnalyzer, type TriageResult } from "./pipeline.ts";
import { identify } from "./identify.ts";
import { parsePe } from "./features.ts";

type R = Record<string, unknown>; const asR = (x: unknown): R => (x && typeof x === "object" ? (x as R) : {}); const arr = (x: unknown): unknown[] => (Array.isArray(x) ? x : []);
const loc = (o: R): string | null => (o.file ? `${String(o.file)}:${String(asR(o.loc).line ?? "?")}` : null);

const ARCHIVE_TYPES = new Set(["zip", "apk", "jar", "ooxml", "ipa", "tar", "gzip", "asar"]);
const INTERESTING_CHILD = new Set(["elf", "pe", "macho", "macho-fat", "dex", "javascript", "script", "js-application", "zip", "apk", "jar", "asar", "wasm", "squashfs"]);

registerAnalyzer({ id: "js-analyzer", description: "AST analysis of JavaScript/Electron (sinks, taint, IPC, web preferences) via @rtk/js-analyzer", effects: effectsFor({}),
  handles: (id) => id.type === "js-application" || id.type === "javascript" || id.type === "asar", run: async ({ path }) => [await analyzeJavaScriptApplication(path)] });
registerAnalyzer({ id: "dotnet-analyzer", description: ".NET metadata/IL analysis via @rtk/dotnet-analyzer (runs a helper process; assembly is never loaded)", effects: effectsFor({ launchesProcess: true }),
  handles: (id) => { if (id.type !== "pe") return false; try { return parsePe(id.path).isDotNet; } catch { return false; } }, run: async ({ path }) => [await inspectManagedAssembly(path)] });
registerAnalyzer({ id: "archive-inspect", description: "Archive inventory and anomaly detection via @rtk/artifacts (read-only)", effects: effectsFor({}),
  handles: (id) => ARCHIVE_TYPES.has(id.type), run: async ({ path }) => [await inspectArchive(path)] });
registerAnalyzer({ id: "archive-recurse", description: "Quota-enforcing extraction into a scratch dir and recursive triage of interesting members", effects: effectsFor({ writesFilesystem: true }),
  handles: (id, { opts }) => ARCHIVE_TYPES.has(id.type) && (opts.depth ?? 1) > 0,
  async run({ path, opts, depth, scratch, recurse }) {
    const maxDepth = opts.depth ?? 1; if (depth >= maxDepth) return [];
    const dest = join(scratch(), "x"); mkdirSync(dest, { recursive: true }); const ex = await extractArchive(path, dest, undefined, { policy: "skip-bad" });
    const res = asR(ex.normalized_result); const out: Evidence[] = [ex]; if (res.status !== "ok" && res.status !== "complete" && !arr(res.manifest).length) return out;
    const files = arr(res.manifest).map(asR).filter((m) => m.type === "file").map((m) => String(m.path)); const summary: { path: string; type: string; band: string; score: number }[] = []; let n = 0;
    for (const rel of files) { if (n >= (opts.maxChildren ?? 25)) break; const full = join(dest, rel); let t; try { t = identify(full); } catch { continue; } if (!INTERESTING_CHILD.has(t.type)) continue; n++;
      const child = await recurse(full); out.push(...child.evidence.filter((e) => e.operation !== "triage_sample")); summary.push({ path: rel, type: t.type, band: child.score.band, score: child.score.score }); }
    out.push(createEvidence({ subject: null, provider: { id: "rtk-triage", name: "rea-toolkit triage pipeline", version: "1" }, predicate_type: "rtk.archive-children", operation: "triage_archive_children", parameters: { archive: path, depth, max_children: opts.maxChildren ?? 25 },
      normalized_result: { children: summary, candidates: files.length, analysed: n }, confidence: "derived", authority: "shipped-artifact", limitations: ["Only members whose type is interesting are triaged; the cap on analysed members is configurable."] }));
    return out;
  } });
registerAnalyzer({ id: "ghidra", description: "Ghidra headless snapshot (functions, strings, externals) via @rtk/ghidra-bridge; opt-in with deep:true", effects: effectsFor({ launchesProcess: true, writesFilesystem: true }),
  handles: (id, { opts }) => !!opts.deep && ["elf", "pe", "macho"].includes(id.type),
  async run({ path, identity }) {
    const { analyzeBinary } = await import("@rtk/ghidra-bridge"); const snap = await analyzeBinary(path); const s = snap as unknown as { functions: { name: string; external?: boolean; entry?: string }[]; strings: { value: string; address: string }[]; externals: { label: string }[]; program: R };
    return [createEvidence({ subject: { name: identity.path.split("/").pop()!, digest: { sha256: identity.sha256 }, local_path: path, format: identity.type, architecture: null }, provider: { id: "rtk-ghidra-bridge", name: "Ghidra headless snapshot", version: String((snap as { ghidra_version?: string }).ghidra_version ?? "") },
      predicate_type: "rtk.ghidra-summary", operation: "ghidra_summary", parameters: {}, normalized_result: { program: s.program, function_count: s.functions.length, externals: s.externals.map((x) => x.label), strings: s.strings.slice(0, 5000).map((x) => ({ v: x.value.slice(0, 300), a: x.address })) },
      confidence: "derived", authority: "shipped-artifact", limitations: ["Ghidra analysis is heuristic; defined strings only; x86-64 ELF is the verified lane."] })];
  } });
registerAnalyzer({ id: "sandbox", description: "Namespace-isolated bounded execution via @rtk/sandbox; opt-in with detonate:true and policy approval (executes the sample)", effects: effectsFor({ executesForeignCode: true, launchesProcess: true }),
  handles: (id, { opts }) => !!opts.detonate && id.type === "elf", run: async ({ path }) => { const { runSandboxed } = await import("@rtk/sandbox"); return [await runSandboxed({ sample: path, isolation: "auto" })]; } });

registerFactsAdapter({ name: "rtk:js-analyzer", match: (e) => e.provider.id === "rtk-js-analyzer" && e.operation === "analyze_javascript_application", apply(e, f: Facts) {
  const r = asR(e.normalized_result); const id = e.evidence_id; addTag(f, "javascript", id); const el = asR(r.electron); if (el.detected) addTag(f, "electron", id);
  for (const w of arr(el.windows).map(asR)) { const wp = asR(w.webPreferences); f.electron.windows.push({ nodeIntegration: wp.nodeIntegration as never, contextIsolation: wp.contextIsolation as never, sandbox: wp.sandbox as never, where: loc(w), evidence_id: id }); }
  for (const i of arr(el.ipc).map(asR)) f.electron.ipc.push({ channel: String(i.channel), senderValidation: typeof i.sender_validation === "boolean" ? i.sender_validation : null, where: loc(i), evidence_id: id });
  f.electron.contextBridgeApis += arr(el.contextBridge ?? el.context_bridge).length;
  // a flow the analyzer marks as guarded (sender/origin validation or allow-list) is kept visible but not treated as attacker-controlled
  const guarded = new Set(arr(r.flows).map(asR).filter((x) => x.guarded === true).map((x) => `${String(x.file)}:${String(asR(x.loc).line)}:${String(x.api)}`));
  for (const s of arr(r.sinks).map(asR)) { const api = String(s.api); const t0 = asR(s.taint).source; const isGuarded = guarded.has(`${String(s.file)}:${String(asR(s.loc).line)}:${api}`); const taint = typeof t0 === "string" ? (isGuarded ? `${t0}-guarded` : t0) : null; f.sinks.push({ kind: String(s.kind), api, where: loc(s), argument: s.argument ? String(asR(s.argument).value ?? "") : null, taint, evidence_id: id }); addApi(f, api, id); addApi(f, api.split(".").pop(), id); if (s.kind === "child-process") addApi(f, "child_process", id); if (s.kind === "timer") addApi(f, "setInterval", id); if (s.kind === "base64-decode") f.sinks.at(-1)!.kind = "base64-decode"; }
  for (const i of arr(r.iocs).map(asR)) extractIocs(String(i.value), f.iocs, { context: `js ${loc(i) ?? ""}`, evidenceId: id, allowDomains: f.allowDomains }, 0, arr(i.encoding).length ? String(i.literal_preview ?? "") : undefined);
} });
registerFactsAdapter({ name: "rtk:dotnet-analyzer", match: (e) => e.provider.id === "rtk-dotnet-analyzer", apply(e, f: Facts) {
  const r = asR(e.normalized_result); const id = e.evidence_id; addTag(f, "dotnet", id);
  for (const c of arr(r.call_edges).map(asR)) { addApi(f, c.target_name, id); if (c.target_type && c.target_name) addApi(f, `${String(c.target_type)}::${String(c.target_name)}`, id); }
  for (const p of arr(r.pinvokes).map(asR)) { addApi(f, p.entry_point, id); addApi(f, `${String(p.dll)}!${String(p.entry_point)}`, id); addTag(f, "pinvoke", id); }
  for (const l of arr(r.user_string_literals)) scan(f, typeof l === "string" ? l : asR(l).value, ".NET ldstr", id);
  for (const x of arr(r.indicators).map(asR)) addTag(f, `dotnet-indicator:${String(x.id)}`, id);
  for (const rs of arr(r.resources).map(asR)) f.iocs.add("embedded-resource", `resource ${String(rs.name)} sha256=${String(rs.sha256)} bytes=${String(rs.size)}`, "unknown", ".NET resource", id);
} });
registerFactsAdapter({ name: "rtk:artifacts", match: (e) => e.provider.id.startsWith("rtk-artifacts") && ["inspect_archive", "extract_archive"].includes(e.operation), apply(e, f: Facts) {
  const r = asR(e.normalized_result); for (const a of arr(r.anomalies).map(asR)) f.anomalies.push({ kind: String(a.code), detail: `${String(a.entry ?? "")} ${String(a.detail ?? "")}`.trim().slice(0, 300), evidence_id: e.evidence_id }); addTag(f, "archive", e.evidence_id);
} });
registerFactsAdapter({ name: "rtk:ghidra", match: (e) => e.operation === "ghidra_summary", apply(e, f: Facts) { const r = asR(e.normalized_result); for (const x of arr(r.externals)) addApi(f, x, e.evidence_id); for (const s of arr(r.strings).map(asR)) scan(f, s.v, `ghidra string @${String(s.a)}`, e.evidence_id); addTag(f, "ghidra", e.evidence_id); } });
registerFactsAdapter({ name: "rtk:sandbox", match: (e) => e.operation === "run_sandboxed", apply(e, f: Facts) {
  const r = asR(e.normalized_result); const id = e.evidence_id; addTag(f, "sandbox-ran", id); if (arr(asR(r.network).attempts).length) addTag(f, "sandbox-network-attempt", id);
  for (const p of arr(r.processes).map(asR)) scan(f, arr(p.cmdline).join(" "), "sandbox process", id);
  scan(f, asR(r.stdout).text, "sandbox stdout", id); scan(f, asR(r.stderr).text, "sandbox stderr", id);
} });
export type { TriageResult };
