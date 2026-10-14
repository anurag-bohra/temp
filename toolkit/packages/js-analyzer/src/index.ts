import { readFileSync } from "node:fs";
import { createEvidence, type Evidence } from "@rtk/evidence";
import { analyzeFile, type BridgeRec, type FlowRec, type IocRec, type IpcRec, type LoadRec, type ModuleRef, type Sink, type WindowRec } from "./analyze-file.ts";
import { collect, DEFAULT_LIMITS, resolveRelative, type Limits } from "./files.ts";

export { compareJavaScriptApplications } from "./compare.ts";
export { DEFAULT_LIMITS } from "./files.ts";
export type { Limits } from "./files.ts";
export type { Sink, WindowRec, IpcRec, BridgeRec, IocRec, FlowRec, ModuleRef, LoadRec, Taint, TaintSource, SinkKind, PrefValue } from "./analyze-file.ts";

export const PROVIDER = { id: "rtk-js-analyzer", name: "RTK JavaScript/Electron static analyzer", version: "0.1.0" } as const;
export const OP_ANALYZE = "analyze_javascript_application";
export const PREDICATE_ANALYZE = "rtk.javascript-application-analysis";

export type AnalyzeOptions = Partial<Limits>;

export interface FileRecord { path: string; sha256: string | null; bytes: number; kind: string; parse_status: string; parse_error?: string; parse_error_loc?: { line: number; column: number } | null }

const cmp = (a: { file: string; loc: { line: number; column: number } }, b: { file: string; loc: { line: number; column: number } }): number =>
  a.file < b.file ? -1 : a.file > b.file ? 1 : a.loc.line - b.loc.line || a.loc.column - b.loc.column;

export async function analyzeJavaScriptApplication(inputPath: string, opts: AnalyzeOptions = {}): Promise<Evidence> {
  const limits: Limits = { ...DEFAULT_LIMITS, ...opts };
  const t0 = Date.now();
  const deadline = t0 + limits.timeBudgetMs;
  const col = collect(inputPath, limits);
  const limitations: string[] = [...col.limitations];
  try {
    const fileSet = new Set(col.files.filter((f) => !f.skipped).map((f) => f.path));
    const files: FileRecord[] = [];
    const modules: { path: string; imports: ModuleRef[] }[] = [];
    const windows: WindowRec[] = [], bridges: BridgeRec[] = [], ipc: IpcRec[] = [], sinks: Sink[] = [], iocs: IocRec[] = [], loads: LoadRec[] = [], flows: FlowRec[] = [];
    let budgetHit = false, depthLimited = 0;

    for (const f of col.files) {
      const rec: FileRecord = { path: f.path, sha256: f.sha256, bytes: f.bytes, kind: f.kind, parse_status: "not-parsed" };
      files.push(rec);
      if (f.skipped) { rec.parse_status = `skipped-${f.skipped}`; continue; }
      if (f.kind === "json") {
        try { JSON.parse(readFileSync(f.abs, "utf8")); rec.parse_status = "json-ok"; } catch (e) { rec.parse_status = "json-error"; rec.parse_error = String((e as Error).message).slice(0, 200); }
        continue;
      }
      if (f.kind !== "javascript") { rec.parse_status = f.kind === "native-addon" ? "native-binary-not-analysed" : "skipped-non-js"; continue; }
      if (Date.now() > deadline) { rec.parse_status = "skipped-time-budget"; budgetHit = true; continue; }
      const code = readFileSync(f.abs, "utf8").replace(/^#!.*/u, (m) => " ".repeat(m.length));
      const r = analyzeFile({ file: f.path, code, fileSet, deadline, maxAstDepth: limits.maxAstDepth });
      rec.parse_status = r.parse.status === "ok" ? "ok" : r.parse.status === "error" ? "parse-error" : "partial-budget-exceeded";
      if (r.parse.error) rec.parse_error = r.parse.error;
      if (r.parse.error_loc !== undefined) rec.parse_error_loc = r.parse.error_loc;
      if (r.parse.status === "budget-exceeded") budgetHit = true;
      if (r.parse.ast_depth_limited) { depthLimited++; rec.parse_status = rec.parse_status === "ok" ? "partial-depth-limit" : rec.parse_status; }
      modules.push({ path: f.path, imports: r.modules });
      windows.push(...r.windows); bridges.push(...r.bridges); ipc.push(...r.ipc); sinks.push(...r.sinks); iocs.push(...r.iocs); loads.push(...r.loads); flows.push(...r.flows);
    }

    for (const f of files) {
      if (f.parse_status === "skipped-too-large") limitations.push(`${f.path}: ${f.bytes} bytes exceeds maxFileBytes=${limits.maxFileBytes}; hashed but not parsed`);
      if (f.parse_status === "skipped-total-bytes-budget") limitations.push(`${f.path}: not read, total byte budget exhausted`);
      if (f.parse_status === "skipped-node_modules-excluded") limitations.push(`${f.path} excluded (set includeNodeModules to analyse dependencies)`);
    }
    if (budgetHit) limitations.push(`time budget ${limits.timeBudgetMs}ms exhausted: some files skipped or partially analysed (parse_status partial-*/skipped-time-budget)`);
    if (depthLimited) limitations.push(`${depthLimited} file(s) exceeded AST depth limit ${limits.maxAstDepth}; deeper subtrees not analysed`);
    limitations.push(
      "static analysis only: nothing was executed; dynamic constructs (computed requires, string-built URLs/commands, obfuscated or eval-generated code) are reported as 'dynamic', never guessed",
      "taint tracking is name-based and intra-file (closure-level): no cross-module data flow, no aliasing through object fields/arrays, no loops/fixpoint; absence of a flow is not proof of safety",
      "guard detection (equality / allowlist membership before a sink) is a heuristic and does not prove the guard sufficient",
      "sender_validation means the handler (or a same-file helper it passes the event to) reads event.senderFrame/sender url/origin/id and compares it; the comparison's correctness is not assessed",
      "IOCs come from JavaScript string literals (plus base64/hex layers up to depth 3); JSON, HTML and string concatenation are not scanned; IPv4 matches may include version strings",
      "Electron webPreferences 'unset' means the Electron default applies, which depends on the Electron version",
    );

    // ----- electron
    let mainEntry: { declared: string | null; resolved: string | null; source: string } = { declared: null, resolved: null, source: "none" };
    let electronVersion: string | null = null;
    const pkgRec = col.files.find((f) => f.path === "package.json" && !f.skipped);
    if (pkgRec) {
      try {
        const pkg = JSON.parse(readFileSync(pkgRec.abs, "utf8"));
        const m = typeof pkg.main === "string" ? pkg.main : null;
        mainEntry = { declared: m, resolved: m ? resolveRelative("package.json", "./" + m, fileSet) : fileSet.has("index.js") ? "index.js" : null, source: m ? "package.json:main" : "default-index.js" };
        const ev = pkg.dependencies?.electron ?? pkg.devDependencies?.electron;
        electronVersion = typeof ev === "string" ? ev : null;
      } catch { /* reported through file record */ }
    }
    windows.sort(cmp); bridges.sort(cmp); ipc.sort(cmp); sinks.sort(cmp); iocs.sort(cmp); loads.sort(cmp); flows.sort(cmp);
    const preloadFiles = new Set<string>();
    const preloads = windows.filter((w) => w.preload.expression_kind !== "unset").map((w) => { if (w.preload.resolved_file) preloadFiles.add(w.preload.resolved_file); return { window: `${w.file}:${w.loc.line}:${w.loc.column}`, expression_kind: w.preload.expression_kind, value: w.preload.value ?? null, resolved_file: w.preload.resolved_file ?? null }; });
    const bridgesOut = bridges.map((b) => ({ ...b, in_preload_file: preloadFiles.has(b.file) }));

    const byKind: Record<string, number> = {};
    for (const s of sinks) byKind[s.kind] = (byKind[s.kind] ?? 0) + 1;
    const isElectron = windows.length > 0 || ipc.length > 0 || bridges.length > 0 || electronVersion !== null;
    const normalized = {
      input: { name: col.inputName, format: col.format },
      limits,
      files,
      modules,
      electron: {
        detected: isElectron, electron_version: electronVersion, main_entry: mainEntry, windows, loads, preloads, context_bridge: bridgesOut, ipc,
        defaults_note: "webPreferences value 'unset' = Electron default for the (unknown) runtime version; 'dynamic' = not statically resolvable",
      },
      sinks, iocs, flows,
      summary: {
        files: files.length, javascript_files: files.filter((f) => f.kind === "javascript").length,
        parsed_ok: files.filter((f) => f.parse_status === "ok").length,
        parse_errors: files.filter((f) => f.parse_status === "parse-error" || f.parse_status === "json-error").length,
        skipped: files.filter((f) => f.parse_status.startsWith("skipped") || f.parse_status.startsWith("partial")).length,
        browser_windows: windows.length,
        insecure_windows: windows.filter((w) => w.webPreferences.nodeIntegration === true || w.webPreferences.contextIsolation === false || w.webPreferences.sandbox === false || w.webPreferences.webSecurity === false).length,
        preload_entrypoints: preloadFiles.size,
        context_bridge_apis: bridges.length,
        ipc: { total: ipc.length, main_handlers: ipc.filter((i) => i.side === "main" && i.kind !== "send").length, renderer_calls: ipc.filter((i) => i.side === "renderer").length, literal_channels: ipc.filter((i) => i.channel_kind === "literal").length, dynamic_channels: ipc.filter((i) => i.channel_kind === "dynamic").length, handlers_without_sender_validation: ipc.filter((i) => i.side === "main" && (i.kind === "handle" || i.kind === "on") && i.sender_validation === false).length },
        sinks: { total: sinks.length, by_kind: byKind, tainted: sinks.filter((s) => s.taint).length },
        iocs: iocs.length, flows: flows.length, unguarded_flows: flows.filter((f) => !f.guarded).length,
      },
    };
    const locations = [
      ...windows.map((w) => ({ kind: "browser-window", file: w.file, ...w.loc })),
      ...sinks.filter((s) => s.taint || s.kind !== "timer").map((s) => ({ kind: `sink:${s.kind}`, file: s.file, ...s.loc })),
      ...iocs.map((i) => ({ kind: `ioc:${i.kind}`, file: i.file, ...i.loc })),
    ];
    return createEvidence({
      subject: { name: col.inputName, digest: { sha256: col.subjectSha256 }, local_path: inputPath, format: col.format, architecture: null },
      provider: { ...PROVIDER },
      predicate_type: PREDICATE_ANALYZE,
      operation: OP_ANALYZE,
      parameters: { limits },
      normalized_result: normalized,
      confidence: "derived",
      authority: "shipped-artifact",
      limitations,
      locations,
    });
  } finally { col.cleanup(); }
}
