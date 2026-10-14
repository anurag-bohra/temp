import { builtinModules } from "node:module";
import { parse } from "@babel/parser";
import { resolveRelative } from "./files.ts";
import { scanLiteral, tryDecodeBase64 } from "./ioc.ts";

/* eslint-disable @typescript-eslint/no-explicit-any */
type N = any;

export type Loc = { line: number; column: number };
export type TaintSource = "network-response" | "ipc-argument" | "env" | "fs-read";
export interface Taint { source: TaintSource; path: string[]; channel?: string | null; guarded?: boolean; guard?: string }
export type PrefValue = boolean | string | number | null | "dynamic" | "unset";
export interface ArgInfo { kind: "literal" | "identifier" | "dynamic" | "function"; value?: string | number | boolean | null; resolved_value?: string | number | boolean; expression?: string }
export type SinkKind = "child-process" | "eval" | "function-constructor" | "vm" | "network-request" | "fs-write" | "base64-decode" | "dynamic-require" | "timer" | "native-addon";
export interface Sink { kind: SinkKind; file: string; loc: Loc; api: string; argument: ArgInfo; decoded_preview?: string; taint?: Taint }
export interface ModuleRef { specifier: string | null; form: "import" | "require" | "dynamic-import" | "export-from"; loc: Loc; status: "resolved" | "builtin" | "electron" | "external" | "unresolved" | "dynamic"; resolved?: string }
export interface WindowRec {
  file: string; loc: Loc; class: string; options_status: "object-literal" | "dynamic" | "none";
  webPreferences: Record<string, PrefValue>; web_preferences_status: "object-literal" | "dynamic" | "unset";
  preload: { expression_kind: "literal" | "dynamic" | "unset"; value?: string; resolved_file?: string | null };
}
export interface BridgeRec { api: string | "dynamic"; members: string[]; members_status: "object-literal" | "dynamic"; world: "main" | "isolated"; file: string; loc: Loc }
export interface IpcRec {
  channel: string | "dynamic"; channel_kind: "literal" | "dynamic"; kind: "handle" | "on" | "invoke" | "send"; side: "main" | "renderer";
  once: boolean; file: string; loc: Loc; sender_validation: boolean | null; handler?: { kind: "inline" | "identifier" | "dynamic"; loc?: Loc };
}
export interface IocRec { kind: "url" | "ip"; value: string; encoding: string[]; file: string; loc: Loc; literal_preview: string }
export interface LoadRec { kind: "loadFile" | "loadURL"; argument: ArgInfo; file: string; loc: Loc }
export interface FlowRec { source: TaintSource; sink_kind: SinkKind; api: string; file: string; loc: Loc; path: string[]; guarded: boolean; guard?: string; channel?: string | null }

export interface FileAnalysis {
  parse: { status: "ok" | "error" | "budget-exceeded"; error?: string; error_loc?: Loc | null; ast_depth_limited?: boolean; nodes?: number };
  modules: ModuleRef[]; windows: WindowRec[]; bridges: BridgeRec[]; ipc: IpcRec[]; sinks: Sink[]; iocs: IocRec[]; loads: LoadRec[]; flows: FlowRec[];
}

export class BudgetError extends Error {}

const BUILTINS = new Set(builtinModules.map((m) => m.replace(/^node:/u, "")));
const SKIP_KEYS = new Set(["loc", "start", "end", "extra", "leadingComments", "trailingComments", "innerComments", "range", "type", "errors", "tokens"]);

function children(n: N): N[] {
  const out: N[] = [];
  for (const k in n) {
    if (SKIP_KEYS.has(k)) continue;
    const v = n[k];
    if (Array.isArray(v)) { for (const c of v) if (c && typeof c.type === "string") out.push(c); }
    else if (v && typeof v.type === "string") out.push(v);
  }
  return out;
}
/** Iterative whole-tree walk (stack-safe) for the pre-passes. */
function walkAll(root: N, f: (n: N) => void): void {
  const st: N[] = [root];
  while (st.length) { const n = st.pop()!; f(n); const c = children(n); for (let i = c.length - 1; i >= 0; i--) st.push(c[i]); }
}

const isFn = (n: N): boolean => !!n && (n.type === "FunctionExpression" || n.type === "ArrowFunctionExpression" || n.type === "FunctionDeclaration" || n.type === "ObjectMethod" || n.type === "ClassMethod");
const locOf = (n: N): Loc => ({ line: n.loc?.start.line ?? 0, column: n.loc?.start.column ?? 0 });
const PREFS = ["nodeIntegration", "contextIsolation", "sandbox", "webSecurity", "nodeIntegrationInWorker", "nodeIntegrationInSubFrames", "enableRemoteModule", "allowRunningInsecureContent", "webviewTag", "experimentalFeatures"];
const GLOBAL_ROOTS = new Set(["window", "globalThis", "global", "self"]);

interface Ref { module: string | null; path: string[] }
interface Scope { vars: Map<string, Taint | null>; parent: Scope | null }

const CP = new Set(["exec", "execSync", "execFile", "execFileSync", "spawn", "spawnSync", "fork"]);
const VM_FNS = new Set(["runInThisContext", "runInNewContext", "runInContext", "compileFunction", "Script", "SourceTextModule"]);
const FS_WRITE = new Set(["writeFile", "writeFileSync", "appendFile", "appendFileSync", "createWriteStream", "copyFile", "copyFileSync", "rename", "renameSync"]);
const FS_READ = new Set(["readFile", "readFileSync", "createReadStream"]);
const NET_MODS = new Set(["http", "https", "http2"]);
const NET_CALLS = new Set(["request", "get"]);

export interface FileCtx { file: string; code: string; fileSet: Set<string>; deadline: number; maxAstDepth: number }

export function analyzeFile(ctx: FileCtx): FileAnalysis {
  const { file, code } = ctx;
  const res: FileAnalysis = { parse: { status: "ok" }, modules: [], windows: [], bridges: [], ipc: [], sinks: [], iocs: [], loads: [], flows: [] };
  let ast: N;
  try {
    ast = parse(code, {
      sourceType: "unambiguous", allowReturnOutsideFunction: true, allowAwaitOutsideFunction: true, allowImportExportEverywhere: true,
      allowSuperOutsideMethod: true, allowUndeclaredExports: true, errorRecovery: false,
      plugins: file.endsWith(".jsx") ? ["jsx"] : [],
    }).program;
  } catch (e: any) {
    res.parse = e instanceof RangeError
      ? { status: "error", error: "parser stack overflow (input nested too deeply)", error_loc: null }
      : { status: "error", error: String(e?.message ?? e).slice(0, 300), error_loc: e?.loc ? { line: e.loc.line, column: e.loc.column } : null };
    return res;
  }

  /* ---------- pre-pass A: aliases, constants, functions ---------- */
  const aliases = new Map<string, Ref>();
  const consts = new Map<string, string | number | boolean>();
  const constObjs = new Map<string, N>();
  const declCount = new Map<string, number>();
  const fnTable = new Map<string, N>();
  const bump = (name: string) => declCount.set(name, (declCount.get(name) ?? 0) + 1);

  const requireSpec = (n: N): string | null => {
    if (n?.type === "CallExpression" && n.callee.type === "Identifier" && n.callee.name === "require" && n.arguments.length >= 1) {
      const a = n.arguments[0];
      if (a.type === "StringLiteral") return a.value.replace(/^node:/u, "");
      if (a.type === "TemplateLiteral" && a.expressions.length === 0) return a.quasis[0].value.cooked.replace(/^node:/u, "");
    }
    return null;
  };
  const resolveRef = (n: N): Ref | null => {
    if (!n) return null;
    if (n.type === "Identifier") {
      const a = aliases.get(n.name);
      if (a && (declCount.get(n.name) ?? 0) <= 1) return a;
      if (n.name === "require" || n.name === "module") return null;
      return GLOBAL_ROOTS.has(n.name) ? { module: null, path: [] } : declCount.has(n.name) ? null : { module: null, path: [n.name] };
    }
    const spec = requireSpec(n);
    if (spec !== null) return { module: spec, path: [] };
    if (n.type === "MemberExpression" || n.type === "OptionalMemberExpression") {
      const base = resolveRef(n.object);
      if (!base) return null;
      let prop: string | null = null;
      if (!n.computed && n.property.type === "Identifier") prop = n.property.name;
      else if (n.computed && n.property.type === "StringLiteral") prop = n.property.value;
      if (prop === null) return null;
      return { module: base.module, path: [...base.path, prop] };
    }
    if (n.type === "SequenceExpression" && n.expressions.length === 2 && n.expressions[0].type === "NumericLiteral") return resolveRef(n.expressions[1]); // (0, eval)
    return null;
  };
  const bindPattern = (id: N, init: N): void => {
    if (id.type === "Identifier") {
      bump(id.name);
      const r = init ? resolveRef(init) : null;
      if (r && (r.module !== null || r.path.length > 0)) aliases.set(id.name, r);
      return;
    }
    if (id.type === "ObjectPattern") {
      const base = init ? resolveRef(init) : null;
      for (const p of id.properties) {
        if (p.type === "RestElement") { if (p.argument.type === "Identifier") bump(p.argument.name); continue; }
        const key = !p.computed && p.key.type === "Identifier" ? p.key.name : p.key.type === "StringLiteral" ? p.key.value : null;
        const v = p.value.type === "AssignmentPattern" ? p.value.left : p.value;
        if (v.type === "Identifier") { bump(v.name); if (base && key) aliases.set(v.name, { module: base.module, path: [...base.path, key] }); }
        else bindPattern(v, null);
      }
      return;
    }
    if (id.type === "ArrayPattern") { for (const e of id.elements) if (e) bindPattern(e, null); return; }
    if (id.type === "AssignmentPattern") bindPattern(id.left, null);
    if (id.type === "RestElement") bindPattern(id.argument, null);
  };
  walkAll(ast, (n) => {
    if (isFn(n)) for (const p of n.params) bindPattern(p, null);
    if (n.type === "ImportDeclaration") {
      const spec = String(n.source.value).replace(/^node:/u, "");
      for (const s of n.specifiers) {
        bump(s.local.name);
        if (s.type === "ImportSpecifier") aliases.set(s.local.name, { module: spec, path: [s.imported.name ?? s.imported.value] });
        else if (s.type === "ImportDefaultSpecifier") aliases.set(s.local.name, { module: spec, path: [] });
        else aliases.set(s.local.name, { module: spec, path: [] });
      }
    } else if (n.type === "VariableDeclarator") {
      bindPattern(n.id, n.init);
      if (n.id.type === "Identifier" && n.init) {
        const i = n.init;
        if (i.type === "StringLiteral" || i.type === "NumericLiteral" || i.type === "BooleanLiteral") consts.set(n.id.name, i.value);
        else if (i.type === "TemplateLiteral" && i.expressions.length === 0) consts.set(n.id.name, i.quasis[0].value.cooked);
        else if (i.type === "ObjectExpression") constObjs.set(n.id.name, i);
        else if (isFn(i)) fnTable.set(n.id.name, i);
      }
    } else if (n.type === "FunctionDeclaration" && n.id) { bump(n.id.name); fnTable.set(n.id.name, n); }
    else if (n.type === "AssignmentExpression" && n.left.type === "Identifier") { bump(n.left.name); bump(n.left.name); }
    else if (n.type === "CatchClause" && n.param) bindPattern(n.param, null);
  });
  for (const [k] of [...consts]) if ((declCount.get(k) ?? 0) !== 1) consts.delete(k);
  for (const [k] of [...constObjs]) if ((declCount.get(k) ?? 0) !== 1) constObjs.delete(k);
  for (const [k] of [...fnTable]) if ((declCount.get(k) ?? 0) !== 1) fnTable.delete(k);

  const constOf = (n: N): string | number | boolean | undefined => {
    if (!n) return undefined;
    if (n.type === "StringLiteral" || n.type === "NumericLiteral" || n.type === "BooleanLiteral") return n.value;
    if (n.type === "TemplateLiteral" && n.expressions.length === 0) return n.quasis[0].value.cooked;
    if (n.type === "Identifier") return consts.get(n.name);
    if (n.type === "UnaryExpression" && n.operator === "!" && n.argument.type === "NumericLiteral") return !n.argument.value;
    return undefined;
  };
  const snippet = (n: N): string => code.slice(n.start, n.end).replace(/\s+/gu, " ").slice(0, 120);
  const argInfo = (n: N | undefined): ArgInfo => {
    if (!n) return { kind: "dynamic", expression: "<missing>" };
    if (isFn(n)) return { kind: "function" };
    if (n.type === "StringLiteral" || n.type === "NumericLiteral" || n.type === "BooleanLiteral") return { kind: "literal", value: n.value };
    if (n.type === "NullLiteral") return { kind: "literal", value: null };
    if (n.type === "TemplateLiteral" && n.expressions.length === 0) return { kind: "literal", value: n.quasis[0].value.cooked };
    if (n.type === "Identifier") { const c = consts.get(n.name); return c === undefined ? { kind: "identifier", value: n.name } : { kind: "identifier", value: n.name, resolved_value: c }; }
    return { kind: "dynamic", expression: snippet(n) };
  };

  /* ---------- pre-pass B: ipc handlers passed by identifier ---------- */
  const IPC_MAIN_METHODS = new Set(["handle", "handleOnce", "on", "once"]);
  const ipcMainCall = (n: N): { method: string } | null => {
    if (n.type !== "CallExpression") return null;
    const r = resolveRef(n.callee);
    if (!r || r.module !== "electron" || r.path.length !== 2 || r.path[0] !== "ipcMain" || !IPC_MAIN_METHODS.has(r.path[1])) return null;
    return { method: r.path[1] };
  };
  const channelOf = (n: N): string | null => { const c = constOf(n); return typeof c === "string" ? c : null; };
  const handlerFnNodes = new Map<N, string | null>(); // function node -> channel (for identifier handlers)
  walkAll(ast, (n) => {
    if (ipcMainCall(n) && n.arguments[1]?.type === "Identifier") {
      const f = fnTable.get(n.arguments[1].name);
      if (f) handlerFnNodes.set(f, channelOf(n.arguments[0]));
    }
  });

  /* ---------- sender validation ---------- */
  const SENDER_READS = new Set(["url", "origin", "getURL", "id", "frameTreeNodeId", "processId", "routingId"]);
  const CMP_METHODS = new Set(["startsWith", "endsWith", "includes", "has", "test", "indexOf", "match", "equals", "some"]);
  const isCmpOp = (op: string) => op === "===" || op === "==" || op === "!==" || op === "!=";
  /** Is node (with ancestor chain) used as an operand of a comparison / membership test? */
  const comparedIn = (anc: N[], idx: number): boolean => {
    // anc[idx] is the value node; climb through member/call wrappers that keep the value flowing (.url -> .startsWith(...) / new URL(x).origin)
    for (let i = idx; i > 0; i--) {
      const p = anc[i - 1], c = anc[i];
      if (p.type === "BinaryExpression" && isCmpOp(p.operator)) return true;
      if (p.type === "MemberExpression" && p.object === c) {
        const gp = anc[i - 2];
        if (!p.computed && CMP_METHODS.has(p.property.name) && gp && gp.type === "CallExpression" && gp.callee === p) return true;
        continue;
      }
      if (p.type === "CallExpression" && p.arguments.includes(c)) {
        const cal = p.callee;
        if (cal.type === "MemberExpression" && !cal.computed && CMP_METHODS.has(cal.property.name)) return true;
        if (cal.type === "NewExpression") continue;
        return false;
      }
      if (p.type === "NewExpression" && p.arguments.includes(c)) continue; // new URL(x).origin
      if (p.type === "CallExpression" && p.callee === c) continue;
      if (p.type === "TemplateLiteral" || p.type === "LogicalExpression" || p.type === "UnaryExpression" || p.type === "ParenthesizedExpression") continue;
      if (p.type === "SwitchStatement" && p.discriminant === c) return true;
      return false;
    }
    return false;
  };
  const senderValidates = (fn: N, depth = 0, seen = new Set<N>()): boolean => {
    if (seen.has(fn) || depth > 2) return false;
    seen.add(fn);
    const evParam = fn.params?.[0];
    if (!evParam) return false;
    const evNames = new Set<string>();
    const senderNames = new Set<string>(); // destructured / aliased sender objects
    if (evParam.type === "Identifier") evNames.add(evParam.name);
    else if (evParam.type === "ObjectPattern") {
      for (const p of evParam.properties) if (p.type === "ObjectProperty" && p.key.type === "Identifier" && (p.key.name === "senderFrame" || p.key.name === "sender") && p.value.type === "Identifier") senderNames.add(p.value.name);
    } else return false;
    const body = fn.body;
    let ok = false;
    const readsVars = new Map<string, true>(); // vars assigned from a sender read
    const isSenderObj = (n: N): boolean => {
      if (n.type === "Identifier") return senderNames.has(n.name);
      if (n.type === "MemberExpression" && !n.computed && n.object.type === "Identifier" && evNames.has(n.object.name) && (n.property.name === "senderFrame" || n.property.name === "sender")) return true;
      if (n.type === "MemberExpression" && !n.computed && isSenderObj(n.object) && n.property.name === "frame") return true;
      return false;
    };
    const scan = (n: N, anc: N[]): void => {
      if (ok) return;
      anc.push(n);
      if (n !== fn && isFn(n) && !(n.type === "ArrowFunctionExpression" || n.type === "FunctionExpression")) { anc.pop(); return; }
      let readNode = false;
      if (n.type === "MemberExpression" && !n.computed && SENDER_READS.has(n.property.name) && isSenderObj(n.object)) readNode = true;
      if (n.type === "CallExpression" && n.callee.type === "MemberExpression" && !n.callee.computed && n.callee.property.name === "getURL" && isSenderObj(n.callee.object)) readNode = true;
      if (readNode) {
        if (comparedIn(anc, anc.length - 1)) { ok = true; anc.pop(); return; }
        const p = anc[anc.length - 2];
        if (p?.type === "VariableDeclarator" && p.id.type === "Identifier") readsVars.set(p.id.name, true);
      }
      if (n.type === "Identifier" && readsVars.has(n.name) && comparedIn(anc, anc.length - 1)) { const p = anc[anc.length - 2]; if (!(p?.type === "VariableDeclarator" && p.id === n)) { ok = true; anc.pop(); return; } }
      if (n.type === "CallExpression" && depth < 2 && n.callee.type === "Identifier" && n.arguments[0]?.type === "Identifier" && evNames.has(n.arguments[0].name)) {
        const g = fnTable.get(n.callee.name);
        if (g && senderValidates(g, depth + 1, seen)) { ok = true; anc.pop(); return; }
      }
      for (const c of children(n)) scan(c, anc);
      anc.pop();
    };
    try { scan(body, [fn]); } catch (e) { if (!(e instanceof RangeError)) throw e; }
    return ok;
  };

  /* ---------- main pass ---------- */
  let nodeCount = 0;
  const pendingSeeds = new Map<N, (Taint | null)[]>();
  const newScope = (parent: Scope | null): Scope => ({ vars: new Map(), parent });
  let scope: Scope = newScope(null);
  const lookupScope = (name: string): Scope | null => { for (let s: Scope | null = scope; s; s = s.parent) if (s.vars.has(name)) return s; return null; };
  const getVar = (name: string): Taint | null => lookupScope(name)?.vars.get(name) ?? null;
  const setVar = (name: string, t: Taint | null, declare: boolean): void => {
    if (declare) { scope.vars.set(name, t); return; }
    (lookupScope(name) ?? scope).vars.set(name, t);
  };
  const merge = (...ts: (Taint | null)[]): Taint | null => {
    const live = ts.filter((t): t is Taint => !!t);
    return live.find((t) => !t.guarded) ?? live[0] ?? null;
  };
  const ext = (t: Taint | null, step: string): Taint | null => (t ? { ...t, path: [...t.path, step].slice(-12) } : null);

  const isNetFetchCall = (callee: N): string | null => {
    const r = resolveRef(callee);
    if (!r) return null;
    if (r.module === null && r.path.length === 1 && r.path[0] === "fetch") return "fetch";
    if (r.module === null && r.path.length === 1 && r.path[0] === "$") return null;
    if (r.module === "axios" || r.module === "got" || r.module === "node-fetch" || r.module === "undici" || r.module === "needle" || r.module === "superagent") return `${r.module}.${r.path.join(".") || "call"}`;
    return null;
  };

  const taintOf = (n: N): Taint | null => {
    if (!n) return null;
    switch (n.type) {
      case "Identifier": return getVar(n.name);
      case "MemberExpression": case "OptionalMemberExpression": {
        const r = resolveRef(n);
        if (r && r.module === null && r.path[0] === "process" && r.path[1] === "env") return { source: "env", path: [`env:${r.path.slice(2).join(".") || "*"}`] };
        if (r && r.module === "process" && r.path[0] === "env") return { source: "env", path: [`env:${r.path.slice(1).join(".") || "*"}`] };
        return taintOf(n.object);
      }
      case "CallExpression": case "OptionalCallExpression": {
        const f = isNetFetchCall(n.callee);
        if (f) return { source: "network-response", path: [`${f}@${file}:${n.loc?.start.line}`] };
        const r = resolveRef(n.callee);
        if (r && r.module === "fs" && FS_READ.has(r.path[r.path.length - 1]) && r.path[r.path.length - 1] !== "createReadStream") return { source: "fs-read", path: [`fs.${r.path[r.path.length - 1]}@${file}:${n.loc?.start.line}`] };
        const parts: (Taint | null)[] = [];
        if (n.callee.type === "MemberExpression" || n.callee.type === "OptionalMemberExpression") parts.push(taintOf(n.callee.object));
        for (const a of n.arguments) if (!isFn(a)) parts.push(taintOf(a.type === "SpreadElement" ? a.argument : a));
        return merge(...parts);
      }
      case "NewExpression": {
        const r = resolveRef(n.callee);
        if (r && r.path[r.path.length - 1] === "WebSocket") return { source: "network-response", path: [`WebSocket@${file}:${n.loc?.start.line}`] };
        return merge(...n.arguments.filter((a: N) => !isFn(a)).map(taintOf));
      }
      case "AwaitExpression": case "UnaryExpression": case "SpreadElement": case "ParenthesizedExpression": case "TSAsExpression": return taintOf(n.argument ?? n.expression);
      case "BinaryExpression": case "LogicalExpression": return merge(taintOf(n.left), taintOf(n.right));
      case "ConditionalExpression": return merge(taintOf(n.consequent), taintOf(n.alternate));
      case "AssignmentExpression": return taintOf(n.right);
      case "TemplateLiteral": return merge(...n.expressions.map(taintOf));
      case "ArrayExpression": return merge(...n.elements.map((e: N) => taintOf(e)));
      case "ObjectExpression": return merge(...n.properties.map((p: N) => (p.type === "ObjectProperty" ? taintOf(p.value) : p.type === "SpreadElement" ? taintOf(p.argument) : null)));
      case "SequenceExpression": return taintOf(n.expressions[n.expressions.length - 1]);
      default: return null;
    }
  };

  const bindTaint = (id: N, t: Taint | null, declare: boolean): void => {
    if (!id) return;
    switch (id.type) {
      case "Identifier": setVar(id.name, t ? ext(t, `var:${id.name}`) : t, declare); break;
      case "ObjectPattern": for (const p of id.properties) bindTaint(p.type === "RestElement" ? p.argument : p.value, t, declare); break;
      case "ArrayPattern": for (const e of id.elements) if (e) bindTaint(e, t, declare); break;
      case "AssignmentPattern": bindTaint(id.left, t, declare); break;
      case "RestElement": bindTaint(id.argument, t, declare); break;
      default: break;
    }
  };
  const rootIdent = (n: N): string | null => { while (n && (n.type === "MemberExpression" || n.type === "OptionalMemberExpression")) n = n.object; return n?.type === "Identifier" ? n.name : null; };

  /* guard detection: comparison against tainted variable guarding later code */
  const terminates = (n: N): boolean => {
    if (!n) return false;
    if (n.type === "ThrowStatement" || n.type === "ReturnStatement") return true;
    if (n.type === "BlockStatement") return n.body.length > 0 && terminates(n.body[n.body.length - 1]);
    return false;
  };
  const guardNames = (test: N, out: Map<string, string>): void => {
    if (!test) return;
    const ids = (e: N): string[] => { const r: string[] = []; walkAll(e, (x) => { if (x.type === "Identifier") r.push(x.name); }); return r; };
    switch (test.type) {
      case "LogicalExpression": guardNames(test.left, out); guardNames(test.right, out); return;
      case "UnaryExpression": guardNames(test.argument, out); return;
      case "BinaryExpression": if (test.operator === "===" || test.operator === "==" || test.operator === "!==" || test.operator === "!=") for (const i of ids(test)) out.set(i, "equality"); return;
      case "CallExpression": {
        const c = test.callee;
        if (c.type === "MemberExpression" && !c.computed && (c.property.name === "has" || c.property.name === "includes")) {
          const objTainted = taintOf(c.object);
          if (!objTainted) for (const a of test.arguments) for (const i of ids(a)) out.set(i, "allowlist-membership");
        } else if (c.type === "MemberExpression" && !c.computed && CMP_METHODS.has(c.property.name)) {
          for (const i of ids(c.object)) if (!out.has(i)) out.set(i, "weak-pattern-check");
        }
        return;
      }
      default: return;
    }
  };
  const applyGuards = (names: Map<string, string>, where: string): Map<string, Taint | null> => {
    const saved = new Map<string, Taint | null>();
    for (const [name, strength] of names) {
      const sc = lookupScope(name);
      const t = sc?.vars.get(name);
      if (!sc || !t || strength === "weak-pattern-check") continue;
      saved.set(name, t);
      sc.vars.set(name, { ...t, guarded: true, guard: `${strength}@${file}:${where}`, path: [...t.path, `guard:${strength}`] });
    }
    return saved;
  };

  const recordSink = (kind: SinkKind, node: N, api: string, arg: N | undefined, taintArgs: N[], extra?: Partial<Sink>): void => {
    const s: Sink = { kind, file, loc: locOf(node), api, argument: argInfo(arg), ...extra };
    const t = merge(...taintArgs.map((a) => taintOf(a?.type === "SpreadElement" ? a.argument : a)));
    if (t) {
      s.taint = { source: t.source, path: t.path, ...(t.channel !== undefined ? { channel: t.channel } : {}), ...(t.guarded ? { guarded: true, guard: t.guard } : {}) };
      res.flows.push({ source: t.source, sink_kind: kind, api, file, loc: s.loc, path: t.path, guarded: !!t.guarded, ...(t.guard ? { guard: t.guard } : {}), ...(t.channel !== undefined ? { channel: t.channel } : {}) });
    }
    res.sinks.push(s);
  };

  const resolvePreload = (n: N | undefined): WindowRec["preload"] => {
    if (!n) return { expression_kind: "unset" };
    const lits: string[] = [];
    const collect = (e: N): boolean => {
      const c = constOf(e);
      if (typeof c === "string") { lits.push(c); return true; }
      if (e.type === "Identifier" && e.name === "__dirname") return true;
      if (e.type === "CallExpression") { const r = resolveRef(e.callee); if (r && r.module === "path" && (r.path[0] === "join" || r.path[0] === "resolve")) return e.arguments.every(collect); return false; }
      if (e.type === "BinaryExpression" && e.operator === "+") return collect(e.left) && collect(e.right);
      return false;
    };
    if (!collect(n) || lits.length === 0) return { expression_kind: "dynamic" };
    const v = lits.join("/").replace(/\/{2,}/gu, "/");
    const resolved = resolveRelative(file, "./" + v.replace(/^\/+/u, ""), ctx.fileSet);
    return { expression_kind: "literal", value: v, resolved_file: resolved };
  };

  const windowFrom = (node: N, cls: string): WindowRec => {
    const w: WindowRec = { file, loc: locOf(node), class: cls, options_status: "none", webPreferences: {}, web_preferences_status: "unset", preload: { expression_kind: "unset" } };
    let opts = node.arguments[0];
    if (opts?.type === "Identifier" && constObjs.has(opts.name)) opts = constObjs.get(opts.name);
    if (!opts) { for (const p of PREFS) w.webPreferences[p] = "unset"; return w; }
    if (opts.type !== "ObjectExpression") { w.options_status = "dynamic"; w.web_preferences_status = "dynamic"; for (const p of PREFS) w.webPreferences[p] = "dynamic"; w.preload = { expression_kind: "dynamic" }; return w; }
    w.options_status = "object-literal";
    const optsSpread = opts.properties.some((p: N) => p.type === "SpreadElement");
    let wp: N = null; let wpDynamic = optsSpread;
    for (const p of opts.properties) {
      if (p.type === "ObjectProperty" && ((!p.computed && p.key.type === "Identifier" && p.key.name === "webPreferences") || (p.key.type === "StringLiteral" && p.key.value === "webPreferences"))) {
        wp = p.value; wpDynamic = false;
      }
    }
    if (wp?.type === "Identifier" && constObjs.has(wp.name)) wp = constObjs.get(wp.name);
    if (!wp) { w.web_preferences_status = wpDynamic ? "dynamic" : "unset"; for (const p of PREFS) w.webPreferences[p] = wpDynamic ? "dynamic" : "unset"; return w; }
    if (wp.type !== "ObjectExpression") { w.web_preferences_status = "dynamic"; for (const p of PREFS) w.webPreferences[p] = "dynamic"; w.preload = { expression_kind: "dynamic" }; return w; }
    w.web_preferences_status = "object-literal";
    const spread = wp.properties.some((p: N) => p.type === "SpreadElement");
    const props = new Map<string, N>();
    for (const p of wp.properties) {
      if (p.type !== "ObjectProperty" && p.type !== "ObjectMethod") continue;
      const k = p.computed ? null : p.key.type === "Identifier" ? p.key.name : p.key.type === "StringLiteral" ? p.key.value : null;
      if (k === null) { continue; }
      props.set(k, p.type === "ObjectProperty" ? p.value : null);
    }
    const hasComputed = wp.properties.some((p: N) => (p.type === "ObjectProperty" || p.type === "ObjectMethod") && (p.computed || (p.key.type !== "Identifier" && p.key.type !== "StringLiteral")));
    for (const p of PREFS) {
      if (props.has(p)) { const c = constOf(props.get(p)); w.webPreferences[p] = c === undefined ? "dynamic" : c; }
      else w.webPreferences[p] = spread || hasComputed ? "dynamic" : "unset";
    }
    w.preload = props.has("preload") ? resolvePreload(props.get("preload")) : spread ? { expression_kind: "dynamic" } : { expression_kind: "unset" };
    return w;
  };

  const handleCall = (n: N): void => {
    const callee = n.callee;
    const r = resolveRef(callee);
    const last = r ? r.path[r.path.length - 1] : undefined;
    const isNew = n.type === "NewExpression";
    const args: N[] = n.arguments;

    // ---- electron: windows / bridge / ipc / loads
    if (isNew && r && (r.module === "electron" ? ["BrowserWindow", "BrowserView", "WebContentsView"].includes(r.path[0] ?? "") && r.path.length === 1 : false)) { res.windows.push(windowFrom(n, r.path[0])); return; }
    if (r && r.module === "electron" && r.path.length === 2 && r.path[0] === "contextBridge" && !isNew) {
      if (r.path[1] === "exposeInMainWorld" || r.path[1] === "exposeInIsolatedWorld") {
        const iso = r.path[1] === "exposeInIsolatedWorld";
        const keyNode = args[iso ? 1 : 0]; let objNode = args[iso ? 2 : 1];
        const key = constOf(keyNode);
        if (objNode?.type === "Identifier" && constObjs.has(objNode.name)) objNode = constObjs.get(objNode.name);
        const members: string[] = []; let status: BridgeRec["members_status"] = "object-literal";
        if (objNode?.type === "ObjectExpression") {
          for (const p of objNode.properties) {
            if (p.type === "SpreadElement") { status = "dynamic"; continue; }
            const k = p.computed ? null : p.key.type === "Identifier" ? p.key.name : p.key.type === "StringLiteral" ? p.key.value : null;
            if (k === null) status = "dynamic"; else members.push(k);
          }
        } else status = "dynamic";
        res.bridges.push({ api: typeof key === "string" ? key : "dynamic", members, members_status: status, world: iso ? "isolated" : "main", file, loc: locOf(n) });
        return;
      }
    }
    if (r && r.module === "electron" && r.path.length === 2 && r.path[0] === "ipcMain" && IPC_MAIN_METHODS.has(r.path[1]) && !isNew) {
      const method = r.path[1];
      const ch = channelOf(args[0]);
      let handler = args[1]; let hKind: "inline" | "identifier" | "dynamic" = "dynamic";
      if (isFn(handler)) hKind = "inline";
      else if (handler?.type === "Identifier" && fnTable.has(handler.name)) { hKind = "identifier"; handler = fnTable.get(handler.name); }
      res.ipc.push({
        channel: ch ?? "dynamic", channel_kind: ch === null ? "dynamic" : "literal", kind: method.startsWith("handle") ? "handle" : "on", side: "main",
        once: method.endsWith("Once") || method === "once", file, loc: locOf(n),
        sender_validation: hKind === "dynamic" ? false : senderValidates(handler),
        handler: { kind: hKind, ...(hKind !== "dynamic" ? { loc: locOf(handler) } : {}) },
      });
      return;
    }
    if (r && r.module === "electron" && r.path.length === 2 && r.path[0] === "ipcRenderer" && ["invoke", "send", "sendSync", "sendToHost", "postMessage"].includes(r.path[1]) && !isNew) {
      const ch = channelOf(args[0]);
      res.ipc.push({ channel: ch ?? "dynamic", channel_kind: ch === null ? "dynamic" : "literal", kind: r.path[1] === "invoke" ? "invoke" : "send", side: "renderer", once: false, file, loc: locOf(n), sender_validation: null });
      return;
    }
    if (!isNew && (callee.type === "MemberExpression") && !callee.computed && (callee.property.name === "loadFile" || callee.property.name === "loadURL") && args.length >= 1) {
      res.loads.push({ kind: callee.property.name, argument: argInfo(args[0]), file, loc: locOf(n) });
    }
    if (!isNew && callee.type === "MemberExpression" && !callee.computed && callee.property.name === "send" && callee.object.type === "MemberExpression" && !callee.object.computed && callee.object.property.name === "webContents") {
      const ch = channelOf(args[0]);
      res.ipc.push({ channel: ch ?? "dynamic", channel_kind: ch === null ? "dynamic" : "literal", kind: "send", side: "main", once: false, file, loc: locOf(n), sender_validation: null });
    }

    // ---- sinks
    if (r) {
      const mod = r.module;
      const api = mod ? `${mod}${r.path.length ? "." + r.path.join(".") : ""}` : r.path.join(".");
      if (mod === "child_process" && last && CP.has(last)) {
        const nonFn = args.filter((a) => !isFn(a));
        recordSink("child-process", n, `child_process.${last}`, args[0], nonFn);
        return;
      }
      if (mod === null && r.path.length === 1 && r.path[0] === "eval" && !isNew) { recordSink("eval", n, "eval", args[0], args); return; }
      if (mod === null && r.path.length === 1 && r.path[0] === "Function") { recordSink("function-constructor", n, "Function", args[args.length - 1], args); return; }
      if (mod === null && r.path.length === 2 && r.path[0] === "Function" && !isNew) { /* Function.prototype.* */ }
      if (mod === "vm" && last && VM_FNS.has(last)) { recordSink("vm", n, `vm.${last}`, args[0], args.filter((a) => !isFn(a))); return; }
      if (mod === null && r.path.length === 1 && (r.path[0] === "setTimeout" || r.path[0] === "setInterval" || r.path[0] === "setImmediate")) {
        const a0 = args[0];
        const t = isFn(a0) ? null : taintOf(a0);
        const s: Sink = { kind: "timer", file, loc: locOf(n), api: r.path[0], argument: argInfo(a0) };
        if (t) { s.taint = { source: t.source, path: t.path }; res.flows.push({ source: t.source, sink_kind: "timer", api: r.path[0], file, loc: s.loc, path: t.path, guarded: !!t.guarded }); }
        res.sinks.push(s); return;
      }
      if (mod === null && r.path.length === 1 && r.path[0] === "atob") { recordSink("base64-decode", n, "atob", args[0], args, decodedExtra(args[0])); return; }
      if (mod === "buffer" || mod === null) {
        const p = mod === null ? r.path : r.path.slice(0);
        if (p.length === 2 && p[0] === "Buffer" && p[1] === "from" && constOf(args[1]) === "base64") { recordSink("base64-decode", n, "Buffer.from(base64)", args[0], [args[0]], decodedExtra(args[0])); return; }
      }
      if (mod === null && r.path.length === 1 && r.path[0] === "fetch") { recordSink("network-request", n, "fetch", args[0], args.slice(1)); return; }
      if (mod && NET_MODS.has(mod) && last && NET_CALLS.has(last) && r.path.length === 1) { recordSink("network-request", n, `${mod}.${last}`, args[0], args.filter((a) => !isFn(a))); return; }
      if (mod === "net" || mod === "tls" || mod === "dgram") { if (last && ["connect", "createConnection", "createSocket"].includes(last)) { recordSink("network-request", n, `${mod}.${last}`, args[0], args.filter((a) => !isFn(a))); return; } }
      if (mod === "axios" || mod === "got" || mod === "node-fetch" || mod === "superagent" || mod === "needle") { recordSink("network-request", n, api, args[0], args.filter((a) => !isFn(a))); return; }
      if (isNew && mod === null && (r.path[r.path.length - 1] === "WebSocket" || r.path[r.path.length - 1] === "EventSource") && r.path.length === 1) { recordSink("network-request", n, r.path[0], args[0], []); return; }
      if (mod === "ws" && isNew) { recordSink("network-request", n, "ws.WebSocket", args[0], []); return; }
      if (mod === "fs" && last && FS_WRITE.has(last)) { recordSink("fs-write", n, `fs.${r.path.join(".")}`, args[0], args.slice(1).filter((a) => !isFn(a))); return; }
      if (mod === null && r.path.length === 1 && r.path[0] === "require" && !isNew) { /* handled below */ }
      if ((mod === "process" || mod === null) && (mod === null ? r.path.join(".") === "process.dlopen" : r.path.join(".") === "dlopen")) { recordSink("native-addon", n, "process.dlopen", args[1], []); return; }
      if (mod === "bindings" || mod === "node-gyp-build" || mod === "node-pre-gyp") { if (r.path.length === 0) { recordSink("native-addon", n, mod, args[0], []); return; } }
    }
    if (isNew && callee.type === "MemberExpression" && !callee.computed && callee.property.name === "open") { /* no-op */ }
    // XMLHttpRequest.open(method, url): receiver unknown statically; match on constructor-bound variable names is not attempted.
    if (!isNew && callee.type === "Identifier" && callee.name === "require" && args.length >= 1) {
      const spec = requireSpec(n);
      if (spec === null) { recordSink("dynamic-require", n, "require", args[0], []); }
      else if (spec.endsWith(".node")) recordSink("native-addon", n, "require(.node)", args[0], []);
      return;
    }
    if (!isNew && callee.type === "MemberExpression" && !callee.computed && callee.property.name === "require" && callee.object.type === "Identifier" && callee.object.name === "module" && args.length >= 1) {
      if (constOf(args[0]) === undefined) recordSink("dynamic-require", n, "module.require", args[0], []);
      return;
    }
  };
  function decodedExtra(a: N | undefined): Partial<Sink> {
    const c = a ? constOf(a) : undefined;
    if (typeof c !== "string") return {};
    const d = tryDecodeBase64(c);
    return d === null ? {} : { decoded_preview: d.slice(0, 200) };
  }

  const handleModules = (n: N): void => {
    const add = (specifier: string | null, form: ModuleRef["form"], node: N): void => {
      if (specifier === null) { res.modules.push({ specifier: null, form, loc: locOf(node), status: "dynamic" }); return; }
      const bare = specifier.replace(/^node:/u, "");
      let m: ModuleRef;
      if (specifier.startsWith(".") || specifier.startsWith("/")) {
        const r = resolveRelative(file, specifier, ctx.fileSet);
        m = r ? { specifier, form, loc: locOf(node), status: "resolved", resolved: r } : { specifier, form, loc: locOf(node), status: "unresolved" };
      } else if (bare === "electron") m = { specifier, form, loc: locOf(node), status: "electron" };
      else if (BUILTINS.has(bare) || BUILTINS.has(bare.split("/")[0])) m = { specifier, form, loc: locOf(node), status: "builtin" };
      else {
        const nm = [...ctx.fileSet].some((f) => f.startsWith(`node_modules/${specifier.split("/")[0]}/`) || f.includes(`/node_modules/${specifier.split("/")[0]}/`));
        m = { specifier, form, loc: locOf(node), status: nm ? "resolved" : "external" };
      }
      res.modules.push(m);
    };
    if (n.type === "ImportDeclaration") add(String(n.source.value), "import", n);
    else if ((n.type === "ExportNamedDeclaration" || n.type === "ExportAllDeclaration") && n.source) add(String(n.source.value), "export-from", n);
    else if (n.type === "ImportExpression" || (n.type === "CallExpression" && n.callee.type === "Import")) {
      const a = n.type === "ImportExpression" ? n.source : n.arguments[0];
      const c = constOf(a); add(typeof c === "string" ? c : null, "dynamic-import", n);
      if (typeof c !== "string") recordSink("dynamic-require", n, "import()", a, []);
    } else if (n.type === "CallExpression" && n.callee.type === "Identifier" && n.callee.name === "require" && n.arguments.length >= 1) {
      const c = constOf(n.arguments[0]); add(typeof c === "string" ? c : null, "require", n);
    }
  };

  const markCallbackSeeds = (n: N): void => {
    const callee = n.callee; const args: N[] = n.arguments;
    const r = resolveRef(callee);
    const fnArgs = args.filter(isFn);
    if (fnArgs.length === 0) return;
    // ipcMain handlers
    const ipc = ipcMainCall(n);
    if (ipc && isFn(args[1])) {
      const ch = channelOf(args[0]);
      pendingSeeds.set(args[1], args[1].params.map((p: N, i: number) => (i === 0 ? null : { source: "ipc-argument" as const, path: [`ipc:${ch ?? "dynamic"}`, `param:${p.type === "Identifier" ? p.name : `#${i}`}`], channel: ch })));
      return;
    }
    // http(s).request/get callback -> response object
    if (r && r.module && NET_MODS.has(r.module) && r.path.length === 1 && NET_CALLS.has(r.path[0])) {
      const cb = args[args.length - 1];
      if (isFn(cb)) pendingSeeds.set(cb, [{ source: "network-response", path: [`${r.module}.${r.path[0]}-response@${file}:${n.loc?.start.line}`] }]);
      return;
    }
    if (r && r.module === "fs" && (r.path[0] === "readFile")) {
      const cb = args[args.length - 1];
      if (isFn(cb)) pendingSeeds.set(cb, [null, { source: "fs-read", path: [`fs.readFile@${file}:${n.loc?.start.line}`] }]);
      return;
    }
    // obj.on('data'|'message'|..., cb) / obj.then(cb) propagate taint of obj into callback param 0
    if ((callee.type === "MemberExpression" || callee.type === "OptionalMemberExpression") && !callee.computed) {
      const m = callee.property.name;
      const ot = taintOf(callee.object);
      if (ot && (m === "then" || m === "on" || m === "once" || m === "addListener" || m === "addEventListener")) {
        for (const a of fnArgs) pendingSeeds.set(a, [ext(ot, `callback:${m}`)]);
      }
    }
  };

  const enterFunction = (fn: N, body: () => void): void => {
    const saved = scope; scope = newScope(saved);
    const seeds = pendingSeeds.get(fn) ?? (handlerFnNodes.has(fn) ? fn.params.map((p: N, i: number) => (i === 0 ? null : { source: "ipc-argument" as const, path: [`ipc:${handlerFnNodes.get(fn) ?? "dynamic"}`, `param:${p.type === "Identifier" ? p.name : `#${i}`}`], channel: handlerFnNodes.get(fn) ?? null })) : []);
    fn.params.forEach((p: N, i: number) => bindTaint(p, seeds[i] ?? null, true));
    try { body(); } finally { scope = saved; }
  };

  let depthLimited = false;
  const visit = (n: N, depth: number): void => {
    if (!n || typeof n.type !== "string") return;
    if (++nodeCount % 2000 === 0 && Date.now() > ctx.deadline) throw new BudgetError("time budget exceeded");
    if (depth > ctx.maxAstDepth) { depthLimited = true; return; }
    handleModules(n);
    switch (n.type) {
      case "FunctionDeclaration": case "FunctionExpression": case "ArrowFunctionExpression": case "ObjectMethod": case "ClassMethod": case "ClassPrivateMethod":
        enterFunction(n, () => { for (const p of n.params) visitPatternDefaults(p, depth + 1); visit(n.body, depth + 1); });
        return;
      case "VariableDeclarator":
        visit(n.init, depth + 1); visitPatternDefaults(n.id, depth + 1);
        bindTaint(n.id, taintOf(n.init), true);
        return;
      case "AssignmentExpression": {
        visit(n.right, depth + 1); visit(n.left, depth + 1);
        const rt = taintOf(n.right);
        if (n.left.type === "Identifier") {
          if (n.operator === "=") bindTaint(n.left, rt, false);
          else if (rt) { bindTaint(n.left, merge(rt, getVar(n.left.name)), false); }
        } else if (n.left.type === "MemberExpression") { const root = rootIdent(n.left); if (root && rt) bindTaint({ type: "Identifier", name: root }, merge(rt, getVar(root)), false); }
        else if (n.left.type === "ObjectPattern" || n.left.type === "ArrayPattern") bindTaint(n.left, rt, false);
        return;
      }
      case "IfStatement": {
        visit(n.test, depth + 1);
        const names = new Map<string, string>(); guardNames(n.test, names);
        const where = String(n.loc?.start.line);
        if (names.size && !terminates(n.consequent)) {
          const saved = applyGuards(names, where); visit(n.consequent, depth + 1);
          for (const [k, v] of saved) (lookupScope(k) ?? scope).vars.set(k, v);
          visit(n.alternate, depth + 1);
        } else {
          visit(n.consequent, depth + 1); visit(n.alternate, depth + 1);
          if (names.size && terminates(n.consequent)) applyGuards(names, where); // stays in effect for the remainder of the scope
        }
        return;
      }
      case "CallExpression": case "NewExpression": case "OptionalCallExpression": {
        if (n.type !== "NewExpression") markCallbackSeeds(n);
        visit(n.callee, depth + 1);
        for (const a of n.arguments) visit(a, depth + 1);
        handleCall(n);
        return;
      }
      case "StringLiteral": scanIoc(n, n.value); return;
      case "TemplateLiteral": for (const q of n.quasis) if (n.expressions.length === 0 && q.value.cooked) scanIoc(n, q.value.cooked); for (const e of n.expressions) visit(e, depth + 1); return;
      default: break;
    }
    for (const c of children(n)) visit(c, depth + 1);
  };
  const visitPatternDefaults = (p: N, depth: number): void => { walkAll(p, (x) => { if (x.type === "AssignmentPattern") visit(x.right, depth); }); };
  const seenIoc = new Set<string>();
  function scanIoc(n: N, s: string): void {
    if (s.length < 7) return;
    for (const h of scanLiteral(s)) {
      const loc = locOf(n); const key = `${h.kind}|${h.value}|${loc.line}:${loc.column}|${h.encoding.join(">")}`;
      if (seenIoc.has(key)) continue; seenIoc.add(key);
      res.iocs.push({ kind: h.kind, value: h.value, encoding: h.encoding, file, loc, literal_preview: s.slice(0, 80) });
    }
  }

  try {
    for (const st of ast.body) visit(st, 0);
    // top-level statements visited individually keep the module scope shared
  } catch (e) {
    if (e instanceof BudgetError) { res.parse = { status: "budget-exceeded", error: "time budget exceeded during analysis; results for this file are partial" }; }
    else if (e instanceof RangeError) { res.parse = { status: "budget-exceeded", error: "stack overflow during analysis; results for this file are partial" }; }
    else throw e;
  }
  res.parse.nodes = nodeCount;
  if (depthLimited) res.parse.ast_depth_limited = true;
  return res;
}
