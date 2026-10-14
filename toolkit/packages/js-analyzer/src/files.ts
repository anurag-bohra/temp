import { createHash } from "node:crypto";
import { closeSync, lstatSync, mkdtempSync, openSync, readSync, readdirSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, extname, join, posix, relative, sep } from "node:path";
import * as asar from "@electron/asar";

export interface Limits {
  maxFiles: number;
  maxFileBytes: number;
  maxTotalBytes: number;
  maxDirDepth: number;
  maxAstDepth: number;
  timeBudgetMs: number;
  includeNodeModules: boolean;
}
export const DEFAULT_LIMITS: Limits = {
  maxFiles: 5000,
  maxFileBytes: 5 * 1024 * 1024,
  maxTotalBytes: 256 * 1024 * 1024,
  maxDirDepth: 40,
  maxAstDepth: 400,
  timeBudgetMs: 30_000,
  includeNodeModules: false,
};

export type FileKind = "javascript" | "json" | "native-addon" | "other";
export interface CollectedFile {
  path: string; // posix, relative to input root
  abs: string;
  bytes: number;
  sha256: string | null;
  kind: FileKind;
  skipped?: "too-large" | "total-bytes-budget" | "node_modules-excluded" | "symlink" | "unreadable";
}
export interface Collected { format: "directory" | "file" | "asar"; files: CollectedFile[]; limitations: string[]; cleanup: () => void; subjectSha256: string; inputName: string }

export const sha256Buf = (b: Uint8Array): string => createHash("sha256").update(b).digest("hex");

function sha256File(abs: string): string {
  const h = createHash("sha256");
  const fd = openSync(abs, "r");
  try {
    const buf = Buffer.allocUnsafe(1 << 20);
    for (;;) { const n = readSync(fd, buf, 0, buf.length, null); if (n === 0) break; h.update(buf.subarray(0, n)); }
  } finally { closeSync(fd); }
  return h.digest("hex");
}

export function kindOf(p: string): FileKind {
  const e = extname(p).toLowerCase();
  if ([".js", ".cjs", ".mjs", ".jsx"].includes(e)) return "javascript";
  if (e === ".json") return "json";
  if (e === ".node") return "native-addon";
  return "other";
}

function walkDir(root: string, limits: Limits, limitations: string[]): CollectedFile[] {
  const out: CollectedFile[] = [];
  let total = 0;
  let truncated = false;
  const rec = (dir: string, depth: number): void => {
    if (truncated) return;
    if (depth > limits.maxDirDepth) { limitations.push(`directory depth limit ${limits.maxDirDepth} reached at ${relative(root, dir) || "."}; deeper content not analysed`); return; }
    let names: string[];
    try { names = readdirSync(dir).sort(); } catch { limitations.push(`unreadable directory ${relative(root, dir) || "."}`); return; }
    for (const n of names) {
      const abs = join(dir, n);
      const rel = relative(root, abs).split(sep).join("/");
      let st;
      try { st = lstatSync(abs); } catch { continue; }
      if (st.isSymbolicLink()) { out.push({ path: rel, abs, bytes: 0, sha256: null, kind: "other", skipped: "symlink" }); continue; }
      if (st.isDirectory()) {
        if (n === "node_modules" && !limits.includeNodeModules) { out.push({ path: rel + "/", abs, bytes: 0, sha256: null, kind: "other", skipped: "node_modules-excluded" }); continue; }
        rec(abs, depth + 1);
        continue;
      }
      if (!st.isFile()) continue;
      if (out.length >= limits.maxFiles) { truncated = true; limitations.push(`file count limit ${limits.maxFiles} reached; remaining files not inventoried`); return; }
      const f: CollectedFile = { path: rel, abs, bytes: st.size, sha256: null, kind: kindOf(rel) };
      if (st.size > limits.maxFileBytes) f.skipped = "too-large";
      else if (total + st.size > limits.maxTotalBytes) f.skipped = "total-bytes-budget";
      if (!f.skipped) { total += st.size; }
      try { f.sha256 = f.skipped === "too-large" && st.size <= 1 << 30 ? sha256File(abs) : f.skipped ? null : sha256Buf(readFileSync(abs)); } catch { f.skipped = "unreadable"; }
      out.push(f);
    }
  };
  rec(root, 0);
  return out;
}

function subjectDigest(files: CollectedFile[]): string {
  const h = createHash("sha256");
  for (const f of files) h.update(`${f.path}\0${f.sha256 ?? "-"}\0${f.bytes}\n`);
  return h.digest("hex");
}

interface AsarNode { files?: Record<string, AsarNode>; size?: number }

function checkAsarHeader(header: AsarNode, limits: Limits): { count: number; bytes: number; bad: string | null } {
  let count = 0, bytes = 0, bad: string | null = null;
  const rec = (n: AsarNode, p: string, depth: number): void => {
    if (bad) return;
    if (depth > limits.maxDirDepth) { bad = `asar nesting deeper than ${limits.maxDirDepth}`; return; }
    for (const [k, v] of Object.entries(n.files ?? {})) {
      if (k === "" || k === "." || k === ".." || k.includes("/") || k.includes("\\") || k.includes("\0")) { bad = `unsafe asar entry name ${JSON.stringify(k)} under ${p || "/"}`; return; }
      if (v.files) rec(v, `${p}/${k}`, depth + 1);
      else { count++; bytes += v.size ?? 0; }
    }
  };
  rec(header, "", 0);
  return { count, bytes, bad };
}

export function collect(input: string, limits: Limits): Collected {
  const st = lstatSync(input);
  const limitations: string[] = [];
  if (st.isDirectory()) {
    const files = walkDir(input, limits, limitations);
    return { format: "directory", files, limitations, cleanup: () => {}, subjectSha256: subjectDigest(files), inputName: basename(input) };
  }
  if (!st.isFile()) throw new Error(`not a file or directory: ${input}`);
  if (input.toLowerCase().endsWith(".asar")) {
    const header = asar.getRawHeader(input).header as AsarNode;
    const chk = checkAsarHeader(header, limits);
    if (chk.bad) throw new Error(`refusing asar: ${chk.bad}`);
    if (chk.count > limits.maxFiles * 4 || chk.bytes > limits.maxTotalBytes) throw new Error(`refusing asar: declared ${chk.count} files / ${chk.bytes} bytes exceeds limits`);
    const tmp = mkdtempSync(join(tmpdir(), "rtk-js-asar-"));
    const cleanup = () => rmSync(tmp, { recursive: true, force: true });
    try {
      asar.extractAll(input, tmp);
      const files = walkDir(tmp, limits, limitations);
      limitations.push("input is an .asar archive: analysed from a temporary extraction (removed afterwards); files stored outside the archive (.asar.unpacked) are not included unless adjacent");
      return { format: "asar", files, limitations, cleanup, subjectSha256: sha256File(input), inputName: basename(input) };
    } catch (e) { cleanup(); throw e; }
  }
  const f: CollectedFile = { path: basename(input), abs: input, bytes: st.size, sha256: null, kind: kindOf(input) };
  if (st.size > limits.maxFileBytes) f.skipped = "too-large";
  f.sha256 = sha256File(input);
  return { format: "file", files: [f], limitations, cleanup: () => {}, subjectSha256: f.sha256, inputName: basename(input) };
}

const EXTS = [".js", ".cjs", ".mjs", ".json", ".node"];
/** Resolve a relative specifier against the collected file set (posix paths). */
export function resolveRelative(fromFile: string, spec: string, fileSet: Set<string>): string | null {
  const base = spec.startsWith("/") ? posix.normalize(spec.slice(1)) : posix.normalize(posix.join(posix.dirname(fromFile), spec));
  if (base.startsWith("..")) return null;
  const cands = [base, ...EXTS.map((e) => base + e), ...EXTS.map((e) => posix.join(base, "index" + e))];
  for (const c of cands) if (fileSet.has(c)) return c;
  return null;
}
