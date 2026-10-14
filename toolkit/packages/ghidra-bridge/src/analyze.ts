import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { chmodSync, copyFileSync, createReadStream, existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import type { GhidraSnapshot } from "./snapshot.ts";

export class GhidraError extends Error { constructor(m: string) { super(m); this.name = new.target.name; } }
export class GhidraNotFoundError extends GhidraError {}
export class GhidraTimeoutError extends GhidraError {}
export class GhidraFailedError extends GhidraError { logTail: string; constructor(m: string, logTail: string) { super(m); this.logTail = logTail; } }
export class GhidraCleanupError extends GhidraError {}

export interface AnalyzeOptions {
  /** Defaults to env GHIDRA_INSTALL_DIR, then /opt/lab/ghidra_12.1.4_PUBLIC. */
  installDir?: string;
  /** Wall-clock limit for the whole analyzeHeadless run (startup + import + analysis + export). Default 600000. */
  timeoutMs?: number;
  /** JVM max heap, e.g. "2G" (passed as GHIDRA_HEADLESS_MAXMEM). Default 2G. */
  maxHeap?: string;
  decompTimeoutSec?: number;
  decompBudgetSec?: number;
  maxFunctions?: number;
  maxSymbols?: number;
  maxStrings?: number;
  /** Directory under which the throwaway work dir is created. Default os.tmpdir(). */
  tmpRoot?: string;
  /** Test hook: observe the work dir / child pid as soon as they exist. */
  onStart?: (info: { workDir: string; pid: number }) => void;
}

export const DEFAULT_INSTALL_DIR = "/opt/lab/ghidra_12.1.4_PUBLIC";
const SCRIPT_DIR = join(dirname(fileURLToPath(import.meta.url)), "..", "ghidra");

export function resolveInstallDir(installDir?: string): string | null {
  const dir = installDir ?? process.env.GHIDRA_INSTALL_DIR ?? DEFAULT_INSTALL_DIR;
  return existsSync(join(dir, "support", "analyzeHeadless")) ? dir : null;
}

export function sha256File(path: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const h = createHash("sha256");
    createReadStream(path).on("data", (d) => h.update(d)).on("end", () => resolve(h.digest("hex"))).on("error", reject);
  });
}

/** PIDs whose process group id equals `pgid` (Linux /proc). */
export function processGroupMembers(pgid: number): number[] {
  const out: number[] = [];
  for (const e of readdirSync("/proc")) {
    if (!/^\d+$/u.test(e)) continue;
    try {
      const stat = readFileSync(`/proc/${e}/stat`, "utf8");
      const rest = stat.slice(stat.lastIndexOf(")") + 2).split(" ");
      if (Number(rest[2]) === pgid && rest[0] !== "Z") out.push(Number(e));
    } catch { /* process vanished */ }
  }
  return out;
}

async function killGroupAndVerify(pgid: number): Promise<number[]> {
  try { process.kill(-pgid, "SIGKILL"); } catch { /* group already gone */ }
  const deadline = Date.now() + 5000;
  let left = processGroupMembers(pgid);
  while (left.length && Date.now() < deadline) { await new Promise((r) => setTimeout(r, 50)); left = processGroupMembers(pgid); }
  return left;
}

/**
 * Run Ghidra headless on a 0600 COPY of `path` inside a throwaway project directory and return the exported snapshot.
 * The child runs in its own process group; on timeout or after completion the whole group is SIGKILLed and verified gone.
 * The work directory (project + copy) is always removed and its removal verified.
 */
export async function analyzeBinary(path: string, opts: AnalyzeOptions = {}): Promise<GhidraSnapshot> {
  const install = resolveInstallDir(opts.installDir);
  if (!install) throw new GhidraNotFoundError("Ghidra not found: set GHIDRA_INSTALL_DIR or pass installDir");
  const st = statSync(path);
  if (!st.isFile()) throw new GhidraError(`Not a regular file: ${path}`);
  const before = await sha256File(path);
  const started = Date.now();
  const root = opts.tmpRoot ?? tmpdir();
  const workDir = mkdtempSync(join(root, "rtk-ghidra-"));
  chmodSync(workDir, 0o700);
  const inDir = join(workDir, "in"); mkdirSync(inDir, { mode: 0o700 });
  const projDir = join(workDir, "proj"); mkdirSync(projDir, { mode: 0o700 });
  const copy = join(inDir, basename(path).replace(/[^A-Za-z0-9._-]/gu, "_") || "target");
  const outJson = join(workDir, "snapshot.json");
  let pgid = 0;
  let stray: number[] = [];
  let primary: unknown;
  let snapshot: GhidraSnapshot | undefined;
  try {
    copyFileSync(path, copy);
    chmodSync(copy, 0o600);
    const scriptOpts = [
      `decompTimeout=${opts.decompTimeoutSec ?? 30}`, `decompBudget=${opts.decompBudgetSec ?? 600}`,
      `maxFunctions=${opts.maxFunctions ?? 5000}`, `maxSymbols=${opts.maxSymbols ?? 50000}`, `maxStrings=${opts.maxStrings ?? 50000}`,
    ].join(",");
    const args = [projDir, "rtk", "-import", copy, "-scriptPath", SCRIPT_DIR, "-postScript", "RtkExport.java", outJson, scriptOpts, "-deleteProject"];
    const env = { ...process.env, GHIDRA_INSTALL_DIR: install, GHIDRA_HEADLESS_MAXMEM: opts.maxHeap ?? "2G" };
    const child = spawn(join(install, "support", "analyzeHeadless"), args, { detached: true, stdio: ["ignore", "pipe", "pipe"], env });
    pgid = child.pid!;
    opts.onStart?.({ workDir, pid: pgid });
    let log = "";
    const onData = (d: Buffer) => { log += d.toString("utf8"); if (log.length > 200_000) log = log.slice(-100_000); };
    child.stdout.on("data", onData); child.stderr.on("data", onData);
    let timedOut = false;
    const exit = new Promise<{ code: number | null; signal: string | null }>((resolve, reject) => {
      child.once("error", reject);
      child.once("close", (code, signal) => resolve({ code, signal }));
    });
    const timer = setTimeout(() => { timedOut = true; try { process.kill(-pgid, "SIGKILL"); } catch { /* gone */ } }, opts.timeoutMs ?? 600_000);
    let res: { code: number | null; signal: string | null };
    try { res = await exit; } finally { clearTimeout(timer); }
    if (timedOut) throw new GhidraTimeoutError(`Ghidra exceeded ${opts.timeoutMs ?? 600_000} ms; process group ${pgid} killed`);
    if (res.code !== 0 || !existsSync(outJson)) {
      throw new GhidraFailedError(`analyzeHeadless failed (exit ${res.code}, signal ${res.signal})`, log.slice(-4000));
    }
    const parsed = JSON.parse(readFileSync(outJson, "utf8")) as GhidraSnapshot;
    if (parsed.schema !== "rtk-ghidra-snapshot/1") throw new GhidraFailedError("unexpected snapshot schema", log.slice(-2000));
    const after = await sha256File(path);
    if (after !== before) throw new GhidraError("SECURITY: original file hash changed during analysis");
    parsed.source = {
      path, sha256: before, size: st.size, elapsed_ms: Date.now() - started,
      options: { timeoutMs: opts.timeoutMs ?? 600_000, maxHeap: opts.maxHeap ?? "2G", decompTimeoutSec: opts.decompTimeoutSec ?? 30, decompBudgetSec: opts.decompBudgetSec ?? 600, maxFunctions: opts.maxFunctions ?? 5000 },
    };
    snapshot = parsed;
  } catch (e) {
    primary = e;
  } finally {
    if (pgid) stray = await killGroupAndVerify(pgid);
    rmSync(workDir, { recursive: true, force: true });
  }
  if (stray.length) throw new GhidraCleanupError(`stray processes remain in group ${pgid}: ${stray.join(",")}`);
  if (existsSync(workDir)) throw new GhidraCleanupError(`work directory not removed: ${workDir}`);
  if (primary) throw primary;
  return snapshot!;
}
