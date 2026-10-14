// @rtk/sandbox — owned, resource-bounded, optionally namespace-isolated execution of a sample for controlled detonation.
// The ONLY package in the toolkit allowed to execute a sample. See README for the exact isolation levels and limits.
//
// Isolation levels (achieved level is probed at runtime and reported honestly):
//   process         own session/process group, prlimit rlimits, env allowlist, fresh scratch cwd, output caps, wall timeout,
//                   unprivileged uid when root, kill-whole-tree + /proc survivor sweep.  NO network/fs isolation.
//   namespace-lite  process + unshare --net --pid --fork --mount-proc --ipc --uts (no network, private PID/proc/IPC/UTS) but the
//                   sample still sees the host filesystem.  Reported as isolation "process" in Evidence.
//   container       namespace-lite + private mount namespace with pivot_root to a minimal tmpfs root (read-only /usr,/bin,/lib*,
//                   read-only sample, private /tmp, rw scratch only) + dropped capabilities.  Reported as "container".
//                   (No seccomp, no cgroup limits, shares the host kernel: NOT a virtual machine.)
import { spawn, execFileSync } from "node:child_process";
import { randomBytes, createHash } from "node:crypto";
import { chmodSync, chownSync, copyFileSync, existsSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, readlinkSync, realpathSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir, hostname } from "node:os";
import { basename, delimiter, isAbsolute, join, resolve } from "node:path";
import { createEvidence, type Evidence } from "@rtk/evidence";
import { clockTicksPerSecond, findMembers, type Member } from "./procscan.ts";
import { diffSnapshots, sha256File, snapshot, type FsChange } from "./fsdiff.ts";
import { parseStrace, type ExecEvent, type NetAttempt } from "./strace.ts";

export { parseStrace } from "./strace.ts";
export { snapshot, diffSnapshots } from "./fsdiff.ts";

export class IsolationUnavailableError extends Error {}

export type RequestedIsolation = "process" | "namespace" | "auto";
export type AchievedLevel = "process" | "namespace-lite" | "container";
export interface SandboxLimits {
  wallTimeMs?: number; cpuSeconds?: number; maxProcesses?: number; maxMemoryBytes?: number; maxFileBytes?: number; maxOpenFiles?: number;
  maxOutputBytes?: number; maxTotalOutputBytes?: number; maxCoreBytes?: number; scratchTmpfsBytes?: number;
}
export interface SandboxSpec {
  /** Path of the sample file (must be executable by the sandbox user, or a script with an interpreter present). */
  sample: string;
  args?: string[];
  isolation?: RequestedIsolation;
  /** Explicit environment values given to the sample (nothing else is inherited except `inheritEnv` names). */
  env?: Record<string, string>;
  inheritEnv?: string[];
  /** Extra text files created in the scratch dir BEFORE the run (not reported as changes). */
  files?: Record<string, string>;
  /** Additional host paths to snapshot before/after (only meaningful where the sample can reach them, i.e. not in `container`). */
  observePaths?: string[];
  limits?: SandboxLimits;
  /** Use strace (when installed) to record network syscalls and execve events. Default true. */
  trace?: boolean;
  pollMs?: number;
  /** Run as uid/gid 65534 when the host process is root (default true). Needed for RLIMIT_NPROC to apply. */
  dropPrivileges?: boolean;
}

const DEFAULTS = {
  wallTimeMs: 10_000, cpuSeconds: 10, maxProcesses: 64, maxMemoryBytes: 1024 ** 3, maxFileBytes: 16 * 1024 ** 2, maxOpenFiles: 256,
  maxOutputBytes: 256 * 1024, maxTotalOutputBytes: 16 * 1024 ** 2, maxCoreBytes: 8 * 1024 ** 2, scratchTmpfsBytes: 16 * 1024 ** 2,
};
const NOBODY = 65534;
const CORE_SIGNALS = new Set(["SIGSEGV", "SIGABRT", "SIGBUS", "SIGFPE", "SIGILL", "SIGQUIT", "SIGSYS", "SIGTRAP", "SIGXCPU", "SIGXFSZ"]);

// ---------------------------------------------------------------- host capability probe
export interface Tools { prlimit: string | null; unshare: string | null; setpriv: string | null; strace: string | null; pivotRoot: string | null; sh: string }
export interface Capabilities { tools: Tools; isRoot: boolean; userns: boolean; levels: Record<AchievedLevel, boolean>; strace: boolean; notes: string[]; corePattern: string | null }

function which(name: string): string | null {
  for (const d of (process.env.PATH ?? "/usr/bin:/bin:/usr/sbin:/sbin").split(delimiter).concat(["/usr/sbin", "/sbin"])) {
    const p = join(d, name); try { if (statSync(p).isFile()) return realpathSync(p); } catch { /* next */ }
  }
  return null;
}
const sq = (s: string): string => `'${s.replaceAll("'", `'\\''`)}'`;
const isRoot = (): boolean => typeof process.geteuid === "function" && process.geteuid() === 0;
const underUsr = (p: string | null): boolean => p !== null && /^\/(usr|bin|lib|sbin)\//u.test(p);

interface Plan {
  level: AchievedLevel; base: string; token: string; userns: boolean; drop: boolean; trace: boolean;
  limits: Required<SandboxLimits>; sampleName: string; args: string[]; tools: Tools;
}
const dirs = (base: string) => ({ work: join(base, "work"), sample: join(base, "sample"), trace: join(base, "trace"), root: join(base, "root") });

function buildContainerScript(base: string, tmpBytes: number, pivotRoot = "pivot_root"): string {
  const d = dirs(base); const L: string[] = ["set -e", "mount --make-rprivate /", `NR=${sq(d.root)}`, `mount -t tmpfs -o size=1m,mode=755 tmpfs "$NR"`];
  for (const name of ["usr", "bin", "lib", "lib64", "sbin"]) {
    let st; try { st = lstatSync("/" + name); } catch { continue; }
    if (st.isSymbolicLink()) L.push(`ln -s ${sq(readlinkSync("/" + name))} "$NR/${name}"`);
    else if (st.isDirectory()) L.push(`mkdir "$NR/${name}"`, `mount --bind /${name} "$NR/${name}"`, `mount -o remount,bind,ro,nosuid,nodev "$NR/${name}"`);
  }
  L.push(
    `mkdir "$NR/proc" "$NR/dev" "$NR/tmp" "$NR/work" "$NR/sample" "$NR/trace" "$NR/etc" "$NR/old"`,
    `mount -t proc proc "$NR/proc"`,
    `mount -t tmpfs -o size=${tmpBytes},mode=1777,nosuid,nodev tmpfs "$NR/tmp"`,
    `mount -t tmpfs -o size=1m,mode=755 tmpfs "$NR/dev"`,
    `for n in null zero urandom random full; do : > "$NR/dev/$n"; mount --bind "/dev/$n" "$NR/dev/$n"; done`,
    `mount --bind ${sq(d.work)} "$NR/work"`,
    `mount --bind ${sq(d.sample)} "$NR/sample"`, `mount -o remount,bind,ro,nosuid,nodev "$NR/sample"`,
    `mount --bind ${sq(d.trace)} "$NR/trace"`,
    `if [ -f /etc/ld.so.cache ]; then : > "$NR/etc/ld.so.cache"; mount --bind /etc/ld.so.cache "$NR/etc/ld.so.cache"; mount -o remount,bind,ro "$NR/etc/ld.so.cache"; fi`,
    `cd "$NR"`, `${sq(pivotRoot)} . old`, `cd /`, `umount -l /old`, `rmdir /old`, `cd /work`, `exec "$@"`,
  );
  return L.join("\n");
}

function buildCommand(plan: Plan): { cmd: string; args: string[]; cwd: string; traceLog: string } {
  const d = dirs(plan.base); const t = plan.tools; const inContainer = plan.level === "container";
  const samplePath = inContainer ? `/sample/${plan.sampleName}` : join(d.sample, plan.sampleName);
  const traceLogInside = inContainer ? "/trace/strace.log" : join(d.trace, "strace.log");
  const tail: string[] = [];
  if (plan.trace && t.strace) tail.push(t.strace, "-f", "-q", "-s", "200", "-e", "trace=network,execve", "-o", traceLogInside, "--");
  if (plan.drop && t.setpriv) tail.push(t.setpriv, `--reuid=${NOBODY}`, `--regid=${NOBODY}`, "--clear-groups", "--no-new-privs", "--bounding-set=-all", "--inh-caps=-all", "--");
  tail.push(samplePath, ...plan.args);
  const L = plan.limits;
  const pr = [t.prlimit!, `--nproc=${L.maxProcesses}`, `--as=${L.maxMemoryBytes}`, `--cpu=${L.cpuSeconds}`, `--fsize=${L.maxFileBytes}`, `--core=${L.maxCoreBytes}`, `--nofile=${L.maxOpenFiles}`, "--"];
  const ns = [t.unshare!, "--net", "--pid", "--fork", "--kill-child", "--ipc", "--uts"];
  if (plan.userns) ns.push("--user", "--map-root-user");
  let argv: string[];
  if (plan.level === "process") argv = [...pr, ...tail];
  else if (plan.level === "namespace-lite") argv = [...pr, ...ns, "--mount-proc", "--", ...tail];
  else argv = [...pr, ...ns, "--mount", "--", t.sh, "-c", buildContainerScript(plan.base, L.scratchTmpfsBytes, t.pivotRoot ?? "pivot_root"), "sh", ...tail];
  return { cmd: argv[0]!, args: argv.slice(1), cwd: d.work, traceLog: join(d.trace, "strace.log") };
}

const sleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));

function discoverTools(): Tools {
  return { prlimit: which("prlimit"), unshare: which("unshare"), setpriv: which("setpriv"), strace: which("strace"), pivotRoot: which("pivot_root"), sh: which("sh") ?? "/bin/sh" };
}

let capCache: Promise<Capabilities> | null = null;
/** Probe (once per process) which isolation levels this host really supports by running a trivial program through each. */
export function probeCapabilities(force = false): Promise<Capabilities> {
  if (force || capCache === null) capCache = doProbe();
  return capCache;
}
async function doProbe(): Promise<Capabilities> {
  const tools = discoverTools(); const notes: string[] = []; const root = isRoot();
  const levels: Record<AchievedLevel, boolean> = { process: false, "namespace-lite": false, container: false };
  let strace = false; let userns = false;
  let corePattern: string | null = null; try { corePattern = readFileSync("/proc/sys/kernel/core_pattern", "utf8").trim(); } catch { /* none */ }
  if (!tools.prlimit) { notes.push("prlimit not found: no sandbox possible (rlimits are mandatory)"); return { tools, isRoot: root, userns, levels, strace, notes, corePattern }; }
  const truePath = which("true") ?? "/bin/true";
  const attempt = async (level: AchievedLevel, useUserns: boolean, trace: boolean): Promise<boolean> => {
    try {
      const r = await execute({ sample: truePath, isolation: level === "process" ? "process" : "namespace", trace, limits: { wallTimeMs: 8000 } }, level, { tools, isRoot: root, userns: useUserns, levels, strace, notes, corePattern }, true);
      return r.status === "exited" && r.exit_code === 0;
    } catch { return false; }
  };
  levels.process = await attempt("process", false, false);
  if (levels.process && tools.strace) strace = await attempt("process", false, true);
  if (tools.unshare) {
    for (const u of root ? [false] : [true]) {
      const lite = await attempt("namespace-lite", u, false);
      if (lite) { levels["namespace-lite"] = true; userns = u; }
      if (lite && tools.sh && tools.pivotRoot && underUsr(tools.setpriv ?? tools.sh) && (await attempt("container", u, false))) levels.container = true;
    }
    if (!levels["namespace-lite"]) notes.push("unshare --net --pid --fork --mount-proc failed on this host (no privilege / user namespaces disabled)");
    else if (!levels.container) notes.push("mount namespace + pivot_root setup failed or required tools missing: no filesystem restriction available");
  } else notes.push("unshare not found: no namespace isolation");
  if (!tools.strace) notes.push("strace not installed: network attempts and short-lived execs are not observed"); else if (!strace) notes.push("strace present but ptrace not permitted: no syscall tracing");
  if (!tools.setpriv && root) notes.push("setpriv missing: sample runs as root and RLIMIT_NPROC is not enforced");
  return { tools, isRoot: root, userns, levels, strace, notes, corePattern };
}

// ---------------------------------------------------------------- result types
export interface StreamCapture { text: string; bytes_total: number; bytes_kept: number; truncated: boolean; sha256: string }
export interface ProcRecord { pid: number; ppid: number; sid: number; pgrp: number; uid: number | null; comm: string; exe: string | null; cmdline: string[]; first_seen_ms: number; last_seen_ms: number; found_by: string[]; escaped_session: boolean }
export interface SandboxResult {
  achieved_level: AchievedLevel; requested_isolation: RequestedIsolation; namespaces: string[];
  status: "exited" | "signaled" | "timeout" | "output-limit"; exit_code: number | null; signal: string | null;
  wall_ms: number; cpu_ms_lower_bound: number; peak_rss_kb: number; peak_hwm_kb: number;
  stdout: StreamCapture; stderr: StreamCapture; limits: Required<SandboxLimits>; run_as_uid: number | null;
  process_tree: {
    processes: ProcRecord[]; sample_count: number; samples: { t_ms: number; pids: number[] }[]; truncated: boolean;
    survivors_at_exit: { pid: number; ppid: number; sid: number; exe: string | null; cmdline: string[]; found_by: string[] }[];
    killed_pids: number[]; verified_no_survivors: boolean; exec_events: ExecEvent[]; max_concurrent: number;
  };
  filesystem: { scratch_changes: FsChange[]; observed_changes: FsChange[]; observed_paths: string[] };
  network: { tracer: "strace" | null; attempts: NetAttempt[]; any_connect_succeeded: boolean; note: string };
  core: { signal_implies_core: boolean; core_pattern: string | null; core_files: string[] };
  sample: { path: string; sha256_before: string; sha256_after: string; unmodified: boolean; copy_sha256: string };
  cleanup: { scratch_removed: boolean; mounts_leaked: boolean; scratch_path: string };
  env_keys: string[]; strace_lines: number;
}

// ---------------------------------------------------------------- execution
const hex = (b: Uint8Array) => createHash("sha256").update(b).digest("hex");
class Capture {
  chunks: Buffer[] = []; kept = 0; total = 0; truncated = false;
  cap: number;
  constructor(cap: number) { this.cap = cap; }
  push(b: Buffer): void {
    this.total += b.length;
    if (this.kept < this.cap) { const room = this.cap - this.kept; const piece = b.length > room ? b.subarray(0, room) : b; this.chunks.push(Buffer.from(piece)); this.kept += piece.length; if (b.length > room) this.truncated = true; } else this.truncated = true;
  }
  done(): StreamCapture { const buf = Buffer.concat(this.chunks); return { text: buf.toString("utf8"), bytes_total: this.total, bytes_kept: this.kept, truncated: this.truncated, sha256: hex(buf) }; }
}

function mountsLeaked(base: string): boolean {
  try { return readFileSync("/proc/self/mountinfo", "utf8").includes(base); } catch { return false; }
}

async function execute(spec: SandboxSpec, level: AchievedLevel, caps: Capabilities, internalProbe = false): Promise<SandboxResult> {
  const limits = { ...DEFAULTS, ...spec.limits } as Required<SandboxLimits>;
  const samplePath = resolve(spec.sample);
  if (!existsSync(samplePath) || !statSync(samplePath).isFile()) throw new Error(`sample is not a file: ${samplePath}`);
  const sha256Before = sha256File(samplePath) ?? "";
  const base = mkdtempSync(join(tmpdir(), "rtk-sbx-")); chmodSync(base, 0o755);
  const d = dirs(base); const token = `rtk-${randomBytes(12).toString("hex")}`;
  const drop = (spec.dropPrivileges ?? true) && caps.isRoot && !caps.userns && caps.tools.setpriv !== null;
  const trace = (spec.trace ?? true) && caps.strace && caps.tools.strace !== null && !internalProbe;
  for (const p of [d.work, d.sample, d.trace, d.root]) mkdirSync(p, { mode: 0o755 });
  if (drop) { chownSync(d.work, NOBODY, NOBODY); }
  chmodSync(d.work, 0o700); if (!drop) chmodSync(d.work, 0o755);
  const sampleName = basename(samplePath).replace(/[^A-Za-z0-9._-]/gu, "_") || "sample";
  copyFileSync(samplePath, join(d.sample, sampleName)); chmodSync(join(d.sample, sampleName), 0o555);
  const copySha = sha256File(join(d.sample, sampleName)) ?? "";
  for (const [name, content] of Object.entries(spec.files ?? {})) {
    if (name.includes("/") || name.includes("..")) throw new Error(`files: name must be a plain file name: ${name}`);
    const fp = join(d.work, name); writeFileSync(fp, content); if (drop) chownSync(fp, NOBODY, NOBODY);
  }
  const plan: Plan = { level, base, token, userns: caps.userns && level !== "process", drop, trace, limits, sampleName, args: spec.args ?? [], tools: caps.tools };
  const { cmd, args, cwd, traceLog } = buildCommand(plan);

  const workView = level === "container" ? "/work" : d.work;
  const env: Record<string, string> = { PATH: "/usr/bin:/bin", HOME: workView, TMPDIR: level === "container" ? "/tmp" : workView, LANG: "C", RTK_SANDBOX_TOKEN: token };
  for (const n of spec.inheritEnv ?? []) if (process.env[n] !== undefined) env[n] = process.env[n]!;
  Object.assign(env, spec.env ?? {});

  const observe = (spec.observePaths ?? []).map((p) => resolve(p));
  const before = snapshot([d.work]); const obsBefore = snapshot(observe);

  const t0 = process.hrtime.bigint(); const elapsed = () => Number((process.hrtime.bigint() - t0) / 1_000_000n);
  const child = spawn(cmd, args, { cwd, env, detached: true, stdio: ["ignore", "pipe", "pipe"] });
  const rootPid = child.pid!;
  const closedP = new Promise<void>((res) => { child.on("close", () => res()); });
  const out = new Capture(limits.maxOutputBytes); const err = new Capture(limits.maxOutputBytes);
  let killReason: "timeout" | "output-limit" | null = null; let totalOut = 0;
  const killGroup = () => { try { process.kill(-rootPid, "SIGKILL"); } catch { /* gone */ } };
  const onData = (c: Capture) => (b: Buffer) => { c.push(b); totalOut += b.length; if (totalOut > limits.maxTotalOutputBytes && !killReason) { killReason = "output-limit"; killGroup(); } };
  child.stdout!.on("data", onData(out)); child.stderr!.on("data", onData(err));

  const records = new Map<string, ProcRecord>(); const samples: { t_ms: number; pids: number[] }[] = []; let lastKey = ""; let treeTrunc = false;
  let peakRss = 0; let peakHwm = 0; let maxConc = 0; let cpuTicksMax = 0;
  const q = { rootPid, token, baseDir: base, selfPid: process.pid };
  const poll = (): Member[] => {
    const ms = findMembers(q); const t = elapsed();
    let rss = 0; let ticks = 0;
    for (const m of ms) {
      const key = `${m.pid}:${m.startTicks}`; const r = records.get(key);
      rss += m.rssKb; ticks += m.cpuTicks; peakHwm = Math.max(peakHwm, m.hwmKb);
      if (m.pid === rootPid) ticks += m.childTicks;
      if (r) { r.last_seen_ms = t; if (m.cmdline.length > r.cmdline.length || (m.exe && m.exe !== r.exe)) { r.exe = m.exe; r.cmdline = m.cmdline; r.comm = m.comm; } for (const f of m.reasons) if (!r.found_by.includes(f)) r.found_by.push(f); }
      else if (records.size < 500) records.set(key, { pid: m.pid, ppid: m.ppid, sid: m.sid, pgrp: m.pgrp, uid: m.uid, comm: m.comm, exe: m.exe, cmdline: m.cmdline, first_seen_ms: t, last_seen_ms: t, found_by: [...m.reasons], escaped_session: m.sid !== rootPid });
      else treeTrunc = true;
    }
    peakRss = Math.max(peakRss, rss); cpuTicksMax = Math.max(cpuTicksMax, ticks); maxConc = Math.max(maxConc, ms.length);
    const k = ms.map((m) => m.pid).join(",");
    if (k !== lastKey && k !== "") { lastKey = k; if (samples.length < 300) samples.push({ t_ms: t, pids: ms.map((m) => m.pid) }); else treeTrunc = true; }
    return ms;
  };
  const pollTimer = setInterval(() => { try { poll(); } catch { /* transient /proc race */ } }, spec.pollMs ?? 20);
  const wallTimer = setTimeout(() => { if (!killReason) killReason = "timeout"; killGroup(); }, limits.wallTimeMs);

  // "Sample finished" = the root exited, or (traced runs) the traced main process logged its exit: under `strace -f` the root
  // (strace) lives until every traced descendant is gone, so a daemonised child would otherwise hide the sample's own exit.
  type Exit = { code: number | null; signal: NodeJS.Signals | null };
  let mainPid: number | null = null; let traceExit: Exit | null = null; let rootExit: Exit | null = null;
  let finish: (e: Exit) => void = () => {};
  const finished = new Promise<Exit>((res) => { finish = res; });
  const checkTrace = () => {
    if (!trace || traceExit) return;
    let txt = ""; try { txt = readFileSync(traceLog, "utf8"); } catch { return; }
    if (mainPid === null) { const m = /^(\d+)\s/u.exec(txt); if (m) mainPid = Number(m[1]); }
    if (mainPid === null) return;
    const m = new RegExp(`^${mainPid}\\s+\\+\\+\\+ (exited with (\\d+)|killed by (SIG\\w+))`, "mu").exec(txt);
    if (m) { traceExit = m[3] ? { code: null, signal: m[3] as NodeJS.Signals } : { code: Number(m[2]), signal: null }; finish(traceExit); }
  };
  child.on("exit", (code, signal) => { rootExit = { code, signal }; checkTrace(); if (!traceExit) finish(rootExit); });
  child.on("error", () => finish({ code: null, signal: null }));
  const traceTimer = setInterval(checkTrace, 10);
  const exit = await finished;
  clearInterval(traceTimer);
  clearTimeout(wallTimer);
  const wallMs = elapsed();
  // Survivors: anything of ours still alive after the root exited (daemonised / setsid children).
  let final: Member[] = []; try { final = poll(); } catch { /* ignore */ }
  const wrapperExes = new Set([caps.tools.strace, caps.tools.unshare, caps.tools.setpriv, caps.tools.prlimit].filter((x): x is string => x !== null));
  const survivors = final.filter((m) => m.pid !== rootPid && !(m.exe !== null && wrapperExes.has(m.exe))).map((m) => ({ pid: m.pid, ppid: m.ppid, sid: m.sid, exe: m.exe, cmdline: m.cmdline, found_by: m.reasons }));
  const killed = new Set<number>();
  for (const m of final) if (m.pid !== rootPid) { killed.add(m.pid); try { process.kill(m.pid, "SIGKILL"); } catch { /* gone */ } }
  killGroup();
  for (let round = 0; round < 60; round++) {
    const ms = findMembers(q); if (ms.length === 0) break;
    for (const m of ms) { killed.add(m.pid); try { process.kill(m.pid, "SIGKILL"); } catch { /* gone */ } }
    await sleep(25);
  }
  await sleep(30);
  clearInterval(pollTimer);
  const verifiedClean = findMembers(q).length === 0;
  await Promise.race([closedP, sleep(2000)]); child.stdout!.destroy(); child.stderr!.destroy();

  const after = snapshot([d.work]); const scratchChanges = diffSnapshots(before, after);
  const obsChanges = diffSnapshots(obsBefore, snapshot(observe));
  let traceText = ""; try { traceText = readFileSync(traceLog, "utf8"); } catch { /* no trace */ }
  const tr = parseStrace(traceText);
  // The first execve of a traced run is the wrapper (setpriv) or the sample itself; keep all, the caller can filter.
  const coreFiles = scratchChanges.filter((c) => /^core(\..*)?$/u.test(basename(c.path)) && c.status === "added").map((c) => c.path.replace(d.work, "<scratch>"));
  const sha256After = sha256File(samplePath) ?? "";
  const signal = exit.signal;
  const status: SandboxResult["status"] = killReason ?? (signal ? "signaled" : "exited");
  const scratchPath = base;
  rmSync(base, { recursive: true, force: true });
  const removed = !existsSync(base);
  const nsList = level === "process" ? [] : ["net", "pid", "ipc", "uts", level === "container" ? "mnt(pivot_root)" : "mnt(proc only)", ...(plan.userns ? ["user"] : [])];

  return {
    achieved_level: level, requested_isolation: spec.isolation ?? "auto", namespaces: nsList,
    status, exit_code: exit.code, signal, wall_ms: wallMs, cpu_ms_lower_bound: Math.round((cpuTicksMax * 1000) / clockTicksPerSecond()), peak_rss_kb: peakRss, peak_hwm_kb: peakHwm,
    stdout: out.done(), stderr: err.done(), limits, run_as_uid: drop ? NOBODY : (process.getuid?.() ?? null),
    process_tree: { processes: [...records.values()].sort((a, b) => a.first_seen_ms - b.first_seen_ms), sample_count: samples.length, samples, truncated: treeTrunc, survivors_at_exit: survivors, killed_pids: [...killed].sort((a, b) => a - b), verified_no_survivors: verifiedClean, exec_events: tr.execs, max_concurrent: maxConc },
    filesystem: { scratch_changes: scratchChanges.map((c) => ({ ...c, path: c.path.replace(d.work, "<scratch>") })), observed_changes: obsChanges, observed_paths: observe },
    network: { tracer: trace ? "strace" : null, attempts: tr.net, any_connect_succeeded: tr.net.some((n) => n.syscall === "connect" && n.succeeded && n.family !== "AF_UNIX"), note: trace ? "syscall-level (strace -f -e trace=network): records attempts and results, not packet contents" : "no tracer: network attempts NOT observed (isolation, if any, still applies)" },
    core: { signal_implies_core: signal !== null && CORE_SIGNALS.has(signal), core_pattern: caps.corePattern, core_files: coreFiles },
    sample: { path: samplePath, sha256_before: sha256Before, sha256_after: sha256After, unmodified: sha256Before === sha256After && copySha === sha256Before, copy_sha256: copySha },
    cleanup: { scratch_removed: removed, mounts_leaked: mountsLeaked(scratchPath), scratch_path: scratchPath },
    env_keys: Object.keys(env).sort(), strace_lines: tr.lines,
  };
}

// ---------------------------------------------------------------- public entry point
export async function runSandboxed(spec: SandboxSpec): Promise<Evidence> {
  const caps = await probeCapabilities();
  const requested = spec.isolation ?? "auto";
  let level: AchievedLevel;
  if (requested === "process") level = "process";
  else if (caps.levels.container) level = "container";
  else if (caps.levels["namespace-lite"]) level = "namespace-lite";
  else if (requested === "namespace") throw new IsolationUnavailableError(`namespace isolation requested but unavailable on this host: ${caps.notes.join("; ") || "unknown"}`);
  else level = "process";
  if (!caps.levels.process) throw new IsolationUnavailableError(`sandbox unusable on this host: ${caps.notes.join("; ")}`);
  const useCaps: Capabilities = level === "process" ? { ...caps, userns: false } : caps;
  const res = await execute(spec, level, useCaps);

  const limitations: string[] = [
    "Shares the host kernel: not a virtual machine; kernel exploits or kernel-level side channels are out of scope of this sandbox.",
    "CPU time and peak RSS are sampled from /proc at ~20 ms intervals: lower bounds (a process that lives <20 ms may be missed); process-tree samples likewise (execve events from strace, when available, cover short-lived children).",
    "No seccomp filter and no cgroup limits: memory is bounded by RLIMIT_AS per process, process count by RLIMIT_NPROC (per uid), disk by RLIMIT_FSIZE and tmpfs size (container level only).",
    "Determinism: a single run; timing and scheduling differ between runs (cf. REA's observed identical-run `changed`).",
  ];
  if (res.achieved_level === "process") limitations.push(`Process-level isolation only: the sample can reach the host network and (read) the host filesystem as uid ${res.run_as_uid}; only resource limits, env allowlist, scratch cwd, timeout and tree-kill apply.${requested === "auto" ? ` Namespace isolation not available/used: ${caps.notes.join("; ") || "not requested"}` : ""}`);
  if (res.achieved_level === "namespace-lite") limitations.push("Namespaces used: net (no interfaces except a DOWN loopback => no network at all), pid, ipc, uts, private /proc. NO restricted filesystem view (mount namespace is only used for /proc): the sample can read the host filesystem. Labelled isolation=process.");
  if (res.achieved_level === "container") limitations.push("Namespaces used: net (no network; loopback is down), pid, ipc, uts, mnt with pivot_root into a minimal tmpfs root (read-only /usr,/bin,/lib*,/sbin; read-only sample copy; private /tmp; rw scratch; minimal /dev; no host /etc or home), capabilities dropped, no_new_privs, uid 65534. Still no seccomp/cgroups and shared kernel; labelled isolation=container, never virtual-machine.");
  if (res.achieved_level === "container" && (spec.observePaths ?? []).length) limitations.push("observePaths are host paths; the sample cannot reach them inside the container view, so empty diffs there are expected.");
  if (res.network.tracer === null) limitations.push("Network attempts not observed: strace unavailable or disabled (namespace isolation, when active, still blocks the network).");
  else limitations.push("Network observation is syscall-level via strace -f -e trace=network,execve; a sample can detect ptrace (anti-analysis) and traced runs are slower.");
  if (res.core.core_pattern?.startsWith("|")) limitations.push(`core_pattern pipes to a handler (${res.core.core_pattern}): core files cannot be detected on disk; only signal-implied core is reported.`);
  if (res.network.tracer === null && res.achieved_level !== "process") limitations.push("Untraced namespace run: unshare reports a signal death of the sample as exit code 128+N, so signal vs exit code can be ambiguous.");
  if (res.status === "timeout") limitations.push("Run was killed at the wall-clock timeout; behaviour after the cut-off is unobserved.");
  if (res.status === "output-limit") limitations.push("Run was killed after exceeding the total output limit.");
  if (res.process_tree.truncated) limitations.push("Process-tree records/samples were truncated at their caps.");
  if (!res.process_tree.verified_no_survivors) limitations.push("WARNING: survivors could not be verified dead after the kill sweep.");
  if (!res.cleanup.scratch_removed) limitations.push("WARNING: scratch directory could not be removed.");

  const subjectName = basename(spec.sample);
  const isolation = res.achieved_level === "container" ? "container" : "process";
  return createEvidence({
    subject: { name: subjectName, digest: { sha256: res.sample.sha256_before }, local_path: res.sample.path, format: null, architecture: null },
    provider: { id: "rtk-sandbox", name: "rtk-sandbox", version: "0.1.0" },
    predicate_type: "controlled-execution-observation",
    operation: "run_sandboxed",
    parameters: { args: spec.args ?? [], requested_isolation: requested, limits: res.limits, inherit_env: spec.inheritEnv ?? [], env_keys: Object.keys(spec.env ?? {}).sort(), files: Object.keys(spec.files ?? {}).sort(), observe_paths: res.filesystem.observed_paths, trace: spec.trace ?? true },
    normalized_result: res,
    confidence: "observed",
    authority: "controlled-replay",
    environment: { id: `rtk-sandbox/${res.achieved_level}/${createHash("sha256").update(hostname()).digest("hex").slice(0, 12)}`, platform: process.platform, architecture: process.arch, isolation },
    limitations,
    locations: res.filesystem.scratch_changes.map((c) => ({ kind: "scratch-file", path: c.path, status: c.status, sha256: c.sha256 })),
  });
}

// Used by tests: spec -> raw result without Evidence wrapping
export async function runSandboxedRaw(spec: SandboxSpec, level: AchievedLevel): Promise<SandboxResult> {
  return execute(spec, level, await probeCapabilities());
}
export type { Evidence };
export const _internals = { buildCommand, buildContainerScript, isAbsolute, readdirSync };
