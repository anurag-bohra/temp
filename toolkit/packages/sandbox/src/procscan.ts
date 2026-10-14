// /proc scanning: process-tree membership (session / pgrp / ppid chain / environment token / cwd) and resource readings.
import { existsSync, readFileSync, readdirSync, readlinkSync } from "node:fs";
import { execFileSync } from "node:child_process";

export interface ProcInfo {
  pid: number; state: string; ppid: number; pgrp: number; sid: number; uid: number | null;
  comm: string; exe: string | null; cmdline: string[]; cwd: string | null;
  cpuTicks: number; childTicks: number; startTicks: number; rssKb: number; hwmKb: number;
  hasToken: boolean;
}
let tickHz: number | null = null;
export function clockTicksPerSecond(): number {
  if (tickHz === null) { try { tickHz = Number(execFileSync("getconf", ["CLK_TCK"], { encoding: "utf8" }).trim()) || 100; } catch { tickHz = 100; } }
  return tickHz;
}
const safe = <T>(f: () => T): T | null => { try { return f(); } catch { return null; } };

export function listPids(): number[] {
  return (safe(() => readdirSync("/proc")) ?? []).filter((n) => /^\d+$/u.test(n)).map(Number);
}
const statusField = (status: string, key: string): string | null => {
  const m = new RegExp(`^${key}:\\s*(.*)$`, "mu").exec(status); return m ? m[1]!.trim() : null;
};
export function readProc(pid: number, token: string | null, withEnv: boolean): ProcInfo | null {
  const stat = safe(() => readFileSync(`/proc/${pid}/stat`, "utf8")); if (stat === null) return null;
  const rp = stat.lastIndexOf(")"); if (rp < 0) return null;
  const comm = stat.slice(stat.indexOf("(") + 1, rp);
  const f = stat.slice(rp + 2).split(" ");
  const status = safe(() => readFileSync(`/proc/${pid}/status`, "utf8")) ?? "";
  const kb = (k: string) => Number((statusField(status, k) ?? "0").split(" ")[0]) || 0;
  const uidS = statusField(status, "Uid");
  const cmdRaw = safe(() => readFileSync(`/proc/${pid}/cmdline`, "latin1")) ?? "";
  let hasToken = false;
  if (withEnv && token !== null) { const env = safe(() => readFileSync(`/proc/${pid}/environ`, "latin1")); hasToken = env !== null && env.includes(token); }
  return {
    pid, state: f[0] ?? "?", ppid: Number(f[1]), pgrp: Number(f[2]), sid: Number(f[3]), uid: uidS ? Number(uidS.split(/\s+/u)[0]) : null,
    comm, exe: safe(() => readlinkSync(`/proc/${pid}/exe`)), cmdline: cmdRaw.split("\0").filter((s, i, a) => s !== "" || i < a.length - 1).slice(0, 64).map((s) => s.slice(0, 512)),
    cwd: safe(() => readlinkSync(`/proc/${pid}/cwd`)),
    cpuTicks: Number(f[11]) + Number(f[12]), childTicks: Number(f[13]) + Number(f[14]), startTicks: Number(f[19]),
    rssKb: kb("VmRSS"), hwmKb: kb("VmHWM"), hasToken,
  };
}

export interface MemberQuery { rootPid: number; token: string; baseDir: string; selfPid: number }
export interface Member extends ProcInfo { reasons: string[] }
/** All live processes belonging to the sandbox run, found by several independent signals (a setsid/double-fork escapee is
 *  reparented to init, so the ppid chain alone is not enough). */
export function findMembers(q: MemberQuery): Member[] {
  const all = new Map<number, ProcInfo>();
  for (const pid of listPids()) { if (pid === q.selfPid) continue; const p = readProc(pid, q.token, true); if (p && p.state !== "Z" && p.state !== "X") all.set(pid, p); }
  const out = new Map<number, Member>();
  for (const p of all.values()) {
    const reasons: string[] = [];
    if (p.pid === q.rootPid) reasons.push("root");
    if (p.sid === q.rootPid) reasons.push("session");
    if (p.pgrp === q.rootPid) reasons.push("pgrp");
    if (p.hasToken) reasons.push("env-token");
    if (p.cwd !== null && p.cwd.startsWith(q.baseDir)) reasons.push("cwd");
    if (p.exe !== null && p.exe.startsWith(q.baseDir)) reasons.push("exe");
    if (reasons.length) out.set(p.pid, { ...p, reasons });
  }
  for (let changed = true; changed;) {
    changed = false;
    for (const p of all.values()) if (!out.has(p.pid) && out.has(p.ppid) && p.pid !== q.selfPid) { out.set(p.pid, { ...p, reasons: ["ppid-chain"] }); changed = true; }
  }
  return [...out.values()].sort((a, b) => a.pid - b.pid);
}
export const pidAlive = (pid: number): boolean => existsSync(`/proc/${pid}`);
