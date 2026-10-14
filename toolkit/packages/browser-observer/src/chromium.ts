import { existsSync, readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";

/** Environment variable that overrides Chromium discovery (path to a chrome / headless_shell executable). */
export const ENV_EXECUTABLE = "RTK_CHROMIUM_PATH";

export interface ChromiumLocation { path: string; source: string }

/**
 * Locate a Chromium. Order: explicit option, $RTK_CHROMIUM_PATH, $PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH,
 * then $PLAYWRIGHT_BROWSERS_PATH (default /opt/pw-browsers and ~/.cache/ms-playwright), preferring the
 * highest-numbered chromium_headless_shell-*, then chromium-*.
 */
export function findChromium(explicit?: string): ChromiumLocation | null {
  if (explicit) return existsSync(explicit) ? { path: explicit, source: "option" } : null;
  for (const v of [ENV_EXECUTABLE, "PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH"]) {
    const p = process.env[v];
    if (p) return existsSync(p) ? { path: p, source: `env:${v}` } : null;
  }
  const roots = [process.env.PLAYWRIGHT_BROWSERS_PATH, "/opt/pw-browsers", join(process.env.HOME ?? "", ".cache/ms-playwright")].filter((x): x is string => !!x && x !== "0");
  for (const root of roots) {
    let names: string[];
    try { names = readdirSync(root); } catch { continue; }
    const num = (n: string) => Number(/-(\d+)$/u.exec(n)?.[1] ?? 0);
    for (const [prefix, rel] of [["chromium_headless_shell-", "chrome-linux/headless_shell"], ["chromium-", "chrome-linux/chrome"]] as const) {
      const c = names.filter((n) => n.startsWith(prefix)).sort((a, b) => num(b) - num(a));
      for (const d of c) { const p = join(root, d, rel); if (existsSync(p)) return { path: p, source: `search:${root}` }; }
    }
  }
  return null;
}

/** Linux only: pids whose command line mentions the given user-data-dir (browser + helpers). */
export function pidsUsingProfile(dir: string): number[] {
  const pids: number[] = [];
  let entries: string[];
  try { entries = readdirSync("/proc"); } catch { return pids; }
  for (const e of entries) {
    if (!/^\d+$/u.test(e) || Number(e) === process.pid) continue;
    try { if (readFileSync(`/proc/${e}/cmdline`, "utf8").includes(dir)) pids.push(Number(e)); } catch { /* process gone */ }
  }
  return pids;
}
export function killProfileProcesses(dir: string): number {
  const pids = pidsUsingProfile(dir);
  for (const p of pids) { try { process.kill(p, "SIGKILL"); } catch { /* already gone */ } }
  return pids.length;
}
