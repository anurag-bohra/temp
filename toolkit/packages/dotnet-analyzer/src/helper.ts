import { spawn, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { cpSync, existsSync, mkdirSync, readFileSync, renameSync, rmSync } from "node:fs";
import { homedir, tmpdir } from "node:os";
import { join } from "node:path";

export class NotImplementedError extends Error {}
export class DotnetUnavailableError extends Error {}
export class HelperError extends Error {}

const SRC_DIR = new URL("../dotnet/MetaReader/", import.meta.url).pathname;

export function dotnetEnv(): NodeJS.ProcessEnv {
  return { ...process.env, DOTNET_CLI_TELEMETRY_OPTOUT: "1", DOTNET_NOLOGO: "1", DOTNET_SKIP_FIRST_TIME_EXPERIENCE: "1", DOTNET_CLI_UI_LANGUAGE: "en", MSBUILDDISABLENODEREUSE: "1" };
}

export function dotnetAvailable(): boolean {
  try { const r = spawnSync("dotnet", ["--version"], { env: dotnetEnv(), encoding: "utf8" }); return r.status === 0; } catch { return false; }
}

function sourceHash(): string {
  const h = createHash("sha256");
  for (const f of ["MetaReader.csproj", "Program.cs"]) h.update(f).update(readFileSync(join(SRC_DIR, f)));
  return h.digest("hex").slice(0, 16);
}

export function defaultCacheDir(): string {
  return process.env.RTK_DOTNET_CACHE ?? join(process.env.XDG_CACHE_HOME ?? (homedir() ? join(homedir(), ".cache") : tmpdir()), "rtk-dotnet-analyzer");
}

/** Build the C# helper once (content-addressed cache dir, atomic rename). Returns the path to MetaReader.dll. */
export function ensureHelperBuilt(cacheDir: string = defaultCacheDir()): string {
  if (!dotnetAvailable()) throw new DotnetUnavailableError("`dotnet` SDK not found on PATH");
  const key = sourceHash();
  const out = join(cacheDir, key, "out");
  const dll = join(out, "MetaReader.dll");
  if (existsSync(dll)) return dll;
  mkdirSync(cacheDir, { recursive: true });
  const work = join(cacheDir, `${key}.build-${process.pid}-${Date.now()}`);
  mkdirSync(work, { recursive: true });
  try {
    cpSync(SRC_DIR, join(work, "src"), { recursive: true, filter: (p) => !/\/(obj|bin)(\/|$)/u.test(p) });
    const r = spawnSync("dotnet", ["build", join(work, "src", "MetaReader.csproj"), "-c", "Release", "-o", join(work, "out"), "--nologo", "-v", "q"], { env: dotnetEnv(), encoding: "utf8", timeout: 300_000 });
    if (r.status !== 0 || !existsSync(join(work, "out", "MetaReader.dll"))) throw new HelperError(`dotnet build of MetaReader failed: ${(r.stdout ?? "") + (r.stderr ?? "")}`.slice(0, 4000));
    mkdirSync(join(cacheDir, key), { recursive: true });
    try { renameSync(join(work, "out"), out); } catch { if (!existsSync(dll)) throw new HelperError("could not install helper into cache"); }
    return dll;
  } finally { rmSync(work, { recursive: true, force: true }); }
}

/** Run the helper on a file; resolves to the parsed JSON document. The target is never loaded or executed. */
export function runHelper(dll: string, file: string, timeoutMs: number): Promise<unknown> {
  return new Promise((resolve, reject) => {
    const p = spawn("dotnet", [dll, file], { env: dotnetEnv(), stdio: ["ignore", "pipe", "pipe"] });
    const out: Buffer[] = []; const err: Buffer[] = []; let size = 0; let done = false;
    const timer = setTimeout(() => { if (!done) { done = true; p.kill("SIGKILL"); reject(new HelperError(`helper timed out after ${timeoutMs} ms`)); } }, timeoutMs);
    p.stdout.on("data", (b: Buffer) => { size += b.length; if (size > 256 * 1024 * 1024) { p.kill("SIGKILL"); } else out.push(b); });
    p.stderr.on("data", (b: Buffer) => err.push(b));
    p.on("error", (e) => { if (!done) { done = true; clearTimeout(timer); reject(new HelperError(String(e))); } });
    p.on("close", (code) => {
      if (done) return; done = true; clearTimeout(timer);
      if (code !== 0) return reject(new HelperError(`helper exited ${code}: ${Buffer.concat(err).toString("utf8").slice(0, 2000)}`));
      try { resolve(JSON.parse(Buffer.concat(out).toString("utf8"))); } catch (e) { reject(new HelperError(`helper produced invalid JSON: ${String(e)}`)); }
    });
  });
}
