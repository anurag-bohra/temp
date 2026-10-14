import { spawn } from "node:child_process";
import { randomBytes } from "node:crypto";
import { existsSync, mkdtempSync, rmSync, writeFileSync, chmodSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { HopperUnavailableError } from "./protocol.ts";

export interface LaunchOptions {
  /** Executable to start. For real Hopper this is the Hopper binary; its CLI for running a script is UNVERIFIED, so no default is assumed. */
  bin: string;
  /** Arguments for `bin`. The placeholders {script}, {socket}, {token_file} are substituted. The socket and token are also given as env vars RTK_HOPPER_SOCKET / RTK_HOPPER_TOKEN_FILE. */
  args: string[];
  /** Path of the bridge script (substituted for {script}). */
  script: string;
  tmpRoot?: string;
  startupTimeoutMs?: number;
}

export interface BridgeHandle {
  socketPath: string;
  token: string;
  dir: string;
  pid: number;
  /** SIGKILL the process group, wait for it to vanish, remove the private directory, verify. */
  stop(): Promise<void>;
}

function groupAlive(pgid: number): boolean { try { process.kill(-pgid, 0); return true; } catch { return false; } }

/** Create a private dir + per-session token, start the bridge host process in its own process group, wait for the socket. */
export async function launchBridge(o: LaunchOptions): Promise<BridgeHandle> {
  if (!existsSync(o.bin)) throw new HopperUnavailableError(`Hopper executable not found: ${o.bin}`);
  const dir = mkdtempSync(join(o.tmpRoot ?? tmpdir(), "rtk-hopper-"));
  chmodSync(dir, 0o700);
  const socketPath = join(dir, "s.sock");
  const tokenFile = join(dir, "token");
  const token = randomBytes(32).toString("hex");
  writeFileSync(tokenFile, token, { mode: 0o600 });
  const sub = (a: string) => a.replaceAll("{script}", o.script).replaceAll("{socket}", socketPath).replaceAll("{token_file}", tokenFile);
  const child = spawn(o.bin, o.args.map(sub), { detached: true, stdio: "ignore", env: { ...process.env, RTK_HOPPER_SOCKET: socketPath, RTK_HOPPER_TOKEN_FILE: tokenFile } });
  const pid = child.pid;
  let exited = false;
  child.once("exit", () => { exited = true; });
  child.once("error", () => { exited = true; });
  child.unref();
  const stop = async () => {
    if (pid) { try { process.kill(-pid, "SIGKILL"); } catch { /* gone */ } }
    const deadline = Date.now() + 5000;
    while (pid && groupAlive(pid) && Date.now() < deadline) await new Promise((r) => setTimeout(r, 25));
    rmSync(dir, { recursive: true, force: true });
    if (pid && groupAlive(pid)) throw new HopperUnavailableError(`bridge process group ${pid} did not exit`);
    if (existsSync(dir)) throw new HopperUnavailableError(`could not remove ${dir}`);
  };
  if (!pid) { await stop(); throw new HopperUnavailableError(`failed to spawn ${o.bin}`); }
  const deadline = Date.now() + (o.startupTimeoutMs ?? 15_000);
  while (!existsSync(socketPath)) {
    if (exited || Date.now() > deadline) {
      await stop();
      throw new HopperUnavailableError(exited ? "bridge process exited before creating its socket" : "timed out waiting for bridge socket");
    }
    await new Promise((r) => setTimeout(r, 25));
  }
  return { socketPath, token, dir, pid, stop };
}
