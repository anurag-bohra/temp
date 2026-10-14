// Configuration from a JSON file and/or environment (env wins over file).
import { readFileSync } from "node:fs";
import { delimiter } from "node:path";
import type { GatewayConfig, GatewayLimits } from "./gateway.ts";
import { DEFAULT_UPSTREAM, type UpstreamSpec } from "./server.ts";

export interface FileConfig { profile?: string; allowedRoots?: string[]; writeRoots?: string[]; baseDir?: string; approveTools?: string[]; auditLog?: string; limits?: Partial<GatewayLimits>; upstream?: UpstreamSpec }
/** Env: RTK_GATEWAY_CONFIG (json file), RTK_PROFILE, RTK_ALLOWED_ROOTS (path-delimiter list), RTK_WRITE_ROOTS, RTK_APPROVE (comma list),
 *  RTK_AUDIT_LOG, RTK_UPSTREAM_COMMAND (JSON array of argv or a space-separated string), RTK_BASE_DIR, RTK_UPSTREAM_ENV_ALLOW (comma list). */
export function loadConfig(env: NodeJS.ProcessEnv = process.env, file?: string): { gateway: GatewayConfig; upstream: UpstreamSpec } {
  const path = file ?? env.RTK_GATEWAY_CONFIG; const f: FileConfig = path ? (JSON.parse(readFileSync(path, "utf8")) as FileConfig) : {};
  const list = (s: string | undefined) => (s ? s.split(delimiter).filter(Boolean) : undefined);
  const csv = (s: string | undefined) => (s ? s.split(",").map((x) => x.trim()).filter(Boolean) : undefined);
  let upstream: UpstreamSpec = f.upstream ?? DEFAULT_UPSTREAM;
  if (env.RTK_UPSTREAM_COMMAND) {
    const t = env.RTK_UPSTREAM_COMMAND.trim(); const argv: string[] = t.startsWith("[") ? (JSON.parse(t) as string[]) : t.split(/\s+/u);
    upstream = { ...upstream, command: argv[0]!, args: argv.slice(1) };
  }
  if (env.RTK_UPSTREAM_ENV_ALLOW) upstream = { ...upstream, envAllow: csv(env.RTK_UPSTREAM_ENV_ALLOW) };
  const gateway: GatewayConfig = {
    profile: env.RTK_PROFILE ?? f.profile ?? "locked",
    allowedRoots: list(env.RTK_ALLOWED_ROOTS) ?? f.allowedRoots ?? [],
    ...(list(env.RTK_WRITE_ROOTS) ?? f.writeRoots ? { writeRoots: list(env.RTK_WRITE_ROOTS) ?? f.writeRoots } : {}),
    ...(env.RTK_BASE_DIR ?? f.baseDir ? { baseDir: env.RTK_BASE_DIR ?? f.baseDir } : {}),
    approveTools: csv(env.RTK_APPROVE) ?? f.approveTools ?? [],
    ...(env.RTK_AUDIT_LOG ?? f.auditLog ? { auditLog: env.RTK_AUDIT_LOG ?? f.auditLog } : {}),
    ...(f.limits ? { limits: f.limits } : {}),
  };
  return { gateway, upstream };
}
