import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { createEvidence, type Evidence } from "@rtk/evidence";

const run = promisify(execFile);
export interface YaraMatch { rule: string; target: string; strings: { offset: number; id: string; data: string }[] }
/** Run the yara CLI (4.x) over one target. Rules file must be supplied by the caller; yara is never installed by this package. */
export async function yaraScan(targetPath: string, rulesPath: string, sha256: string, o: { yaraCmd?: string; timeoutMs?: number; recursive?: boolean } = {}): Promise<Evidence> {
  const cmd = o.yaraCmd ?? process.env.RTK_YARA_COMMAND ?? "yara"; const args = ["-s", ...(o.recursive ? ["-r"] : []), rulesPath, targetPath];
  let stdout = "", stderr = "", code = 0;
  try { ({ stdout, stderr } = await run(cmd, args, { timeout: o.timeoutMs ?? 60000, maxBuffer: 16 << 20 })); } catch (e) { const x = e as { code?: string | number; stdout?: string; stderr?: string; killed?: boolean }; if (x.code === "ENOENT") throw new Error(`yara executable not found (${cmd}); set RTK_YARA_COMMAND`); stdout = x.stdout ?? ""; stderr = x.stderr ?? String(e); code = typeof x.code === "number" ? x.code : 1; if (x.killed) stderr += " (timeout)"; }
  const matches: YaraMatch[] = []; let cur: YaraMatch | null = null;
  for (const line of stdout.split("\n")) {
    if (!line.trim()) continue; const sm = /^0x([0-9a-f]+):(\$[^:]*):\s?(.*)$/u.exec(line);
    if (sm && cur) cur.strings.push({ offset: parseInt(sm[1]!, 16), id: sm[2]!, data: sm[3]!.slice(0, 200) });
    else { const m = /^(\S+)\s+(.+)$/u.exec(line); if (m) { cur = { rule: m[1]!, target: m[2]!, strings: [] }; matches.push(cur); } }
  }
  return createEvidence({
    subject: { name: targetPath.split("/").pop()!, digest: { sha256 }, local_path: targetPath, format: null, architecture: null },
    provider: { id: "rtk-yara", name: "YARA command-line scan", version: null }, predicate_type: "rtk.yara-scan", operation: "yara_scan",
    parameters: { rules: rulesPath, recursive: o.recursive ?? false }, normalized_result: { matches, exit_code: code, stderr: stderr.slice(0, 2000) },
    confidence: code > 1 ? "inferred" : "observed", authority: "shipped-artifact",
    limitations: ["Matches are signature hits against the supplied rules; a clean scan does not establish absence of malicious behaviour.", ...(code > 1 ? [`yara exited with ${code}: results may be incomplete`] : [])],
  });
}
