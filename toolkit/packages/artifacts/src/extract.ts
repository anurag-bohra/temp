import { closeSync, constants, fchmodSync, lstatSync, mkdirSync, openSync, realpathSync, rmdirSync, rmSync, unlinkSync, writeSync } from "node:fs";
import { basename, join, resolve, sep } from "node:path";
import { createEvidence } from "@rtk/evidence";
import type { Evidence } from "@rtk/evidence";
import type { Anomaly, AnomalyCode, Quotas } from "./types.ts";
import { EntryError, QuotaError, resolveQuotas } from "./types.ts";
import { fileSource } from "./source.ts";
import { analyzeListing, isBlocking, mkAnomaly, openContainer, segmentsOf } from "./archive.ts";
import { Budget, consumeEntry } from "./consume.ts";
import { ARCHIVE_LIMITATIONS, PROVIDER } from "./inspect.ts";
import { createHash } from "node:crypto";

export interface ExtractOptions {
  /** strict (default): the first refused entry fails the whole extraction and everything is cleaned up. skip-bad: refused entries are skipped and reported; quota breaches still fail everything. */
  policy?: "strict" | "skip-bad";
  /** keep the owner-exec bit (file mode 0700 instead of 0600). setuid/setgid/sticky are never preserved. */
  preserveExec?: boolean;
}
export interface ManifestEntry { path: string; type: "file" | "dir"; size: number | null; sha256: string | null; mode: string }
export interface Refusal { entry: string | null; code: AnomalyCode; detail: string }
interface Failure { code: AnomalyCode; entry: string | null; detail: string }

class ExtractFailure extends Error { f: Failure; constructor(f: Failure) { super(f.detail); this.f = f; } }

export async function extractArchive(path: string, destDir: string, quotas?: Partial<Quotas>, opts: ExtractOptions = {}): Promise<Evidence> {
  const q = resolveQuotas(quotas); const policy = opts.policy ?? "strict"; const abs = resolve(path); const destAbs = resolve(destDir);
  try { if (!lstatSync(destAbs).isDirectory()) throw new Error(`destination exists and is not a directory: ${destAbs}`); } catch (e) { if ((e as NodeJS.ErrnoException).code !== "ENOENT") throw e; }
  const src = fileSource(abs);
  const archSha = (() => { const h = createHash("sha256"); for (let o = 0; o < src.size; o += 1 << 20) h.update(src.read(o, 1 << 20)); return h.digest("hex"); })();
  const budget = new Budget(q);
  const manifest: ManifestEntry[] = []; const refusals: Refusal[] = [];
  const createdFiles: string[] = []; const createdDirs: string[] = []; let createdRoot: string | undefined;
  let failure: Failure | null = null; let cleaned = false; let anomalies: Anomaly[] = []; let format = "unknown"; let discarded = 0;
  let opened: Awaited<ReturnType<typeof openContainer>> | null = null;
  const refuse = (entry: string | null, code: AnomalyCode, detail: string) => {
    if (policy === "strict") throw new ExtractFailure({ code, entry, detail });
    refusals.push({ entry, code, detail });
  };
  try {
    opened = await openContainer(src, budget, basename(abs), { toFile: true, nameHint: basename(abs) });
    format = opened.format;
    const an = analyzeListing(opened.entries, q, basename(abs));
    anomalies = [...opened.anomalies, ...an.anomalies];
    // listing-level refusals happen BEFORE anything is written
    for (const a of opened.anomalies) {
      if (a.fatal || a.code === "unsupported-format") throw new ExtractFailure({ code: a.code, entry: a.entry, detail: a.detail });
      if (a.code === "corrupt-archive") refuse(a.entry, a.code, a.detail);
    }
    if (policy === "strict") for (const e of opened.entries) { const b = (an.byEntry.get(e.index) ?? []).find((x) => isBlocking(x.code)); if (b) throw new ExtractFailure({ code: b.code, entry: e.name, detail: b.detail }); }

    createdRoot = mkdirSync(destAbs, { recursive: true, mode: 0o700 });
    const realDest = realpathSync(destAbs);
    const inside = (p: string) => p === realDest || p.startsWith(realDest + sep);

    const mkdirSafe = (segs: string[], entryName: string): string => {
      let cur = realDest;
      for (const s of segs) {
        const next = join(cur, s);
        let st; try { st = lstatSync(next); } catch (e) { if ((e as NodeJS.ErrnoException).code !== "ENOENT") throw e; st = null; }
        if (st === null) { mkdirSync(next, { mode: 0o700 }); createdDirs.push(next); }
        else if (st.isSymbolicLink()) throw new EntryError("symlink-through", `path component ${JSON.stringify(s)} is an existing symlink`);
        else if (!st.isDirectory()) throw new EntryError("path-conflict", `path component ${JSON.stringify(s)} exists and is not a directory`);
        if (realpathSync(next) !== next || !inside(next)) throw new EntryError("path-traversal", `resolved path of ${JSON.stringify(entryName)} escapes the destination`);
        cur = next;
      }
      return cur;
    };

    for (const e of opened.entries) {
      const list = an.byEntry.get(e.index) ?? [];
      const block = list.find((x) => isBlocking(x.code));
      if (block) { refuse(e.name, block.code, block.detail); continue; }
      const segs = segmentsOf(e.name);
      try {
        if (e.type === "dir") { if (segs.length) { mkdirSafe(segs, e.name); manifest.push({ path: segs.join("/"), type: "dir", size: null, sha256: null, mode: "0700" }); } continue; }
        if (e.type === "symlink" || e.type === "hardlink") { refusals.push({ entry: e.name, code: e.type === "symlink" ? "symlink" : "hardlink", detail: `${e.type} entries are never created (target ${JSON.stringify(e.linkTarget)})` }); continue; }
        if (e.type !== "file") { refuse(e.name, "special-file", `unsupported entry type ${e.type}`); continue; }
        if (!e.stream) throw new EntryError("corrupt-data", "entry has no readable data");
        if (segs.length === 0) throw new EntryError("empty-name", "file entry has no usable path");
        const parent = mkdirSafe(segs.slice(0, -1), e.name);
        const target = join(parent, segs[segs.length - 1]!);
        if (!inside(target)) throw new EntryError("path-traversal", "target resolves outside the destination");
        let exists = true; try { lstatSync(target); } catch (er) { if ((er as NodeJS.ErrnoException).code === "ENOENT") exists = false; else throw er; }
        if (exists) throw new EntryError("would-overwrite", `${segs.join("/")} already exists; never overwriting`);
        const mode = opts.preserveExec && e.mode !== null && (e.mode & 0o100) ? 0o700 : 0o600;
        const fd = openSync(target, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, mode);
        createdFiles.push(target);
        let res;
        try { res = await consumeEntry(e, budget, (c) => { let o = 0; while (o < c.length) o += writeSync(fd, c, o, c.length - o); }); fchmodSync(fd, mode); }
        catch (err) { try { closeSync(fd); } catch { /* */ } try { unlinkSync(target); } catch { /* */ } createdFiles.pop(); throw err; }
        closeSync(fd);
        if (!inside(realpathSync(target))) { unlinkSync(target); createdFiles.pop(); throw new EntryError("path-traversal", "extracted file resolves outside the destination"); }
        manifest.push({ path: segs.join("/"), type: "file", size: res.size, sha256: res.sha256, mode: mode.toString(8).padStart(4, "0") });
      } catch (err) {
        if (err instanceof EntryError) refuse(e.name, err.code, err.message);
        else throw err;
      }
    }
  } catch (err) {
    if (err instanceof ExtractFailure) failure = err.f;
    else if (err instanceof QuotaError) failure = { code: err.code, entry: null, detail: err.message };
    else if (err instanceof EntryError) failure = { code: err.code, entry: null, detail: err.message };
    else { failure = { code: "corrupt-data", entry: null, detail: `unexpected error: ${(err as Error).message}` }; }
  } finally {
    opened?.close(); src.close();
  }
  if (failure) {
    discarded = manifest.length; manifest.length = 0;
    for (const f of createdFiles.reverse()) { try { unlinkSync(f); } catch { /* gone */ } }
    for (const d of createdDirs.reverse()) { try { rmdirSync(d); } catch { /* not empty / gone */ } }
    if (createdRoot) { try { rmSync(createdRoot, { recursive: true, force: true }); } catch { /* */ } }
    cleaned = true;
    if (failure.code && !anomalies.some((a) => a.code === failure!.code)) anomalies.push(mkAnomaly(failure.code, failure.entry, failure.detail, basename(abs), true));
  }
  const status = failure ? "failed" : refusals.some((r) => r.code !== "symlink" && r.code !== "hardlink") ? "partial" : "ok";
  const files = manifest.filter((m) => m.type === "file");
  return createEvidence({
    subject: { name: basename(abs), digest: { sha256: archSha }, local_path: abs, format, architecture: null },
    provider: PROVIDER, predicate_type: "rtk.artifacts", operation: "extract_archive",
    parameters: { dest: destAbs, policy, quotas: q, preserve_exec: opts.preserveExec ?? false },
    normalized_result: {
      status, policy, dest: destAbs, format, failure, cleaned_up: cleaned, discarded_entries: discarded, refusals, anomalies, manifest,
      totals: { files: files.length, dirs: manifest.length - files.length, bytes: files.reduce((a, m) => a + (m.size ?? 0), 0), refused: refusals.length },
    },
    confidence: "observed", authority: "shipped-artifact",
    limitations: [
      ...ARCHIVE_LIMITATIONS,
      "Extraction writes regular files and directories only: symlinks, hardlinks, device nodes and FIFOs are never created (reported as refusals/skips). Nested archives are extracted as plain files, not unpacked.",
      "Path safety is checked per component with lstat/realpath at write time and files are opened O_EXCL|O_NOFOLLOW; a concurrent local attacker racing the destination directory is out of scope.",
      "File modes are normalised to 0600 (0700 with preserveExec); ownership and timestamps are not restored.",
    ],
    locations: files.map((m) => ({ kind: "extracted-file", path: m.path, sha256: m.sha256, size: m.size })),
  });
}
