// Filesystem snapshot / diff (path, status added|removed|modified, sha256).
import { lstatSync, readdirSync, readlinkSync, openSync, readSync, closeSync } from "node:fs";
import { createHash } from "node:crypto";
import { join } from "node:path";

export interface FsEntry { type: "file" | "dir" | "symlink" | "other"; size: number; mode: number; sha256: string | null; target: string | null; hashSkipped?: boolean }
export type Snapshot = Map<string, FsEntry>;
export interface FsChange { path: string; status: "added" | "removed" | "modified"; type: FsEntry["type"]; size: number; sha256: string | null }

const MAX_HASH = 64 * 1024 * 1024; const MAX_ENTRIES = 20000;
export function sha256File(path: string, limit = Infinity): string | null {
  const h = createHash("sha256"); const fd = openSync(path, "r"); const buf = Buffer.allocUnsafe(1 << 20); let total = 0;
  try { for (;;) { const n = readSync(fd, buf, 0, buf.length, null); if (n === 0) break; total += n; if (total > limit) return null; h.update(buf.subarray(0, n)); } } finally { closeSync(fd); }
  return h.digest("hex");
}
export function snapshot(roots: string[]): Snapshot {
  const snap: Snapshot = new Map();
  const visit = (p: string, depth: number) => {
    if (snap.size >= MAX_ENTRIES || depth > 32) return;
    let st; try { st = lstatSync(p); } catch { return; }
    if (st.isSymbolicLink()) { snap.set(p, { type: "symlink", size: st.size, mode: st.mode, sha256: null, target: readlinkSync(p) }); return; }
    if (st.isDirectory()) {
      snap.set(p, { type: "dir", size: 0, mode: st.mode, sha256: null, target: null });
      let names: string[] = []; try { names = readdirSync(p).sort(); } catch { /* unreadable */ }
      for (const n of names) visit(join(p, n), depth + 1);
    } else if (st.isFile()) {
      let sha: string | null = null; let skipped = false;
      try { sha = st.size <= MAX_HASH ? sha256File(p, MAX_HASH) : null; if (sha === null) skipped = true; } catch { skipped = true; }
      snap.set(p, { type: "file", size: st.size, mode: st.mode, sha256: sha, target: null, ...(skipped ? { hashSkipped: true } : {}) });
    } else snap.set(p, { type: "other", size: 0, mode: st.mode, sha256: null, target: null });
  };
  for (const r of roots) visit(r, 0);
  return snap;
}
export function diffSnapshots(before: Snapshot, after: Snapshot): FsChange[] {
  const out: FsChange[] = [];
  for (const [p, a] of after) {
    const b = before.get(p);
    if (!b) out.push({ path: p, status: "added", type: a.type, size: a.size, sha256: a.sha256 });
    else if (a.type !== b.type || a.sha256 !== b.sha256 || a.target !== b.target || (a.type === "file" && a.size !== b.size) || (a.type !== "dir" && a.mode !== b.mode)) out.push({ path: p, status: "modified", type: a.type, size: a.size, sha256: a.sha256 });
  }
  for (const [p, b] of before) if (!after.has(p)) out.push({ path: p, status: "removed", type: b.type, size: b.size, sha256: b.sha256 });
  return out.sort((x, y) => x.path.localeCompare(y.path));
}
