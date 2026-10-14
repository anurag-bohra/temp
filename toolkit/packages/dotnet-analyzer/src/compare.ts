import { createEvidence } from "@rtk/evidence";
import type { Evidence } from "@rtk/evidence";
import { managedResultOf, PROVIDER } from "./analyze.ts";
import type { ManagedMethod } from "./analyze.ts";

const setDiff = <T>(a: T[], b: T[]): { added: T[]; removed: T[] } => {
  const sa = new Set(a), sb = new Set(b);
  return { added: b.filter((x) => !sa.has(x)), removed: a.filter((x) => !sb.has(x)) };
};
const multisetEq = (a: string[], b: string[]) => a.length === b.length && [...a].sort().every((x, i) => x === [...b].sort()[i]);

export interface MethodDiff { method: string; il_changed: boolean; literal_changed: boolean; il_sha256: [string | null, string | null]; literals_added: string[]; literals_removed: string[]; edges_added: string[]; edges_removed: string[] }

const LIMITS = [
  "Compares static metadata/IL only; semantics are not evaluated. A changed IL hash does not imply changed behaviour (e.g. recompilation shifts tokens) and an unchanged hash does not imply unchanged behaviour (tokens resolve differently per assembly).",
  "Methods are matched by Namespace.Type::Name(param-types); renamed methods appear as removed + added.",
  "IL hash covers IL bytes only, so a change in a #US string of the same length may leave the hash unchanged: literals are therefore compared separately (that is the point of literal_changed_il_unchanged).",
  "IL hashes include metadata tokens; any edit that shifts #US/MemberRef/TypeRef rows changes hashes of unrelated methods. The 'edges' diff (resolved names) is token-independent.",
];

export function compareManagedAssemblies(evA: Evidence, evB: Evidence): Evidence {
  const a = managedResultOf(evA), b = managedResultOf(evB);
  const ma = new Map(a.methods.map((m) => [m.full_name, m])), mb = new Map(b.methods.map((m) => [m.full_name, m]));
  const edgesOf = (r: typeof a, m: string) => r.call_edges.filter((e) => e.caller === m).map((e) => `${e.opcode} ${e.target}`);
  const added: string[] = [], removed: string[] = [], changed: MethodDiff[] = [];
  let unchanged = 0;
  const litChangedIlSame: string[] = [], ilChangedOnly: string[] = [];
  for (const [k, m] of mb) if (!ma.has(k)) added.push(k);
  for (const [k, m] of ma) {
    const n = mb.get(k);
    if (!n) { removed.push(k); continue; }
    const ilCh = (m as ManagedMethod).il_sha256 !== n.il_sha256;
    const litCh = !multisetEq(m.literals, n.literals);
    const ea = edgesOf(a, k), eb = edgesOf(b, k); const ed = setDiff(ea, eb);
    const edgeCh = ed.added.length + ed.removed.length > 0;
    if (!ilCh && !litCh && !edgeCh) { unchanged++; continue; }
    const ld = setDiff(m.literals, n.literals);
    changed.push({ method: k, il_changed: ilCh, literal_changed: litCh, il_sha256: [m.il_sha256, n.il_sha256], literals_added: ld.added, literals_removed: ld.removed, edges_added: ed.added, edges_removed: ed.removed });
    if (litCh && !ilCh) litChangedIlSame.push(k);
    if (ilCh && !litCh) ilChangedOnly.push(k);
  }
  const ilOnlyView = { unchanged_by_il_hash: [...ma.keys()].filter((k) => mb.has(k) && ma.get(k)!.il_sha256 === mb.get(k)!.il_sha256) };
  const pk = (p: { dll: string | null; entry_point: string; declaring_method: string }) => `${(p.dll ?? "").toLowerCase()}!${p.entry_point} <- ${p.declaring_method}`;
  const pd = setDiff(a.pinvokes.map(pk), b.pinvokes.map(pk));
  const rk = (r: { name: string; sha256: string | null }) => `${r.name}#${r.sha256}`;
  const rd = setDiff(a.resources.map(rk), b.resources.map(rk));
  const usd = setDiff(a.user_string_literals.map((x) => x.value), b.user_string_literals.map((x) => x.value));
  const ik = (i: { id: string; method: string; target: string }) => `${i.id} @ ${i.method} -> ${i.target}`;
  const ind = setDiff(a.indicators.map(ik), b.indicators.map(ik));
  const refd = setDiff(a.assembly_references.map((r) => `${r.name} ${r.version}`), b.assembly_references.map((r) => `${r.name} ${r.version}`));
  const result = {
    identity: { a: a.identity, b: b.identity, same_mvid: a.identity.mvid === b.identity.mvid },
    methods: { added, removed, changed, unchanged_count: unchanged, literal_changed_il_unchanged: litChangedIlSame, il_changed_literals_same: ilChangedOnly },
    il_hash_only_view: { methods_reported_unchanged: ilOnlyView.unchanged_by_il_hash.length, hides_literal_changes_in: litChangedIlSame },
    literals: { assembly_added: usd.added, assembly_removed: usd.removed },
    pinvokes: pd, resources: rd, indicators: ind, assembly_references: refd,
    identical: added.length + removed.length + changed.length + pd.added.length + pd.removed.length + rd.added.length + rd.removed.length + usd.added.length + usd.removed.length === 0,
  };
  return createEvidence({
    subject: evB.subject, provider: PROVIDER, predicate_type: "rtk.dotnet", operation: "compare_managed_assemblies",
    parameters: { a: evA.evidence_id, b: evB.evidence_id, a_sha256: evA.subject?.digest.sha256, b_sha256: evB.subject?.digest.sha256 },
    normalized_result: result, confidence: "derived", authority: "shipped-artifact", limitations: LIMITS,
    evidence_links: [{ rel: "compared", evidence_id: evA.evidence_id }, { rel: "compared", evidence_id: evB.evidence_id }],
  });
}
