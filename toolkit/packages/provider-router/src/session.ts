import { canonicalDigest, createEvidence } from "@rtk/evidence";
import type { Evidence } from "@rtk/evidence";
import type { AnalysisProvider, AnalysisProviderBinding, AnalysisSnapshot, CapabilityEntry, JsonObject, SnapshotIdentity, Target } from "./types.ts";
import { OperationRoutingError, ProviderSelectionError, SessionStateError, SnapshotIdentityError } from "./errors.ts";
import { Registry } from "./registry.ts";

export const ROUTER_PROVIDER = { id: "rtk-provider-router", name: "RTK provider router", version: "0.1.0" } as const;

const cmp = (a: string, b: string): number => (a < b ? -1 : a > b ? 1 : 0);
const deepFreeze = <T>(v: T): T => {
  if (v && typeof v === "object") { for (const x of Object.values(v)) deepFreeze(x); Object.freeze(v); }
  return v;
};

export function profileDigest(p: { id: string; version: string; settings: unknown }): string {
  return canonicalDigest({ provider_id: p.id, provider_version: p.version, settings: p.settings });
}

export interface OpenResult {
  binding: AnalysisProviderBinding;
  /** Evidence emitted on a fresh bind; the same record is returned again on reuse. */
  evidence: Evidence;
  reused: boolean;
}

interface Active {
  target: Target;
  binding: AnalysisProviderBinding;
  evidence: Evidence;
  deep: AnalysisProvider;
  deepRelease: () => void;
  aux: { provider: AnalysisProvider; release: () => void }[];
  routes: Map<string, AnalysisProvider>;
  snapshot: AnalysisSnapshot | null;
}

// Plain provider instances can serve only one session at a time.
const busyInstances = new WeakSet<AnalysisProvider>();

/**
 * One session = one target bound to one deep provider with one immutable binding.
 * Switching provider/profile/target requires an explicit close() then open().
 * Reopening the same target+provider+profile reuses the existing binding.
 */
export class BinarySession {
  readonly #registry: Registry;
  #active: Active | null = null;
  #transition: Promise<unknown> = Promise.resolve();

  constructor(registry: Registry) { this.#registry = registry; }

  #serialize<T>(fn: () => Promise<T>): Promise<T> {
    const run = this.#transition.then(fn, fn);
    this.#transition = run.catch(() => undefined);
    return run;
  }

  binding(): AnalysisProviderBinding | null { return this.#active?.binding ?? null; }
  target(): Target | null { return this.#active ? { ...this.#active.target } : null; }
  isOpen(): boolean { return this.#active !== null; }

  open(target: Target, opts: { provider?: string } = {}): Promise<OpenResult> {
    return this.#serialize(() => this.#open(target, opts.provider ?? "auto"));
  }

  async #open(target: Target, requested: string): Promise<OpenResult> {
    if (!/^[a-f0-9]{64}$/u.test(target.sha256)) throw new TypeError("target.sha256 must be 64 lowercase hex chars");
    const sel = this.#registry.select(target, requested);
    const metaProfile = sel.entry.meta.profile();
    const digest = profileDigest({ id: sel.entry.meta.id, version: sel.entry.meta.version, settings: metaProfile.settings });
    const cur = this.#active;
    if (cur) {
      if (cur.binding.target_sha256 === target.sha256 && cur.binding.provider_id === sel.entry.meta.id && cur.binding.profile_digest === digest) {
        return { binding: cur.binding, evidence: cur.evidence, reused: true };
      }
      throw new SessionStateError(
        `Session already bound to ${cur.binding.provider_id} for target ${cur.binding.target_sha256.slice(0, 12)}; close() before opening a different target, provider or profile`,
      );
    }

    const acquired: { provider: AnalysisProvider; release: () => void }[] = [];
    const acquire = (e: { meta: AnalysisProvider; factory: (() => AnalysisProvider) | null }) => {
      if (e.factory) { const p = e.factory(); const a = { provider: p, release: () => {} }; acquired.push(a); return a; }
      if (busyInstances.has(e.meta)) throw new SessionStateError(`Provider instance "${e.meta.id}" is in use by another session; register a factory for concurrent sessions`);
      busyInstances.add(e.meta);
      const a = { provider: e.meta, release: () => busyInstances.delete(e.meta) };
      acquired.push(a);
      return a;
    };
    const opened: AnalysisProvider[] = [];
    const rollback = async () => {
      for (const p of opened.reverse()) { try { await p.close(); } catch { /* best effort */ } }
      for (const a of acquired) a.release();
    };
    try {
      const deep = acquire(sel.entry);
      try { await deep.provider.open(target); } catch (e) {
        throw new ProviderSelectionError("open_failed", sel.entry.meta.id, `Provider "${sel.entry.meta.id}" failed to open target (no fallback): ${(e as Error).message}`);
      }
      opened.push(deep.provider);
      const aux: Active["aux"] = [];
      for (const ae of this.#registry.auxiliary()) {
        if (ae.meta.supports(target).status !== "supported") continue;
        const a = acquire(ae);
        await a.provider.open(target);
        opened.push(a.provider);
        aux.push(a);
      }
      const routes = new Map<string, AnalysisProvider>();
      for (const a of aux) for (const o of a.provider.operations()) routes.set(o, a.provider);
      for (const o of deep.provider.operations()) {
        if (routes.has(o)) throw new SessionStateError(`Operation "${o}" is claimed by both the deep and an auxiliary provider`);
      }
      const binding: AnalysisProviderBinding = deepFreeze({
        provider_id: sel.entry.meta.id,
        provider_name: sel.entry.meta.name,
        provider_version: sel.entry.meta.version,
        target_sha256: target.sha256,
        profile: structuredClone(metaProfile),
        profile_digest: digest,
        selection: sel.source,
        operations: [...deep.provider.operations()].sort(cmp),
        auxiliary_providers: aux.map((a) => ({ id: a.provider.id, version: a.provider.version, operations: [...a.provider.operations()].sort(cmp) })).sort((x, y) => cmp(x.id, y.id)),
      });
      const evidence = createEvidence({
        subject: { name: target.name ?? target.path, digest: { sha256: target.sha256 }, local_path: target.path, format: target.format ?? null, architecture: target.architecture ?? null },
        provider: ROUTER_PROVIDER,
        analysis_profile: { provider_id: binding.provider_id, profile_digest: binding.profile_digest, settings: binding.profile.settings },
        predicate_type: "analysis_provider_binding",
        operation: "bind_provider",
        parameters: { requested_provider: requested },
        normalized_result: { analysis_provider_binding: binding },
        confidence: "observed",
        authority: "shipped-artifact",
        limitations: ["Records which provider/profile will answer for this target; it says nothing about analysis completeness."],
      });
      this.#active = { target: { ...target }, binding, evidence, deep: deep.provider, deepRelease: deep.release, aux, routes, snapshot: null };
      return { binding, evidence, reused: false };
    } catch (e) {
      await rollback();
      throw e;
    }
  }

  close(): Promise<void> {
    return this.#serialize(async () => {
      const a = this.#active;
      if (!a) return;
      this.#active = null;
      const errs: unknown[] = [];
      for (const p of [...a.aux.map((x) => x.provider), a.deep]) {
        try { await p.close(); } catch (e) { errs.push(e); }
      }
      a.deepRelease();
      for (const x of a.aux) x.release();
      if (errs.length) throw new AggregateError(errs, "provider close failed");
    });
  }

  /** Route by operation name: auxiliary table first (disjoint from deep by construction), else the deep binding. */
  async call(operation: string, args: JsonObject = {}): Promise<unknown> {
    const a = this.#active;
    if (!a) throw new SessionStateError("No open binary; call open() first");
    const aux = a.routes.get(operation);
    if (aux) return aux.call(operation, args);
    if (a.binding.operations.includes(operation)) return a.deep.call(operation, args);
    throw new OperationRoutingError(`Operation "${operation}" is not provided by the bound provider ${a.binding.provider_id} or any auxiliary provider (no fallback to other deep providers)`);
  }

  capabilities(): CapabilityEntry[] {
    return this.#registry.inventory(this.#active?.target, this.#active?.binding.provider_id);
  }

  snapshotIdentity(): SnapshotIdentity {
    const b = this.#active?.binding;
    if (!b) throw new SessionStateError("No open binary");
    return { target_sha256: b.target_sha256, provider_id: b.provider_id, profile_digest: b.profile_digest };
  }

  /** Import a snapshot; target sha256, concrete provider id and profile digest must all match the binding exactly. */
  importSnapshot(snapshot: AnalysisSnapshot): void {
    const b = this.#active?.binding;
    if (!b) throw new SessionStateError("No open binary");
    const bad: string[] = [];
    if (snapshot.target_sha256 !== b.target_sha256) bad.push("target sha256");
    if (snapshot.provider_id !== b.provider_id) bad.push(`provider (${snapshot.provider_id} != ${b.provider_id})`);
    if (snapshot.profile_digest !== b.profile_digest) bad.push("profile digest");
    if (bad.length) throw new SnapshotIdentityError(bad);
    this.#active!.snapshot = deepFreeze(structuredClone(snapshot));
  }
  snapshot(): AnalysisSnapshot | null { return this.#active?.snapshot ?? null; }
}
