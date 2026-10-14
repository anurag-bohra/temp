import type { AnalysisProvider, CapabilityEntry, ProviderEntry, Target } from "./types.ts";
import { ProviderSelectionError, RegistryConfigError } from "./errors.ts";

const cmp = (a: string, b: string): number => (a < b ? -1 : a > b ? 1 : 0);

export interface RegistryEntry {
  /** Metadata instance (the instance itself when no factory was given). */
  readonly meta: AnalysisProvider;
  readonly factory: (() => AnalysisProvider) | null;
}

export interface Selection {
  readonly entry: RegistryEntry;
  readonly source: "auto" | "explicit";
}

/**
 * Deterministic provider registry. Registration order never affects selection:
 * candidates are sorted by id. There is no priority and no fallback: `auto`
 * picks the first (by id) deep provider that supports the target; an explicit
 * id that is unknown/unsupported/unavailable is an error.
 */
export class Registry {
  readonly #entries: readonly RegistryEntry[];

  constructor(providers: readonly ProviderEntry[]) {
    const seen = new Set<string>();
    const entries: RegistryEntry[] = [];
    for (const p of providers) {
      const factory = typeof p === "function" ? p : null;
      const meta = factory ? factory() : p as AnalysisProvider;
      if (!/^[a-z0-9][a-z0-9._-]*$/u.test(meta.id)) throw new RegistryConfigError(`Invalid provider id: ${meta.id}`);
      if (meta.id === "auto") throw new RegistryConfigError(`Provider id "auto" is reserved`);
      if (seen.has(meta.id)) throw new RegistryConfigError(`Duplicate provider id: ${meta.id}`);
      seen.add(meta.id);
      const ops = meta.operations();
      if (new Set(ops).size !== ops.length) throw new RegistryConfigError(`Provider ${meta.id} declares an operation more than once`);
      entries.push({ meta, factory });
    }
    entries.sort((a, b) => cmp(a.meta.id, b.meta.id));
    // Auxiliary operations must be disjoint from each other and from EVERY deep provider's operations.
    const owner = new Map<string, string>();
    const deepOps = new Set<string>();
    for (const e of entries) if (e.meta.kind === "deep") for (const o of e.meta.operations()) deepOps.add(o);
    for (const e of entries) {
      if (e.meta.kind !== "auxiliary") continue;
      for (const o of e.meta.operations()) {
        if (deepOps.has(o)) throw new RegistryConfigError(`Auxiliary provider ${e.meta.id} operation "${o}" collides with a deep provider operation; auxiliaries never override the deep binding`);
        const prev = owner.get(o);
        if (prev !== undefined) throw new RegistryConfigError(`Auxiliary providers ${prev} and ${e.meta.id} both declare operation "${o}"`);
        owner.set(o, e.meta.id);
      }
    }
    this.#entries = Object.freeze(entries);
  }

  /** Candidates in canonical (id) order. */
  candidates(): readonly RegistryEntry[] { return this.#entries; }
  deep(): readonly RegistryEntry[] { return this.#entries.filter((e) => e.meta.kind === "deep"); }
  auxiliary(): readonly RegistryEntry[] { return this.#entries.filter((e) => e.meta.kind === "auxiliary"); }
  identities(): readonly { id: string; name: string; version: string; kind: string }[] {
    return this.#entries.map((e) => ({ id: e.meta.id, name: e.meta.name, version: e.meta.version, kind: e.meta.kind }));
  }

  select(target: Target, requested: string = "auto"): Selection {
    if (requested === "auto") {
      for (const e of this.deep()) {
        if (e.meta.supports(target).status === "supported") return { entry: e, source: "auto" };
      }
      throw new ProviderSelectionError("no_supported_provider", "auto", "No deep provider supports this target");
    }
    const e = this.#entries.find((x) => x.meta.id === requested);
    if (!e) throw new ProviderSelectionError("unknown_provider", requested, `Unknown provider "${requested}"`);
    if (e.meta.kind !== "deep") throw new ProviderSelectionError("not_deep_provider", requested, `Provider "${requested}" is auxiliary and cannot be selected as the deep provider`);
    const s = e.meta.supports(target);
    if (s.status === "unavailable") throw new ProviderSelectionError("provider_unavailable", requested, `Provider "${requested}" is unavailable: ${s.reason} (no fallback)`);
    if (s.status === "unsupported") throw new ProviderSelectionError("unsupported_target", requested, `Provider "${requested}" does not support this target: ${s.reason} (no fallback)`);
    return { entry: e, source: "explicit" };
  }

  /** Capability inventory; with a target, includes per-provider support; `selectedId` marks the bound deep provider. */
  inventory(target?: Target, selectedId?: string): CapabilityEntry[] {
    return this.#entries.map((e) => ({
      provider_id: e.meta.id,
      name: e.meta.name,
      version: e.meta.version,
      kind: e.meta.kind,
      support: target ? e.meta.supports(target) : { status: "unknown" as const, reason: "no target supplied" },
      selected: e.meta.id === selectedId,
      operations: [...e.meta.operations()].sort(cmp),
    }));
  }
}
