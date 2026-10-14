export interface Quotas {
  /** max entries per archive (listing is cut off and flagged fatal when exceeded) */
  maxEntries: number;
  /** max total decompressed bytes across the whole inspection/extraction incl. nested layers */
  maxTotalSize: number;
  /** max decompressed bytes of one entry */
  maxEntrySize: number;
  /** max decompressed/compressed ratio per entry (checked once an entry has produced > ratioMinBytes) */
  maxRatio: number;
  ratioMinBytes: number;
  /** nested archive depth (0 = top level) */
  maxDepth: number;
  maxNameLength: number;
  /** max bytes of a nested archive buffered for recursive inspection */
  maxNestedBytes: number;
}
export const DEFAULT_QUOTAS: Quotas = {
  maxEntries: 10_000, maxTotalSize: 1024 ** 3, maxEntrySize: 512 * 1024 ** 2, maxRatio: 100, ratioMinBytes: 64 * 1024,
  maxDepth: 3, maxNameLength: 4096, maxNestedBytes: 64 * 1024 ** 2,
};
export const resolveQuotas = (q?: Partial<Quotas>): Quotas => ({ ...DEFAULT_QUOTAS, ...(q ?? {}) });

export type Severity = "info" | "low" | "medium" | "high";
/** Machine-readable anomaly codes. `blocking` ones make extraction refuse the entry (strict: whole extraction). `fatal` ones are quota breaches that stop everything. */
export const ANOMALY_CODES = {
  "path-traversal": { severity: "high", blocking: true },
  "absolute-path": { severity: "high", blocking: true },
  "drive-letter": { severity: "high", blocking: true },
  "control-char": { severity: "medium", blocking: true },
  "empty-name": { severity: "medium", blocking: true },
  "name-too-long": { severity: "medium", blocking: true },
  "backslash-separator": { severity: "low", blocking: false },
  "symlink": { severity: "medium", blocking: true },
  "symlink-escape": { severity: "high", blocking: true },
  "symlink-through": { severity: "high", blocking: true },
  "hardlink": { severity: "medium", blocking: true },
  "hardlink-escape": { severity: "high", blocking: true },
  "device-node": { severity: "high", blocking: true },
  "special-file": { severity: "medium", blocking: true },
  "special-mode": { severity: "low", blocking: false },
  "duplicate-name": { severity: "medium", blocking: true },
  "case-collision": { severity: "medium", blocking: true },
  "encrypted-entry": { severity: "medium", blocking: true },
  "unsupported-compression": { severity: "medium", blocking: true },
  "size-mismatch": { severity: "high", blocking: true },
  "crc-mismatch": { severity: "medium", blocking: true },
  "integrity-mismatch": { severity: "high", blocking: true },
  "corrupt-data": { severity: "medium", blocking: true },
  "local-header-mismatch": { severity: "high", blocking: true },
  "entry-count-mismatch": { severity: "medium", blocking: false },
  "corrupt-archive": { severity: "medium", blocking: false },
  "asar-offset-out-of-range": { severity: "high", blocking: true },
  "asar-overlap": { severity: "high", blocking: true },
  "asar-unpacked-external": { severity: "info", blocking: true },
  "would-overwrite": { severity: "medium", blocking: true },
  "path-conflict": { severity: "medium", blocking: true },
  "entry-count-exceeded": { severity: "high", blocking: true },
  "total-size-exceeded": { severity: "high", blocking: true },
  "entry-size-exceeded": { severity: "high", blocking: true },
  "ratio-exceeded": { severity: "high", blocking: true },
  "depth-exceeded": { severity: "high", blocking: false },
  "nested-too-large": { severity: "low", blocking: false },
  "unsupported-format": { severity: "medium", blocking: true },
} as const satisfies Record<string, { severity: Severity; blocking: boolean }>;
export type AnomalyCode = keyof typeof ANOMALY_CODES;
/** Quota breaches: abort the whole operation (and clean up) regardless of policy. */
export const FATAL_CODES: readonly AnomalyCode[] = ["entry-count-exceeded", "total-size-exceeded", "entry-size-exceeded", "ratio-exceeded"];

export interface Anomaly { code: AnomalyCode; severity: Severity; entry: string | null; detail: string; archive: string; fatal: boolean }

export type EntryType = "file" | "dir" | "symlink" | "hardlink" | "device" | "fifo" | "other";

/** Reader-level view of an entry. `stream()` yields DECOMPRESSED bytes, unbounded: the consumer enforces quotas while reading. */
export interface RawEntry {
  index: number;
  name: string;
  type: EntryType;
  declaredSize: number | null;
  compressedSize: number | null;
  mode: number | null;
  linkTarget: string | null;
  encrypted: boolean;
  crc32: number | null;
  method: string;
  /** codes found by the reader itself (e.g. encrypted-entry, local-header-mismatch) */
  flags: { code: AnomalyCode; detail: string }[];
  expectedSha256?: string;
  stream: (() => AsyncGenerator<Buffer>) | null;
}

export class QuotaError extends Error { code: AnomalyCode; constructor(code: AnomalyCode, detail: string) { super(detail); this.code = code; } }
export class EntryError extends Error { code: AnomalyCode; constructor(code: AnomalyCode, detail: string) { super(detail); this.code = code; } }
export class NotImplementedError extends Error {}
