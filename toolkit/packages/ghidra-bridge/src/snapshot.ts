export interface Range { start: string; end: string }
export interface CallRef { entry: string; name: string }
export interface GhidraFunction {
  entry: string; name: string; external: boolean; thunk: boolean; thunk_target: string | null;
  signature: string; calling_convention: string | null; namespace: string;
  body: Range[]; callers: CallRef[]; callees: CallRef[];
  call_sites: { site: string; target: string | null; indirect: boolean; unresolved: boolean }[];
  has_unresolved_indirect_calls: boolean;
  locals: { name: string; type: string; length: number; storage: string; parameter: boolean; stack_offset: number; stack: boolean }[];
}
export interface GhidraString {
  address: string; value: string; encoding: string; data_type: string; length: number;
  xrefs: { from: string; type: string; function: string | null; function_entry: string | null }[];
}
export interface GhidraSnapshot {
  schema: "rtk-ghidra-snapshot/1";
  ghidra_version: string;
  program: {
    name: string; format: string; language_id: string; processor: string; endian: string; pointer_size: number;
    compiler_spec: string; image_base: string | null; executable_sha256: string | null;
    entry_points: { address: string; name: string | null }[];
  };
  memory_blocks: { name: string; start: string; end: string; size: number; read: boolean; write: boolean; execute: boolean; initialized: boolean; overlay: boolean; volatile: boolean }[];
  functions: GhidraFunction[];
  strings: GhidraString[];
  strings_truncated: boolean;
  externals: { library: string; label: string; original_name: string | null; address: string | null; function: boolean }[];
  symbols: { name: string; address: string | null; type: string; source: string; namespace: string; primary: boolean; external: boolean }[];
  symbols_truncated: boolean;
  decompiled: { entry: string; name: string; code: string | null; high_locals: { name: string; type: string | null; size: number; parameter: boolean }[]; error: string | null; truncated: boolean }[];
  decompile_ms: number;
  warnings: string[];
  /** Added by the Node wrapper (not by the Java script). */
  source: { path: string; sha256: string; size: number; elapsed_ms: number; options: Record<string, unknown> };
}
