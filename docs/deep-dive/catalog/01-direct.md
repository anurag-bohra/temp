# Tool family: Native inspection (official-proxy 'direct' family)

Generated mechanically from `.cache/mcp-tool-catalog.json` (produced by `scripts/generate-mcp-tool-catalog.mjs`, which registers every tool through the MCP SDK and exports the advertised JSON Schema 2020-12 input/output schemas) and `docs/public/product-catalog.json` (family `direct`, surface `official-proxy`, 41 tools). Input schemas below are **verbatim**. Output schemas are verbatim in `tool-specs/<tool>.json` (field `outputSchema`) because several exceed 100 KB; the complete per-tool spec (description, effects, annotations, inputSchema, outputSchema) is in that file.

| Tool | Kind | Session? | Providers advertising it | CLI command |
|---|---|---|---|---|
| [`address_name`](#addressname) | official-proxy | no | ghidra, hopper | — |
| [`address_to_file_offset`](#addresstofileoffset) | official-proxy | no | ghidra, hopper | `rea address-to-file-offset` |
| [`annotate_native_function`](#annotatenativefunction) | official-proxy | no | ghidra | `rea annotate-native-function` |
| [`comment`](#comment) | official-proxy | no | hopper | — |
| [`current_address`](#currentaddress) | official-proxy | no | hopper | — |
| [`current_document`](#currentdocument) | official-proxy | no | hopper | — |
| [`current_procedure`](#currentprocedure) | official-proxy | no | hopper | — |
| [`goto_address`](#gotoaddress) | official-proxy | no | hopper | — |
| [`inline_comment`](#inlinecomment) | official-proxy | no | hopper | — |
| [`inspect_native_data_type`](#inspectnativedatatype) | official-proxy | no | ghidra | `rea inspect-native-data-type` |
| [`inspect_native_instruction`](#inspectnativeinstruction) | official-proxy | no | ghidra | `rea inspect-native-instruction` |
| [`inspect_native_load_image`](#inspectnativeloadimage) | official-proxy | no | ghidra | `rea inspect-native-load-image` |
| [`list_bookmarks`](#listbookmarks) | official-proxy | no | hopper | — |
| [`list_documents`](#listdocuments) | official-proxy | no | ghidra, hopper, ida | — |
| [`list_names`](#listnames) | official-proxy | no | ghidra, hopper | — |
| [`list_procedures`](#listprocedures) | official-proxy | no | ghidra, hopper, ida | — |
| [`list_segments`](#listsegments) | official-proxy | no | ghidra, hopper | — |
| [`list_strings`](#liststrings) | official-proxy | no | ghidra, hopper, ida | — |
| [`next_address`](#nextaddress) | official-proxy | no | hopper | — |
| [`prev_address`](#prevaddress) | official-proxy | no | hopper | — |
| [`procedure_address`](#procedureaddress) | official-proxy | no | ghidra, hopper, ida | — |
| [`procedure_assembly`](#procedureassembly) | official-proxy | no | ghidra, hopper, ida | — |
| [`procedure_callees`](#procedurecallees) | official-proxy | no | ghidra, hopper, ida | — |
| [`procedure_callers`](#procedurecallers) | official-proxy | no | ghidra, hopper, ida | — |
| [`procedure_info`](#procedureinfo) | official-proxy | no | ghidra, hopper | — |
| [`procedure_pseudo_code`](#procedurepseudocode) | official-proxy | no | ghidra, hopper, ida | — |
| [`procedure_references`](#procedurereferences) | official-proxy | no | ghidra, hopper | — |
| [`read_bytes`](#readbytes) | official-proxy | no | ghidra, hopper | `rea read-bytes` |
| [`read_function_instructions`](#readfunctioninstructions) | official-proxy | no | ghidra, hopper, ida | — |
| [`resolve_containing_procedure`](#resolvecontainingprocedure) | official-proxy | no | ghidra, hopper, ida | — |
| [`resolve_native_call_targets`](#resolvenativecalltargets) | official-proxy | no | ghidra | `rea resolve-native-call-targets` |
| [`search_bytes`](#searchbytes) | official-proxy | no | ghidra | `rea search-bytes` |
| [`search_procedures`](#searchprocedures) | official-proxy | no | ghidra, hopper, ida | — |
| [`search_strings`](#searchstrings) | official-proxy | no | ghidra, hopper, ida | — |
| [`set_address_name`](#setaddressname) | official-proxy | no | ghidra, hopper | — |
| [`set_addresses_names`](#setaddressesnames) | official-proxy | no | ghidra, hopper | — |
| [`set_bookmark`](#setbookmark) | official-proxy | no | hopper | — |
| [`set_comment`](#setcomment) | official-proxy | no | hopper | — |
| [`set_inline_comment`](#setinlinecomment) | official-proxy | no | hopper | — |
| [`unset_bookmark`](#unsetbookmark) | official-proxy | no | hopper | — |
| [`xrefs`](#xrefs) | official-proxy | no | ghidra, hopper, ida | `rea xrefs` |

## address_name

<a id="addressname"></a>

**Title:** Address Name  
**Kind:** `official-proxy` · **Requires session:** false · **analysisOperation:** address_name  
**Providers:** ghidra, hopper  
**Effects set (true flags):** mutatesSession  
**MCP annotations:** `{"destructiveHint":false,"idempotentHint":true,"openWorldHint":false,"readOnlyHint":false}`

**Description (verbatim, as advertised to the agent):**

> Resolve the primary analyzed name at a code or data address. Headless providers require an explicit address; GUI providers may default to their current cursor. Null means the provider has no primary name at that address.

**Input schema (verbatim, JSON Schema 2020-12):**

<details><summary>inputSchema for address_name</summary>

```json
{
  "$defs": {
    "__schema0": {
      "$ref": "#/$defs/__schema1",
      "description": "The active target's provider document name; use open_binary to switch targets"
    },
    "__schema1": {
      "type": "string"
    },
    "__schema2": {
      "description": "A provider-normalized address; default memory uses 0x-prefixed hexadecimal",
      "type": "string"
    }
  },
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "additionalProperties": false,
  "examples": [
    {}
  ],
  "properties": {
    "address": {
      "$ref": "#/$defs/__schema2",
      "description": "A provider-normalized address; default memory uses 0x-prefixed hexadecimal"
    },
    "document": {
      "$ref": "#/$defs/__schema0",
      "description": "The active target's provider document name; use open_binary to switch targets"
    }
  },
  "type": "object"
}
```

</details>

**Output schema:** see [`tool-specs/address_name.json`](../tool-specs/address_name.json) (`outputSchema`).

---

## address_to_file_offset

<a id="addresstofileoffset"></a>

**Title:** Address To File Offset  
**Kind:** `official-proxy` · **Requires session:** false · **analysisOperation:** address_to_file_offset  
**Providers:** ghidra, hopper  
**Effects set (true flags):** mutatesSession  
**MCP annotations:** `{"destructiveHint":false,"idempotentHint":true,"openWorldHint":false,"readOnlyHint":false}`

**Description (verbatim, as advertised to the agent):**

> Map one provider-normalized virtual address to its original nonnegative file offset. Hopper verifies the original bytes against the selected executable digest and translates FAT image-relative offsets using the loaded header. Results preserve the provider coordinate, image base, and source path. Unmapped addresses fail explicitly; changed or unavailable sources return typed errors retaining native mapping facts as partial evidence.

**Input schema (verbatim, JSON Schema 2020-12):**

<details><summary>inputSchema for address_to_file_offset</summary>

```json
{
  "$defs": {
    "__schema0": {
      "description": "A provider-normalized address; default memory uses 0x-prefixed hexadecimal",
      "type": "string"
    },
    "__schema1": {
      "$ref": "#/$defs/__schema2",
      "description": "The active target's provider document name; use open_binary to switch targets"
    },
    "__schema2": {
      "type": "string"
    }
  },
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "additionalProperties": false,
  "examples": [
    {
      "address": "0x1000"
    }
  ],
  "properties": {
    "address": {
      "$ref": "#/$defs/__schema0",
      "description": "A provider-normalized address; default memory uses 0x-prefixed hexadecimal"
    },
    "document": {
      "$ref": "#/$defs/__schema1",
      "description": "The active target's provider document name; use open_binary to switch targets"
    }
  },
  "required": [
    "address"
  ],
  "type": "object"
}
```

</details>

**Output schema:** see [`tool-specs/address_to_file_offset.json`](../tool-specs/address_to_file_offset.json) (`outputSchema`).

---

## annotate_native_function

<a id="annotatenativefunction"></a>

**Title:** Annotate Native Function  
**Kind:** `official-proxy` · **Requires session:** false · **analysisOperation:** annotate_native_function  
**Providers:** ghidra  
**Effects set (true flags):** launchesProcess, mayDiscardData, mutatesSession, mutatesTarget, writesFilesystem  
**MCP annotations:** `{"destructiveHint":true,"idempotentHint":true,"openWorldHint":true,"readOnlyHint":false}`

**Description (verbatim, as advertised to the agent):**

> Atomically update one function name and/or entry comments, read them back, and return a refreshed complete function dossier. Ghidra changes its ephemeral session analysis database only; original executable bytes remain unchanged. Empty comment text clears that comment. Edits remain available to subsequent MCP calls until close; CLI returns the updated dossier before discarding its session. Invalid edits roll back the entire operation. Windows P0 and providers without this capability are unsupported.

**Input schema (verbatim, JSON Schema 2020-12):**

<details><summary>inputSchema for annotate_native_function</summary>

```json
{
  "$defs": {
    "__schema0": {
      "minLength": 1,
      "type": "string"
    },
    "__schema1": {
      "minLength": 1,
      "type": "string"
    },
    "__schema2": {
      "$ref": "#/$defs/__schema3",
      "description": "Regular entry comment; empty text clears it"
    },
    "__schema3": {
      "type": "string"
    },
    "__schema4": {
      "$ref": "#/$defs/__schema5",
      "description": "Inline entry comment; empty text clears it"
    },
    "__schema5": {
      "type": "string"
    }
  },
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "additionalProperties": false,
  "examples": [
    {
      "comment": "Analyst observation",
      "name": "entry",
      "procedure": "0x10100"
    }
  ],
  "properties": {
    "comment": {
      "$ref": "#/$defs/__schema2",
      "description": "Regular entry comment; empty text clears it"
    },
    "inline_comment": {
      "$ref": "#/$defs/__schema4",
      "description": "Inline entry comment; empty text clears it"
    },
    "name": {
      "$ref": "#/$defs/__schema1",
      "description": "Exact name used by this operation."
    },
    "procedure": {
      "$ref": "#/$defs/__schema0"
    }
  },
  "required": [
    "procedure"
  ],
  "type": "object"
}
```

</details>

**Output schema:** see [`tool-specs/annotate_native_function.json`](../tool-specs/annotate_native_function.json) (`outputSchema`).

---

## comment

<a id="comment"></a>

**Title:** Comment  
**Kind:** `official-proxy` · **Requires session:** false · **analysisOperation:** comment  
**Providers:** hopper  
**Effects set (true flags):** mutatesSession  
**MCP annotations:** `{"destructiveHint":false,"idempotentHint":true,"openWorldHint":false,"readOnlyHint":false}`

**Description (verbatim, as advertised to the agent):**

> Read the regular analysis comment at an address, defaulting to the current cursor. This is read-only and returns null when no comment exists; use set_comment to persist a finding.

**Input schema (verbatim, JSON Schema 2020-12):**

<details><summary>inputSchema for comment</summary>

```json
{
  "$defs": {
    "__schema0": {
      "$ref": "#/$defs/__schema1",
      "description": "The active target's provider document name; use open_binary to switch targets"
    },
    "__schema1": {
      "type": "string"
    },
    "__schema2": {
      "description": "A provider-normalized address; default memory uses 0x-prefixed hexadecimal",
      "type": "string"
    }
  },
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "additionalProperties": false,
  "examples": [
    {}
  ],
  "properties": {
    "address": {
      "$ref": "#/$defs/__schema2",
      "description": "A provider-normalized address; default memory uses 0x-prefixed hexadecimal"
    },
    "document": {
      "$ref": "#/$defs/__schema0",
      "description": "The active target's provider document name; use open_binary to switch targets"
    }
  },
  "type": "object"
}
```

</details>

**Output schema:** see [`tool-specs/comment.json`](../tool-specs/comment.json) (`outputSchema`).

---

## current_address

<a id="currentaddress"></a>

**Title:** Current Address  
**Kind:** `official-proxy` · **Requires session:** false · **analysisOperation:** current_address  
**Providers:** hopper  
**Effects set (true flags):** mutatesSession  
**MCP annotations:** `{"destructiveHint":false,"idempotentHint":true,"openWorldHint":false,"readOnlyHint":false}`

**Description (verbatim, as advertised to the agent):**

> Return Hopper's current cursor address for the selected document. Use only for interactive navigation state; prefer explicit addresses in reproducible investigations.

**Input schema (verbatim, JSON Schema 2020-12):**

<details><summary>inputSchema for current_address</summary>

```json
{
  "$defs": {
    "__schema0": {
      "$ref": "#/$defs/__schema1",
      "description": "The active target's provider document name; use open_binary to switch targets"
    },
    "__schema1": {
      "type": "string"
    }
  },
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "additionalProperties": false,
  "examples": [
    {}
  ],
  "properties": {
    "document": {
      "$ref": "#/$defs/__schema0",
      "description": "The active target's provider document name; use open_binary to switch targets"
    }
  },
  "type": "object"
}
```

</details>

**Output schema:** see [`tool-specs/current_address.json`](../tool-specs/current_address.json) (`outputSchema`).

---

## current_document

<a id="currentdocument"></a>

**Title:** Current Document  
**Kind:** `official-proxy` · **Requires session:** false · **analysisOperation:** current_document  
**Providers:** hopper  
**Effects set (true flags):** mutatesSession  
**MCP annotations:** `{"destructiveHint":false,"idempotentHint":true,"openWorldHint":false,"readOnlyHint":false}`

**Description (verbatim, as advertised to the agent):**

> Return the document currently selected by REA's Hopper bridge.

**Input schema (verbatim, JSON Schema 2020-12):**

<details><summary>inputSchema for current_document</summary>

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "additionalProperties": false,
  "examples": [
    {}
  ],
  "properties": {},
  "type": "object"
}
```

</details>

**Output schema:** see [`tool-specs/current_document.json`](../tool-specs/current_document.json) (`outputSchema`).

---

## current_procedure

<a id="currentprocedure"></a>

**Title:** Current Procedure  
**Kind:** `official-proxy` · **Requires session:** false · **analysisOperation:** current_procedure  
**Providers:** hopper  
**Effects set (true flags):** mutatesSession  
**MCP annotations:** `{"destructiveHint":false,"idempotentHint":true,"openWorldHint":false,"readOnlyHint":false}`

**Description (verbatim, as advertised to the agent):**

> Return the analyzed procedure containing Hopper's current cursor. This uses GUI cursor state and is not a procedure-name lookup.

**Input schema (verbatim, JSON Schema 2020-12):**

<details><summary>inputSchema for current_procedure</summary>

```json
{
  "$defs": {
    "__schema0": {
      "$ref": "#/$defs/__schema1",
      "description": "The active target's provider document name; use open_binary to switch targets"
    },
    "__schema1": {
      "type": "string"
    }
  },
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "additionalProperties": false,
  "examples": [
    {}
  ],
  "properties": {
    "document": {
      "$ref": "#/$defs/__schema0",
      "description": "The active target's provider document name; use open_binary to switch targets"
    }
  },
  "type": "object"
}
```

</details>

**Output schema:** see [`tool-specs/current_procedure.json`](../tool-specs/current_procedure.json) (`outputSchema`).

---

## goto_address

<a id="gotoaddress"></a>

**Title:** Goto Address  
**Kind:** `official-proxy` · **Requires session:** false · **analysisOperation:** goto_address  
**Providers:** hopper  
**Effects set (true flags):** changesUiState, mutatesSession  
**MCP annotations:** `{"destructiveHint":false,"idempotentHint":true,"openWorldHint":false,"readOnlyHint":false}`

**Description (verbatim, as advertised to the agent):**

> Move Hopper's GUI cursor to a mapped address and return the observed cursor address. Interior coordinates snap to the containing analyzed object's start. Unmapped destinations fail without moving the cursor. This changes navigation state but not analysis data; use explicit-address tools for headless workflows.

**Input schema (verbatim, JSON Schema 2020-12):**

<details><summary>inputSchema for goto_address</summary>

```json
{
  "$defs": {
    "__schema0": {
      "description": "A provider-normalized address; default memory uses 0x-prefixed hexadecimal",
      "type": "string"
    },
    "__schema1": {
      "$ref": "#/$defs/__schema2",
      "description": "The active target's provider document name; use open_binary to switch targets"
    },
    "__schema2": {
      "type": "string"
    }
  },
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "additionalProperties": false,
  "examples": [
    {
      "address": "0x1000"
    }
  ],
  "properties": {
    "address": {
      "$ref": "#/$defs/__schema0",
      "description": "A provider-normalized address; default memory uses 0x-prefixed hexadecimal"
    },
    "document": {
      "$ref": "#/$defs/__schema1",
      "description": "The active target's provider document name; use open_binary to switch targets"
    }
  },
  "required": [
    "address"
  ],
  "type": "object"
}
```

</details>

**Output schema:** see [`tool-specs/goto_address.json`](../tool-specs/goto_address.json) (`outputSchema`).

---

## inline_comment

<a id="inlinecomment"></a>

**Title:** Inline Comment  
**Kind:** `official-proxy` · **Requires session:** false · **analysisOperation:** inline_comment  
**Providers:** hopper  
**Effects set (true flags):** mutatesSession  
**MCP annotations:** `{"destructiveHint":false,"idempotentHint":true,"openWorldHint":false,"readOnlyHint":false}`

**Description (verbatim, as advertised to the agent):**

> Read the inline instruction comment at an address, defaulting to the current cursor. Returns null when absent; use set_inline_comment to write one.

**Input schema (verbatim, JSON Schema 2020-12):**

<details><summary>inputSchema for inline_comment</summary>

```json
{
  "$defs": {
    "__schema0": {
      "$ref": "#/$defs/__schema1",
      "description": "The active target's provider document name; use open_binary to switch targets"
    },
    "__schema1": {
      "type": "string"
    },
    "__schema2": {
      "description": "A provider-normalized address; default memory uses 0x-prefixed hexadecimal",
      "type": "string"
    }
  },
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "additionalProperties": false,
  "examples": [
    {}
  ],
  "properties": {
    "address": {
      "$ref": "#/$defs/__schema2",
      "description": "A provider-normalized address; default memory uses 0x-prefixed hexadecimal"
    },
    "document": {
      "$ref": "#/$defs/__schema0",
      "description": "The active target's provider document name; use open_binary to switch targets"
    }
  },
  "type": "object"
}
```

</details>

**Output schema:** see [`tool-specs/inline_comment.json`](../tool-specs/inline_comment.json) (`outputSchema`).

---

## inspect_native_data_type

<a id="inspectnativedatatype"></a>

**Title:** Inspect Native Data Type  
**Kind:** `official-proxy` · **Requires session:** false · **analysisOperation:** inspect_native_data_type  
**Providers:** ghidra  
**Effects set (true flags):** mutatesSession  
**MCP annotations:** `{"destructiveHint":false,"idempotentHint":true,"openWorldHint":false,"readOnlyHint":false}`

**Description (verbatim, as advertised to the agent):**

> Inspect one recovered type by exact database category path or defined typed data address. Returns observed size, alignment, packing, fields, bitfields, enum values, and child type identities; source-level authority and flexible-tail semantics remain unknown unless substantiated.

**Input schema (verbatim, JSON Schema 2020-12):**

<details><summary>inputSchema for inspect_native_data_type</summary>

```json
{
  "$defs": {
    "__schema0": {
      "minLength": 1,
      "type": "string"
    },
    "__schema1": {
      "minLength": 1,
      "type": "string"
    },
    "__schema2": {
      "type": "string"
    }
  },
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "additionalProperties": false,
  "examples": [
    {
      "type": "/MyStruct"
    }
  ],
  "properties": {
    "address": {
      "$ref": "#/$defs/__schema1"
    },
    "document": {
      "$ref": "#/$defs/__schema2",
      "description": "Exact provider document or program identity."
    },
    "type": {
      "$ref": "#/$defs/__schema0"
    }
  },
  "type": "object"
}
```

</details>

**Output schema:** see [`tool-specs/inspect_native_data_type.json`](../tool-specs/inspect_native_data_type.json) (`outputSchema`).

---

## inspect_native_instruction

<a id="inspectnativeinstruction"></a>

**Title:** Inspect Native Instruction  
**Kind:** `official-proxy` · **Requires session:** false · **analysisOperation:** inspect_native_instruction  
**Providers:** ghidra  
**Effects set (true flags):** mutatesSession  
**MCP annotations:** `{"destructiveHint":false,"idempotentHint":true,"openWorldHint":false,"readOnlyHint":false}`

**Description (verbatim, as advertised to the agent):**

> Inspect one exact code or data address: decoded bytes, mnemonic, ordered operand tokens, flow, outgoing instruction references and typed incoming references where available. Incoming references preserve source, access kind, operand index and analysis provenance even at data addresses; they do not prove runtime access. Memory addressing decomposition is unavailable when the provider supplies only tokens. Data, interior instruction addresses and undecodable bytes are distinct outcomes.

**Input schema (verbatim, JSON Schema 2020-12):**

<details><summary>inputSchema for inspect_native_instruction</summary>

```json
{
  "$defs": {
    "__schema0": {
      "minLength": 1,
      "type": "string"
    },
    "__schema1": {
      "type": "string"
    }
  },
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "additionalProperties": false,
  "examples": [
    {
      "address": "0x1000"
    }
  ],
  "properties": {
    "address": {
      "$ref": "#/$defs/__schema0"
    },
    "document": {
      "$ref": "#/$defs/__schema1",
      "description": "Exact provider document or program identity."
    }
  },
  "required": [
    "address"
  ],
  "type": "object"
}
```

</details>

**Output schema:** see [`tool-specs/inspect_native_instruction.json`](../tool-specs/inspect_native_instruction.json) (`outputSchema`).

---

## inspect_native_load_image

<a id="inspectnativeloadimage"></a>

**Title:** Inspect Native Load Image  
**Kind:** `official-proxy` · **Requires session:** false · **analysisOperation:** inspect_native_load_image  
**Providers:** ghidra  
**Effects set (true flags):** mutatesSession  
**MCP annotations:** `{"destructiveHint":false,"idempotentHint":true,"openWorldHint":false,"readOnlyHint":false}`

**Description (verbatim, as advertised to the agent):**

> Verify the provider's loaded DOS MZ or explicitly selected COM image against its immutable target snapshot: complete original/modified source-byte digests, header/module file mappings and memory digests, relocations and external entry. Returns measured observations and independent checks with mismatch coordinates. COM verification includes its imposed entry register context and does not claim PSP/runtime coverage. Overlay and uninitialized coverage remain explicit; other formats return unsupported. Does not execute or modify the target.

**Input schema (verbatim, JSON Schema 2020-12):**

<details><summary>inputSchema for inspect_native_load_image</summary>

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "additionalProperties": false,
  "examples": [
    {}
  ],
  "properties": {},
  "type": "object"
}
```

</details>

**Output schema:** see [`tool-specs/inspect_native_load_image.json`](../tool-specs/inspect_native_load_image.json) (`outputSchema`).

---

## list_bookmarks

<a id="listbookmarks"></a>

**Title:** List Bookmarks  
**Kind:** `official-proxy` · **Requires session:** false · **analysisOperation:** list_bookmarks  
**Providers:** hopper  
**Effects set (true flags):** mutatesSession  
**MCP annotations:** `{"destructiveHint":false,"idempotentHint":true,"openWorldHint":false,"readOnlyHint":false}`

**Description (verbatim, as advertised to the agent):**

> List every bookmark in the selected Hopper document as address and name pairs; unnamed bookmarks retain a null name. Use bookmarks as analyst-authored navigation aids; this does not discover code references.

**Input schema (verbatim, JSON Schema 2020-12):**

<details><summary>inputSchema for list_bookmarks</summary>

```json
{
  "$defs": {
    "__schema0": {
      "$ref": "#/$defs/__schema1",
      "description": "The active target's provider document name; use open_binary to switch targets"
    },
    "__schema1": {
      "type": "string"
    }
  },
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "additionalProperties": false,
  "examples": [
    {}
  ],
  "properties": {
    "document": {
      "$ref": "#/$defs/__schema0",
      "description": "The active target's provider document name; use open_binary to switch targets"
    }
  },
  "type": "object"
}
```

</details>

**Output schema:** see [`tool-specs/list_bookmarks.json`](../tool-specs/list_bookmarks.json) (`outputSchema`).

---

## list_documents

<a id="listdocuments"></a>

**Title:** List Documents  
**Kind:** `official-proxy` · **Requires session:** false · **analysisOperation:** list_documents  
**Providers:** ghidra, hopper, ida  
**Effects set (true flags):** mutatesSession  
**MCP annotations:** `{"destructiveHint":false,"idempotentHint":true,"openWorldHint":false,"readOnlyHint":false}`

**Description (verbatim, as advertised to the agent):**

> List provider program or document identities. Hopper may expose several documents; a Ghidra headless session contains exactly its one imported Program.

**Input schema (verbatim, JSON Schema 2020-12):**

<details><summary>inputSchema for list_documents</summary>

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "additionalProperties": false,
  "examples": [
    {}
  ],
  "properties": {},
  "type": "object"
}
```

</details>

**Output schema:** see [`tool-specs/list_documents.json`](../tool-specs/list_documents.json) (`outputSchema`).

---

## list_names

<a id="listnames"></a>

**Title:** List Names  
**Kind:** `official-proxy` · **Requires session:** false · **analysisOperation:** list_names  
**Providers:** ghidra, hopper  
**Effects set (true flags):** mutatesSession  
**MCP annotations:** `{"destructiveHint":false,"idempotentHint":true,"openWorldHint":false,"readOnlyHint":false}`

**Description (verbatim, as advertised to the agent):**

> List every analyzed memory and external symbol as address/value pairs. Provider metadata distinguishes Ghidra primary, dynamic, external, type, and source facts when available.

**Input schema (verbatim, JSON Schema 2020-12):**

<details><summary>inputSchema for list_names</summary>

```json
{
  "$defs": {
    "__schema0": {
      "$ref": "#/$defs/__schema1",
      "description": "The active target's provider document name; use open_binary to switch targets"
    },
    "__schema1": {
      "type": "string"
    },
    "__schema2": {
      "description": "A provider-normalized address; default memory uses 0x-prefixed hexadecimal",
      "type": "string"
    }
  },
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "additionalProperties": false,
  "examples": [
    {}
  ],
  "properties": {
    "address": {
      "$ref": "#/$defs/__schema2",
      "description": "A provider-normalized address; default memory uses 0x-prefixed hexadecimal"
    },
    "document": {
      "$ref": "#/$defs/__schema0",
      "description": "The active target's provider document name; use open_binary to switch targets"
    }
  },
  "type": "object"
}
```

</details>

**Output schema:** see [`tool-specs/list_names.json`](../tool-specs/list_names.json) (`outputSchema`).

---

## list_procedures

<a id="listprocedures"></a>

**Title:** List Procedures  
**Kind:** `official-proxy` · **Requires session:** false · **analysisOperation:** list_procedures  
**Providers:** ghidra, hopper, ida  
**Effects set (true flags):** mutatesSession  
**MCP annotations:** `{"destructiveHint":false,"idempotentHint":true,"openWorldHint":false,"readOnlyHint":false}`

**Description (verbatim, as advertised to the agent):**

> List every analyzed procedure as address/value pairs after provider analysis. Ghidra metadata distinguishes thunks and external functions; use returned addresses in later function operations.

**Input schema (verbatim, JSON Schema 2020-12):**

<details><summary>inputSchema for list_procedures</summary>

```json
{
  "$defs": {
    "__schema0": {
      "$ref": "#/$defs/__schema1",
      "description": "The active target's provider document name; use open_binary to switch targets"
    },
    "__schema1": {
      "type": "string"
    }
  },
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "additionalProperties": false,
  "examples": [
    {}
  ],
  "properties": {
    "document": {
      "$ref": "#/$defs/__schema0",
      "description": "The active target's provider document name; use open_binary to switch targets"
    }
  },
  "type": "object"
}
```

</details>

**Output schema:** see [`tool-specs/list_procedures.json`](../tool-specs/list_procedures.json) (`outputSchema`).

---

## list_segments

<a id="listsegments"></a>

**Title:** List Segments  
**Kind:** `official-proxy` · **Requires session:** false · **analysisOperation:** list_segments  
**Providers:** ghidra, hopper  
**Effects set (true flags):** mutatesSession  
**MCP annotations:** `{"destructiveHint":false,"idempotentHint":true,"openWorldHint":false,"readOnlyHint":false}`

**Description (verbatim, as advertised to the agent):**

> List segments or memory blocks using exclusive end addresses. Ghidra reports block permissions, address space, image base, initialization, and overlay facts; Hopper marks unavailable permissions explicitly.

**Input schema (verbatim, JSON Schema 2020-12):**

<details><summary>inputSchema for list_segments</summary>

```json
{
  "$defs": {
    "__schema0": {
      "$ref": "#/$defs/__schema1",
      "description": "The active target's provider document name; use open_binary to switch targets"
    },
    "__schema1": {
      "type": "string"
    }
  },
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "additionalProperties": false,
  "examples": [
    {}
  ],
  "properties": {
    "document": {
      "$ref": "#/$defs/__schema0",
      "description": "The active target's provider document name; use open_binary to switch targets"
    }
  },
  "type": "object"
}
```

</details>

**Output schema:** see [`tool-specs/list_segments.json`](../tool-specs/list_segments.json) (`outputSchema`).

---

## list_strings

<a id="liststrings"></a>

**Title:** List Strings  
**Kind:** `official-proxy` · **Requires session:** false · **analysisOperation:** list_strings  
**Providers:** ghidra, hopper, ida  
**Effects set (true flags):** mutatesSession  
**MCP annotations:** `{"destructiveHint":false,"idempotentHint":true,"openWorldHint":false,"readOnlyHint":false}`

**Description (verbatim, as advertised to the agent):**

> List every provider-defined string object, or filter to one address, as address/value pairs with encoding, terminator status, and byte length when available. Hopper reads complete typed objects and retains its original display text as provider_value; long literals may span adjacent unterminated objects.

**Input schema (verbatim, JSON Schema 2020-12):**

<details><summary>inputSchema for list_strings</summary>

```json
{
  "$defs": {
    "__schema0": {
      "$ref": "#/$defs/__schema1",
      "description": "The active target's provider document name; use open_binary to switch targets"
    },
    "__schema1": {
      "type": "string"
    },
    "__schema2": {
      "description": "A provider-normalized address; default memory uses 0x-prefixed hexadecimal",
      "type": "string"
    }
  },
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "additionalProperties": false,
  "examples": [
    {}
  ],
  "properties": {
    "address": {
      "$ref": "#/$defs/__schema2",
      "description": "A provider-normalized address; default memory uses 0x-prefixed hexadecimal"
    },
    "document": {
      "$ref": "#/$defs/__schema0",
      "description": "The active target's provider document name; use open_binary to switch targets"
    }
  },
  "type": "object"
}
```

</details>

**Output schema:** see [`tool-specs/list_strings.json`](../tool-specs/list_strings.json) (`outputSchema`).

---

## next_address

<a id="nextaddress"></a>

**Title:** Next Address  
**Kind:** `official-proxy` · **Requires session:** false · **analysisOperation:** next_address  
**Providers:** hopper  
**Effects set (true flags):** mutatesSession  
**MCP annotations:** `{"destructiveHint":false,"idempotentHint":true,"openWorldHint":false,"readOnlyHint":false}`

**Description (verbatim, as advertised to the agent):**

> Return the next analyzed object address after an explicit address or current cursor. This is a navigation primitive, not instruction-flow or CFG analysis.

**Input schema (verbatim, JSON Schema 2020-12):**

<details><summary>inputSchema for next_address</summary>

```json
{
  "$defs": {
    "__schema0": {
      "$ref": "#/$defs/__schema1",
      "description": "The active target's provider document name; use open_binary to switch targets"
    },
    "__schema1": {
      "type": "string"
    },
    "__schema2": {
      "description": "A provider-normalized address; default memory uses 0x-prefixed hexadecimal",
      "type": "string"
    }
  },
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "additionalProperties": false,
  "examples": [
    {}
  ],
  "properties": {
    "address": {
      "$ref": "#/$defs/__schema2",
      "description": "A provider-normalized address; default memory uses 0x-prefixed hexadecimal"
    },
    "document": {
      "$ref": "#/$defs/__schema0",
      "description": "The active target's provider document name; use open_binary to switch targets"
    }
  },
  "type": "object"
}
```

</details>

**Output schema:** see [`tool-specs/next_address.json`](../tool-specs/next_address.json) (`outputSchema`).

---

## prev_address

<a id="prevaddress"></a>

**Title:** Prev Address  
**Kind:** `official-proxy` · **Requires session:** false · **analysisOperation:** prev_address  
**Providers:** hopper  
**Effects set (true flags):** mutatesSession  
**MCP annotations:** `{"destructiveHint":false,"idempotentHint":true,"openWorldHint":false,"readOnlyHint":false}`

**Description (verbatim, as advertised to the agent):**

> Return the previous analyzed object start before an explicit address or current cursor. This is a navigation primitive and may fail at document boundaries; data objects and instructions remain distinct from control flow.

**Input schema (verbatim, JSON Schema 2020-12):**

<details><summary>inputSchema for prev_address</summary>

```json
{
  "$defs": {
    "__schema0": {
      "$ref": "#/$defs/__schema1",
      "description": "The active target's provider document name; use open_binary to switch targets"
    },
    "__schema1": {
      "type": "string"
    },
    "__schema2": {
      "description": "A provider-normalized address; default memory uses 0x-prefixed hexadecimal",
      "type": "string"
    }
  },
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "additionalProperties": false,
  "examples": [
    {}
  ],
  "properties": {
    "address": {
      "$ref": "#/$defs/__schema2",
      "description": "A provider-normalized address; default memory uses 0x-prefixed hexadecimal"
    },
    "document": {
      "$ref": "#/$defs/__schema0",
      "description": "The active target's provider document name; use open_binary to switch targets"
    }
  },
  "type": "object"
}
```

</details>

**Output schema:** see [`tool-specs/prev_address.json`](../tool-specs/prev_address.json) (`outputSchema`).

---

## procedure_address

<a id="procedureaddress"></a>

**Title:** Procedure Address  
**Kind:** `official-proxy` · **Requires session:** false · **analysisOperation:** procedure_address  
**Providers:** ghidra, hopper, ida  
**Effects set (true flags):** mutatesSession  
**MCP annotations:** `{"destructiveHint":false,"idempotentHint":true,"openWorldHint":false,"readOnlyHint":false}`

**Description (verbatim, as advertised to the agent):**

> Resolve an unambiguous procedure symbol name or provider-normalized address to its canonical entry address. External address spaces remain explicit.

**Input schema (verbatim, JSON Schema 2020-12):**

<details><summary>inputSchema for procedure_address</summary>

```json
{
  "$defs": {
    "__schema0": {
      "description": "The procedure name or address",
      "type": "string"
    },
    "__schema1": {
      "$ref": "#/$defs/__schema2",
      "description": "The active target's provider document name; use open_binary to switch targets"
    },
    "__schema2": {
      "type": "string"
    }
  },
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "additionalProperties": false,
  "examples": [
    {
      "procedure": "main"
    }
  ],
  "properties": {
    "document": {
      "$ref": "#/$defs/__schema1",
      "description": "The active target's provider document name; use open_binary to switch targets"
    },
    "procedure": {
      "$ref": "#/$defs/__schema0",
      "description": "The procedure name or address"
    }
  },
  "required": [
    "procedure"
  ],
  "type": "object"
}
```

</details>

**Output schema:** see [`tool-specs/procedure_address.json`](../tool-specs/procedure_address.json) (`outputSchema`).

---

## procedure_assembly

<a id="procedureassembly"></a>

**Title:** Procedure Assembly  
**Kind:** `official-proxy` · **Requires session:** false · **analysisOperation:** procedure_assembly  
**Providers:** ghidra, hopper, ida  
**Effects set (true flags):** mutatesSession  
**MCP annotations:** `{"destructiveHint":false,"idempotentHint":true,"openWorldHint":false,"readOnlyHint":false}`

**Description (verbatim, as advertised to the agent):**

> Return assembly for one analyzed procedure identified by symbol or hexadecimal address. Use when pseudocode loses calling-convention or instruction-level detail; output is currently returned as one unpaginated string. Ghidra terminal-call assumptions that may cut the analyzed body are reported in Evidence limitations.

**Input schema (verbatim, JSON Schema 2020-12):**

<details><summary>inputSchema for procedure_assembly</summary>

```json
{
  "$defs": {
    "__schema0": {
      "description": "The procedure name or address",
      "type": "string"
    },
    "__schema1": {
      "$ref": "#/$defs/__schema2",
      "description": "The active target's provider document name; use open_binary to switch targets"
    },
    "__schema2": {
      "type": "string"
    }
  },
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "additionalProperties": false,
  "examples": [
    {
      "procedure": "main"
    }
  ],
  "properties": {
    "document": {
      "$ref": "#/$defs/__schema1",
      "description": "The active target's provider document name; use open_binary to switch targets"
    },
    "procedure": {
      "$ref": "#/$defs/__schema0",
      "description": "The procedure name or address"
    }
  },
  "required": [
    "procedure"
  ],
  "type": "object"
}
```

</details>

**Output schema:** see [`tool-specs/procedure_assembly.json`](../tool-specs/procedure_assembly.json) (`outputSchema`).

---

## procedure_callees

<a id="procedurecallees"></a>

**Title:** Procedure Callees  
**Kind:** `official-proxy` · **Requires session:** false · **analysisOperation:** procedure_callees  
**Providers:** ghidra, hopper, ida  
**Effects set (true flags):** mutatesSession  
**MCP annotations:** `{"destructiveHint":false,"idempotentHint":true,"openWorldHint":false,"readOnlyHint":false}`

**Description (verbatim, as advertised to the agent):**

> Return the provider's resolved direct callees for one procedure identified by symbol or address. Unresolved indirect calls may be absent; use analyze_function and typed references to preserve available edge uncertainty. Ghidra terminal-call assumptions that may cut the analyzed body are reported in Evidence limitations.

**Input schema (verbatim, JSON Schema 2020-12):**

<details><summary>inputSchema for procedure_callees</summary>

```json
{
  "$defs": {
    "__schema0": {
      "description": "The procedure name or address",
      "type": "string"
    },
    "__schema1": {
      "$ref": "#/$defs/__schema2",
      "description": "The active target's provider document name; use open_binary to switch targets"
    },
    "__schema2": {
      "type": "string"
    }
  },
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "additionalProperties": false,
  "examples": [
    {
      "procedure": "main"
    }
  ],
  "properties": {
    "document": {
      "$ref": "#/$defs/__schema1",
      "description": "The active target's provider document name; use open_binary to switch targets"
    },
    "procedure": {
      "$ref": "#/$defs/__schema0",
      "description": "The procedure name or address"
    }
  },
  "required": [
    "procedure"
  ],
  "type": "object"
}
```

</details>

**Output schema:** see [`tool-specs/procedure_callees.json`](../tool-specs/procedure_callees.json) (`outputSchema`).

---

## procedure_callers

<a id="procedurecallers"></a>

**Title:** Procedure Callers  
**Kind:** `official-proxy` · **Requires session:** false · **analysisOperation:** procedure_callers  
**Providers:** ghidra, hopper, ida  
**Effects set (true flags):** mutatesSession  
**MCP annotations:** `{"destructiveHint":false,"idempotentHint":true,"openWorldHint":false,"readOnlyHint":false}`

**Description (verbatim, as advertised to the agent):**

> Return the provider's resolved direct callers for one procedure identified by symbol or address. Results reflect completed static analysis and may omit unresolved indirect references. Ghidra terminal-call assumptions that may cut the analyzed body are reported in Evidence limitations.

**Input schema (verbatim, JSON Schema 2020-12):**

<details><summary>inputSchema for procedure_callers</summary>

```json
{
  "$defs": {
    "__schema0": {
      "description": "The procedure name or address",
      "type": "string"
    },
    "__schema1": {
      "$ref": "#/$defs/__schema2",
      "description": "The active target's provider document name; use open_binary to switch targets"
    },
    "__schema2": {
      "type": "string"
    }
  },
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "additionalProperties": false,
  "examples": [
    {
      "procedure": "main"
    }
  ],
  "properties": {
    "document": {
      "$ref": "#/$defs/__schema1",
      "description": "The active target's provider document name; use open_binary to switch targets"
    },
    "procedure": {
      "$ref": "#/$defs/__schema0",
      "description": "The procedure name or address"
    }
  },
  "required": [
    "procedure"
  ],
  "type": "object"
}
```

</details>

**Output schema:** see [`tool-specs/procedure_callers.json`](../tool-specs/procedure_callers.json) (`outputSchema`).

---

## procedure_info

<a id="procedureinfo"></a>

**Title:** Procedure Info  
**Kind:** `official-proxy` · **Requires session:** false · **analysisOperation:** procedure_info  
**Providers:** ghidra, hopper  
**Effects set (true flags):** mutatesSession  
**MCP annotations:** `{"destructiveHint":false,"idempotentHint":true,"openWorldHint":false,"readOnlyHint":false}`

**Description (verbatim, as advertised to the agent):**

> Return provider metadata for one procedure identified by symbol or address: entrypoint, signature, locals, size, block count, and complete inclusive body ranges when observed. Extents reflect the provider's analyzed body; Ghidra terminal-call assumptions that may cut it are reported in Evidence limitations. Hopper locals preserve observed names and signed stack displacements; source types remain unknown. Body byte count and enclosing span remain distinct; unavailable extent is explicit.

**Input schema (verbatim, JSON Schema 2020-12):**

<details><summary>inputSchema for procedure_info</summary>

```json
{
  "$defs": {
    "__schema0": {
      "description": "The procedure name or address",
      "type": "string"
    },
    "__schema1": {
      "$ref": "#/$defs/__schema2",
      "description": "The active target's provider document name; use open_binary to switch targets"
    },
    "__schema2": {
      "type": "string"
    }
  },
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "additionalProperties": false,
  "examples": [
    {
      "procedure": "main"
    }
  ],
  "properties": {
    "document": {
      "$ref": "#/$defs/__schema1",
      "description": "The active target's provider document name; use open_binary to switch targets"
    },
    "procedure": {
      "$ref": "#/$defs/__schema0",
      "description": "The procedure name or address"
    }
  },
  "required": [
    "procedure"
  ],
  "type": "object"
}
```

</details>

**Output schema:** see [`tool-specs/procedure_info.json`](../tool-specs/procedure_info.json) (`outputSchema`).

---

## procedure_pseudo_code

<a id="procedurepseudocode"></a>

**Title:** Procedure Pseudo Code  
**Kind:** `official-proxy` · **Requires session:** false · **analysisOperation:** procedure_pseudo_code  
**Providers:** ghidra, hopper, ida  
**Effects set (true flags):** mutatesSession  
**MCP annotations:** `{"destructiveHint":false,"idempotentHint":true,"openWorldHint":false,"readOnlyHint":false}`

**Description (verbatim, as advertised to the agent):**

> Decompile one analyzed procedure by symbol name or provider-normalized address. Ghidra also accepts file-offset:0x... selectors and falls back to a unique source-file mapping when a 0x-prefixed number resolves to no procedure; existing analysis addresses take precedence and ambiguous mappings fail explicitly. Returns provider-specific pseudocode, never original source or cross-provider text equivalence, and may return null; request procedure_assembly when instruction precision matters. Ghidra no-return assumptions may cut the analyzed body; Evidence limitations report observed terminal calls and available callee identities.

**Input schema (verbatim, JSON Schema 2020-12):**

<details><summary>inputSchema for procedure_pseudo_code</summary>

```json
{
  "$defs": {
    "__schema0": {
      "description": "The procedure name or address",
      "type": "string"
    },
    "__schema1": {
      "$ref": "#/$defs/__schema2",
      "description": "The active target's provider document name; use open_binary to switch targets"
    },
    "__schema2": {
      "type": "string"
    }
  },
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "additionalProperties": false,
  "examples": [
    {
      "procedure": "main"
    }
  ],
  "properties": {
    "document": {
      "$ref": "#/$defs/__schema1",
      "description": "The active target's provider document name; use open_binary to switch targets"
    },
    "procedure": {
      "$ref": "#/$defs/__schema0",
      "description": "The procedure name or address"
    }
  },
  "required": [
    "procedure"
  ],
  "type": "object"
}
```

</details>

**Output schema:** see [`tool-specs/procedure_pseudo_code.json`](../tool-specs/procedure_pseudo_code.json) (`outputSchema`).

---

## procedure_references

<a id="procedurereferences"></a>

**Title:** Procedure References  
**Kind:** `official-proxy` · **Requires session:** false · **analysisOperation:** procedure_references  
**Providers:** ghidra, hopper  
**Effects set (true flags):** mutatesSession  
**MCP annotations:** `{"destructiveHint":false,"idempotentHint":true,"openWorldHint":false,"readOnlyHint":false}`

**Description (verbatim, as advertised to the agent):**

> Return every raw incoming or outgoing reference edge for one procedure. Endpoint procedures are resolved only from provider containment. Ghidra preserves detailed reference flags. Hopper preserves native CallReference classifications and exact endpoints while leaving unavailable detailed flags explicit.

**Input schema (verbatim, JSON Schema 2020-12):**

<details><summary>inputSchema for procedure_references</summary>

```json
{
  "$defs": {
    "__schema0": {
      "description": "The procedure name or address",
      "type": "string"
    },
    "__schema1": {
      "default": "outgoing",
      "enum": [
        "incoming",
        "outgoing"
      ],
      "type": "string"
    },
    "__schema2": {
      "$ref": "#/$defs/__schema3",
      "description": "The active target's provider document name; use open_binary to switch targets"
    },
    "__schema3": {
      "type": "string"
    }
  },
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "additionalProperties": false,
  "examples": [
    {
      "direction": "outgoing",
      "procedure": "main"
    }
  ],
  "properties": {
    "direction": {
      "$ref": "#/$defs/__schema1",
      "description": "Direction in which to traverse or compare relationships."
    },
    "document": {
      "$ref": "#/$defs/__schema2",
      "description": "The active target's provider document name; use open_binary to switch targets"
    },
    "procedure": {
      "$ref": "#/$defs/__schema0",
      "description": "The procedure name or address"
    }
  },
  "required": [
    "procedure"
  ],
  "type": "object"
}
```

</details>

**Output schema:** see [`tool-specs/procedure_references.json`](../tool-specs/procedure_references.json) (`outputSchema`).

---

## read_bytes

<a id="readbytes"></a>

**Title:** Read Bytes  
**Kind:** `official-proxy` · **Requires session:** false · **analysisOperation:** read_bytes  
**Providers:** ghidra, hopper  
**Effects set (true flags):** mutatesSession  
**MCP annotations:** `{"destructiveHint":false,"idempotentHint":true,"openWorldHint":false,"readOnlyHint":false}`

**Description (verbatim, as advertised to the agent):**

> Read analyzed bytes from one provider-normalized virtual address. The hexadecimal payload reports the exact returned length; incomplete reads remain explicit and unsupported provider APIs return typed capability unavailability.

**Input schema (verbatim, JSON Schema 2020-12):**

<details><summary>inputSchema for read_bytes</summary>

```json
{
  "$defs": {
    "__schema0": {
      "description": "A provider-normalized address; default memory uses 0x-prefixed hexadecimal",
      "type": "string"
    },
    "__schema1": {
      "default": 256,
      "maximum": 9007199254740991,
      "minimum": 1,
      "type": "integer"
    },
    "__schema2": {
      "$ref": "#/$defs/__schema3",
      "description": "The active target's provider document name; use open_binary to switch targets"
    },
    "__schema3": {
      "type": "string"
    }
  },
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "additionalProperties": false,
  "examples": [
    {
      "address": "0x1000",
      "length": 16
    }
  ],
  "properties": {
    "address": {
      "$ref": "#/$defs/__schema0",
      "description": "A provider-normalized address; default memory uses 0x-prefixed hexadecimal"
    },
    "document": {
      "$ref": "#/$defs/__schema2",
      "description": "The active target's provider document name; use open_binary to switch targets"
    },
    "length": {
      "$ref": "#/$defs/__schema1"
    }
  },
  "required": [
    "address"
  ],
  "type": "object"
}
```

</details>

**Output schema:** see [`tool-specs/read_bytes.json`](../tool-specs/read_bytes.json) (`outputSchema`).

---

## read_function_instructions

<a id="readfunctioninstructions"></a>

**Title:** Read Function Instructions  
**Kind:** `official-proxy` · **Requires session:** false · **analysisOperation:** read_function_instructions  
**Providers:** ghidra, hopper, ida  
**Effects set (true flags):** mutatesSession  
**MCP annotations:** `{"destructiveHint":false,"idempotentHint":true,"openWorldHint":false,"readOnlyHint":false}`

**Description (verbatim, as advertised to the agent):**

> Return every raw instruction for one analyzed procedure. Instruction text and body extent are provider-specific. Ghidra terminal-call assumptions that may cut the analyzed body are reported in limitations.

**Input schema (verbatim, JSON Schema 2020-12):**

<details><summary>inputSchema for read_function_instructions</summary>

```json
{
  "$defs": {
    "__schema0": {
      "description": "The procedure name or address",
      "type": "string"
    },
    "__schema1": {
      "$ref": "#/$defs/__schema2",
      "description": "The document name"
    },
    "__schema2": {
      "type": "string"
    }
  },
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "additionalProperties": false,
  "examples": [
    {
      "procedure": "main"
    }
  ],
  "properties": {
    "document": {
      "$ref": "#/$defs/__schema1",
      "description": "The document name"
    },
    "procedure": {
      "$ref": "#/$defs/__schema0",
      "description": "The procedure name or address"
    }
  },
  "required": [
    "procedure"
  ],
  "type": "object"
}
```

</details>

**Output schema:** see [`tool-specs/read_function_instructions.json`](../tool-specs/read_function_instructions.json) (`outputSchema`).

---

## resolve_containing_procedure

<a id="resolvecontainingprocedure"></a>

**Title:** Resolve Containing Procedure  
**Kind:** `official-proxy` · **Requires session:** false · **analysisOperation:** resolve_containing_procedure  
**Providers:** ghidra, hopper, ida  
**Effects set (true flags):** mutatesSession  
**MCP annotations:** `{"destructiveHint":false,"idempotentHint":true,"openWorldHint":false,"readOnlyHint":false}`

**Description (verbatim, as advertised to the agent):**

> Resolve an arbitrary address, including an interior instruction or exact external entry, to its provider-analyzed containing procedure. A negative result distinguishes outside segments from not in a procedure and is never guessed from nearby symbols.

**Input schema (verbatim, JSON Schema 2020-12):**

<details><summary>inputSchema for resolve_containing_procedure</summary>

```json
{
  "$defs": {
    "__schema0": {
      "description": "A provider-normalized address; default memory uses 0x-prefixed hexadecimal",
      "type": "string"
    },
    "__schema1": {
      "$ref": "#/$defs/__schema2",
      "description": "The active target's provider document name; use open_binary to switch targets"
    },
    "__schema2": {
      "type": "string"
    }
  },
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "additionalProperties": false,
  "examples": [
    {
      "address": "0x1000"
    }
  ],
  "properties": {
    "address": {
      "$ref": "#/$defs/__schema0",
      "description": "A provider-normalized address; default memory uses 0x-prefixed hexadecimal"
    },
    "document": {
      "$ref": "#/$defs/__schema1",
      "description": "The active target's provider document name; use open_binary to switch targets"
    }
  },
  "required": [
    "address"
  ],
  "type": "object"
}
```

</details>

**Output schema:** see [`tool-specs/resolve_containing_procedure.json`](../tool-specs/resolve_containing_procedure.json) (`outputSchema`).

---

## resolve_native_call_targets

<a id="resolvenativecalltargets"></a>

**Title:** Resolve Native Call Targets  
**Kind:** `official-proxy` · **Requires session:** false · **analysisOperation:** resolve_native_call_targets  
**Providers:** ghidra  
**Effects set (true flags):** mutatesSession  
**MCP annotations:** `{"destructiveHint":false,"idempotentHint":true,"openWorldHint":false,"readOnlyHint":false}`

**Description (verbatim, as advertised to the agent):**

> Resolve one explicit static call site using typed provider call references. Preserves ambiguous targets as candidates and unresolved computed calls as unknown; does not execute code or traverse a call graph.

**Input schema (verbatim, JSON Schema 2020-12):**

<details><summary>inputSchema for resolve_native_call_targets</summary>

```json
{
  "$defs": {
    "__schema0": {
      "minLength": 1,
      "type": "string"
    },
    "__schema1": {
      "type": "string"
    }
  },
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "additionalProperties": false,
  "examples": [
    {
      "address": "0x1000"
    }
  ],
  "properties": {
    "address": {
      "$ref": "#/$defs/__schema0"
    },
    "document": {
      "$ref": "#/$defs/__schema1",
      "description": "Exact provider document or program identity."
    }
  },
  "required": [
    "address"
  ],
  "type": "object"
}
```

</details>

**Output schema:** see [`tool-specs/resolve_native_call_targets.json`](../tool-specs/resolve_native_call_targets.json) (`outputSchema`).

---

## search_bytes

<a id="searchbytes"></a>

**Title:** Search Bytes  
**Kind:** `official-proxy` · **Requires session:** false · **analysisOperation:** search_bytes  
**Providers:** ghidra  
**Effects set (true flags):** mutatesSession  
**MCP annotations:** `{"destructiveHint":false,"idempotentHint":true,"openWorldHint":false,"readOnlyHint":false}`

**Description (verbatim, as advertised to the agent):**

> Find masked byte signatures in initialized analyzed memory. Hex byte pairs and ?? wildcards are supported; an optional equal-length hex mask selects bits. Bounds are inclusive. Matches are ordered by provider address and never span blocks. Coverage describes this page; reuse the same query with next_cursor to continue. Uninitialized blocks are listed separately. Ghidra only; Hopper is unavailable.

**Input schema (verbatim, JSON Schema 2020-12):**

<details><summary>inputSchema for search_bytes</summary>

```json
{
  "$defs": {
    "__schema0": {
      "pattern": "^([0-9a-fA-F]{2}|\\?\\?)(\\s*([0-9a-fA-F]{2}|\\?\\?))*$",
      "type": "string"
    },
    "__schema1": {
      "pattern": "^[0-9a-fA-F]{2}(\\s*[0-9a-fA-F]{2})*$",
      "type": "string"
    },
    "__schema2": {
      "$ref": "#/$defs/__schema3",
      "description": "The active target's provider document name; use open_binary to switch targets"
    },
    "__schema3": {
      "type": "string"
    },
    "__schema4": {
      "$ref": "#/$defs/__schema5"
    },
    "__schema5": {
      "description": "A provider-normalized address; default memory uses 0x-prefixed hexadecimal",
      "type": "string"
    },
    "__schema6": {
      "$ref": "#/$defs/__schema5"
    },
    "__schema7": {
      "default": 100,
      "maximum": 1000,
      "minimum": 1,
      "type": "integer"
    },
    "__schema8": {
      "minLength": 1,
      "type": "string"
    }
  },
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "additionalProperties": false,
  "examples": [
    {
      "limit": 100,
      "pattern": "48 8B ?? ?? 89"
    }
  ],
  "properties": {
    "cursor": {
      "$ref": "#/$defs/__schema8"
    },
    "document": {
      "$ref": "#/$defs/__schema2",
      "description": "The active target's provider document name; use open_binary to switch targets"
    },
    "end": {
      "$ref": "#/$defs/__schema6",
      "description": "A provider-normalized address; default memory uses 0x-prefixed hexadecimal"
    },
    "limit": {
      "$ref": "#/$defs/__schema7"
    },
    "mask": {
      "$ref": "#/$defs/__schema1"
    },
    "pattern": {
      "$ref": "#/$defs/__schema0",
      "description": "Literal text or regular expression used to filter matching results."
    },
    "start": {
      "$ref": "#/$defs/__schema4",
      "description": "A provider-normalized address; default memory uses 0x-prefixed hexadecimal"
    }
  },
  "required": [
    "pattern"
  ],
  "type": "object"
}
```

</details>

**Output schema:** see [`tool-specs/search_bytes.json`](../tool-specs/search_bytes.json) (`outputSchema`).

---

## search_procedures

<a id="searchprocedures"></a>

**Title:** Search Procedures  
**Kind:** `official-proxy` · **Requires session:** false · **analysisOperation:** search_procedures  
**Providers:** ghidra, hopper, ida  
**Effects set (true flags):** mutatesSession  
**MCP annotations:** `{"destructiveHint":false,"idempotentHint":true,"openWorldHint":false,"readOnlyHint":false}`

**Description (verbatim, as advertised to the agent):**

> Search every analyzed procedure name using literal matching by default or regex when requested. Results are deterministic and complete. Hopper regex mode uses ECMAScript Unicode syntax in a cancellable worker; a matching deadline leaves its API usable.

**Input schema (verbatim, JSON Schema 2020-12):**

<details><summary>inputSchema for search_procedures</summary>

```json
{
  "$defs": {
    "__schema0": {
      "description": "The literal text or regex pattern to search for",
      "minLength": 1,
      "type": "string"
    },
    "__schema1": {
      "default": "literal",
      "enum": [
        "literal",
        "regex"
      ],
      "type": "string"
    },
    "__schema2": {
      "$ref": "#/$defs/__schema3",
      "default": false,
      "description": "Whether to match case"
    },
    "__schema3": {
      "type": "boolean"
    },
    "__schema4": {
      "$ref": "#/$defs/__schema5",
      "description": "The document name"
    },
    "__schema5": {
      "type": "string"
    }
  },
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "additionalProperties": false,
  "examples": [
    {
      "case_sensitive": false,
      "mode": "literal",
      "pattern": "main"
    }
  ],
  "properties": {
    "case_sensitive": {
      "$ref": "#/$defs/__schema2",
      "description": "Whether to match case"
    },
    "document": {
      "$ref": "#/$defs/__schema4",
      "description": "The document name"
    },
    "mode": {
      "$ref": "#/$defs/__schema1",
      "description": "Operation mode that selects the requested behavior."
    },
    "pattern": {
      "$ref": "#/$defs/__schema0",
      "description": "The literal text or regex pattern to search for"
    }
  },
  "required": [
    "pattern"
  ],
  "type": "object"
}
```

</details>

**Output schema:** see [`tool-specs/search_procedures.json`](../tool-specs/search_procedures.json) (`outputSchema`).

---

## search_strings

<a id="searchstrings"></a>

**Title:** Search Strings  
**Kind:** `official-proxy` · **Requires session:** false · **analysisOperation:** search_strings  
**Providers:** ghidra, hopper, ida  
**Effects set (true flags):** mutatesSession  
**MCP annotations:** `{"destructiveHint":false,"idempotentHint":true,"openWorldHint":false,"readOnlyHint":false}`

**Description (verbatim, as advertised to the agent):**

> Search every provider-defined string object using literal matching by default or regex when requested. Results are deterministic and complete over those defined objects, not every text sequence in artifact bytes. Ghidra may omit packed or undefined literals, including Rust strings; an empty result does not prove text is absent. If an address is known, read_bytes and xrefs inspect its bytes and references. Hopper retains typed byte decoding, native display, and explicit decoding unknowns. Adjacent long-literal fragments match independently. Hopper regex mode uses ECMAScript Unicode syntax in a cancellable worker; a matching deadline leaves its API usable.

**Input schema (verbatim, JSON Schema 2020-12):**

<details><summary>inputSchema for search_strings</summary>

```json
{
  "$defs": {
    "__schema0": {
      "description": "The literal text or regex pattern to search for",
      "minLength": 1,
      "type": "string"
    },
    "__schema1": {
      "default": "literal",
      "enum": [
        "literal",
        "regex"
      ],
      "type": "string"
    },
    "__schema2": {
      "$ref": "#/$defs/__schema3",
      "default": false,
      "description": "Whether to match case"
    },
    "__schema3": {
      "type": "boolean"
    },
    "__schema4": {
      "$ref": "#/$defs/__schema5",
      "description": "The document name"
    },
    "__schema5": {
      "type": "string"
    }
  },
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "additionalProperties": false,
  "examples": [
    {
      "case_sensitive": false,
      "mode": "literal",
      "pattern": "authorization failed"
    }
  ],
  "properties": {
    "case_sensitive": {
      "$ref": "#/$defs/__schema2",
      "description": "Whether to match case"
    },
    "document": {
      "$ref": "#/$defs/__schema4",
      "description": "The document name"
    },
    "mode": {
      "$ref": "#/$defs/__schema1",
      "description": "Operation mode that selects the requested behavior."
    },
    "pattern": {
      "$ref": "#/$defs/__schema0",
      "description": "The literal text or regex pattern to search for"
    }
  },
  "required": [
    "pattern"
  ],
  "type": "object"
}
```

</details>

**Output schema:** see [`tool-specs/search_strings.json`](../tool-specs/search_strings.json) (`outputSchema`).

---

## set_address_name

<a id="setaddressname"></a>

**Title:** Set Address Name  
**Kind:** `official-proxy` · **Requires session:** false · **analysisOperation:** set_address_name  
**Providers:** ghidra, hopper  
**Effects set (true flags):** mayDiscardData, mutatesSession, mutatesTarget  
**MCP annotations:** `{"destructiveHint":true,"idempotentHint":true,"openWorldHint":false,"readOnlyHint":false}`

**Description (verbatim, as advertised to the agent):**

> Assign an analyst name to one mapped hexadecimal address and report whether the native edit succeeded and exact readback matched. Hopper rejects symbol names exceeding 1024 UTF-16 code units before mutation, and rejects names owned by another address; use set_addresses_names to explicitly move or swap labels among selected addresses. This mutates analysis metadata.

**Input schema (verbatim, JSON Schema 2020-12):**

<details><summary>inputSchema for set_address_name</summary>

```json
{
  "$defs": {
    "__schema0": {
      "description": "A provider-normalized address; default memory uses 0x-prefixed hexadecimal",
      "type": "string"
    },
    "__schema1": {
      "type": "string"
    },
    "__schema2": {
      "$ref": "#/$defs/__schema3",
      "description": "The active target's provider document name; use open_binary to switch targets"
    },
    "__schema3": {
      "type": "string"
    }
  },
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "additionalProperties": false,
  "examples": [
    {
      "address": "0x1000",
      "name": "entry"
    }
  ],
  "properties": {
    "address": {
      "$ref": "#/$defs/__schema0",
      "description": "A provider-normalized address; default memory uses 0x-prefixed hexadecimal"
    },
    "document": {
      "$ref": "#/$defs/__schema2",
      "description": "The active target's provider document name; use open_binary to switch targets"
    },
    "name": {
      "$ref": "#/$defs/__schema1",
      "description": "Exact name used by this operation."
    }
  },
  "required": [
    "address",
    "name"
  ],
  "type": "object"
}
```

</details>

**Output schema:** see [`tool-specs/set_address_name.json`](../tool-specs/set_address_name.json) (`outputSchema`).

---

## set_addresses_names

<a id="setaddressesnames"></a>

**Title:** Set Addresses Names  
**Kind:** `official-proxy` · **Requires session:** false · **analysisOperation:** set_addresses_names  
**Providers:** ghidra, hopper  
**Effects set (true flags):** mayDiscardData, mutatesSession, mutatesTarget  
**MCP annotations:** `{"destructiveHint":true,"idempotentHint":true,"openWorldHint":false,"readOnlyHint":false}`

**Description (verbatim, as advertised to the agent):**

> Assign analyst names to multiple mapped addresses in one call and return per-address edit/readback success booleans. Hopper validates mapped destinations, native string representations, its 1024 UTF-16 code-unit symbol-name limit, and unique destinations/names before applying edits. Existing labels may move or swap only among explicitly selected addresses; unselected label owners remain unchanged. This mutates analysis metadata; verify failures individually.

**Input schema (verbatim, JSON Schema 2020-12):**

<details><summary>inputSchema for set_addresses_names</summary>

```json
{
  "$defs": {
    "__schema0": {
      "additionalProperties": {
        "type": "string"
      },
      "propertyNames": {
        "type": "string"
      },
      "type": "object"
    },
    "__schema1": {
      "$ref": "#/$defs/__schema2",
      "description": "The active target's provider document name; use open_binary to switch targets"
    },
    "__schema2": {
      "type": "string"
    }
  },
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "additionalProperties": false,
  "examples": [
    {
      "names": {
        "0x1000": "entry"
      }
    }
  ],
  "properties": {
    "document": {
      "$ref": "#/$defs/__schema1",
      "description": "The active target's provider document name; use open_binary to switch targets"
    },
    "names": {
      "$ref": "#/$defs/__schema0"
    }
  },
  "required": [
    "names"
  ],
  "type": "object"
}
```

</details>

**Output schema:** see [`tool-specs/set_addresses_names.json`](../tool-specs/set_addresses_names.json) (`outputSchema`).

---

## set_bookmark

<a id="setbookmark"></a>

**Title:** Set Bookmark  
**Kind:** `official-proxy` · **Requires session:** false · **analysisOperation:** set_bookmark  
**Providers:** hopper  
**Effects set (true flags):** mayDiscardData, mutatesSession, mutatesTarget  
**MCP annotations:** `{"destructiveHint":true,"idempotentHint":true,"openWorldHint":false,"readOnlyHint":false}`

**Description (verbatim, as advertised to the agent):**

> Create or replace a bookmark at a mapped hexadecimal address and report success. This mutates navigation metadata; bookmarks are analyst-authored navigation aids, not binary evidence.

**Input schema (verbatim, JSON Schema 2020-12):**

<details><summary>inputSchema for set_bookmark</summary>

```json
{
  "$defs": {
    "__schema0": {
      "description": "A provider-normalized address; default memory uses 0x-prefixed hexadecimal",
      "type": "string"
    },
    "__schema1": {
      "type": "string"
    },
    "__schema2": {
      "$ref": "#/$defs/__schema3",
      "description": "The active target's provider document name; use open_binary to switch targets"
    },
    "__schema3": {
      "type": "string"
    }
  },
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "additionalProperties": false,
  "examples": [
    {
      "address": "0x1000"
    }
  ],
  "properties": {
    "address": {
      "$ref": "#/$defs/__schema0",
      "description": "A provider-normalized address; default memory uses 0x-prefixed hexadecimal"
    },
    "document": {
      "$ref": "#/$defs/__schema2",
      "description": "The active target's provider document name; use open_binary to switch targets"
    },
    "name": {
      "$ref": "#/$defs/__schema1",
      "description": "Exact name used by this operation."
    }
  },
  "required": [
    "address"
  ],
  "type": "object"
}
```

</details>

**Output schema:** see [`tool-specs/set_bookmark.json`](../tool-specs/set_bookmark.json) (`outputSchema`).

---

## set_comment

<a id="setcomment"></a>

**Title:** Set Comment  
**Kind:** `official-proxy` · **Requires session:** false · **analysisOperation:** set_comment  
**Providers:** hopper  
**Effects set (true flags):** mayDiscardData, mutatesSession, mutatesTarget  
**MCP annotations:** `{"destructiveHint":true,"idempotentHint":true,"openWorldHint":false,"readOnlyHint":false}`

**Description (verbatim, as advertised to the agent):**

> Write a regular analysis comment at a hexadecimal address and return whether readback matched. An empty comment clears it. This mutates the Hopper document; use comments to record evidence IDs or reasoning.

**Input schema (verbatim, JSON Schema 2020-12):**

<details><summary>inputSchema for set_comment</summary>

```json
{
  "$defs": {
    "__schema0": {
      "description": "A provider-normalized address; default memory uses 0x-prefixed hexadecimal",
      "type": "string"
    },
    "__schema1": {
      "type": "string"
    },
    "__schema2": {
      "$ref": "#/$defs/__schema3",
      "description": "The active target's provider document name; use open_binary to switch targets"
    },
    "__schema3": {
      "type": "string"
    }
  },
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "additionalProperties": false,
  "examples": [
    {
      "address": "0x1000",
      "comment": "validated entry point"
    }
  ],
  "properties": {
    "address": {
      "$ref": "#/$defs/__schema0",
      "description": "A provider-normalized address; default memory uses 0x-prefixed hexadecimal"
    },
    "comment": {
      "$ref": "#/$defs/__schema1",
      "description": "Exact analyst comment text to write."
    },
    "document": {
      "$ref": "#/$defs/__schema2",
      "description": "The active target's provider document name; use open_binary to switch targets"
    }
  },
  "required": [
    "address",
    "comment"
  ],
  "type": "object"
}
```

</details>

**Output schema:** see [`tool-specs/set_comment.json`](../tool-specs/set_comment.json) (`outputSchema`).

---

## set_inline_comment

<a id="setinlinecomment"></a>

**Title:** Set Inline Comment  
**Kind:** `official-proxy` · **Requires session:** false · **analysisOperation:** set_inline_comment  
**Providers:** hopper  
**Effects set (true flags):** mayDiscardData, mutatesSession, mutatesTarget  
**MCP annotations:** `{"destructiveHint":true,"idempotentHint":true,"openWorldHint":false,"readOnlyHint":false}`

**Description (verbatim, as advertised to the agent):**

> Write an inline instruction comment at a hexadecimal address and return whether readback matched. An empty comment clears it; Hopper may flatten newlines, producing false on exact readback. This mutates analysis metadata.

**Input schema (verbatim, JSON Schema 2020-12):**

<details><summary>inputSchema for set_inline_comment</summary>

```json
{
  "$defs": {
    "__schema0": {
      "description": "A provider-normalized address; default memory uses 0x-prefixed hexadecimal",
      "type": "string"
    },
    "__schema1": {
      "type": "string"
    },
    "__schema2": {
      "$ref": "#/$defs/__schema3",
      "description": "The active target's provider document name; use open_binary to switch targets"
    },
    "__schema3": {
      "type": "string"
    }
  },
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "additionalProperties": false,
  "examples": [
    {
      "address": "0x1000",
      "comment": "calls parser"
    }
  ],
  "properties": {
    "address": {
      "$ref": "#/$defs/__schema0",
      "description": "A provider-normalized address; default memory uses 0x-prefixed hexadecimal"
    },
    "comment": {
      "$ref": "#/$defs/__schema1",
      "description": "Exact analyst comment text to write."
    },
    "document": {
      "$ref": "#/$defs/__schema2",
      "description": "The active target's provider document name; use open_binary to switch targets"
    }
  },
  "required": [
    "address",
    "comment"
  ],
  "type": "object"
}
```

</details>

**Output schema:** see [`tool-specs/set_inline_comment.json`](../tool-specs/set_inline_comment.json) (`outputSchema`).

---

## unset_bookmark

<a id="unsetbookmark"></a>

**Title:** Unset Bookmark  
**Kind:** `official-proxy` · **Requires session:** false · **analysisOperation:** unset_bookmark  
**Providers:** hopper  
**Effects set (true flags):** mayDiscardData, mutatesSession, mutatesTarget  
**MCP annotations:** `{"destructiveHint":true,"idempotentHint":true,"openWorldHint":false,"readOnlyHint":false}`

**Description (verbatim, as advertised to the agent):**

> Remove the bookmark at a mapped hexadecimal address and return whether it is absent. Hopper also permits removing an existing legacy bookmark outside mapped memory. This mutates navigation metadata and does not alter binary bytes.

**Input schema (verbatim, JSON Schema 2020-12):**

<details><summary>inputSchema for unset_bookmark</summary>

```json
{
  "$defs": {
    "__schema0": {
      "description": "A provider-normalized address; default memory uses 0x-prefixed hexadecimal",
      "type": "string"
    },
    "__schema1": {
      "$ref": "#/$defs/__schema2",
      "description": "The active target's provider document name; use open_binary to switch targets"
    },
    "__schema2": {
      "type": "string"
    }
  },
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "additionalProperties": false,
  "examples": [
    {
      "address": "0x1000"
    }
  ],
  "properties": {
    "address": {
      "$ref": "#/$defs/__schema0",
      "description": "A provider-normalized address; default memory uses 0x-prefixed hexadecimal"
    },
    "document": {
      "$ref": "#/$defs/__schema1",
      "description": "The active target's provider document name; use open_binary to switch targets"
    }
  },
  "required": [
    "address"
  ],
  "type": "object"
}
```

</details>

**Output schema:** see [`tool-specs/unset_bookmark.json`](../tool-specs/unset_bookmark.json) (`outputSchema`).

---

## xrefs

<a id="xrefs"></a>

**Title:** Xrefs  
**Kind:** `official-proxy` · **Requires session:** false · **analysisOperation:** xrefs  
**Providers:** ghidra, hopper, ida  
**Effects set (true flags):** mutatesSession  
**MCP annotations:** `{"destructiveHint":false,"idempotentHint":true,"openWorldHint":false,"readOnlyHint":false}`

**Description (verbatim, as advertised to the agent):**

> Return analyzed references to a code or data address. Hopper may default to its current cursor; headless providers such as Ghidra require an explicit address. Use to connect strings, globals, selectors, and functions; bare addresses are untyped and indirect references may be incomplete. Use inspect_native_instruction at the target address for typed incoming references where supported.

**Input schema (verbatim, JSON Schema 2020-12):**

<details><summary>inputSchema for xrefs</summary>

```json
{
  "$defs": {
    "__schema0": {
      "$ref": "#/$defs/__schema1",
      "description": "The active target's provider document name; use open_binary to switch targets"
    },
    "__schema1": {
      "type": "string"
    },
    "__schema2": {
      "description": "A provider-normalized address; default memory uses 0x-prefixed hexadecimal",
      "type": "string"
    }
  },
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "additionalProperties": false,
  "examples": [
    {}
  ],
  "properties": {
    "address": {
      "$ref": "#/$defs/__schema2",
      "description": "A provider-normalized address; default memory uses 0x-prefixed hexadecimal"
    },
    "document": {
      "$ref": "#/$defs/__schema0",
      "description": "The active target's provider document name; use open_binary to switch targets"
    }
  },
  "type": "object"
}
```

</details>

**Output schema:** see [`tool-specs/xrefs.json`](../tool-specs/xrefs.json) (`outputSchema`).

---

