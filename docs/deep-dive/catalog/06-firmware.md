# Tool family: Firmware

Generated mechanically from `.cache/mcp-tool-catalog.json` (produced by `scripts/generate-mcp-tool-catalog.mjs`, which registers every tool through the MCP SDK and exports the advertised JSON Schema 2020-12 input/output schemas) and `docs/public/product-catalog.json` (family `firmware`, surface `firmware-provider`, 2 tools). Input schemas below are **verbatim**. Output schemas are verbatim in `tool-specs/<tool>.json` (field `outputSchema`) because several exceed 100 KB; the complete per-tool spec (description, effects, annotations, inputSchema, outputSchema) is in that file.

| Tool | Kind | Session? | Providers advertising it | CLI command |
|---|---|---|---|---|
| [`extract_firmware`](#extractfirmware) | firmware-provider | no | unblob | `rea extract-firmware` |
| [`inspect_firmware_regions`](#inspectfirmwareregions) | firmware-provider | no | binwalk | `rea inspect-firmware-regions` |

## extract_firmware

<a id="extractfirmware"></a>

**Title:** Extract Firmware  
**Kind:** `firmware-provider` · **Requires session:** false · **analysisOperation:** null  
**Providers:** unblob  
**Effects set (true flags):** NOT idempotent, launchesProcess, mutatesSession, writesFilesystem  
**MCP annotations:** `{"destructiveHint":false,"idempotentHint":false,"openWorldHint":true,"readOnlyHint":false}`

**Description (verbatim, as advertised to the agent):**

> Extract caller-selected firmware bytes with Unblob 26.6.x (verified with 26.6.4) into an absent output directory. Returns verified child paths/digests, task derivations, unknown chunks, extraction diagnostics and explicit extraction_gaps rows naming unextracted regions, missing extractor dependencies and a continuation_id referencing shared extraction_continuations recovery instructions. Preserves the default sandbox; publishes regular files only. Linux, caller-supplied tool, format-specific extractors and util-linux prlimit required. No mounts or extracted-code execution. Select a returned native file with open_binary for Ghidra analysis; decompressed offsets are not original-file addresses.

**Input schema (verbatim, JSON Schema 2020-12):**

<details><summary>inputSchema for extract_firmware</summary>

```json
{
  "$defs": {
    "__schema0": {
      "$ref": "#/$defs/__schema1",
      "description": "Absolute local firmware file; never executed. Relative paths are rejected.",
      "minLength": 1,
      "pattern": "^[^\\x00]*$",
      "type": "string"
    },
    "__schema1": {
      "minLength": 1,
      "pattern": "^[^\\x00]*$",
      "type": "string"
    },
    "__schema10": {
      "$ref": "#/$defs/__schema11",
      "default": 10000,
      "description": "Staging entry budget, including directories and links"
    },
    "__schema11": {
      "maximum": 100000,
      "minimum": 1,
      "type": "integer"
    },
    "__schema2": {
      "$ref": "#/$defs/__schema1",
      "description": "Absolute, absent output directory; parent must exist",
      "minLength": 1,
      "pattern": "^[^\\x00]*$",
      "type": "string"
    },
    "__schema3": {
      "$ref": "#/$defs/__schema4",
      "description": "Explicit file-byte interval; omit to extract the whole file"
    },
    "__schema4": {
      "additionalProperties": false,
      "properties": {
        "length": {
          "$ref": "#/$defs/__schema5",
          "exclusiveMinimum": 0
        },
        "offset": {
          "$ref": "#/$defs/__schema5"
        }
      },
      "required": [
        "offset",
        "length"
      ],
      "type": "object"
    },
    "__schema5": {
      "maximum": 9007199254740991,
      "minimum": 0,
      "type": "integer"
    },
    "__schema6": {
      "$ref": "#/$defs/__schema7",
      "default": 3,
      "description": "Extraction depth; reaching it yields partial analysis"
    },
    "__schema7": {
      "maximum": 10,
      "minimum": 1,
      "type": "integer"
    },
    "__schema8": {
      "$ref": "#/$defs/__schema9",
      "default": 268435456,
      "description": "Staging file-byte budget, checked during extraction; transient overshoot is possible"
    },
    "__schema9": {
      "maximum": 536870912,
      "minimum": 1,
      "type": "integer"
    }
  },
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "additionalProperties": false,
  "examples": [
    {
      "output_directory": "/tmp/firmware-output",
      "path": "/tmp/firmware.bin",
      "range": {
        "length": 4096,
        "offset": 64
      }
    }
  ],
  "properties": {
    "max_depth": {
      "$ref": "#/$defs/__schema6",
      "description": "Extraction depth; reaching it yields partial analysis"
    },
    "max_output_bytes": {
      "$ref": "#/$defs/__schema8",
      "description": "Staging file-byte budget, checked during extraction; transient overshoot is possible"
    },
    "max_output_files": {
      "$ref": "#/$defs/__schema10",
      "description": "Staging entry budget, including directories and links"
    },
    "output_directory": {
      "$ref": "#/$defs/__schema2",
      "description": "Absolute, absent output directory; parent must exist"
    },
    "path": {
      "$ref": "#/$defs/__schema0",
      "description": "Absolute local firmware file; never executed. Relative paths are rejected."
    },
    "range": {
      "$ref": "#/$defs/__schema3",
      "description": "Explicit file-byte interval; omit to extract the whole file"
    }
  },
  "required": [
    "path",
    "output_directory"
  ],
  "type": "object"
}
```

</details>

**Output schema:** see [`tool-specs/extract_firmware.json`](../tool-specs/extract_firmware.json) (`outputSchema`).

---

## inspect_firmware_regions

<a id="inspectfirmwareregions"></a>

**Title:** Inspect Firmware Regions  
**Kind:** `firmware-provider` · **Requires session:** false · **analysisOperation:** null  
**Providers:** binwalk  
**Effects set (true flags):** launchesProcess, mutatesSession, writesFilesystem  
**MCP annotations:** `{"destructiveHint":false,"idempotentHint":true,"openWorldHint":true,"readOnlyHint":false}`

**Description (verbatim, as advertised to the agent):**

> Inspect signature candidates in a local firmware file with Binwalk 3.1.x (verified with 3.1.0). Returns offsets, reported lengths, descriptions and raw confidence values. Length validation and runtime addresses remain unknown. No extraction or target execution. Linux, caller-supplied tool and util-linux prlimit required; 128 MiB input limit, one worker and 120-second deadline.

**Input schema (verbatim, JSON Schema 2020-12):**

<details><summary>inputSchema for inspect_firmware_regions</summary>

```json
{
  "$defs": {
    "__schema0": {
      "description": "Absolute local firmware file; never executed. Relative paths are rejected.",
      "minLength": 1,
      "pattern": "^[^\\x00]*$",
      "type": "string"
    }
  },
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "additionalProperties": false,
  "examples": [
    {
      "path": "/tmp/firmware.bin"
    }
  ],
  "properties": {
    "path": {
      "$ref": "#/$defs/__schema0",
      "description": "Absolute local firmware file; never executed. Relative paths are rejected."
    }
  },
  "required": [
    "path"
  ],
  "type": "object"
}
```

</details>

**Output schema:** see [`tool-specs/inspect_firmware_regions.json`](../tool-specs/inspect_firmware_regions.json) (`outputSchema`).

---

