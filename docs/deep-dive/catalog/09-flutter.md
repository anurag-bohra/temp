# Tool family: Flutter/Dart AOT

Generated mechanically from `.cache/mcp-tool-catalog.json` (produced by `scripts/generate-mcp-tool-catalog.mjs`, which registers every tool through the MCP SDK and exports the advertised JSON Schema 2020-12 input/output schemas) and `docs/public/product-catalog.json` (family `flutter`, surface `flutter-provider`, 2 tools). Input schemas below are **verbatim**. Output schemas are verbatim in `tool-specs/<tool>.json` (field `outputSchema`) because several exceed 100 KB; the complete per-tool spec (description, effects, annotations, inputSchema, outputSchema) is in that file.

| Tool | Kind | Session? | Providers advertising it | CLI command |
|---|---|---|---|---|
| [`identify_flutter_build`](#identifyflutterbuild) | flutter-provider | no | flutter | `rea identify-flutter-build` |
| [`inspect_dart_aot`](#inspectdartaot) | flutter-provider | no | flutter | `rea inspect-dart-aot` |

## identify_flutter_build

<a id="identifyflutterbuild"></a>

**Title:** Identify Flutter Build  
**Kind:** `flutter-provider` · **Requires session:** false · **analysisOperation:** null  
**Providers:** flutter  
**Effects set (true flags):** mutatesSession, writesFilesystem  
**MCP annotations:** `{"destructiveHint":false,"idempotentHint":true,"openWorldHint":false,"readOnlyHint":false}`

**Description (verbatim, as advertised to the agent):**

> Identify a Flutter app's build facts by pure parsing: the Dart VM snapshot hash from every lib/<abi>/libapp.so AOT section (vm and isolate, cross-checked), per-ABI library digests, the engine library's GNU build-id, and any labeled Dart version or toolchain strings libflutter.so carries. The snapshot hash is the artifact that maps to a Dart SDK release through an external dataset; REA performs no lookup. No engine, no execution, no external tools.

**Input schema (verbatim, JSON Schema 2020-12):**

<details><summary>inputSchema for identify_flutter_build</summary>

```json
{
  "$defs": {
    "__schema0": {
      "description": "Local APK file to inspect",
      "minLength": 1,
      "pattern": "^[^\\x00]*$",
      "type": "string"
    }
  },
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "additionalProperties": false,
  "examples": [
    {
      "path": "/targets/Example.apk"
    }
  ],
  "properties": {
    "path": {
      "$ref": "#/$defs/__schema0",
      "description": "Local APK file to inspect"
    }
  },
  "required": [
    "path"
  ],
  "type": "object"
}
```

</details>

**Output schema:** see [`tool-specs/identify_flutter_build.json`](../tool-specs/identify_flutter_build.json) (`outputSchema`).

---

## inspect_dart_aot

<a id="inspectdartaot"></a>

**Title:** Inspect Dart Aot  
**Kind:** `flutter-provider` · **Requires session:** false · **analysisOperation:** null  
**Providers:** flutter  
**Effects set (true flags):** mutatesSession, writesFilesystem  
**MCP annotations:** `{"destructiveHint":false,"idempotentHint":true,"openWorldHint":false,"readOnlyHint":false}`

**Description (verbatim, as advertised to the agent):**

> Inspect one ABI's Dart AOT snapshot inside an APK: the four snapshot symbols located through the ELF dynamic symbol table with their offsets, sizes, and section headers (magic, kind, length), the snapshot hash, and a bounded string-pool projection from the isolate data section (package: source URIs, dart: SDK URIs, identifier-like tokens) exposing the app's dependency structure. String-pool entries are byte-pattern observations, not deserialized cluster semantics; typed class and function recovery needs an SDK-specific parser. Omitted or complete detail returns the full observation. Select detail: "summary" for target/ABI/library identity, all snapshot headers, coverage and original lower-bound counts without string lists. The complete source stays retained; read returned strings via inspect_analysis_view with parent_evidence_id and kind dart-aot, collection package_uris/dart_uris/class_like_tokens, offset and limit. Exhausting pages does not imply complete pool coverage. No engine, no execution.

**Input schema (verbatim, JSON Schema 2020-12):**

<details><summary>inputSchema for inspect_dart_aot</summary>

```json
{
  "$defs": {
    "__schema0": {
      "description": "Local APK file carrying a Flutter AOT payload",
      "minLength": 1,
      "pattern": "^[^\\x00]*$",
      "type": "string"
    },
    "__schema1": {
      "$ref": "#/$defs/__schema2",
      "description": "ABI to inspect; defaults to arm64-v8a, x86_64, x86, armeabi-v7a, then remaining ABIs alphabetically"
    },
    "__schema2": {
      "maxLength": 16,
      "minLength": 2,
      "pattern": "^[a-z0-9_\\x2d]+$",
      "type": "string"
    },
    "__schema3": {
      "enum": [
        "complete",
        "summary"
      ],
      "type": "string"
    }
  },
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "additionalProperties": false,
  "examples": [
    {
      "path": "/targets/Example.apk"
    },
    {
      "abi": "arm64-v8a",
      "path": "/targets/Example.apk"
    },
    {
      "detail": "summary",
      "path": "/targets/Example.apk"
    }
  ],
  "properties": {
    "abi": {
      "$ref": "#/$defs/__schema1",
      "description": "ABI to inspect; defaults to arm64-v8a, x86_64, x86, armeabi-v7a, then remaining ABIs alphabetically"
    },
    "detail": {
      "$ref": "#/$defs/__schema3"
    },
    "path": {
      "$ref": "#/$defs/__schema0",
      "description": "Local APK file carrying a Flutter AOT payload"
    }
  },
  "required": [
    "path"
  ],
  "type": "object"
}
```

</details>

**Output schema:** see [`tool-specs/inspect_dart_aot.json`](../tool-specs/inspect_dart_aot.json) (`outputSchema`).

---

