# Tool family: Android static analysis

Generated mechanically from `.cache/mcp-tool-catalog.json` (produced by `scripts/generate-mcp-tool-catalog.mjs`, which registers every tool through the MCP SDK and exports the advertised JSON Schema 2020-12 input/output schemas) and `docs/public/product-catalog.json` (family `android`, surface `android-provider`, 5 tools). Input schemas below are **verbatim**. Output schemas are verbatim in `tool-specs/<tool>.json` (field `outputSchema`) because several exceed 100 KB; the complete per-tool spec (description, effects, annotations, inputSchema, outputSchema) is in that file.

| Tool | Kind | Session? | Providers advertising it | CLI command |
|---|---|---|---|---|
| [`inspect_android_class`](#inspectandroidclass) | android-provider | no | jadx | `rea inspect-android-class` |
| [`inspect_android_method`](#inspectandroidmethod) | android-provider | no | jadx | `rea inspect-android-method` |
| [`inspect_android_package`](#inspectandroidpackage) | android-provider | no | jadx | `rea inspect-android-package` |
| [`search_android_classes`](#searchandroidclasses) | android-provider | no | jadx | `rea search-android-classes` |
| [`trace_android_references`](#traceandroidreferences) | android-provider | no | jadx | `rea trace-android-references` |

## inspect_android_class

<a id="inspectandroidclass"></a>

**Title:** Inspect Android Class  
**Kind:** `android-provider` · **Requires session:** false · **analysisOperation:** null  
**Providers:** jadx  
**Effects set (true flags):** launchesProcess, mutatesSession, writesFilesystem  
**MCP annotations:** `{"destructiveHint":false,"idempotentHint":true,"openWorldHint":true,"readOnlyHint":false}`

**Description (verbatim, as advertised to the agent):**

> Inspect one exact Android class's parsed methods, fields and inner classes, including synthetic members. Returns display signatures and exact DEX prototypes without generating source. A prototype is not a complete raw method ID; overload indices remain consistent within the artifact and engine session.

**Input schema (verbatim, JSON Schema 2020-12):**

<details><summary>inputSchema for inspect_android_class</summary>

```json
{
  "$defs": {
    "__schema0": {
      "description": "Local APK path; the target is never executed",
      "minLength": 1,
      "pattern": "^[^\\x00]*$",
      "type": "string"
    },
    "__schema1": {
      "description": "Exact fully qualified class name",
      "minLength": 1,
      "type": "string"
    }
  },
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "additionalProperties": false,
  "examples": [
    {
      "class_name": "example.MainActivity",
      "path": "/tmp/Example.apk"
    }
  ],
  "properties": {
    "class_name": {
      "$ref": "#/$defs/__schema1",
      "description": "Exact fully qualified class name"
    },
    "path": {
      "$ref": "#/$defs/__schema0",
      "description": "Local APK path; the target is never executed"
    }
  },
  "required": [
    "path",
    "class_name"
  ],
  "type": "object"
}
```

</details>

**Output schema:** see [`tool-specs/inspect_android_class.json`](../tool-specs/inspect_android_class.json) (`outputSchema`).

---

## inspect_android_method

<a id="inspectandroidmethod"></a>

**Title:** Inspect Android Method  
**Kind:** `android-provider` · **Requires session:** false · **analysisOperation:** null  
**Providers:** jadx  
**Effects set (true flags):** launchesProcess, mutatesSession, writesFilesystem  
**MCP annotations:** `{"destructiveHint":false,"idempotentHint":true,"openWorldHint":true,"readOnlyHint":false}`

**Description (verbatim, as advertised to the agent):**

> Decompile one Android method with smali fallback. Requires explicit overload_index when multiple methods share a name. Reports its DEX prototype, representation, fallback markers and source truncation; display signatures may be aliases.

**Input schema (verbatim, JSON Schema 2020-12):**

<details><summary>inputSchema for inspect_android_method</summary>

```json
{
  "$defs": {
    "__schema0": {
      "description": "Local APK path; the target is never executed",
      "minLength": 1,
      "pattern": "^[^\\x00]*$",
      "type": "string"
    },
    "__schema1": {
      "description": "Exact fully qualified class name",
      "minLength": 1,
      "type": "string"
    },
    "__schema2": {
      "minLength": 1,
      "type": "string"
    },
    "__schema3": {
      "$ref": "#/$defs/__schema4",
      "description": "Explicit index among same-name methods; required when ambiguous"
    },
    "__schema4": {
      "maximum": 9007199254740991,
      "minimum": 0,
      "type": "integer"
    }
  },
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "additionalProperties": false,
  "examples": [
    {
      "class_name": "example.MainActivity",
      "method_name": "onCreate",
      "path": "/tmp/Example.apk"
    }
  ],
  "properties": {
    "class_name": {
      "$ref": "#/$defs/__schema1",
      "description": "Exact fully qualified class name"
    },
    "method_name": {
      "$ref": "#/$defs/__schema2"
    },
    "overload_index": {
      "$ref": "#/$defs/__schema3",
      "description": "Explicit index among same-name methods; required when ambiguous"
    },
    "path": {
      "$ref": "#/$defs/__schema0",
      "description": "Local APK path; the target is never executed"
    }
  },
  "required": [
    "path",
    "class_name",
    "method_name"
  ],
  "type": "object"
}
```

</details>

**Output schema:** see [`tool-specs/inspect_android_method.json`](../tool-specs/inspect_android_method.json) (`outputSchema`).

---

## inspect_android_package

<a id="inspectandroidpackage"></a>

**Title:** Inspect Android Package  
**Kind:** `android-provider` · **Requires session:** false · **analysisOperation:** null  
**Providers:** jadx  
**Effects set (true flags):** launchesProcess, mutatesSession, writesFilesystem  
**MCP annotations:** `{"destructiveHint":false,"idempotentHint":true,"openWorldHint":true,"readOnlyHint":false}`

**Description (verbatim, as advertised to the agent):**

> Inspect a local APK's package, SDK and permission declarations, decoded manifest and class/resource counts. Omitted or complete detail preserves the complete result. Select detail: "summary" for all declarations, engine identity and counts without decoded manifest text or duplicate raw calls; retains the complete source and returns a distinct linked inspect_analysis_view summary. Read the exact retained manifest with view kind android, facet manifest, offset and limit (UTF-16 code units), using normalized_result.parent_evidence_id. Does not execute the APK or verify signatures. Requires a caller-supplied JADX MCP JAR and JDK; uses one worker in an isolated temporary workspace.

**Input schema (verbatim, JSON Schema 2020-12):**

<details><summary>inputSchema for inspect_android_package</summary>

```json
{
  "$defs": {
    "__schema0": {
      "description": "Local APK path; the target is never executed",
      "minLength": 1,
      "pattern": "^[^\\x00]*$",
      "type": "string"
    },
    "__schema1": {
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
      "path": "/tmp/Example.apk"
    },
    {
      "detail": "summary",
      "path": "/tmp/Example.apk"
    }
  ],
  "properties": {
    "detail": {
      "$ref": "#/$defs/__schema1"
    },
    "path": {
      "$ref": "#/$defs/__schema0",
      "description": "Local APK path; the target is never executed"
    }
  },
  "required": [
    "path"
  ],
  "type": "object"
}
```

</details>

**Output schema:** see [`tool-specs/inspect_android_package.json`](../tool-specs/inspect_android_package.json) (`outputSchema`).

---

## search_android_classes

<a id="searchandroidclasses"></a>

**Title:** Search Android Classes  
**Kind:** `android-provider` · **Requires session:** false · **analysisOperation:** null  
**Providers:** jadx  
**Effects set (true flags):** launchesProcess, mutatesSession, writesFilesystem  
**MCP annotations:** `{"destructiveHint":false,"idempotentHint":true,"openWorldHint":true,"readOnlyHint":false}`

**Description (verbatim, as advertised to the agent):**

> Search complete decompiler class-name rows in an explicit local APK by case-sensitive substring. Empty query inventories all rows. Repeated names remain repeated and appear in duplicate_names; the provider accepts only class names for lookup, so these rows do not identify which same-name class node a later lookup selects. Retains artifact and engine identity; no APK execution.

**Input schema (verbatim, JSON Schema 2020-12):**

<details><summary>inputSchema for search_android_classes</summary>

```json
{
  "$defs": {
    "__schema0": {
      "description": "Local APK path; the target is never executed",
      "minLength": 1,
      "pattern": "^[^\\x00]*$",
      "type": "string"
    },
    "__schema1": {
      "description": "Case-sensitive class-name substring; empty lists all classes",
      "type": "string"
    }
  },
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "additionalProperties": false,
  "examples": [
    {
      "path": "/tmp/Example.apk",
      "query": "Activity"
    }
  ],
  "properties": {
    "path": {
      "$ref": "#/$defs/__schema0",
      "description": "Local APK path; the target is never executed"
    },
    "query": {
      "$ref": "#/$defs/__schema1",
      "description": "Case-sensitive class-name substring; empty lists all classes"
    }
  },
  "required": [
    "path",
    "query"
  ],
  "type": "object"
}
```

</details>

**Output schema:** see [`tool-specs/search_android_classes.json`](../tool-specs/search_android_classes.json) (`outputSchema`).

---

## trace_android_references

<a id="traceandroidreferences"></a>

**Title:** Trace Android References  
**Kind:** `android-provider` · **Requires session:** false · **analysisOperation:** null  
**Providers:** jadx  
**Effects set (true flags):** launchesProcess, mutatesSession, writesFilesystem  
**MCP annotations:** `{"destructiveHint":false,"idempotentHint":true,"openWorldHint":true,"readOnlyHint":false}`

**Description (verbatim, as advertised to the agent):**

> Trace incoming static using nodes to an exact Android class or selected method overload. The total counts containing nodes, not individual invoke instructions. Use inspect_android_class to choose an overload_index when names collide. Source lines and the containing node dex_offset remain unknown. direct_invokes carries exact DEX code-unit instruction offsets when available; direct_invokes_exhaustive false marks byte-bounded partial instruction evidence, and null means coverage is unknown. Using-node coverage remains separate; no runtime calls are inferred.

**Input schema (verbatim, JSON Schema 2020-12):**

<details><summary>inputSchema for trace_android_references</summary>

```json
{
  "$defs": {
    "__schema0": {
      "description": "Local APK path; the target is never executed",
      "minLength": 1,
      "pattern": "^[^\\x00]*$",
      "type": "string"
    },
    "__schema1": {
      "description": "Exact fully qualified class name",
      "minLength": 1,
      "type": "string"
    },
    "__schema2": {
      "$ref": "#/$defs/__schema3",
      "description": "Omit for class references; select ambiguous methods with overload_index"
    },
    "__schema3": {
      "minLength": 1,
      "type": "string"
    },
    "__schema4": {
      "$ref": "#/$defs/__schema5",
      "description": "Index among same-name methods from inspect_android_class; requires method_name"
    },
    "__schema5": {
      "maximum": 9007199254740991,
      "minimum": 0,
      "type": "integer"
    }
  },
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "additionalProperties": false,
  "examples": [
    {
      "class_name": "example.MainActivity",
      "path": "/tmp/Example.apk"
    }
  ],
  "properties": {
    "class_name": {
      "$ref": "#/$defs/__schema1",
      "description": "Exact fully qualified class name"
    },
    "method_name": {
      "$ref": "#/$defs/__schema2",
      "description": "Omit for class references; select ambiguous methods with overload_index"
    },
    "overload_index": {
      "$ref": "#/$defs/__schema4",
      "description": "Index among same-name methods from inspect_android_class; requires method_name"
    },
    "path": {
      "$ref": "#/$defs/__schema0",
      "description": "Local APK path; the target is never executed"
    }
  },
  "required": [
    "path",
    "class_name"
  ],
  "type": "object"
}
```

</details>

**Output schema:** see [`tool-specs/trace_android_references.json`](../tool-specs/trace_android_references.json) (`outputSchema`).

---

