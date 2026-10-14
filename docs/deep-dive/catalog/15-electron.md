# Tool family: Electron / JavaScript application analysis

Generated mechanically from `.cache/mcp-tool-catalog.json` (produced by `scripts/generate-mcp-tool-catalog.mjs`, which registers every tool through the MCP SDK and exports the advertised JSON Schema 2020-12 input/output schemas) and `docs/public/product-catalog.json` (family `electron`, surface `electron-provider`, 6 tools). Input schemas below are **verbatim**. Output schemas are verbatim in `tool-specs/<tool>.json` (field `outputSchema`) because several exceed 100 KB; the complete per-tool spec (description, effects, annotations, inputSchema, outputSchema) is in that file.

| Tool | Kind | Session? | Providers advertising it | CLI command |
|---|---|---|---|---|
| [`analyze_javascript_application`](#analyzejavascriptapplication) | electron-provider | no | rea-javascript-application | `rea analyze-javascript-application` |
| [`capture_electron_scenario`](#captureelectronscenario) | electron-provider | no | rea-playwright-electron-active | `rea capture-electron-scenario` |
| [`inspect_electron_fuses`](#inspectelectronfuses) | artifact-provider | no | electron-fuses | `rea inspect-electron-fuses` |
| [`inspect_electron_page`](#inspectelectronpage) | electron-provider | no | rea-cdp-electron | `rea inspect-electron-page` |
| [`list_electron_targets`](#listelectrontargets) | electron-provider | no | rea-cdp-electron | `rea list-electron-targets` |
| [`reconcile_javascript_runtime`](#reconcilejavascriptruntime) | electron-provider | no | rea-javascript-runtime-reconciliation | `rea reconcile-javascript-runtime` |

## analyze_javascript_application

<a id="analyzejavascriptapplication"></a>

**Title:** Analyze Javascript Application  
**Kind:** `electron-provider` · **Requires session:** false · **analysisOperation:** null  
**Providers:** rea-javascript-application  
**Effects set (true flags):** mutatesSession  
**MCP annotations:** `{"destructiveHint":false,"idempotentHint":true,"openWorldHint":false,"readOnlyHint":false}`

**Description (verbatim, as advertised to the agent):**

> Reconstruct one local ASAR or extracted JavaScript application as an inline application graph without executing it. Returns recovered graph nodes, edges, semantic relations, integrity contradictions, limitations, and coverage. Select source_paths to acquire and analyze only exact inventoried file paths; the complete artifact inventory and identity remain intact, and unselected sources remain explicit unknowns. Dependencies are not implicitly analyzed. Select detail summary to retain the complete analysis Evidence in this session and receive only its summary view, then inspect selected modules or pages with inspect_analysis_view. Summary detail reduces delivery, whereas source_paths bounds source analysis. Integrity mismatches fail by default; record-and-continue retains observed bytes as untrusted and marks graph coverage partial.

**Input schema (verbatim, JSON Schema 2020-12):**

<details><summary>inputSchema for analyze_javascript_application</summary>

```json
{
  "$defs": {
    "__schema0": {
      "minLength": 1,
      "pattern": "^[^\\x00]*$",
      "type": "string"
    },
    "__schema1": {
      "default": "auto",
      "enum": [
        "auto",
        "asar",
        "directory"
      ],
      "type": "string"
    },
    "__schema10": {
      "maximum": 16384,
      "minimum": 128,
      "type": "integer"
    },
    "__schema11": {
      "$ref": "#/$defs/__schema12",
      "description": "Maximum startup, analysis and transfer time per JavaScript source, in milliseconds; defaults to 300000. On timeout, return collected partial Evidence and stop the analysis."
    },
    "__schema12": {
      "maximum": 2147483647,
      "minimum": 1,
      "type": "integer"
    },
    "__schema13": {
      "$ref": "#/$defs/__schema14",
      "default": "complete",
      "description": "complete returns the complete analysis Evidence inline. summary retains that complete Evidence in this session and returns its inspect_analysis_view summary; inspect pages, items or facets through normalized_result.parent_evidence_id."
    },
    "__schema14": {
      "enum": [
        "complete",
        "summary"
      ],
      "type": "string"
    },
    "__schema2": {
      "default": "fail",
      "enum": [
        "fail",
        "record-and-continue"
      ],
      "type": "string"
    },
    "__schema3": {
      "description": "Exact relevant file paths from the artifact inventory, relative to the application root, analyzed in first-request order before unselected scopes; no globs or implicit dependencies. Omit to analyze all sources.",
      "items": {
        "$ref": "#/$defs/__schema4"
      },
      "minItems": 1,
      "type": "array"
    },
    "__schema4": {
      "minLength": 1,
      "type": "string"
    },
    "__schema5": {
      "$ref": "#/$defs/__schema6",
      "description": "Maximum retained semantic nodes across the application; defaults to 100000. Worker heap and parent result admission remain enforced."
    },
    "__schema6": {
      "maximum": 1000000,
      "minimum": 1,
      "type": "integer"
    },
    "__schema7": {
      "$ref": "#/$defs/__schema8",
      "description": "Maximum retained semantic nodes per source file; defaults to 20000, additionally bounded by max_semantic_nodes and memory/transfer limits."
    },
    "__schema8": {
      "maximum": 1000000,
      "minimum": 1,
      "type": "integer"
    },
    "__schema9": {
      "$ref": "#/$defs/__schema10",
      "description": "Maximum V8 old-space heap in MiB for the isolated JavaScript source analyzer; defaults to 1024. This does not change the CLI/MCP process heap. When REA runs on Bun, which ignores V8 heap flags, Windows instead limits the analyzer's committed memory to this budget plus a 512 MiB runtime reserve; other Bun hosts enforce no limit."
    }
  },
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "additionalProperties": false,
  "examples": [
    {
      "format": "auto",
      "input_path": "/Applications/Example.app/Contents/Resources/app.asar",
      "integrity_policy": "fail"
    },
    {
      "detail": "summary",
      "input_path": "/Applications/Example.app/Contents/Resources/app.asar",
      "source_paths": [
        "package.json",
        "main.js",
        "preload.js"
      ]
    },
    {
      "detail": "summary",
      "input_path": "/Applications/Example.app/Contents/Resources/app.asar"
    }
  ],
  "properties": {
    "analysis_timeout_ms": {
      "$ref": "#/$defs/__schema11",
      "description": "Maximum startup, analysis and transfer time per JavaScript source, in milliseconds; defaults to 300000. On timeout, return collected partial Evidence and stop the analysis."
    },
    "detail": {
      "$ref": "#/$defs/__schema13",
      "description": "complete returns the complete analysis Evidence inline. summary retains that complete Evidence in this session and returns its inspect_analysis_view summary; inspect pages, items or facets through normalized_result.parent_evidence_id."
    },
    "format": {
      "$ref": "#/$defs/__schema1",
      "description": "Declared input artifact format."
    },
    "input_path": {
      "$ref": "#/$defs/__schema0",
      "description": "Local filesystem path for input."
    },
    "integrity_policy": {
      "$ref": "#/$defs/__schema2"
    },
    "max_heap_mb": {
      "$ref": "#/$defs/__schema9",
      "description": "Maximum V8 old-space heap in MiB for the isolated JavaScript source analyzer; defaults to 1024. This does not change the CLI/MCP process heap. When REA runs on Bun, which ignores V8 heap flags, Windows instead limits the analyzer's committed memory to this budget plus a 512 MiB runtime reserve; other Bun hosts enforce no limit."
    },
    "max_semantic_nodes": {
      "$ref": "#/$defs/__schema5",
      "description": "Maximum retained semantic nodes across the application; defaults to 100000. Worker heap and parent result admission remain enforced."
    },
    "max_semantic_nodes_per_file": {
      "$ref": "#/$defs/__schema7",
      "description": "Maximum retained semantic nodes per source file; defaults to 20000, additionally bounded by max_semantic_nodes and memory/transfer limits."
    },
    "source_paths": {
      "$ref": "#/$defs/__schema3",
      "description": "Exact relevant file paths from the artifact inventory, relative to the application root, analyzed in first-request order before unselected scopes; no globs or implicit dependencies. Omit to analyze all sources."
    }
  },
  "required": [
    "input_path"
  ],
  "type": "object"
}
```

</details>

**Output schema:** see [`tool-specs/analyze_javascript_application.json`](../tool-specs/analyze_javascript_application.json) (`outputSchema`).

---

## capture_electron_scenario

<a id="captureelectronscenario"></a>

**Title:** Capture Electron Scenario  
**Kind:** `electron-provider` · **Requires session:** false · **analysisOperation:** null  
**Providers:** rea-playwright-electron-active  
**Effects set (true flags):** accessesNetwork, changesUiState, executesForeignCode, NOT idempotent, launchesProcess, mayDiscardData, mutatesSession, mutatesTarget, writesFilesystem  
**MCP annotations:** `{"destructiveHint":true,"idempotentHint":false,"openWorldHint":true,"readOnlyHint":false}`

**Description (verbatim, as advertised to the agent):**

> Use this for a provider-owned Electron run when passive CDP or Inspector observation cannot exercise application behavior. REA owns startup and teardown, accepts caller-defined click/wait actions plus window-targeted renderer reload/crash and synthetic open-url/second-instance delivery, and returns correlated window/WebContents/process/preload/session/navigation/shell/IPC evidence without retaining payload values. Actions wait for completion or request cancellation; a missing click target can keep the request pending. Results identify observed and unavailable event families, coverage status, action targets, and truncation. Cleanup failures retain collected observations with explicit cleanup uncertainty. External shell, navigation, permission, download, popup, updater, and OS-integration effects are blocked and recorded. Use passive Electron tools for observation-only work.

**Input schema (verbatim, JSON Schema 2020-12):**

<details><summary>inputSchema for capture_electron_scenario</summary>

```json
{
  "$defs": {
    "__schema0": {
      "$ref": "#/$defs/__schema1",
      "description": "Absolute local filesystem path for the Electron executable; relative paths are rejected."
    },
    "__schema1": {
      "minLength": 1,
      "pattern": "^[^\\x00]*$",
      "type": "string"
    },
    "__schema2": {
      "$ref": "#/$defs/__schema1",
      "description": "Absolute local filesystem path for the Electron application; relative paths are rejected."
    },
    "__schema3": {
      "$ref": "#/$defs/__schema1",
      "description": "Absolute local filesystem root for application-relative paths; omit to derive it from the application path. Relative paths are rejected."
    },
    "__schema4": {
      "default": [],
      "items": {
        "pattern": "^[^\\x00]*$",
        "type": "string"
      },
      "type": "array"
    },
    "__schema5": {
      "default": [],
      "items": {
        "oneOf": [
          {
            "additionalProperties": false,
            "properties": {
              "kind": {
                "const": "click",
                "type": "string"
              },
              "selector": {
                "minLength": 1,
                "type": "string"
              },
              "step_id": {
                "minLength": 1,
                "type": "string"
              },
              "window_index": {
                "$ref": "#/$defs/__schema6",
                "default": 0
              }
            },
            "required": [
              "step_id",
              "kind",
              "selector"
            ],
            "type": "object"
          },
          {
            "additionalProperties": false,
            "properties": {
              "duration_ms": {
                "maximum": 9007199254740991,
                "minimum": 0,
                "type": "integer"
              },
              "kind": {
                "const": "wait",
                "type": "string"
              },
              "step_id": {
                "minLength": 1,
                "type": "string"
              },
              "window_index": {
                "$ref": "#/$defs/__schema6"
              }
            },
            "required": [
              "step_id",
              "kind",
              "duration_ms"
            ],
            "type": "object"
          },
          {
            "additionalProperties": false,
            "properties": {
              "kind": {
                "const": "renderer-reload",
                "type": "string"
              },
              "step_id": {
                "minLength": 1,
                "type": "string"
              },
              "window_index": {
                "$ref": "#/$defs/__schema6",
                "default": 0
              }
            },
            "required": [
              "step_id",
              "kind"
            ],
            "type": "object"
          },
          {
            "additionalProperties": false,
            "properties": {
              "kind": {
                "const": "renderer-crash",
                "type": "string"
              },
              "step_id": {
                "minLength": 1,
                "type": "string"
              },
              "window_index": {
                "$ref": "#/$defs/__schema6",
                "default": 0
              }
            },
            "required": [
              "step_id",
              "kind"
            ],
            "type": "object"
          },
          {
            "additionalProperties": false,
            "properties": {
              "delivery": {
                "enum": [
                  "open-url",
                  "second-instance"
                ],
                "type": "string"
              },
              "kind": {
                "const": "deep-link",
                "type": "string"
              },
              "step_id": {
                "minLength": 1,
                "type": "string"
              },
              "url": {
                "minLength": 1,
                "type": "string"
              }
            },
            "required": [
              "step_id",
              "kind",
              "delivery",
              "url"
            ],
            "type": "object"
          }
        ]
      },
      "type": "array"
    },
    "__schema6": {
      "maximum": 9007199254740991,
      "minimum": 0,
      "type": "integer"
    }
  },
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "additionalProperties": false,
  "examples": [
    {
      "actions": [
        {
          "kind": "click",
          "selector": "#run",
          "step_id": "exercise-ipc"
        }
      ],
      "application_path": "/Applications/Example.app/Contents/Resources/main.js",
      "args": [],
      "executable_path": "/Applications/Electron.app/Contents/MacOS/Electron"
    }
  ],
  "properties": {
    "actions": {
      "$ref": "#/$defs/__schema5"
    },
    "application_path": {
      "$ref": "#/$defs/__schema2",
      "description": "Absolute local filesystem path for the Electron application; relative paths are rejected."
    },
    "application_root": {
      "$ref": "#/$defs/__schema3",
      "description": "Absolute local filesystem root for application-relative paths; omit to derive it from the application path. Relative paths are rejected."
    },
    "args": {
      "$ref": "#/$defs/__schema4"
    },
    "executable_path": {
      "$ref": "#/$defs/__schema0",
      "description": "Absolute local filesystem path for the Electron executable; relative paths are rejected."
    }
  },
  "required": [
    "executable_path",
    "application_path"
  ],
  "type": "object"
}
```

</details>

**Output schema:** see [`tool-specs/capture_electron_scenario.json`](../tool-specs/capture_electron_scenario.json) (`outputSchema`).

---

## inspect_electron_fuses

<a id="inspectelectronfuses"></a>

**Title:** Inspect Electron Fuses  
**Kind:** `artifact-provider` · **Requires session:** false · **analysisOperation:** inspect_electron_fuses  
**Providers:** electron-fuses  
**Effects set (true flags):** mutatesSession  
**MCP annotations:** `{"destructiveHint":false,"idempotentHint":true,"openWorldHint":false,"readOnlyHint":false}`

**Description (verbatim, as advertised to the agent):**

> Inspect packaged Electron fuse bytes in one local macOS app bundle, Electron Framework binary, Windows PE executable, or Linux ELF executable. Returns the artifact digest, per-slice wire version, fuse index, version-1 name, state, and raw byte, plus derived implications for Inspector flags, ELECTRON_RUN_AS_NODE, embedded ASAR integrity, and app.asar-only loading. A missing sentinel is unknown fuse state. Reads artifact bytes only and does not modify the selected file or open a runtime target.

**Input schema (verbatim, JSON Schema 2020-12):**

<details><summary>inputSchema for inspect_electron_fuses</summary>

```json
{
  "$defs": {
    "__schema0": {
      "description": "Absolute filesystem path to a macOS .app bundle, Electron Framework binary, Windows PE executable, or Linux ELF executable",
      "minLength": 1,
      "pattern": "^[^\\x00]*$",
      "type": "string"
    }
  },
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "additionalProperties": false,
  "examples": [
    {
      "path": "/Applications/Example.app"
    }
  ],
  "properties": {
    "path": {
      "$ref": "#/$defs/__schema0",
      "description": "Absolute filesystem path to a macOS .app bundle, Electron Framework binary, Windows PE executable, or Linux ELF executable"
    }
  },
  "required": [
    "path"
  ],
  "type": "object"
}
```

</details>

**Output schema:** see [`tool-specs/inspect_electron_fuses.json`](../tool-specs/inspect_electron_fuses.json) (`outputSchema`).

---

## inspect_electron_page

<a id="inspectelectronpage"></a>

**Title:** Inspect Electron Page  
**Kind:** `electron-provider` · **Requires session:** false · **analysisOperation:** null  
**Providers:** rea-cdp-electron  
**Effects set (true flags):** accessesNetwork, mutatesSession  
**MCP annotations:** `{"destructiveHint":false,"idempotentHint":true,"openWorldHint":true,"readOnlyHint":false}`

**Description (verbatim, as advertised to the agent):**

> Passively inspect one Electron file page by supplying its loopback CDP endpoint and target ID. The provider rechecks that the target currently exists at that endpoint and is a local file page. Returns frames, DOM structure, resource paths, and scripts without evaluating renderer JavaScript or invoking Electron APIs. The selected endpoint exposes every local file page and its metadata to this tool.

**Input schema (verbatim, JSON Schema 2020-12):**

<details><summary>inputSchema for inspect_electron_page</summary>

```json
{
  "$defs": {
    "__schema0": {
      "additionalProperties": false,
      "properties": {
        "cdp_endpoint": {
          "$ref": "#/$defs/__schema1",
          "description": "Literal loopback Chrome DevTools Protocol endpoint."
        },
        "include_script_sources": {
          "const": false,
          "default": false,
          "description": "Whether to include script sources in the result.",
          "type": "boolean"
        },
        "observation_ms": {
          "$ref": "#/$defs/__schema3"
        },
        "target_id": {
          "$ref": "#/$defs/__schema2",
          "description": "Exact CDP target identifier selected from the endpoint's target listing."
        }
      },
      "required": [
        "cdp_endpoint",
        "target_id"
      ],
      "type": "object"
    },
    "__schema1": {
      "minLength": 1,
      "type": "string"
    },
    "__schema2": {
      "minLength": 1,
      "type": "string"
    },
    "__schema3": {
      "default": 100,
      "maximum": 9007199254740991,
      "minimum": 0,
      "type": "integer"
    },
    "__schema4": {
      "additionalProperties": false,
      "properties": {
        "cdp_endpoint": {
          "$ref": "#/$defs/__schema1",
          "description": "Literal loopback Chrome DevTools Protocol endpoint."
        },
        "include_script_sources": {
          "const": true,
          "description": "Whether to include script sources in the result.",
          "type": "boolean"
        },
        "observation_ms": {
          "$ref": "#/$defs/__schema3"
        },
        "target_id": {
          "$ref": "#/$defs/__schema2",
          "description": "Exact CDP target identifier selected from the endpoint's target listing."
        }
      },
      "required": [
        "cdp_endpoint",
        "target_id",
        "include_script_sources"
      ],
      "type": "object"
    }
  },
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "additionalProperties": false,
  "description": "Provide a complete input group: cdp_endpoint + target_id + [observation_ms] + [include_script_sources]; cdp_endpoint + target_id + include_script_sources + [observation_ms].",
  "examples": [
    {
      "cdp_endpoint": "http://127.0.0.1:9223",
      "target_id": "TARGET_ID_FROM_LIST_ELECTRON_TARGETS"
    }
  ],
  "minProperties": 2,
  "properties": {
    "cdp_endpoint": {
      "$ref": "#/$defs/__schema1",
      "description": "Literal loopback Chrome DevTools Protocol endpoint."
    },
    "include_script_sources": {
      "anyOf": [
        {
          "const": false,
          "default": false,
          "type": "boolean"
        },
        {
          "const": true,
          "type": "boolean"
        }
      ],
      "description": "Whether to include script sources in the result."
    },
    "observation_ms": {
      "$ref": "#/$defs/__schema3"
    },
    "target_id": {
      "$ref": "#/$defs/__schema2",
      "description": "Exact CDP target identifier selected from the endpoint's target listing."
    }
  },
  "required": [
    "cdp_endpoint",
    "target_id"
  ],
  "type": "object"
}
```

</details>

**Output schema:** see [`tool-specs/inspect_electron_page.json`](../tool-specs/inspect_electron_page.json) (`outputSchema`).

---

## list_electron_targets

<a id="listelectrontargets"></a>

**Title:** List Electron Targets  
**Kind:** `electron-provider` · **Requires session:** false · **analysisOperation:** null  
**Providers:** rea-cdp-electron  
**Effects set (true flags):** accessesNetwork, mutatesSession  
**MCP annotations:** `{"destructiveHint":false,"idempotentHint":true,"openWorldHint":true,"readOnlyHint":false}`

**Description (verbatim, as advertised to the agent):**

> List every Electron file:// page target from a selected loopback CDP endpoint. Local file paths are canonicalized after symlink resolution. Selecting an endpoint exposes every eligible target and its local path metadata.

**Input schema (verbatim, JSON Schema 2020-12):**

<details><summary>inputSchema for list_electron_targets</summary>

```json
{
  "$defs": {
    "__schema0": {
      "minLength": 1,
      "type": "string"
    }
  },
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "additionalProperties": false,
  "examples": [
    {
      "cdp_endpoint": "http://127.0.0.1:9223"
    }
  ],
  "properties": {
    "cdp_endpoint": {
      "$ref": "#/$defs/__schema0",
      "description": "Literal loopback Chrome DevTools Protocol endpoint."
    }
  },
  "required": [
    "cdp_endpoint"
  ],
  "type": "object"
}
```

</details>

**Output schema:** see [`tool-specs/list_electron_targets.json`](../tool-specs/list_electron_targets.json) (`outputSchema`).

---

## reconcile_javascript_runtime

<a id="reconcilejavascriptruntime"></a>

**Title:** Reconcile Javascript Runtime  
**Kind:** `electron-provider` · **Requires session:** false · **analysisOperation:** null  
**Providers:** rea-javascript-runtime-reconciliation  
**Effects set (true flags):** mutatesSession  
**MCP annotations:** `{"destructiveHint":false,"idempotentHint":true,"openWorldHint":false,"readOnlyHint":false}`

**Description (verbatim, as advertised to the agent):**

> Reconcile verified static JavaScript application graphs with existing passive web/Electron CDP, passive V8 Inspector, or provider-owned active Electron Evidence. Active Electron captures contribute an explicitly partial target-only runtime record; they never invent renderer scripts, frames, workers, or execution claims. Exact captured-source digests take priority over caller-declared file/URL mappings; target, frame, script, and worker ambiguity remains explicit, and source-map authority stays separate.

**Input schema (verbatim, JSON Schema 2020-12):**

<details><summary>inputSchema for reconcile_javascript_runtime</summary>

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "additionalProperties": false,
  "properties": {
    "runtime_observations": {
      "items": {
        "additionalProperties": false,
        "properties": {
          "analysis_profile": {
            "anyOf": [
              {
                "additionalProperties": false,
                "properties": {
                  "digest": {
                    "pattern": "^[a-f0-9]{64}$",
                    "type": "string"
                  },
                  "parameters": {
                    "additionalProperties": {},
                    "type": "object"
                  },
                  "provider": {
                    "additionalProperties": false,
                    "properties": {
                      "id": {
                        "minLength": 1,
                        "type": "string"
                      },
                      "name": {
                        "description": "Exact name used by this operation.",
                        "minLength": 1,
                        "type": "string"
                      },
                      "version": {
                        "minLength": 1,
                        "type": "string"
                      }
                    },
                    "required": [
                      "id",
                      "name",
                      "version"
                    ],
                    "type": "object"
                  }
                },
                "required": [
                  "provider",
                  "parameters",
                  "digest"
                ],
                "type": "object"
              },
              {
                "type": "null"
              }
            ]
          },
          "authority": {
            "enum": [
              "shipped-artifact",
              "controlled-replay",
              "historical-reference",
              "external-service",
              "analyst-inference"
            ],
            "type": "string"
          },
          "confidence": {
            "enum": [
              "observed",
              "derived",
              "inferred"
            ],
            "type": "string"
          },
          "environment": {
            "anyOf": [
              {
                "additionalProperties": false,
                "properties": {
                  "architecture": {
                    "minLength": 1,
                    "type": "string"
                  },
                  "id": {
                    "minLength": 1,
                    "type": "string"
                  },
                  "isolation": {
                    "enum": [
                      "none",
                      "process",
                      "container",
                      "virtual-machine"
                    ],
                    "type": "string"
                  },
                  "platform": {
                    "minLength": 1,
                    "type": "string"
                  }
                },
                "required": [
                  "id",
                  "platform",
                  "architecture",
                  "isolation"
                ],
                "type": "object"
              },
              {
                "type": "null"
              }
            ]
          },
          "evidence_id": {
            "description": "Stable identifier of the recorded Evidence observation.",
            "pattern": "^ev_[a-f0-9]{64}$",
            "type": "string"
          },
          "evidence_links": {
            "items": {
              "pattern": "^ev_[a-f0-9]{64}$",
              "type": "string"
            },
            "type": "array"
          },
          "limitations": {
            "items": {
              "type": "string"
            },
            "type": "array"
          },
          "locations": {
            "items": {
              "oneOf": [
                {
                  "additionalProperties": false,
                  "properties": {
                    "address": {
                      "minLength": 1,
                      "type": "string"
                    },
                    "kind": {
                      "const": "address",
                      "type": "string"
                    }
                  },
                  "required": [
                    "kind",
                    "address"
                  ],
                  "type": "object"
                },
                {
                  "additionalProperties": false,
                  "properties": {
                    "end": {
                      "minLength": 1,
                      "type": "string"
                    },
                    "kind": {
                      "const": "address-range",
                      "type": "string"
                    },
                    "start": {
                      "minLength": 1,
                      "type": "string"
                    }
                  },
                  "required": [
                    "kind",
                    "start",
                    "end"
                  ],
                  "type": "object"
                },
                {
                  "additionalProperties": false,
                  "properties": {
                    "kind": {
                      "const": "artifact-path",
                      "type": "string"
                    },
                    "path": {
                      "description": "Local filesystem path used by this operation.",
                      "minLength": 1,
                      "type": "string"
                    }
                  },
                  "required": [
                    "kind",
                    "path"
                  ],
                  "type": "object"
                },
                {
                  "additionalProperties": false,
                  "properties": {
                    "kind": {
                      "const": "file-offset",
                      "type": "string"
                    },
                    "offset": {
                      "maximum": 9007199254740991,
                      "minimum": 0,
                      "type": "integer"
                    }
                  },
                  "required": [
                    "kind",
                    "offset"
                  ],
                  "type": "object"
                },
                {
                  "additionalProperties": false,
                  "properties": {
                    "end": {
                      "maximum": 9007199254740991,
                      "minimum": 0,
                      "type": "integer"
                    },
                    "kind": {
                      "const": "file-offset-range",
                      "type": "string"
                    },
                    "start": {
                      "maximum": 9007199254740991,
                      "minimum": 0,
                      "type": "integer"
                    }
                  },
                  "required": [
                    "kind",
                    "start",
                    "end"
                  ],
                  "type": "object"
                }
              ]
            },
            "type": "array"
          },
          "normalized_result": {},
          "operation": {
            "minLength": 1,
            "type": "string"
          },
          "parameters": {
            "additionalProperties": {},
            "type": "object"
          },
          "predicate_type": {
            "minLength": 1,
            "type": "string"
          },
          "provider": {
            "additionalProperties": false,
            "properties": {
              "id": {
                "minLength": 1,
                "type": "string"
              },
              "name": {
                "description": "Exact name used by this operation.",
                "minLength": 1,
                "type": "string"
              },
              "version": {
                "anyOf": [
                  {
                    "type": "string"
                  },
                  {
                    "type": "null"
                  }
                ]
              }
            },
            "required": [
              "id",
              "name",
              "version"
            ],
            "type": "object"
          },
          "raw_result": {
            "anyOf": [
              {},
              {
                "type": "null"
              }
            ]
          },
          "relationship_coverage": {
            "anyOf": [
              {
                "oneOf": [
                  {
                    "additionalProperties": false,
                    "properties": {
                      "diagnostics": {
                        "items": {
                          "minLength": 1,
                          "type": "string"
                        },
                        "minItems": 1,
                        "type": "array"
                      },
                      "status": {
                        "const": "complete",
                        "description": "Current lifecycle or verification status.",
                        "type": "string"
                      }
                    },
                    "required": [
                      "status"
                    ],
                    "type": "object"
                  },
                  {
                    "additionalProperties": false,
                    "properties": {
                      "diagnostics": {
                        "items": {
                          "minLength": 1,
                          "type": "string"
                        },
                        "minItems": 1,
                        "type": "array"
                      },
                      "limitations": {
                        "items": {
                          "minLength": 1,
                          "type": "string"
                        },
                        "minItems": 1,
                        "type": "array"
                      },
                      "limited_directions": {
                        "anyOf": [
                          {
                            "maxItems": 1,
                            "minItems": 1,
                            "prefixItems": [
                              {
                                "const": "callers",
                                "type": "string"
                              }
                            ],
                            "type": "array"
                          },
                          {
                            "maxItems": 1,
                            "minItems": 1,
                            "prefixItems": [
                              {
                                "const": "callees",
                                "type": "string"
                              }
                            ],
                            "type": "array"
                          },
                          {
                            "maxItems": 2,
                            "minItems": 2,
                            "prefixItems": [
                              {
                                "const": "callers",
                                "type": "string"
                              },
                              {
                                "const": "callees",
                                "type": "string"
                              }
                            ],
                            "type": "array"
                          }
                        ]
                      },
                      "status": {
                        "const": "partial",
                        "description": "Current lifecycle or verification status.",
                        "type": "string"
                      }
                    },
                    "required": [
                      "status",
                      "limitations"
                    ],
                    "type": "object"
                  },
                  {
                    "additionalProperties": false,
                    "properties": {
                      "diagnostics": {
                        "items": {
                          "minLength": 1,
                          "type": "string"
                        },
                        "minItems": 1,
                        "type": "array"
                      },
                      "limited_directions": {
                        "anyOf": [
                          {
                            "maxItems": 1,
                            "minItems": 1,
                            "prefixItems": [
                              {
                                "const": "callers",
                                "type": "string"
                              }
                            ],
                            "type": "array"
                          },
                          {
                            "maxItems": 1,
                            "minItems": 1,
                            "prefixItems": [
                              {
                                "const": "callees",
                                "type": "string"
                              }
                            ],
                            "type": "array"
                          },
                          {
                            "maxItems": 2,
                            "minItems": 2,
                            "prefixItems": [
                              {
                                "const": "callers",
                                "type": "string"
                              },
                              {
                                "const": "callees",
                                "type": "string"
                              }
                            ],
                            "type": "array"
                          }
                        ]
                      },
                      "reason": {
                        "minLength": 1,
                        "type": "string"
                      },
                      "status": {
                        "const": "unknown",
                        "description": "Current lifecycle or verification status.",
                        "type": "string"
                      }
                    },
                    "required": [
                      "status",
                      "reason"
                    ],
                    "type": "object"
                  }
                ]
              },
              {
                "type": "null"
              }
            ],
            "default": null
          },
          "subject": {
            "anyOf": [
              {
                "oneOf": [
                  {
                    "additionalProperties": false,
                    "properties": {
                      "architecture": {
                        "anyOf": [
                          {
                            "enum": [
                              "x86",
                              "x86_64",
                              "arm",
                              "arm64",
                              "mips",
                              "riscv",
                              "powerpc"
                            ],
                            "type": "string"
                          },
                          {
                            "type": "null"
                          }
                        ]
                      },
                      "digest": {
                        "additionalProperties": false,
                        "properties": {
                          "sha256": {
                            "pattern": "^[a-f0-9]{64}$",
                            "type": "string"
                          }
                        },
                        "required": [
                          "sha256"
                        ],
                        "type": "object"
                      },
                      "format": {
                        "description": "Declared input artifact format.",
                        "enum": [
                          "hopper",
                          "analysis-database",
                          "mach-o",
                          "elf",
                          "pe",
                          "dos-mz",
                          "dos-com",
                          "zip",
                          "ipa",
                          "apk",
                          "msix",
                          "appx",
                          "hap",
                          "hsp",
                          "app-pack",
                          "asar",
                          "dmg",
                          "pkg",
                          "plist",
                          "javascript",
                          "source-map",
                          "directory",
                          "file",
                          "unknown",
                          "mach-o-universal",
                          "javascript-bundle",
                          "entitlements"
                        ],
                        "type": "string"
                      },
                      "local_path": {
                        "description": "Local filesystem path for local.",
                        "pattern": "^[^\\x00]*$",
                        "type": "string"
                      },
                      "name": {
                        "description": "Exact name used by this operation.",
                        "minLength": 1,
                        "type": "string"
                      }
                    },
                    "required": [
                      "name",
                      "digest",
                      "local_path",
                      "format",
                      "architecture"
                    ],
                    "type": "object"
                  },
                  {
                    "additionalProperties": false,
                    "properties": {
                      "architecture": {
                        "anyOf": [
                          {
                            "enum": [
                              "6502",
                              "x86",
                              "x86_64",
                              "arm",
                              "arm64",
                              "mips",
                              "riscv",
                              "powerpc"
                            ],
                            "type": "string"
                          },
                          {
                            "type": "null"
                          }
                        ]
                      },
                      "digest": {
                        "additionalProperties": false,
                        "properties": {
                          "sha256": {
                            "pattern": "^[a-f0-9]{64}$",
                            "type": "string"
                          }
                        },
                        "required": [
                          "sha256"
                        ],
                        "type": "object"
                      },
                      "format": {
                        "const": "raw-binary",
                        "description": "Declared input artifact format.",
                        "type": "string"
                      },
                      "local_path": {
                        "description": "Local filesystem path for local.",
                        "pattern": "^[^\\x00]*$",
                        "type": "string"
                      },
                      "name": {
                        "description": "Exact name used by this operation.",
                        "minLength": 1,
                        "type": "string"
                      }
                    },
                    "required": [
                      "name",
                      "digest",
                      "local_path",
                      "format",
                      "architecture"
                    ],
                    "type": "object"
                  }
                ]
              },
              {
                "type": "null"
              }
            ]
          }
        },
        "required": [
          "evidence_id",
          "subject",
          "provider",
          "analysis_profile",
          "predicate_type",
          "operation",
          "parameters",
          "raw_result",
          "normalized_result",
          "confidence",
          "authority",
          "environment",
          "limitations",
          "locations",
          "evidence_links"
        ],
        "type": "object"
      },
      "minItems": 1,
      "type": "array"
    },
    "static_layers": {
      "items": {
        "additionalProperties": false,
        "properties": {
          "analysis": {
            "additionalProperties": false,
            "properties": {
              "analysis_profile": {
                "anyOf": [
                  {
                    "additionalProperties": false,
                    "properties": {
                      "digest": {
                        "pattern": "^[a-f0-9]{64}$",
                        "type": "string"
                      },
                      "parameters": {
                        "additionalProperties": {},
                        "type": "object"
                      },
                      "provider": {
                        "additionalProperties": false,
                        "properties": {
                          "id": {
                            "minLength": 1,
                            "type": "string"
                          },
                          "name": {
                            "description": "Exact name used by this operation.",
                            "minLength": 1,
                            "type": "string"
                          },
                          "version": {
                            "minLength": 1,
                            "type": "string"
                          }
                        },
                        "required": [
                          "id",
                          "name",
                          "version"
                        ],
                        "type": "object"
                      }
                    },
                    "required": [
                      "provider",
                      "parameters",
                      "digest"
                    ],
                    "type": "object"
                  },
                  {
                    "type": "null"
                  }
                ]
              },
              "authority": {
                "enum": [
                  "shipped-artifact",
                  "controlled-replay",
                  "historical-reference",
                  "external-service",
                  "analyst-inference"
                ],
                "type": "string"
              },
              "confidence": {
                "enum": [
                  "observed",
                  "derived",
                  "inferred"
                ],
                "type": "string"
              },
              "environment": {
                "anyOf": [
                  {
                    "additionalProperties": false,
                    "properties": {
                      "architecture": {
                        "minLength": 1,
                        "type": "string"
                      },
                      "id": {
                        "minLength": 1,
                        "type": "string"
                      },
                      "isolation": {
                        "enum": [
                          "none",
                          "process",
                          "container",
                          "virtual-machine"
                        ],
                        "type": "string"
                      },
                      "platform": {
                        "minLength": 1,
                        "type": "string"
                      }
                    },
                    "required": [
                      "id",
                      "platform",
                      "architecture",
                      "isolation"
                    ],
                    "type": "object"
                  },
                  {
                    "type": "null"
                  }
                ]
              },
              "evidence_id": {
                "description": "Stable identifier of the recorded Evidence observation.",
                "pattern": "^ev_[a-f0-9]{64}$",
                "type": "string"
              },
              "evidence_links": {
                "items": {
                  "pattern": "^ev_[a-f0-9]{64}$",
                  "type": "string"
                },
                "type": "array"
              },
              "limitations": {
                "items": {
                  "type": "string"
                },
                "type": "array"
              },
              "locations": {
                "items": {
                  "oneOf": [
                    {
                      "additionalProperties": false,
                      "properties": {
                        "address": {
                          "minLength": 1,
                          "type": "string"
                        },
                        "kind": {
                          "const": "address",
                          "type": "string"
                        }
                      },
                      "required": [
                        "kind",
                        "address"
                      ],
                      "type": "object"
                    },
                    {
                      "additionalProperties": false,
                      "properties": {
                        "end": {
                          "minLength": 1,
                          "type": "string"
                        },
                        "kind": {
                          "const": "address-range",
                          "type": "string"
                        },
                        "start": {
                          "minLength": 1,
                          "type": "string"
                        }
                      },
                      "required": [
                        "kind",
                        "start",
                        "end"
                      ],
                      "type": "object"
                    },
                    {
                      "additionalProperties": false,
                      "properties": {
                        "kind": {
                          "const": "artifact-path",
                          "type": "string"
                        },
                        "path": {
                          "description": "Local filesystem path used by this operation.",
                          "minLength": 1,
                          "type": "string"
                        }
                      },
                      "required": [
                        "kind",
                        "path"
                      ],
                      "type": "object"
                    },
                    {
                      "additionalProperties": false,
                      "properties": {
                        "kind": {
                          "const": "file-offset",
                          "type": "string"
                        },
                        "offset": {
                          "maximum": 9007199254740991,
                          "minimum": 0,
                          "type": "integer"
                        }
                      },
                      "required": [
                        "kind",
                        "offset"
                      ],
                      "type": "object"
                    },
                    {
                      "additionalProperties": false,
                      "properties": {
                        "end": {
                          "maximum": 9007199254740991,
                          "minimum": 0,
                          "type": "integer"
                        },
                        "kind": {
                          "const": "file-offset-range",
                          "type": "string"
                        },
                        "start": {
                          "maximum": 9007199254740991,
                          "minimum": 0,
                          "type": "integer"
                        }
                      },
                      "required": [
                        "kind",
                        "start",
                        "end"
                      ],
                      "type": "object"
                    }
                  ]
                },
                "type": "array"
              },
              "normalized_result": {},
              "operation": {
                "minLength": 1,
                "type": "string"
              },
              "parameters": {
                "additionalProperties": {},
                "type": "object"
              },
              "predicate_type": {
                "minLength": 1,
                "type": "string"
              },
              "provider": {
                "additionalProperties": false,
                "properties": {
                  "id": {
                    "minLength": 1,
                    "type": "string"
                  },
                  "name": {
                    "description": "Exact name used by this operation.",
                    "minLength": 1,
                    "type": "string"
                  },
                  "version": {
                    "anyOf": [
                      {
                        "type": "string"
                      },
                      {
                        "type": "null"
                      }
                    ]
                  }
                },
                "required": [
                  "id",
                  "name",
                  "version"
                ],
                "type": "object"
              },
              "raw_result": {
                "anyOf": [
                  {},
                  {
                    "type": "null"
                  }
                ]
              },
              "relationship_coverage": {
                "anyOf": [
                  {
                    "oneOf": [
                      {
                        "additionalProperties": false,
                        "properties": {
                          "diagnostics": {
                            "items": {
                              "minLength": 1,
                              "type": "string"
                            },
                            "minItems": 1,
                            "type": "array"
                          },
                          "status": {
                            "const": "complete",
                            "description": "Current lifecycle or verification status.",
                            "type": "string"
                          }
                        },
                        "required": [
                          "status"
                        ],
                        "type": "object"
                      },
                      {
                        "additionalProperties": false,
                        "properties": {
                          "diagnostics": {
                            "items": {
                              "minLength": 1,
                              "type": "string"
                            },
                            "minItems": 1,
                            "type": "array"
                          },
                          "limitations": {
                            "items": {
                              "minLength": 1,
                              "type": "string"
                            },
                            "minItems": 1,
                            "type": "array"
                          },
                          "limited_directions": {
                            "anyOf": [
                              {
                                "maxItems": 1,
                                "minItems": 1,
                                "prefixItems": [
                                  {
                                    "const": "callers",
                                    "type": "string"
                                  }
                                ],
                                "type": "array"
                              },
                              {
                                "maxItems": 1,
                                "minItems": 1,
                                "prefixItems": [
                                  {
                                    "const": "callees",
                                    "type": "string"
                                  }
                                ],
                                "type": "array"
                              },
                              {
                                "maxItems": 2,
                                "minItems": 2,
                                "prefixItems": [
                                  {
                                    "const": "callers",
                                    "type": "string"
                                  },
                                  {
                                    "const": "callees",
                                    "type": "string"
                                  }
                                ],
                                "type": "array"
                              }
                            ]
                          },
                          "status": {
                            "const": "partial",
                            "description": "Current lifecycle or verification status.",
                            "type": "string"
                          }
                        },
                        "required": [
                          "status",
                          "limitations"
                        ],
                        "type": "object"
                      },
                      {
                        "additionalProperties": false,
                        "properties": {
                          "diagnostics": {
                            "items": {
                              "minLength": 1,
                              "type": "string"
                            },
                            "minItems": 1,
                            "type": "array"
                          },
                          "limited_directions": {
                            "anyOf": [
                              {
                                "maxItems": 1,
                                "minItems": 1,
                                "prefixItems": [
                                  {
                                    "const": "callers",
                                    "type": "string"
                                  }
                                ],
                                "type": "array"
                              },
                              {
                                "maxItems": 1,
                                "minItems": 1,
                                "prefixItems": [
                                  {
                                    "const": "callees",
                                    "type": "string"
                                  }
                                ],
                                "type": "array"
                              },
                              {
                                "maxItems": 2,
                                "minItems": 2,
                                "prefixItems": [
                                  {
                                    "const": "callers",
                                    "type": "string"
                                  },
                                  {
                                    "const": "callees",
                                    "type": "string"
                                  }
                                ],
                                "type": "array"
                              }
                            ]
                          },
                          "reason": {
                            "minLength": 1,
                            "type": "string"
                          },
                          "status": {
                            "const": "unknown",
                            "description": "Current lifecycle or verification status.",
                            "type": "string"
                          }
                        },
                        "required": [
                          "status",
                          "reason"
                        ],
                        "type": "object"
                      }
                    ]
                  },
                  {
                    "type": "null"
                  }
                ],
                "default": null
              },
              "subject": {
                "anyOf": [
                  {
                    "oneOf": [
                      {
                        "additionalProperties": false,
                        "properties": {
                          "architecture": {
                            "anyOf": [
                              {
                                "enum": [
                                  "x86",
                                  "x86_64",
                                  "arm",
                                  "arm64",
                                  "mips",
                                  "riscv",
                                  "powerpc"
                                ],
                                "type": "string"
                              },
                              {
                                "type": "null"
                              }
                            ]
                          },
                          "digest": {
                            "additionalProperties": false,
                            "properties": {
                              "sha256": {
                                "pattern": "^[a-f0-9]{64}$",
                                "type": "string"
                              }
                            },
                            "required": [
                              "sha256"
                            ],
                            "type": "object"
                          },
                          "format": {
                            "description": "Declared input artifact format.",
                            "enum": [
                              "hopper",
                              "analysis-database",
                              "mach-o",
                              "elf",
                              "pe",
                              "dos-mz",
                              "dos-com",
                              "zip",
                              "ipa",
                              "apk",
                              "msix",
                              "appx",
                              "hap",
                              "hsp",
                              "app-pack",
                              "asar",
                              "dmg",
                              "pkg",
                              "plist",
                              "javascript",
                              "source-map",
                              "directory",
                              "file",
                              "unknown",
                              "mach-o-universal",
                              "javascript-bundle",
                              "entitlements"
                            ],
                            "type": "string"
                          },
                          "local_path": {
                            "description": "Local filesystem path for local.",
                            "pattern": "^[^\\x00]*$",
                            "type": "string"
                          },
                          "name": {
                            "description": "Exact name used by this operation.",
                            "minLength": 1,
                            "type": "string"
                          }
                        },
                        "required": [
                          "name",
                          "digest",
                          "local_path",
                          "format",
                          "architecture"
                        ],
                        "type": "object"
                      },
                      {
                        "additionalProperties": false,
                        "properties": {
                          "architecture": {
                            "anyOf": [
                              {
                                "enum": [
                                  "6502",
                                  "x86",
                                  "x86_64",
                                  "arm",
                                  "arm64",
                                  "mips",
                                  "riscv",
                                  "powerpc"
                                ],
                                "type": "string"
                              },
                              {
                                "type": "null"
                              }
                            ]
                          },
                          "digest": {
                            "additionalProperties": false,
                            "properties": {
                              "sha256": {
                                "pattern": "^[a-f0-9]{64}$",
                                "type": "string"
                              }
                            },
                            "required": [
                              "sha256"
                            ],
                            "type": "object"
                          },
                          "format": {
                            "const": "raw-binary",
                            "description": "Declared input artifact format.",
                            "type": "string"
                          },
                          "local_path": {
                            "description": "Local filesystem path for local.",
                            "pattern": "^[^\\x00]*$",
                            "type": "string"
                          },
                          "name": {
                            "description": "Exact name used by this operation.",
                            "minLength": 1,
                            "type": "string"
                          }
                        },
                        "required": [
                          "name",
                          "digest",
                          "local_path",
                          "format",
                          "architecture"
                        ],
                        "type": "object"
                      }
                    ]
                  },
                  {
                    "type": "null"
                  }
                ]
              }
            },
            "required": [
              "evidence_id",
              "subject",
              "provider",
              "analysis_profile",
              "predicate_type",
              "operation",
              "parameters",
              "raw_result",
              "normalized_result",
              "confidence",
              "authority",
              "environment",
              "limitations",
              "locations",
              "evidence_links"
            ],
            "type": "object"
          },
          "role": {
            "default": "application",
            "enum": [
              "application",
              "cache",
              "assets"
            ],
            "type": "string"
          },
          "runtime_mappings": {
            "default": [],
            "items": {
              "oneOf": [
                {
                  "additionalProperties": false,
                  "properties": {
                    "artifact_prefix": {
                      "default": "",
                      "type": "string"
                    },
                    "kind": {
                      "const": "file-root",
                      "type": "string"
                    },
                    "root": {
                      "minLength": 1,
                      "type": "string"
                    }
                  },
                  "required": [
                    "kind",
                    "root"
                  ],
                  "type": "object"
                },
                {
                  "additionalProperties": false,
                  "properties": {
                    "artifact_prefix": {
                      "default": "",
                      "type": "string"
                    },
                    "kind": {
                      "const": "url-prefix",
                      "type": "string"
                    },
                    "prefix": {
                      "minLength": 1,
                      "type": "string"
                    }
                  },
                  "required": [
                    "kind",
                    "prefix"
                  ],
                  "type": "object"
                }
              ]
            },
            "type": "array"
          }
        },
        "required": [
          "analysis"
        ],
        "type": "object"
      },
      "minItems": 1,
      "type": "array"
    }
  },
  "required": [
    "static_layers",
    "runtime_observations"
  ],
  "type": "object"
}
```

</details>

**Output schema:** see [`tool-specs/reconcile_javascript_runtime.json`](../tool-specs/reconcile_javascript_runtime.json) (`outputSchema`).

---

