# Tool family: Session, Evidence, comparison & process capture

Generated mechanically from `.cache/mcp-tool-catalog.json` (produced by `scripts/generate-mcp-tool-catalog.mjs`, which registers every tool through the MCP SDK and exports the advertised JSON Schema 2020-12 input/output schemas) and `docs/public/product-catalog.json` (family `session`, surface `session`, 21 tools). Input schemas below are **verbatim**. Output schemas are verbatim in `tool-specs/<tool>.json` (field `outputSchema`) because several exceed 100 KB; the complete per-tool spec (description, effects, annotations, inputSchema, outputSchema) is in that file.

| Tool | Kind | Session? | Providers advertising it | CLI command |
|---|---|---|---|---|
| [`binary_session`](#binarysession) | session | yes | (built-in / not provider-listed) | — |
| [`build_call_path`](#buildcallpath) | session | yes | (built-in / not provider-listed) | — |
| [`capture_process_scenario`](#captureprocessscenario) | session | yes | (built-in / not provider-listed) | — |
| [`close_binary`](#closebinary) | session | yes | (built-in / not provider-listed) | — |
| [`compare_artifacts`](#compareartifacts) | session | yes | (built-in / not provider-listed) | — |
| [`compare_bundles`](#comparebundles) | session | yes | (built-in / not provider-listed) | — |
| [`compare_functions`](#comparefunctions) | session | yes | (built-in / not provider-listed) | — |
| [`compare_process_captures`](#compareprocesscaptures) | session | yes | (built-in / not provider-listed) | `rea compare-process-captures` |
| [`correlate_static_and_runtime`](#correlatestaticandruntime) | session | yes | (built-in / not provider-listed) | — |
| [`export_evidence_bundle`](#exportevidencebundle) | session | yes | (built-in / not provider-listed) | — |
| [`find_changed_behavior`](#findchangedbehavior) | session | yes | (built-in / not provider-listed) | — |
| [`get_evidence_bundle`](#getevidencebundle) | session | yes | (built-in / not provider-listed) | — |
| [`get_navigation_context`](#getnavigationcontext) | session | yes | (built-in / not provider-listed) | — |
| [`import_evidence_bundle`](#importevidencebundle) | session | yes | (built-in / not provider-listed) | — |
| [`inspect_address_context`](#inspectaddresscontext) | session | yes | (built-in / not provider-listed) | — |
| [`list_unknowns`](#listunknowns) | session | yes | (built-in / not provider-listed) | — |
| [`open_binary`](#openbinary) | session | yes | (built-in / not provider-listed) | — |
| [`record_unknown`](#recordunknown) | session | yes | (built-in / not provider-listed) | — |
| [`update_unknown`](#updateunknown) | session | yes | (built-in / not provider-listed) | — |
| [`verify_reconstruction`](#verifyreconstruction) | session | yes | (built-in / not provider-listed) | — |
| [`verify_unknown_resolution`](#verifyunknownresolution) | session | yes | (built-in / not provider-listed) | — |

## binary_session

<a id="binarysession"></a>

**Title:** Binary Session  
**Kind:** `session` · **Requires session:** true · **analysisOperation:** null  
**Providers:** n/a  
**Effects set (true flags):** launchesProcess  
**MCP annotations:** `{"destructiveHint":false,"idempotentHint":true,"openWorldHint":true,"readOnlyHint":false}`

**Description (verbatim, as advertised to the agent):**

> Report the complete current target, provider, capability availability, client-feature, analysis, and server-identity status without starting analysis.

**Input schema (verbatim, JSON Schema 2020-12):**

<details><summary>inputSchema for binary_session</summary>

```json
{
  "$defs": {
    "__schema0": {
      "minLength": 1,
      "type": "string"
    },
    "__schema1": {
      "pattern": "^[a-f0-9]{64}$",
      "type": "string"
    },
    "__schema2": {
      "description": "Absolute local filesystem path expected for the running server; relative paths are rejected.",
      "minLength": 1,
      "pattern": "^[^\\x00]*$",
      "type": "string"
    }
  },
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "additionalProperties": false,
  "examples": [
    {}
  ],
  "properties": {
    "expected_catalog_digest": {
      "$ref": "#/$defs/__schema1",
      "description": "Expected catalog digest used to reject stale or mismatched input."
    },
    "expected_package_version": {
      "$ref": "#/$defs/__schema0",
      "description": "Expected package version used to reject stale or mismatched input."
    },
    "expected_server_path": {
      "$ref": "#/$defs/__schema2",
      "description": "Absolute local filesystem path expected for the running server; relative paths are rejected."
    }
  },
  "type": "object"
}
```

</details>

**Output schema:** see [`tool-specs/binary_session.json`](../tool-specs/binary_session.json) (`outputSchema`).

---

## build_call_path

<a id="buildcallpath"></a>

**Title:** Build Call Path  
**Kind:** `session` · **Requires session:** true · **analysisOperation:** null  
**Providers:** n/a  
**Effects set (true flags):** mutatesSession  
**MCP annotations:** `{"destructiveHint":false,"idempotentHint":true,"openWorldHint":false,"readOnlyHint":false}`

**Description (verbatim, as advertised to the agent):**

> Build every shortest direct-callee path inline from complete analyze_function Evidence records using exact canonical addresses. Missing dossiers and provider mixing remain unknown; every node and edge cites source Evidence.

**Input schema (verbatim, JSON Schema 2020-12):**

<details><summary>inputSchema for build_call_path</summary>

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "additionalProperties": false,
  "properties": {
    "functions": {
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
    "goal": {
      "additionalProperties": false,
      "properties": {
        "address": {
          "pattern": "^(?:(?:[A-Za-z0-9._~\\x2d]|%[0-9a-fA-F]{2})+:)?0[xX][0-9a-fA-F]+$",
          "type": "string"
        }
      },
      "required": [
        "address"
      ],
      "type": "object"
    },
    "start": {
      "additionalProperties": false,
      "properties": {
        "address": {
          "pattern": "^(?:(?:[A-Za-z0-9._~\\x2d]|%[0-9a-fA-F]{2})+:)?0[xX][0-9a-fA-F]+$",
          "type": "string"
        }
      },
      "required": [
        "address"
      ],
      "type": "object"
    }
  },
  "required": [
    "functions",
    "start",
    "goal"
  ],
  "type": "object"
}
```

</details>

**Output schema:** see [`tool-specs/build_call_path.json`](../tool-specs/build_call_path.json) (`outputSchema`).

---

## capture_process_scenario

<a id="captureprocessscenario"></a>

**Title:** Capture Process Scenario  
**Kind:** `session` · **Requires session:** true · **analysisOperation:** null  
**Providers:** n/a  
**Effects set (true flags):** accessesNetwork, executesForeignCode, NOT idempotent, launchesProcess, mutatesSession, writesFilesystem  
**MCP annotations:** `{"destructiveHint":true,"idempotentHint":false,"openWorldHint":true,"readOnlyHint":false}`

**Description (verbatim, as advertised to the agent):**

> Run one caller-selected command under a PTY and return process capture Evidence with residual unknowns. The renderer admits at most 1,000,000 combined terminal cells, computed as columns × (rows + scrollback); every resize uses the selected scrollback and must fit the same budget. Supply a smaller terminal shape when that product is too large; dimensions are never clamped. A command name resolves through the inherited PATH; the working directory defaults to the caller's current directory; host environment variables are inherited with scenario overrides. Environment keys cannot contain '=' or NUL, and REA_PROCESS_RUN_ID is reserved for process ownership. Filesystem snapshots are opt-in through filesystem_observation_paths. A positive finalization_ms makes a timeout or idle deadline send SIGTERM to the captured root through its start identity, keep observing, and send SIGKILL once after the interval; exit.finalization records each attempt with its delivery result and the observed exit, and cancellation still ends the run at once. The target runs with the current user's permissions; this is not a security sandbox.

**Input schema (verbatim, JSON Schema 2020-12):**

<details><summary>inputSchema for capture_process_scenario</summary>

```json
{
  "$defs": {
    "__schema0": {
      "$ref": "#/$defs/__schema1",
      "minLength": 1
    },
    "__schema1": {
      "pattern": "^[^\\x00]*$",
      "type": "string"
    },
    "__schema10": {
      "default": [],
      "items": {
        "oneOf": [
          {
            "additionalProperties": false,
            "properties": {
              "at_ms": {
                "$ref": "#/$defs/__schema11"
              },
              "data": {
                "type": "string"
              },
              "sensitive": {
                "default": false,
                "type": "boolean"
              },
              "type": {
                "const": "input",
                "type": "string"
              }
            },
            "required": [
              "at_ms",
              "type",
              "data"
            ],
            "type": "object"
          },
          {
            "additionalProperties": false,
            "properties": {
              "at_ms": {
                "$ref": "#/$defs/__schema11"
              },
              "columns": {
                "maximum": 65535,
                "minimum": 1,
                "type": "integer"
              },
              "rows": {
                "maximum": 65535,
                "minimum": 1,
                "type": "integer"
              },
              "type": {
                "const": "resize",
                "type": "string"
              }
            },
            "required": [
              "at_ms",
              "type",
              "columns",
              "rows"
            ],
            "type": "object"
          },
          {
            "additionalProperties": false,
            "properties": {
              "at_ms": {
                "$ref": "#/$defs/__schema11"
              },
              "signal": {
                "enum": [
                  "SIGINT",
                  "SIGTERM",
                  "SIGKILL"
                ],
                "type": "string"
              },
              "type": {
                "const": "signal",
                "type": "string"
              }
            },
            "required": [
              "at_ms",
              "type",
              "signal"
            ],
            "type": "object"
          }
        ]
      },
      "type": "array"
    },
    "__schema11": {
      "maximum": 9007199254740991,
      "minimum": 0,
      "type": "integer"
    },
    "__schema12": {
      "$ref": "#/$defs/__schema13",
      "default": 30000
    },
    "__schema13": {
      "exclusiveMinimum": 0,
      "maximum": 9007199254740991,
      "type": "integer"
    },
    "__schema14": {
      "$ref": "#/$defs/__schema13",
      "default": 30000
    },
    "__schema15": {
      "default": 100,
      "maximum": 9007199254740991,
      "minimum": 0,
      "type": "integer"
    },
    "__schema16": {
      "$ref": "#/$defs/__schema17",
      "default": 0,
      "description": "Milliseconds a target may keep running after SIGTERM when timeout_ms or idle_timeout_ms fires, before SIGKILL; 0 sends SIGKILL immediately. Both signals reach the captured root only while its launch-time start identity still matches; cancellation ends the run at once."
    },
    "__schema17": {
      "maximum": 9007199254740991,
      "minimum": 0,
      "type": "integer"
    },
    "__schema18": {
      "additionalProperties": false,
      "default": {
        "file_bytes": 10000000,
        "files": 10000,
        "filesystem_depth": 16,
        "output_bytes": 1000000,
        "processes": 1000
      },
      "properties": {
        "file_bytes": {
          "$ref": "#/$defs/__schema13",
          "default": 10000000,
          "description": "Byte count for file."
        },
        "files": {
          "$ref": "#/$defs/__schema13",
          "default": 10000
        },
        "filesystem_depth": {
          "default": 16,
          "maximum": 9007199254740991,
          "minimum": 0,
          "type": "integer"
        },
        "output_bytes": {
          "$ref": "#/$defs/__schema13",
          "default": 1000000,
          "description": "Byte count for output."
        },
        "processes": {
          "$ref": "#/$defs/__schema13",
          "default": 1000
        }
      },
      "type": "object"
    },
    "__schema19": {
      "additionalProperties": false,
      "default": {
        "paths": false,
        "patterns": [],
        "pids": true,
        "ports": true,
        "time_bucket_ms": 10
      },
      "properties": {
        "paths": {
          "default": false,
          "type": "boolean"
        },
        "patterns": {
          "default": [],
          "items": {
            "additionalProperties": false,
            "properties": {
              "pattern": {
                "description": "Literal text to replace in captured output; not a regular expression.",
                "type": "string"
              },
              "replacement": {
                "type": "string"
              }
            },
            "required": [
              "pattern",
              "replacement"
            ],
            "type": "object"
          },
          "type": "array"
        },
        "pids": {
          "default": true,
          "type": "boolean"
        },
        "ports": {
          "default": true,
          "type": "boolean"
        },
        "time_bucket_ms": {
          "$ref": "#/$defs/__schema13",
          "default": 10
        }
      },
      "type": "object"
    },
    "__schema2": {
      "default": [],
      "items": {
        "$ref": "#/$defs/__schema1"
      },
      "type": "array"
    },
    "__schema3": {
      "$ref": "#/$defs/__schema1",
      "default": "."
    },
    "__schema4": {
      "additionalProperties": {
        "$ref": "#/$defs/__schema1"
      },
      "default": {},
      "propertyNames": {
        "minLength": 1,
        "pattern": "^(?:[^=\\x00R][^=\\x00]*|R(?:[^=\\x00E][^=\\x00]*|E(?:[^=\\x00A][^=\\x00]*|A(?:[^=\\x00_][^=\\x00]*|_(?:[^=\\x00P][^=\\x00]*|P(?:[^=\\x00R][^=\\x00]*|R(?:[^=\\x00O][^=\\x00]*|O(?:[^=\\x00C][^=\\x00]*|C(?:[^=\\x00E][^=\\x00]*|E(?:[^=\\x00S][^=\\x00]*|S(?:[^=\\x00S][^=\\x00]*|S(?:[^=\\x00_][^=\\x00]*|_(?:[^=\\x00R][^=\\x00]*|R(?:[^=\\x00U][^=\\x00]*|U(?:[^=\\x00N][^=\\x00]*|N(?:[^=\\x00_][^=\\x00]*|_(?:[^=\\x00I][^=\\x00]*|I(?:[^=\\x00D][^=\\x00]*|D[^=\\x00]+)?)?)?)?)?)?)?)?)?)?)?)?)?)?)?)?)?)$",
        "type": "string"
      },
      "type": "object"
    },
    "__schema5": {
      "default": [],
      "items": {
        "$ref": "#/$defs/__schema1",
        "minLength": 1
      },
      "type": "array"
    },
    "__schema6": {
      "additionalProperties": false,
      "default": {
        "columns": 80,
        "rows": 24,
        "scrollback": 1000
      },
      "description": "The visible terminal and scrollback together must use at most 1,000,000 xterm renderer cells: columns × (rows + scrollback). Resize events use the same scrollback and limit.",
      "properties": {
        "columns": {
          "$ref": "#/$defs/__schema7"
        },
        "rows": {
          "$ref": "#/$defs/__schema8"
        },
        "scrollback": {
          "$ref": "#/$defs/__schema9"
        }
      },
      "type": "object"
    },
    "__schema7": {
      "default": 80,
      "maximum": 65535,
      "minimum": 1,
      "type": "integer"
    },
    "__schema8": {
      "default": 24,
      "maximum": 65535,
      "minimum": 1,
      "type": "integer"
    },
    "__schema9": {
      "default": 1000,
      "maximum": 9007199254740991,
      "minimum": 0,
      "type": "integer"
    }
  },
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "additionalProperties": false,
  "examples": [
    {
      "arguments": [],
      "environment": {},
      "events": [],
      "executable": "/usr/bin/true",
      "filesystem_observation_paths": [],
      "finalization_ms": 1500,
      "idle_timeout_ms": 30000,
      "limits": {
        "file_bytes": 10000000,
        "files": 10000,
        "filesystem_depth": 16,
        "output_bytes": 1000000,
        "processes": 1000
      },
      "normalization": {
        "paths": false,
        "patterns": [],
        "pids": true,
        "ports": true,
        "time_bucket_ms": 10
      },
      "settle_ms": 100,
      "terminal": {
        "columns": 80,
        "rows": 24,
        "scrollback": 1000
      },
      "timeout_ms": 30000,
      "working_directory": "/tmp"
    }
  ],
  "properties": {
    "arguments": {
      "$ref": "#/$defs/__schema2"
    },
    "environment": {
      "$ref": "#/$defs/__schema4"
    },
    "events": {
      "$ref": "#/$defs/__schema10"
    },
    "executable": {
      "$ref": "#/$defs/__schema0",
      "description": "Command name or executable path to run."
    },
    "filesystem_observation_paths": {
      "$ref": "#/$defs/__schema5"
    },
    "finalization_ms": {
      "$ref": "#/$defs/__schema16",
      "description": "Milliseconds a target may keep running after SIGTERM when timeout_ms or idle_timeout_ms fires, before SIGKILL; 0 sends SIGKILL immediately. Both signals reach the captured root only while its launch-time start identity still matches; cancellation ends the run at once."
    },
    "idle_timeout_ms": {
      "$ref": "#/$defs/__schema14"
    },
    "limits": {
      "$ref": "#/$defs/__schema18",
      "description": "Resource budgets that bound execution and retained output for this operation."
    },
    "normalization": {
      "$ref": "#/$defs/__schema19"
    },
    "settle_ms": {
      "$ref": "#/$defs/__schema15"
    },
    "terminal": {
      "$ref": "#/$defs/__schema6",
      "description": "The visible terminal and scrollback together must use at most 1,000,000 xterm renderer cells: columns × (rows + scrollback). Resize events use the same scrollback and limit."
    },
    "timeout_ms": {
      "$ref": "#/$defs/__schema12"
    },
    "working_directory": {
      "$ref": "#/$defs/__schema3"
    }
  },
  "required": [
    "executable"
  ],
  "type": "object"
}
```

</details>

**Output schema:** see [`tool-specs/capture_process_scenario.json`](../tool-specs/capture_process_scenario.json) (`outputSchema`).

---

## close_binary

<a id="closebinary"></a>

**Title:** Close Binary  
**Kind:** `session` · **Requires session:** true · **analysisOperation:** null  
**Providers:** n/a  
**Effects set (true flags):** NOT idempotent, mayDiscardData, mutatesSession, writesFilesystem  
**MCP annotations:** `{"destructiveHint":true,"idempotentHint":false,"openWorldHint":false,"readOnlyHint":false}`

**Description (verbatim, as advertised to the agent):**

> Drain earlier provider requests, optionally write a provider-neutral analysis snapshot atomically to the caller-supplied path, then close the active target and every provider resource started for it. Later provider requests wait until this lifecycle operation finishes. Existing files require explicit overwrite; a failed save leaves the session open so cached analysis is not lost. Metadata edits prevent immutable snapshot saves until the session is recreated; export_evidence_bundle preserves mutable observations before closing without a snapshot.

**Input schema (verbatim, JSON Schema 2020-12):**

<details><summary>inputSchema for close_binary</summary>

```json
{
  "$defs": {
    "__schema0": {
      "description": "Absolute local filesystem path for the analysis snapshot; relative paths are rejected.",
      "minLength": 1,
      "pattern": "^[^\\x00]*$",
      "type": "string"
    },
    "__schema1": {
      "default": false,
      "type": "boolean"
    }
  },
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "additionalProperties": false,
  "examples": [
    {
      "overwrite": false
    }
  ],
  "properties": {
    "overwrite": {
      "$ref": "#/$defs/__schema1",
      "description": "Whether an existing destination may be replaced."
    },
    "snapshot_path": {
      "$ref": "#/$defs/__schema0",
      "description": "Absolute local filesystem path for the analysis snapshot; relative paths are rejected."
    }
  },
  "type": "object"
}
```

</details>

**Output schema:** see [`tool-specs/close_binary.json`](../tool-specs/close_binary.json) (`outputSchema`).

---

## compare_artifacts

<a id="compareartifacts"></a>

**Title:** Compare Artifacts  
**Kind:** `session` · **Requires session:** true · **analysisOperation:** null  
**Providers:** n/a  
**Effects set (true flags):** mutatesSession  
**MCP annotations:** `{"destructiveHint":false,"idempotentHint":true,"openWorldHint":false,"readOnlyHint":false}`

**Description (verbatim, as advertised to the agent):**

> Compare complete artifact inventories by logical occurrence path, content identity, metadata, and graph relations. Pass the inventory Evidence nested in each inspect_artifact result as left and right. Every delta cites both inputs, and gaps yield truncated or unknown, never equivalence. Returns every change inline.

**Input schema (verbatim, JSON Schema 2020-12):**

<details><summary>inputSchema for compare_artifacts</summary>

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "additionalProperties": false,
  "properties": {
    "left": {
      "additionalProperties": false,
      "description": "Left-hand input used for comparison or differential execution.",
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
    "right": {
      "additionalProperties": false,
      "description": "Right-hand input used for comparison or differential execution.",
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
    }
  },
  "required": [
    "left",
    "right"
  ],
  "type": "object"
}
```

</details>

**Output schema:** see [`tool-specs/compare_artifacts.json`](../tool-specs/compare_artifacts.json) (`outputSchema`).

---

## compare_bundles

<a id="comparebundles"></a>

**Title:** Compare Bundles  
**Kind:** `session` · **Requires session:** true · **analysisOperation:** null  
**Providers:** n/a  
**Effects set (true flags):** mutatesSession  
**MCP annotations:** `{"destructiveHint":false,"idempotentHint":true,"openWorldHint":false,"readOnlyHint":false}`

**Description (verbatim, as advertised to the agent):**

> Compare two canonical Evidence bundles by exact record membership, explicit one-to-one observation pairs, and complete residual-unknown revision histories. Missing bundle members describe omission only, never behavioral equivalence; output is digest-anchored and returns every change inline.

**Input schema (verbatim, JSON Schema 2020-12):**

<details><summary>inputSchema for compare_bundles</summary>

```json
{
  "$defs": {
    "__schema0": {
      "minLength": 1,
      "pattern": "^[^\\x00]*$",
      "type": "string"
    },
    "__schema1": {
      "default": [],
      "items": {
        "properties": {
          "left_evidence_id": {
            "$ref": "#/$defs/__schema2",
            "description": "Exact Evidence identifier for the left observation."
          },
          "right_evidence_id": {
            "$ref": "#/$defs/__schema2",
            "description": "Exact Evidence identifier for the right observation."
          }
        },
        "required": [
          "left_evidence_id",
          "right_evidence_id"
        ],
        "type": "object"
      },
      "type": "array"
    },
    "__schema2": {
      "pattern": "^ev_[a-f0-9]{64}$",
      "type": "string"
    }
  },
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "additionalProperties": false,
  "examples": [
    {
      "left_bundle_path": "/tmp/left-evidence.json",
      "record_pairs": [],
      "right_bundle_path": "/tmp/right-evidence.json"
    }
  ],
  "properties": {
    "left_bundle_path": {
      "$ref": "#/$defs/__schema0",
      "description": "Local filesystem path for left bundle."
    },
    "record_pairs": {
      "$ref": "#/$defs/__schema1"
    },
    "right_bundle_path": {
      "$ref": "#/$defs/__schema0",
      "description": "Local filesystem path for right bundle."
    }
  },
  "required": [
    "left_bundle_path",
    "right_bundle_path"
  ],
  "type": "object"
}
```

</details>

**Output schema:** see [`tool-specs/compare_bundles.json`](../tool-specs/compare_bundles.json) (`outputSchema`).

---

## compare_functions

<a id="comparefunctions"></a>

**Title:** Compare Functions  
**Kind:** `session` · **Requires session:** true · **analysisOperation:** null  
**Providers:** n/a  
**Effects set (true flags):** mutatesSession  
**MCP annotations:** `{"destructiveHint":false,"idempotentHint":true,"openWorldHint":false,"readOnlyHint":false}`

**Description (verbatim, as advertised to the agent):**

> Compare two explicit sets of analyze_function Evidence across identity, exact provider text, calls, references, strings, and address-normalized CFG topology. Missing or provider-incompatible facets remain truncated or unknown; every conclusion cites both Evidence sets.

**Input schema (verbatim, JSON Schema 2020-12):**

<details><summary>inputSchema for compare_functions</summary>

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "additionalProperties": false,
  "properties": {
    "left": {
      "additionalProperties": false,
      "description": "Left-hand input used for comparison or differential execution.",
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
    "right": {
      "additionalProperties": false,
      "description": "Right-hand input used for comparison or differential execution.",
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
    }
  },
  "required": [
    "left",
    "right"
  ],
  "type": "object"
}
```

</details>

**Output schema:** see [`tool-specs/compare_functions.json`](../tool-specs/compare_functions.json) (`outputSchema`).

---

## compare_process_captures

<a id="compareprocesscaptures"></a>

**Title:** Compare Process Captures  
**Kind:** `session` · **Requires session:** true · **analysisOperation:** null  
**Providers:** n/a  
**Effects set (true flags):** mutatesSession  
**MCP annotations:** `{"destructiveHint":false,"idempotentHint":true,"openWorldHint":false,"readOnlyHint":false}`

**Description (verbatim, as advertised to the agent):**

> Compare two compatible process capture observations across terminal, interaction, lifecycle, process, filesystem, command-shim, HTTP, and WebSocket evidence. Optional trace_spec validates exact events against an explicit partial order or finite trace language; concurrency is never inferred from timestamps or broad sorting. Missing, journal-free, or truncated observations are never treated as equivalent.

**Input schema (verbatim, JSON Schema 2020-12):**

<details><summary>inputSchema for compare_process_captures</summary>

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "additionalProperties": false,
  "properties": {
    "left": {
      "additionalProperties": false,
      "description": "Left-hand input used for comparison or differential execution.",
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
    "max_capture_age_ms": {
      "description": "Maximum permitted capture age ms for this operation.",
      "maximum": 9007199254740991,
      "minimum": 0,
      "type": "integer"
    },
    "right": {
      "additionalProperties": false,
      "description": "Right-hand input used for comparison or differential execution.",
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
    "trace_spec": {
      "additionalProperties": false,
      "properties": {
        "events": {
          "items": {
            "additionalProperties": false,
            "properties": {
              "cardinality": {
                "default": {
                  "kind": "required"
                },
                "oneOf": [
                  {
                    "additionalProperties": false,
                    "properties": {
                      "kind": {
                        "const": "required",
                        "type": "string"
                      }
                    },
                    "required": [
                      "kind"
                    ],
                    "type": "object"
                  },
                  {
                    "additionalProperties": false,
                    "properties": {
                      "kind": {
                        "const": "optional",
                        "type": "string"
                      }
                    },
                    "required": [
                      "kind"
                    ],
                    "type": "object"
                  },
                  {
                    "additionalProperties": false,
                    "properties": {
                      "count": {
                        "maximum": 9007199254740991,
                        "minimum": 0,
                        "type": "integer"
                      },
                      "kind": {
                        "const": "exact",
                        "type": "string"
                      }
                    },
                    "required": [
                      "kind",
                      "count"
                    ],
                    "type": "object"
                  },
                  {
                    "additionalProperties": false,
                    "properties": {
                      "kind": {
                        "const": "range",
                        "type": "string"
                      },
                      "max": {
                        "maximum": 9007199254740991,
                        "minimum": 0,
                        "type": "integer"
                      },
                      "min": {
                        "maximum": 9007199254740991,
                        "minimum": 0,
                        "type": "integer"
                      }
                    },
                    "required": [
                      "kind",
                      "min",
                      "max"
                    ],
                    "type": "object"
                  }
                ]
              },
              "exact": {},
              "id": {
                "pattern": "^[A-Za-z][A-Za-z0-9._\\x2d]*$",
                "type": "string"
              },
              "ignore_fields": {
                "items": {
                  "enum": [
                    "sequence",
                    "at_ms",
                    "scheduled_at_ms",
                    "dispatched_at_ms",
                    "elapsed_ms"
                  ],
                  "type": "string"
                },
                "type": "array"
              },
              "source": {
                "enum": [
                  "terminal_raw",
                  "terminal_rendered",
                  "interaction",
                  "lifecycle",
                  "process",
                  "filesystem"
                ],
                "type": "string"
              }
            },
            "required": [
              "id",
              "source",
              "exact"
            ],
            "type": "object"
          },
          "minItems": 1,
          "type": "array"
        },
        "language": {
          "oneOf": [
            {
              "additionalProperties": false,
              "properties": {
                "happens_before": {
                  "default": [],
                  "items": {
                    "additionalProperties": false,
                    "properties": {
                      "after": {
                        "description": "The later or right-hand observation to compare.",
                        "pattern": "^[A-Za-z][A-Za-z0-9._\\x2d]*$",
                        "type": "string"
                      },
                      "before": {
                        "description": "The earlier or left-hand observation to compare.",
                        "pattern": "^[A-Za-z][A-Za-z0-9._\\x2d]*$",
                        "type": "string"
                      }
                    },
                    "required": [
                      "before",
                      "after"
                    ],
                    "type": "object"
                  },
                  "type": "array"
                },
                "kind": {
                  "const": "partial_order",
                  "type": "string"
                },
                "not_before": {
                  "default": [],
                  "items": {
                    "additionalProperties": false,
                    "properties": {
                      "anchor": {
                        "pattern": "^[A-Za-z][A-Za-z0-9._\\x2d]*$",
                        "type": "string"
                      },
                      "event": {
                        "pattern": "^[A-Za-z][A-Za-z0-9._\\x2d]*$",
                        "type": "string"
                      }
                    },
                    "required": [
                      "event",
                      "anchor"
                    ],
                    "type": "object"
                  },
                  "type": "array"
                },
                "prefix": {
                  "default": [],
                  "items": {
                    "pattern": "^[A-Za-z][A-Za-z0-9._\\x2d]*$",
                    "type": "string"
                  },
                  "type": "array"
                },
                "suffix": {
                  "default": [],
                  "items": {
                    "pattern": "^[A-Za-z][A-Za-z0-9._\\x2d]*$",
                    "type": "string"
                  },
                  "type": "array"
                },
                "unordered_groups": {
                  "default": [],
                  "items": {
                    "additionalProperties": false,
                    "properties": {
                      "events": {
                        "items": {
                          "pattern": "^[A-Za-z][A-Za-z0-9._\\x2d]*$",
                          "type": "string"
                        },
                        "minItems": 2,
                        "type": "array"
                      }
                    },
                    "required": [
                      "events"
                    ],
                    "type": "object"
                  },
                  "type": "array"
                }
              },
              "required": [
                "kind"
              ],
              "type": "object"
            },
            {
              "additionalProperties": false,
              "properties": {
                "kind": {
                  "const": "finite_traces",
                  "type": "string"
                },
                "variants": {
                  "items": {
                    "additionalProperties": false,
                    "properties": {
                      "id": {
                        "pattern": "^[A-Za-z][A-Za-z0-9._\\x2d]*$",
                        "type": "string"
                      },
                      "trace": {
                        "items": {
                          "anyOf": [
                            {
                              "pattern": "^[A-Za-z][A-Za-z0-9._\\x2d]*$",
                              "type": "string"
                            },
                            {
                              "additionalProperties": false,
                              "properties": {
                                "unordered": {
                                  "items": {
                                    "pattern": "^[A-Za-z][A-Za-z0-9._\\x2d]*$",
                                    "type": "string"
                                  },
                                  "minItems": 2,
                                  "type": "array"
                                }
                              },
                              "required": [
                                "unordered"
                              ],
                              "type": "object"
                            }
                          ]
                        },
                        "type": "array"
                      }
                    },
                    "required": [
                      "id",
                      "trace"
                    ],
                    "type": "object"
                  },
                  "minItems": 1,
                  "type": "array"
                }
              },
              "required": [
                "kind",
                "variants"
              ],
              "type": "object"
            }
          ]
        }
      },
      "required": [
        "events",
        "language"
      ],
      "type": "object"
    }
  },
  "required": [
    "left",
    "right"
  ],
  "type": "object"
}
```

</details>

**Output schema:** see [`tool-specs/compare_process_captures.json`](../tool-specs/compare_process_captures.json) (`outputSchema`).

---

## correlate_static_and_runtime

<a id="correlatestaticandruntime"></a>

**Title:** Correlate Static And Runtime  
**Kind:** `session` · **Requires session:** true · **analysisOperation:** null  
**Providers:** n/a  
**Effects set (true flags):** mutatesSession  
**MCP annotations:** `{"destructiveHint":false,"idempotentHint":true,"openWorldHint":false,"readOnlyHint":false}`

**Description (verbatim, as advertised to the agent):**

> Evaluate every explicit caller-declared hypothesis between exact static comparison findings and runtime comparison dimensions. Similar names or paths are never auto-matched, consistent cochange never proves causality, and unknown or truncated inputs remain unresolved. Returns all correlations and their complete Evidence closure inline.

**Input schema (verbatim, JSON Schema 2020-12):**

<details><summary>inputSchema for correlate_static_and_runtime</summary>

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "additionalProperties": false,
  "properties": {
    "mappings": {
      "items": {
        "additionalProperties": false,
        "properties": {
          "hypothesis": {
            "additionalProperties": false,
            "properties": {
              "expected_pattern": {
                "description": "Expected pattern used to reject stale or mismatched input.",
                "enum": [
                  "cochanged",
                  "static_only",
                  "runtime_only",
                  "both_unchanged"
                ],
                "type": "string"
              },
              "statement": {
                "minLength": 1,
                "type": "string"
              }
            },
            "required": [
              "statement",
              "expected_pattern"
            ],
            "type": "object"
          },
          "runtime": {
            "additionalProperties": false,
            "properties": {
              "comparison_evidence_id": {
                "description": "Exact Evidence identifier for the comparison observation.",
                "pattern": "^ev_[a-f0-9]{64}$",
                "type": "string"
              },
              "dimension": {
                "enum": [
                  "terminal",
                  "interaction",
                  "exit",
                  "filesystem",
                  "process"
                ],
                "type": "string"
              }
            },
            "required": [
              "comparison_evidence_id",
              "dimension"
            ],
            "type": "object"
          },
          "side_alignment": {
            "enum": [
              "left_to_left",
              "left_to_right"
            ],
            "type": "string"
          },
          "static": {
            "additionalProperties": false,
            "properties": {
              "comparison_evidence_id": {
                "description": "Exact Evidence identifier for the comparison observation.",
                "pattern": "^ev_[a-f0-9]{64}$",
                "type": "string"
              },
              "selector": {
                "oneOf": [
                  {
                    "additionalProperties": false,
                    "properties": {
                      "kind": {
                        "const": "artifact",
                        "type": "string"
                      },
                      "logical_path": {
                        "description": "Local filesystem path for logical.",
                        "minLength": 1,
                        "type": "string"
                      }
                    },
                    "required": [
                      "kind",
                      "logical_path"
                    ],
                    "type": "object"
                  },
                  {
                    "additionalProperties": false,
                    "properties": {
                      "dimension": {
                        "enum": [
                          "identity",
                          "pseudocode",
                          "assembly",
                          "comments",
                          "calls",
                          "references",
                          "strings_names",
                          "cfg"
                        ],
                        "type": "string"
                      },
                      "kind": {
                        "const": "function",
                        "type": "string"
                      }
                    },
                    "required": [
                      "kind",
                      "dimension"
                    ],
                    "type": "object"
                  }
                ]
              }
            },
            "required": [
              "comparison_evidence_id",
              "selector"
            ],
            "type": "object"
          }
        },
        "required": [
          "static",
          "runtime",
          "side_alignment",
          "hypothesis"
        ],
        "type": "object"
      },
      "minItems": 1,
      "type": "array"
    },
    "runtime_comparisons": {
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
    "static_comparisons": {
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
    }
  },
  "required": [
    "static_comparisons",
    "runtime_comparisons",
    "mappings"
  ],
  "type": "object"
}
```

</details>

**Output schema:** see [`tool-specs/correlate_static_and_runtime.json`](../tool-specs/correlate_static_and_runtime.json) (`outputSchema`).

---

## export_evidence_bundle

<a id="exportevidencebundle"></a>

**Title:** Export Evidence Bundle  
**Kind:** `session` · **Requires session:** true · **analysisOperation:** null  
**Providers:** n/a  
**Effects set (true flags):** mayDiscardData, writesFilesystem  
**MCP annotations:** `{"destructiveHint":true,"idempotentHint":true,"openWorldHint":false,"readOnlyHint":false}`

**Description (verbatim, as advertised to the agent):**

> Atomically write the session's deterministic Evidence bundle to the requested local path. Existing files require overwrite: true; records and manifests use canonical byte-stable ordering.

**Input schema (verbatim, JSON Schema 2020-12):**

<details><summary>inputSchema for export_evidence_bundle</summary>

```json
{
  "$defs": {
    "__schema0": {
      "description": "Absolute local filesystem path for the exported evidence bundle; relative paths are rejected.",
      "minLength": 1,
      "pattern": "^[^\\x00]*$",
      "type": "string"
    },
    "__schema1": {
      "default": false,
      "type": "boolean"
    }
  },
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "additionalProperties": false,
  "examples": [
    {
      "overwrite": false,
      "path": "/tmp/evidence.json"
    }
  ],
  "properties": {
    "overwrite": {
      "$ref": "#/$defs/__schema1",
      "description": "Whether an existing destination may be replaced."
    },
    "path": {
      "$ref": "#/$defs/__schema0",
      "description": "Absolute local filesystem path for the exported evidence bundle; relative paths are rejected."
    }
  },
  "required": [
    "path"
  ],
  "type": "object"
}
```

</details>

**Output schema:** see [`tool-specs/export_evidence_bundle.json`](../tool-specs/export_evidence_bundle.json) (`outputSchema`).

---

## find_changed_behavior

<a id="findchangedbehavior"></a>

**Title:** Find Changed Behavior  
**Kind:** `session` · **Requires session:** true · **analysisOperation:** null  
**Providers:** n/a  
**Effects set (true flags):** mutatesSession  
**MCP annotations:** `{"destructiveHint":false,"idempotentHint":true,"openWorldHint":false,"readOnlyHint":false}`

**Description (verbatim, as advertised to the agent):**

> Aggregate validated process and artifact comparison Evidence. Runtime observations remain distinct from static behavior candidates; missing or incomplete comparisons produce unresolved findings, never causal claims. Returns every finding inline.

**Input schema (verbatim, JSON Schema 2020-12):**

<details><summary>inputSchema for find_changed_behavior</summary>

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "additionalProperties": false,
  "properties": {
    "comparisons": {
      "description": "Validated comparison Evidence records to aggregate.",
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
    }
  },
  "required": [
    "comparisons"
  ],
  "type": "object"
}
```

</details>

**Output schema:** see [`tool-specs/find_changed_behavior.json`](../tool-specs/find_changed_behavior.json) (`outputSchema`).

---

## get_evidence_bundle

<a id="getevidencebundle"></a>

**Title:** Get Evidence Bundle  
**Kind:** `session` · **Requires session:** true · **analysisOperation:** null  
**Providers:** n/a  
**Effects set (true flags):** none (pure read)  
**MCP annotations:** `{"destructiveHint":false,"idempotentHint":true,"openWorldHint":false,"readOnlyHint":true}`

**Description (verbatim, as advertised to the agent):**

> Return every retained Evidence record and residual unknown as a complete canonical bundle by default. detail=summary discovers retained records without copying or transferring their payloads; optionally filter by exact Evidence ID, operation, target SHA-256, analysis-profile digest or canonical native procedure address. Metadata distinguishes complete record retention from native value-flow truncation or unavailable/unknown coverage. Use a discovered evidence_id with inspect_analysis_view without restarting a provider. Filters apply only to summary delivery.

**Input schema (verbatim, JSON Schema 2020-12):**

<details><summary>inputSchema for get_evidence_bundle</summary>

```json
{
  "$defs": {
    "__schema0": {
      "default": "complete",
      "enum": [
        "complete",
        "summary"
      ],
      "type": "string"
    },
    "__schema1": {
      "additionalProperties": false,
      "properties": {
        "analysis_profile_digest": {
          "$ref": "#/$defs/__schema2"
        },
        "evidence_id": {
          "description": "Stable identifier of the recorded Evidence observation.",
          "pattern": "^ev_[a-f0-9]{64}$",
          "type": "string"
        },
        "operation": {
          "minLength": 1,
          "type": "string"
        },
        "procedure_address": {
          "minLength": 1,
          "type": "string"
        },
        "target_sha256": {
          "$ref": "#/$defs/__schema2",
          "description": "Exact SHA-256 digest of target."
        }
      },
      "type": "object"
    },
    "__schema2": {
      "pattern": "^[a-f0-9]{64}$",
      "type": "string"
    }
  },
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "additionalProperties": false,
  "examples": [
    {
      "detail": "summary",
      "filters": {
        "operation": "analyze_function",
        "procedure_address": "0x1000"
      }
    }
  ],
  "properties": {
    "detail": {
      "$ref": "#/$defs/__schema0"
    },
    "filters": {
      "$ref": "#/$defs/__schema1"
    }
  },
  "type": "object"
}
```

</details>

**Output schema:** see [`tool-specs/get_evidence_bundle.json`](../tool-specs/get_evidence_bundle.json) (`outputSchema`).

---

## get_navigation_context

<a id="getnavigationcontext"></a>

**Title:** Get Navigation Context  
**Kind:** `session` · **Requires session:** true · **analysisOperation:** null  
**Providers:** n/a  
**Effects set (true flags):** mutatesSession  
**MCP annotations:** `{"destructiveHint":false,"idempotentHint":true,"openWorldHint":false,"readOnlyHint":false}`

**Description (verbatim, as advertised to the agent):**

> Return the selected document, current address, and containing/current procedure in one provider-neutral result. The result reflects sequential provider observations, not an atomic cursor snapshot; a cursor outside any procedure returns procedure: null.

**Input schema (verbatim, JSON Schema 2020-12):**

<details><summary>inputSchema for get_navigation_context</summary>

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
    {}
  ],
  "properties": {
    "document": {
      "$ref": "#/$defs/__schema0",
      "description": "Exact provider document or program identity."
    }
  },
  "type": "object"
}
```

</details>

**Output schema:** see [`tool-specs/get_navigation_context.json`](../tool-specs/get_navigation_context.json) (`outputSchema`).

---

## import_evidence_bundle

<a id="importevidencebundle"></a>

**Title:** Import Evidence Bundle  
**Kind:** `session` · **Requires session:** true · **analysisOperation:** null  
**Providers:** n/a  
**Effects set (true flags):** mutatesSession  
**MCP annotations:** `{"destructiveHint":false,"idempotentHint":true,"openWorldHint":false,"readOnlyHint":false}`

**Description (verbatim, as advertised to the agent):**

> Read the JSON bundle at the supplied local path, validate every Evidence ID and canonical manifest, then atomically merge it. Imported content is data only and is never executed.

**Input schema (verbatim, JSON Schema 2020-12):**

<details><summary>inputSchema for import_evidence_bundle</summary>

```json
{
  "$defs": {
    "__schema0": {
      "description": "Absolute local filesystem path for the evidence bundle to import; relative paths are rejected.",
      "minLength": 1,
      "pattern": "^[^\\x00]*$",
      "type": "string"
    }
  },
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "additionalProperties": false,
  "examples": [
    {
      "path": "/tmp/evidence.json"
    }
  ],
  "properties": {
    "path": {
      "$ref": "#/$defs/__schema0",
      "description": "Absolute local filesystem path for the evidence bundle to import; relative paths are rejected."
    }
  },
  "required": [
    "path"
  ],
  "type": "object"
}
```

</details>

**Output schema:** see [`tool-specs/import_evidence_bundle.json`](../tool-specs/import_evidence_bundle.json) (`outputSchema`).

---

## inspect_address_context

<a id="inspectaddresscontext"></a>

**Title:** Inspect Address Context  
**Kind:** `session` · **Requires session:** true · **analysisOperation:** null  
**Providers:** n/a  
**Effects set (true flags):** mutatesSession  
**MCP annotations:** `{"destructiveHint":false,"idempotentHint":true,"openWorldHint":false,"readOnlyHint":false}`

**Description (verbatim, as advertised to the agent):**

> Inspect one explicit reproducible address for its analyzed name, containing procedure, regular and inline comments, and matching bookmarks. Each unsupported facet returns a typed unavailable outcome; use xrefs, assembly, or pseudocode for those deeper views.

**Input schema (verbatim, JSON Schema 2020-12):**

<details><summary>inputSchema for inspect_address_context</summary>

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

**Output schema:** see [`tool-specs/inspect_address_context.json`](../tool-specs/inspect_address_context.json) (`outputSchema`).

---

## list_unknowns

<a id="listunknowns"></a>

**Title:** List Unknowns  
**Kind:** `session` · **Requires session:** true · **analysisOperation:** null  
**Providers:** n/a  
**Effects set (true flags):** none (pure read)  
**MCP annotations:** `{"destructiveHint":false,"idempotentHint":true,"openWorldHint":false,"readOnlyHint":true}`

**Description (verbatim, as advertised to the agent):**

> List current residual-unknown heads in deterministic ID order, with optional exact status, severity, and domain filters. Results are complete inline by default; supply offset and limit to page the filtered order. total is the matching-head count and next_offset is null when the page exhausts the result. This is read-only; unresolved, contradicted, and non-truth dispositions remain distinct.

**Input schema (verbatim, JSON Schema 2020-12):**

<details><summary>inputSchema for list_unknowns</summary>

```json
{
  "$defs": {
    "__schema0": {
      "enum": [
        "open",
        "investigating",
        "blocked",
        "contradicted",
        "resolved"
      ],
      "type": "string"
    },
    "__schema1": {
      "enum": [
        "low",
        "medium",
        "high",
        "critical"
      ],
      "type": "string"
    },
    "__schema2": {
      "minLength": 1,
      "type": "string"
    },
    "__schema3": {
      "$ref": "#/$defs/__schema4",
      "default": 0,
      "description": "Zero-based offset in the stable filtered unknown ID order."
    },
    "__schema4": {
      "maximum": 9007199254740991,
      "minimum": 0,
      "type": "integer"
    },
    "__schema5": {
      "$ref": "#/$defs/__schema6",
      "description": "Optional maximum number of heads to return. Omit to return every matching head from offset."
    },
    "__schema6": {
      "exclusiveMinimum": 0,
      "maximum": 9007199254740991,
      "type": "integer"
    }
  },
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "additionalProperties": false,
  "examples": [
    {
      "limit": 50,
      "offset": 0
    }
  ],
  "properties": {
    "domain": {
      "$ref": "#/$defs/__schema2"
    },
    "limit": {
      "$ref": "#/$defs/__schema5",
      "description": "Optional maximum number of heads to return. Omit to return every matching head from offset."
    },
    "offset": {
      "$ref": "#/$defs/__schema3",
      "description": "Zero-based offset in the stable filtered unknown ID order."
    },
    "severity": {
      "$ref": "#/$defs/__schema1"
    },
    "status": {
      "$ref": "#/$defs/__schema0",
      "description": "Current lifecycle or verification status."
    }
  },
  "type": "object"
}
```

</details>

**Output schema:** see [`tool-specs/list_unknowns.json`](../tool-specs/list_unknowns.json) (`outputSchema`).

---

## open_binary

<a id="openbinary"></a>

**Title:** Open Binary  
**Kind:** `session` · **Requires session:** true · **analysisOperation:** null  
**Providers:** n/a  
**Effects set (true flags):** launchesProcess, mutatesSession  
**MCP annotations:** `{"destructiveHint":false,"idempotentHint":true,"openWorldHint":true,"readOnlyHint":false}`

**Description (verbatim, as advertised to the agent):**

> Open a local executable, application bundle, archive, JavaScript, source map, plist, or analysis database after validation. format=dos-com explicitly interprets 1..65280 headerless bytes as a DOS COM analysis image. format=raw-binary interprets headerless bytes with a required architecture and entry_point; file offset 0 maps at that address. Omission preserves header-based detection. provider_id selects one deep provider or deterministic auto selection; the binding remains stable until close or an explicit switch, with no failure fallback. Reopening the same target and profile retains its active database and metadata edits. An optional analysis snapshot is imported atomically and must match the binary identity, concrete provider, and canonical analysis profile exactly; importing into a session with metadata mutations requires closing and reopening it first.

**Input schema (verbatim, JSON Schema 2020-12):**

<details><summary>inputSchema for open_binary</summary>

```json
{
  "$defs": {
    "__schema0": {
      "$ref": "#/$defs/__schema1",
      "description": "Absolute local filesystem path for the analysis target; relative paths are rejected.",
      "minLength": 1,
      "pattern": "^[^\\x00]*$",
      "type": "string"
    },
    "__schema1": {
      "minLength": 1,
      "pattern": "^[^\\x00]*$",
      "type": "string"
    },
    "__schema2": {
      "$ref": "#/$defs/__schema3",
      "description": "Explicit headerless interpretation: dos-com or raw-binary. Omission preserves header-based detection."
    },
    "__schema3": {
      "enum": [
        "dos-com",
        "raw-binary"
      ],
      "type": "string"
    },
    "__schema4": {
      "$ref": "#/$defs/__schema5",
      "description": "Caller-supplied CPU family. Required with format=raw-binary; rejected otherwise."
    },
    "__schema5": {
      "enum": [
        "6502",
        "x86",
        "x86_64",
        "arm",
        "arm64"
      ],
      "type": "string"
    },
    "__schema6": {
      "$ref": "#/$defs/__schema7",
      "description": "Caller-supplied load and entry address (0xhex). File offset 0 is mapped here. Required with format=raw-binary; rejected otherwise."
    },
    "__schema7": {
      "pattern": "^0x[0-9A-Fa-f]{1,16}$",
      "type": "string"
    },
    "__schema8": {
      "anyOf": [
        {
          "const": "auto",
          "type": "string"
        },
        {
          "minLength": 1,
          "pattern": "^[a-z][a-z0-9\\x2d]*$",
          "type": "string"
        }
      ]
    },
    "__schema9": {
      "$ref": "#/$defs/__schema1",
      "description": "Absolute local filesystem path for the analysis snapshot; relative paths are rejected.",
      "minLength": 1,
      "pattern": "^[^\\x00]*$",
      "type": "string"
    }
  },
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "additionalProperties": false,
  "examples": [
    {
      "path": "/tmp/fixture"
    }
  ],
  "properties": {
    "architecture": {
      "$ref": "#/$defs/__schema4",
      "description": "Caller-supplied CPU family. Required with format=raw-binary; rejected otherwise."
    },
    "entry_point": {
      "$ref": "#/$defs/__schema6",
      "description": "Caller-supplied load and entry address (0xhex). File offset 0 is mapped here. Required with format=raw-binary; rejected otherwise."
    },
    "format": {
      "$ref": "#/$defs/__schema2",
      "description": "Explicit headerless interpretation: dos-com or raw-binary. Omission preserves header-based detection."
    },
    "path": {
      "$ref": "#/$defs/__schema0",
      "description": "Absolute local filesystem path for the analysis target; relative paths are rejected."
    },
    "provider_id": {
      "$ref": "#/$defs/__schema8",
      "description": "Exact deep-analysis provider ID, or automatic selection when omitted."
    },
    "snapshot_path": {
      "$ref": "#/$defs/__schema9",
      "description": "Absolute local filesystem path for the analysis snapshot; relative paths are rejected."
    }
  },
  "required": [
    "path"
  ],
  "type": "object"
}
```

</details>

**Output schema:** see [`tool-specs/open_binary.json`](../tool-specs/open_binary.json) (`outputSchema`).

---

## record_unknown

<a id="recordunknown"></a>

**Title:** Record Unknown  
**Kind:** `session` · **Requires session:** true · **analysisOperation:** null  
**Providers:** n/a  
**Effects set (true flags):** NOT idempotent, mutatesSession  
**MCP annotations:** `{"destructiveHint":false,"idempotentHint":false,"openWorldHint":false,"readOnlyHint":false}`

**Description (verbatim, as advertised to the agent):**

> Create one deterministic residual unknown and immutable mutation evidence. Validates all evidence and relationship references, and rejects duplicate stable identity.

**Input schema (verbatim, JSON Schema 2020-12):**

<details><summary>inputSchema for record_unknown</summary>

```json
{
  "$defs": {
    "__schema0": {
      "minLength": 1,
      "type": "string"
    },
    "__schema1": {
      "enum": [
        "low",
        "medium",
        "high",
        "critical"
      ],
      "type": "string"
    },
    "__schema10": {
      "items": {
        "additionalProperties": false,
        "properties": {
          "type": {
            "enum": [
              "depends-on",
              "related-to",
              "contradicts"
            ],
            "type": "string"
          },
          "unknown_id": {
            "description": "Exact residual-unknown identifier.",
            "pattern": "^unk_[a-f0-9]{64}$",
            "type": "string"
          }
        },
        "required": [
          "type",
          "unknown_id"
        ],
        "type": "object"
      },
      "type": "array"
    },
    "__schema11": {
      "default": [],
      "items": {
        "$ref": "#/$defs/__schema3"
      },
      "type": "array"
    },
    "__schema12": {
      "default": [],
      "items": {
        "$ref": "#/$defs/__schema3"
      },
      "type": "array"
    },
    "__schema2": {
      "additionalProperties": false,
      "properties": {
        "comparison_evidence_id": {
          "$ref": "#/$defs/__schema3",
          "description": "Exact Evidence identifier for the comparison observation."
        },
        "dimensions": {
          "$ref": "#/$defs/__schema4"
        }
      },
      "required": [
        "comparison_evidence_id",
        "dimensions"
      ],
      "type": "object"
    },
    "__schema3": {
      "pattern": "^ev_[a-f0-9]{64}$",
      "type": "string"
    },
    "__schema4": {
      "items": {
        "$ref": "#/$defs/__schema5"
      },
      "minItems": 1,
      "type": "array"
    },
    "__schema5": {
      "anyOf": [
        {
          "const": "overall",
          "type": "string"
        },
        {
          "enum": [
            "identity",
            "pseudocode",
            "assembly",
            "comments",
            "calls",
            "references",
            "strings_names",
            "cfg"
          ],
          "type": "string"
        }
      ]
    },
    "__schema6": {
      "anyOf": [
        {
          "enum": [
            "shipped-artifact",
            "controlled-replay",
            "historical-reference",
            "external-service",
            "analyst-inference"
          ],
          "type": "string"
        },
        {
          "type": "null"
        }
      ]
    },
    "__schema7": {
      "enum": [
        "observed",
        "derived",
        "inferred"
      ],
      "type": "string"
    },
    "__schema8": {
      "anyOf": [
        {
          "additionalProperties": false,
          "properties": {
            "architecture": {
              "anyOf": [
                {
                  "minLength": 1,
                  "type": "string"
                },
                {
                  "type": "null"
                }
              ]
            },
            "id": {
              "anyOf": [
                {
                  "minLength": 1,
                  "type": "string"
                },
                {
                  "type": "null"
                }
              ]
            },
            "isolation": {
              "anyOf": [
                {
                  "enum": [
                    "none",
                    "process",
                    "container",
                    "virtual-machine"
                  ],
                  "type": "string"
                },
                {
                  "type": "null"
                }
              ]
            },
            "platform": {
              "anyOf": [
                {
                  "minLength": 1,
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
    "__schema9": {
      "items": {
        "additionalProperties": false,
        "properties": {
          "operation": {
            "minLength": 1,
            "type": "string"
          },
          "rationale": {
            "$ref": "#/$defs/__schema0"
          }
        },
        "required": [
          "operation",
          "rationale"
        ],
        "type": "object"
      },
      "type": "array"
    }
  },
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "additionalProperties": false,
  "examples": [
    {
      "contradicting_evidence_ids": [],
      "domain": "protocol",
      "question": "Does this branch require an unavailable external service?",
      "recommended_probes": [
        {
          "operation": "capture_process_scenario",
          "rationale": "Replay branch."
        }
      ],
      "relationships": [],
      "required_authority": "controlled-replay",
      "required_confidence": "observed",
      "required_environment": null,
      "severity": "medium",
      "supporting_evidence_ids": []
    }
  ],
  "properties": {
    "comparison_conclusion_scope": {
      "$ref": "#/$defs/__schema2"
    },
    "contradicting_evidence_ids": {
      "$ref": "#/$defs/__schema12",
      "description": "Ordered Evidence identifiers for the contradicting observations."
    },
    "domain": {
      "$ref": "#/$defs/__schema0"
    },
    "question": {
      "$ref": "#/$defs/__schema0",
      "description": "Concrete unresolved question to retain for later investigation."
    },
    "recommended_probes": {
      "$ref": "#/$defs/__schema9"
    },
    "relationships": {
      "$ref": "#/$defs/__schema10"
    },
    "required_authority": {
      "$ref": "#/$defs/__schema6"
    },
    "required_confidence": {
      "$ref": "#/$defs/__schema7"
    },
    "required_environment": {
      "$ref": "#/$defs/__schema8"
    },
    "severity": {
      "$ref": "#/$defs/__schema1"
    },
    "supporting_evidence_ids": {
      "$ref": "#/$defs/__schema11",
      "description": "Ordered Evidence identifiers for the supporting observations."
    }
  },
  "required": [
    "question",
    "severity",
    "domain",
    "required_authority",
    "required_confidence",
    "required_environment",
    "recommended_probes",
    "relationships"
  ],
  "type": "object"
}
```

</details>

**Output schema:** see [`tool-specs/record_unknown.json`](../tool-specs/record_unknown.json) (`outputSchema`).

---

## update_unknown

<a id="updateunknown"></a>

**Title:** Update Unknown  
**Kind:** `session` · **Requires session:** true · **analysisOperation:** null  
**Providers:** n/a  
**Effects set (true flags):** NOT idempotent, mutatesSession  
**MCP annotations:** `{"destructiveHint":false,"idempotentHint":false,"openWorldHint":false,"readOnlyHint":false}`

**Description (verbatim, as advertised to the agent):**

> Append one immutable full-state revision and mutation evidence. Requires exact expected_revision; stale concurrent writers fail instead of overwriting newer analysis.

**Input schema (verbatim, JSON Schema 2020-12):**

<details><summary>inputSchema for update_unknown</summary>

```json
{
  "$defs": {
    "__schema0": {
      "pattern": "^unk_[a-f0-9]{64}$",
      "type": "string"
    },
    "__schema1": {
      "maximum": 9007199254740991,
      "minimum": 1,
      "type": "integer"
    },
    "__schema10": {
      "items": {
        "additionalProperties": false,
        "properties": {
          "operation": {
            "minLength": 1,
            "type": "string"
          },
          "rationale": {
            "$ref": "#/$defs/__schema11"
          }
        },
        "required": [
          "operation",
          "rationale"
        ],
        "type": "object"
      },
      "type": "array"
    },
    "__schema11": {
      "minLength": 1,
      "type": "string"
    },
    "__schema12": {
      "items": {
        "additionalProperties": false,
        "properties": {
          "type": {
            "enum": [
              "depends-on",
              "related-to",
              "contradicts"
            ],
            "type": "string"
          },
          "unknown_id": {
            "$ref": "#/$defs/__schema0",
            "description": "Exact residual-unknown identifier."
          }
        },
        "required": [
          "type",
          "unknown_id"
        ],
        "type": "object"
      },
      "type": "array"
    },
    "__schema13": {
      "anyOf": [
        {
          "oneOf": [
            {
              "additionalProperties": false,
              "properties": {
                "disposition": {
                  "const": "verified",
                  "type": "string"
                },
                "evidence_ids": {
                  "items": {
                    "$ref": "#/$defs/__schema5"
                  },
                  "minItems": 1,
                  "type": "array"
                },
                "rationale": {
                  "$ref": "#/$defs/__schema11"
                }
              },
              "required": [
                "disposition",
                "rationale",
                "evidence_ids"
              ],
              "type": "object"
            },
            {
              "additionalProperties": false,
              "properties": {
                "disposition": {
                  "enum": [
                    "withdrawn",
                    "out-of-scope"
                  ],
                  "type": "string"
                },
                "evidence_ids": {
                  "items": {
                    "$ref": "#/$defs/__schema5"
                  },
                  "type": "array"
                },
                "rationale": {
                  "$ref": "#/$defs/__schema11"
                }
              },
              "required": [
                "disposition",
                "rationale",
                "evidence_ids"
              ],
              "type": "object"
            }
          ]
        },
        {
          "type": "null"
        }
      ]
    },
    "__schema2": {
      "enum": [
        "open",
        "investigating",
        "blocked",
        "contradicted",
        "resolved"
      ],
      "type": "string"
    },
    "__schema3": {
      "enum": [
        "low",
        "medium",
        "high",
        "critical"
      ],
      "type": "string"
    },
    "__schema4": {
      "items": {
        "$ref": "#/$defs/__schema5"
      },
      "type": "array"
    },
    "__schema5": {
      "pattern": "^ev_[a-f0-9]{64}$",
      "type": "string"
    },
    "__schema6": {
      "items": {
        "$ref": "#/$defs/__schema5"
      },
      "type": "array"
    },
    "__schema7": {
      "anyOf": [
        {
          "enum": [
            "shipped-artifact",
            "controlled-replay",
            "historical-reference",
            "external-service",
            "analyst-inference"
          ],
          "type": "string"
        },
        {
          "type": "null"
        }
      ]
    },
    "__schema8": {
      "enum": [
        "observed",
        "derived",
        "inferred"
      ],
      "type": "string"
    },
    "__schema9": {
      "anyOf": [
        {
          "additionalProperties": false,
          "properties": {
            "architecture": {
              "anyOf": [
                {
                  "minLength": 1,
                  "type": "string"
                },
                {
                  "type": "null"
                }
              ]
            },
            "id": {
              "anyOf": [
                {
                  "minLength": 1,
                  "type": "string"
                },
                {
                  "type": "null"
                }
              ]
            },
            "isolation": {
              "anyOf": [
                {
                  "enum": [
                    "none",
                    "process",
                    "container",
                    "virtual-machine"
                  ],
                  "type": "string"
                },
                {
                  "type": "null"
                }
              ]
            },
            "platform": {
              "anyOf": [
                {
                  "minLength": 1,
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
    }
  },
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "additionalProperties": false,
  "examples": [
    {
      "contradicting_evidence_ids": [],
      "expected_revision": 1,
      "recommended_probes": [],
      "relationships": [],
      "required_authority": "controlled-replay",
      "required_confidence": "observed",
      "required_environment": null,
      "resolution": null,
      "severity": "medium",
      "status": "investigating",
      "supporting_evidence_ids": [],
      "unknown_id": "unk_0000000000000000000000000000000000000000000000000000000000000000"
    }
  ],
  "properties": {
    "contradicting_evidence_ids": {
      "$ref": "#/$defs/__schema6",
      "description": "Ordered Evidence identifiers for the contradicting observations."
    },
    "expected_revision": {
      "$ref": "#/$defs/__schema1",
      "description": "Expected revision used to reject stale or mismatched input."
    },
    "recommended_probes": {
      "$ref": "#/$defs/__schema10"
    },
    "relationships": {
      "$ref": "#/$defs/__schema12"
    },
    "required_authority": {
      "$ref": "#/$defs/__schema7"
    },
    "required_confidence": {
      "$ref": "#/$defs/__schema8"
    },
    "required_environment": {
      "$ref": "#/$defs/__schema9"
    },
    "resolution": {
      "$ref": "#/$defs/__schema13"
    },
    "severity": {
      "$ref": "#/$defs/__schema3"
    },
    "status": {
      "$ref": "#/$defs/__schema2",
      "description": "Current lifecycle or verification status."
    },
    "supporting_evidence_ids": {
      "$ref": "#/$defs/__schema4",
      "description": "Ordered Evidence identifiers for the supporting observations."
    },
    "unknown_id": {
      "$ref": "#/$defs/__schema0",
      "description": "Exact residual-unknown identifier."
    }
  },
  "required": [
    "unknown_id",
    "expected_revision",
    "status",
    "severity",
    "supporting_evidence_ids",
    "contradicting_evidence_ids",
    "required_authority",
    "required_confidence",
    "required_environment",
    "recommended_probes",
    "relationships",
    "resolution"
  ],
  "type": "object"
}
```

</details>

**Output schema:** see [`tool-specs/update_unknown.json`](../tool-specs/update_unknown.json) (`outputSchema`).

---

## verify_reconstruction

<a id="verifyreconstruction"></a>

**Title:** Verify Reconstruction  
**Kind:** `session` · **Requires session:** true · **analysisOperation:** null  
**Providers:** n/a  
**Effects set (true flags):** mutatesSession  
**MCP annotations:** `{"destructiveHint":false,"idempotentHint":true,"openWorldHint":false,"readOnlyHint":false}`

**Description (verbatim, as advertised to the agent):**

> Verify a finite typed behavioral and structural specification against a canonical Evidence bundle. Pass means every declared claim has complete comparable authority—not global source equivalence; changed claims fail and missing, limited, or unresolved evidence stays unknown.

**Input schema (verbatim, JSON Schema 2020-12):**

<details><summary>inputSchema for verify_reconstruction</summary>

```json
{
  "$defs": {
    "__schema0": {
      "properties": {
        "claims": {
          "$ref": "#/$defs/__schema2"
        },
        "name": {
          "$ref": "#/$defs/__schema1",
          "description": "Exact name used by this operation."
        }
      },
      "required": [
        "name",
        "claims"
      ],
      "type": "object"
    },
    "__schema1": {
      "minLength": 1,
      "type": "string"
    },
    "__schema2": {
      "items": {
        "$ref": "#/$defs/__schema3"
      },
      "minItems": 1,
      "type": "array"
    },
    "__schema3": {
      "oneOf": [
        {
          "properties": {
            "claim_id": {
              "$ref": "#/$defs/__schema4"
            },
            "comparison_evidence_id": {
              "$ref": "#/$defs/__schema6",
              "description": "Exact Evidence identifier for the comparison observation."
            },
            "dimension": {
              "enum": [
                "overall",
                "terminal",
                "interaction",
                "exit",
                "filesystem",
                "process"
              ],
              "type": "string"
            },
            "kind": {
              "const": "behavioral",
              "type": "string"
            },
            "title": {
              "$ref": "#/$defs/__schema5"
            }
          },
          "required": [
            "claim_id",
            "title",
            "comparison_evidence_id",
            "kind",
            "dimension"
          ],
          "type": "object"
        },
        {
          "properties": {
            "claim_id": {
              "$ref": "#/$defs/__schema4"
            },
            "comparison_evidence_id": {
              "$ref": "#/$defs/__schema6",
              "description": "Exact Evidence identifier for the comparison observation."
            },
            "dimension": {
              "enum": [
                "overall",
                "identity",
                "pseudocode",
                "assembly",
                "comments",
                "calls",
                "references",
                "strings_names",
                "cfg"
              ],
              "type": "string"
            },
            "kind": {
              "const": "structural-function",
              "type": "string"
            },
            "title": {
              "$ref": "#/$defs/__schema5"
            }
          },
          "required": [
            "claim_id",
            "title",
            "comparison_evidence_id",
            "kind",
            "dimension"
          ],
          "type": "object"
        },
        {
          "properties": {
            "claim_id": {
              "$ref": "#/$defs/__schema4"
            },
            "comparison_evidence_id": {
              "$ref": "#/$defs/__schema6",
              "description": "Exact Evidence identifier for the comparison observation."
            },
            "dimension": {
              "const": "overall",
              "type": "string"
            },
            "kind": {
              "const": "structural-artifact",
              "type": "string"
            },
            "title": {
              "$ref": "#/$defs/__schema5"
            }
          },
          "required": [
            "claim_id",
            "title",
            "comparison_evidence_id",
            "kind",
            "dimension"
          ],
          "type": "object"
        }
      ]
    },
    "__schema4": {
      "pattern": "^[A-Za-z][A-Za-z0-9._\\x2d]*$",
      "type": "string"
    },
    "__schema5": {
      "minLength": 1,
      "type": "string"
    },
    "__schema6": {
      "pattern": "^ev_[a-f0-9]{64}$",
      "type": "string"
    }
  },
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "additionalProperties": false,
  "examples": [
    {
      "specification": {
        "claims": [
          {
            "claim_id": "terminal-output",
            "comparison_evidence_id": "ev_38ed13bff29e8b0299cb7498be55b08f8fe629d9a12af1ccc4498c38b98c57d8",
            "dimension": "terminal",
            "kind": "behavioral",
            "title": "Terminal output remains equivalent"
          }
        ],
        "name": "Terminal compatibility"
      }
    }
  ],
  "properties": {
    "specification": {
      "$ref": "#/$defs/__schema0"
    }
  },
  "required": [
    "specification"
  ],
  "type": "object"
}
```

</details>

**Output schema:** see [`tool-specs/verify_reconstruction.json`](../tool-specs/verify_reconstruction.json) (`outputSchema`).

---

## verify_unknown_resolution

<a id="verifyunknownresolution"></a>

**Title:** Verify Unknown Resolution  
**Kind:** `session` · **Requires session:** true · **analysisOperation:** null  
**Providers:** n/a  
**Effects set (true flags):** none (pure read)  
**MCP annotations:** `{"destructiveHint":false,"idempotentHint":true,"openWorldHint":false,"readOnlyHint":true}`

**Description (verbatim, as advertised to the agent):**

> Revalidate the current residual-unknown head against live bundled evidence, exact authority/confidence/environment requirements, and revision integrity. Withdrawn and out-of-scope dispositions are not truth claims.

**Input schema (verbatim, JSON Schema 2020-12):**

<details><summary>inputSchema for verify_unknown_resolution</summary>

```json
{
  "$defs": {
    "__schema0": {
      "pattern": "^unk_[a-f0-9]{64}$",
      "type": "string"
    }
  },
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "additionalProperties": false,
  "examples": [
    {
      "unknown_id": "unk_0000000000000000000000000000000000000000000000000000000000000000"
    }
  ],
  "properties": {
    "unknown_id": {
      "$ref": "#/$defs/__schema0",
      "description": "Exact residual-unknown identifier."
    }
  },
  "required": [
    "unknown_id"
  ],
  "type": "object"
}
```

</details>

**Output schema:** see [`tool-specs/verify_unknown_resolution.json`](../tool-specs/verify_unknown_resolution.json) (`outputSchema`).

---

