# Tool family: Application workflows

Generated mechanically from `.cache/mcp-tool-catalog.json` (produced by `scripts/generate-mcp-tool-catalog.mjs`, which registers every tool through the MCP SDK and exports the advertised JSON Schema 2020-12 input/output schemas) and `docs/public/product-catalog.json` (family `application`, surface `application-workflow`, 15 tools). Input schemas below are **verbatim**. Output schemas are verbatim in `tool-specs/<tool>.json` (field `outputSchema`) because several exceed 100 KB; the complete per-tool spec (description, effects, annotations, inputSchema, outputSchema) is in that file.

| Tool | Kind | Session? | Providers advertising it | CLI command |
|---|---|---|---|---|
| [`build_reconstruction_obligation_ledger`](#buildreconstructionobligationledger) | application | no | rea-javascript-application-workflows | `rea build-reconstruction-obligation-ledger` |
| [`compare_application_versions`](#compareapplicationversions) | application | no | rea-javascript-application-workflows | `rea compare-application-versions` |
| [`compare_javascript_export_shapes`](#comparejavascriptexportshapes) | application | no | rea-javascript-application-workflows | `rea compare-javascript-export-shapes` |
| [`compare_source_to_bundle`](#comparesourcetobundle) | application | no | rea-javascript-application-workflows | `rea compare-source-to-bundle` |
| [`evaluate_reconstruction_coverage`](#evaluatereconstructioncoverage) | application | no | rea-javascript-application-workflows | `rea evaluate-reconstruction-coverage` |
| [`export_web_scripts`](#exportwebscripts) | application | no | rea-web-script-export | `rea export-web-scripts` |
| [`inspect_analysis_view`](#inspectanalysisview) | application | no | rea-analysis-view | `rea inspect-analysis-view` |
| [`project_android_application_graph`](#projectandroidapplicationgraph) | application | no | rea-android-application | `rea project-android-application-graph` |
| [`project_apple_application_graph`](#projectappleapplicationgraph) | application | no | rea-apple-application | `rea project-apple-application-graph` |
| [`project_harmony_application_graph`](#projectharmonyapplicationgraph) | application | no | rea-javascript-application-workflows | `rea project-harmony-application-graph` |
| [`recover_javascript_sources`](#recoverjavascriptsources) | application | no | wakaru | `rea recover-javascript-sources` |
| [`trace_application_feature`](#traceapplicationfeature) | application | no | rea-javascript-application-workflows | `rea trace-application-feature` |
| [`trace_javascript_semantics`](#tracejavascriptsemantics) | application | no | rea-javascript-application-workflows | `rea trace-javascript-semantics` |
| [`trace_web_module_imports`](#tracewebmoduleimports) | application | no | rea-web-script-export | `rea trace-web-module-imports` |
| [`trace_web_source_location`](#tracewebsourcelocation) | application | no | rea-web-script-export | `rea trace-web-source-location` |

## build_reconstruction_obligation_ledger

<a id="buildreconstructionobligationledger"></a>

**Title:** Build Reconstruction Obligation Ledger  
**Kind:** `application` · **Requires session:** false · **analysisOperation:** null  
**Providers:** rea-javascript-application-workflows  
**Effects set (true flags):** mutatesSession  
**MCP annotations:** `{"destructiveHint":false,"idempotentHint":true,"openWorldHint":false,"readOnlyHint":false}`

**Description (verbatim, as advertised to the agent):**

> Generate the complete deterministic ReconstructionObligationLedger from an authenticated Evidence bundle, reviewed obligations, and an explicit reconstruction manifest. Static candidates remain candidates; duplicate ownership, missing original or reconstruction cases, missing parser/type, weak verifier authority, unenumerated claims, contradictions, dependencies, and residual unknowns fail closed. The inline result carries the full-ledger closure digest and typed per-obligation diagnostics.

**Input schema (verbatim, JSON Schema 2020-12):**

<details><summary>inputSchema for build_reconstruction_obligation_ledger</summary>

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "additionalProperties": false,
  "examples": [
    {
      "evidence_bundle": {
        "artifacts": [],
        "captures": [],
        "environments": [],
        "providers": [],
        "records": [],
        "scenarios": [],
        "unknowns": []
      },
      "manifest": {
        "bindings": [],
        "contradictions": []
      },
      "reviewed_obligations": []
    }
  ],
  "properties": {
    "evidence_bundle": {
      "additionalProperties": false,
      "properties": {
        "artifacts": {
          "items": {
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
                  }
                },
                "required": [
                  "digest",
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
                  }
                },
                "required": [
                  "digest",
                  "format",
                  "architecture"
                ],
                "type": "object"
              }
            ]
          },
          "type": "array"
        },
        "captures": {
          "items": {
            "additionalProperties": false,
            "properties": {
              "evidence_id": {
                "description": "Stable identifier of the recorded Evidence observation.",
                "pattern": "^ev_[a-f0-9]{64}$",
                "type": "string"
              },
              "predicate_type": {
                "minLength": 1,
                "type": "string"
              }
            },
            "required": [
              "evidence_id",
              "predicate_type"
            ],
            "type": "object"
          },
          "type": "array"
        },
        "environments": {
          "items": {
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
          "type": "array"
        },
        "providers": {
          "items": {
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
          "type": "array"
        },
        "records": {
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
          "type": "array"
        },
        "scenarios": {
          "items": {
            "additionalProperties": false,
            "properties": {
              "authority": {
                "const": "controlled-replay",
                "type": "string"
              },
              "evidence_id": {
                "description": "Stable identifier of the recorded Evidence observation.",
                "pattern": "^ev_[a-f0-9]{64}$",
                "type": "string"
              },
              "operation": {
                "minLength": 1,
                "type": "string"
              }
            },
            "required": [
              "evidence_id",
              "operation",
              "authority"
            ],
            "type": "object"
          },
          "type": "array"
        },
        "unknowns": {
          "items": {
            "additionalProperties": false,
            "properties": {
              "comparison_conclusion_scope": {
                "additionalProperties": false,
                "properties": {
                  "comparison_evidence_id": {
                    "description": "Exact Evidence identifier for the comparison observation.",
                    "pattern": "^ev_[a-f0-9]{64}$",
                    "type": "string"
                  },
                  "dimensions": {
                    "items": {
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
                    "minItems": 1,
                    "type": "array"
                  }
                },
                "required": [
                  "comparison_evidence_id",
                  "dimensions"
                ],
                "type": "object"
              },
              "contradicting_evidence_ids": {
                "description": "Ordered Evidence identifiers for the contradicting observations.",
                "items": {
                  "pattern": "^ev_[a-f0-9]{64}$",
                  "type": "string"
                },
                "type": "array"
              },
              "domain": {
                "minLength": 1,
                "type": "string"
              },
              "mutation_evidence_ids": {
                "description": "Ordered Evidence identifiers for the mutation observations.",
                "items": {
                  "pattern": "^ev_[a-f0-9]{64}$",
                  "type": "string"
                },
                "minItems": 1,
                "type": "array"
              },
              "previous_revision_digest": {
                "anyOf": [
                  {
                    "pattern": "^[a-f0-9]{64}$",
                    "type": "string"
                  },
                  {
                    "type": "null"
                  }
                ]
              },
              "question": {
                "description": "Concrete unresolved question to retain for later investigation.",
                "minLength": 1,
                "type": "string"
              },
              "recommended_probes": {
                "items": {
                  "additionalProperties": false,
                  "properties": {
                    "operation": {
                      "minLength": 1,
                      "type": "string"
                    },
                    "rationale": {
                      "minLength": 1,
                      "type": "string"
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
              "relationships": {
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
              "required_authority": {
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
              "required_confidence": {
                "enum": [
                  "observed",
                  "derived",
                  "inferred"
                ],
                "type": "string"
              },
              "required_environment": {
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
              "resolution": {
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
                              "pattern": "^ev_[a-f0-9]{64}$",
                              "type": "string"
                            },
                            "minItems": 1,
                            "type": "array"
                          },
                          "rationale": {
                            "minLength": 1,
                            "type": "string"
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
                              "pattern": "^ev_[a-f0-9]{64}$",
                              "type": "string"
                            },
                            "type": "array"
                          },
                          "rationale": {
                            "minLength": 1,
                            "type": "string"
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
              "revision": {
                "maximum": 9007199254740991,
                "minimum": 1,
                "type": "integer"
              },
              "revision_digest": {
                "pattern": "^[a-f0-9]{64}$",
                "type": "string"
              },
              "scope_digest": {
                "anyOf": [
                  {
                    "pattern": "^[a-f0-9]{64}$",
                    "type": "string"
                  },
                  {
                    "type": "null"
                  }
                ]
              },
              "severity": {
                "enum": [
                  "low",
                  "medium",
                  "high",
                  "critical"
                ],
                "type": "string"
              },
              "status": {
                "description": "Current lifecycle or verification status.",
                "enum": [
                  "open",
                  "investigating",
                  "blocked",
                  "contradicted",
                  "resolved"
                ],
                "type": "string"
              },
              "supporting_evidence_ids": {
                "description": "Ordered Evidence identifiers for the supporting observations.",
                "items": {
                  "pattern": "^ev_[a-f0-9]{64}$",
                  "type": "string"
                },
                "type": "array"
              },
              "unknown_id": {
                "description": "Exact residual-unknown identifier.",
                "pattern": "^unk_[a-f0-9]{64}$",
                "type": "string"
              }
            },
            "required": [
              "unknown_id",
              "revision",
              "previous_revision_digest",
              "revision_digest",
              "scope_digest",
              "question",
              "status",
              "severity",
              "domain",
              "supporting_evidence_ids",
              "contradicting_evidence_ids",
              "required_authority",
              "required_confidence",
              "required_environment",
              "recommended_probes",
              "relationships",
              "resolution",
              "mutation_evidence_ids"
            ],
            "type": "object"
          },
          "type": "array"
        }
      },
      "required": [
        "artifacts",
        "providers",
        "environments",
        "scenarios",
        "captures",
        "unknowns",
        "records"
      ],
      "type": "object"
    },
    "manifest": {
      "additionalProperties": false,
      "properties": {
        "bindings": {
          "items": {
            "additionalProperties": false,
            "properties": {
              "fixtures": {
                "items": {
                  "additionalProperties": false,
                  "properties": {
                    "authority": {
                      "enum": [
                        "unit",
                        "integration",
                        "protocol",
                        "renderer",
                        "packaged-process",
                        "native-abi",
                        "live-observation",
                        "external"
                      ],
                      "type": "string"
                    },
                    "case_kind": {
                      "enum": [
                        "positive",
                        "negative",
                        "malformed",
                        "cancellation",
                        "teardown"
                      ],
                      "type": "string"
                    },
                    "evidence_ids": {
                      "items": {
                        "pattern": "^ev_[a-f0-9]{64}$",
                        "type": "string"
                      },
                      "minItems": 1,
                      "type": "array"
                    },
                    "fixture_id": {
                      "pattern": "^[A-Za-z][A-Za-z0-9._:\\x2f\\x2d]*$",
                      "type": "string"
                    }
                  },
                  "required": [
                    "fixture_id",
                    "case_kind",
                    "authority",
                    "evidence_ids"
                  ],
                  "type": "object"
                },
                "type": "array"
              },
              "obligation_id": {
                "pattern": "^[A-Za-z][A-Za-z0-9._:\\x2f\\x2d]*$",
                "type": "string"
              },
              "original_cases": {
                "items": {
                  "additionalProperties": false,
                  "properties": {
                    "evidence_id": {
                      "description": "Stable identifier of the recorded Evidence observation.",
                      "pattern": "^ev_[a-f0-9]{64}$",
                      "type": "string"
                    },
                    "kind": {
                      "enum": [
                        "positive",
                        "negative",
                        "malformed",
                        "cancellation",
                        "teardown"
                      ],
                      "type": "string"
                    },
                    "location": {
                      "minLength": 1,
                      "type": "string"
                    }
                  },
                  "required": [
                    "kind",
                    "evidence_id",
                    "location"
                  ],
                  "type": "object"
                },
                "type": "array"
              },
              "owner": {
                "additionalProperties": false,
                "properties": {
                  "module_path": {
                    "description": "Local filesystem path for module.",
                    "minLength": 1,
                    "type": "string"
                  },
                  "owner_sha256": {
                    "description": "Exact SHA-256 digest of owner.",
                    "pattern": "^[a-f0-9]{64}$",
                    "type": "string"
                  },
                  "symbol": {
                    "minLength": 1,
                    "type": "string"
                  }
                },
                "required": [
                  "module_path",
                  "symbol",
                  "owner_sha256"
                ],
                "type": "object"
              },
              "parser_type": {
                "anyOf": [
                  {
                    "additionalProperties": false,
                    "properties": {
                      "domain_type": {
                        "minLength": 1,
                        "type": "string"
                      },
                      "parser": {
                        "minLength": 1,
                        "type": "string"
                      },
                      "schema": {
                        "minLength": 1,
                        "type": "string"
                      }
                    },
                    "required": [
                      "parser",
                      "schema",
                      "domain_type"
                    ],
                    "type": "object"
                  },
                  {
                    "type": "null"
                  }
                ]
              },
              "verifier": {
                "anyOf": [
                  {
                    "additionalProperties": false,
                    "properties": {
                      "authority": {
                        "enum": [
                          "unit",
                          "integration",
                          "protocol",
                          "renderer",
                          "packaged-process",
                          "native-abi",
                          "live-observation",
                          "external"
                        ],
                        "type": "string"
                      },
                      "claim_id": {
                        "pattern": "^[A-Za-z][A-Za-z0-9._:\\x2f\\x2d]*$",
                        "type": "string"
                      },
                      "command": {
                        "minLength": 1,
                        "type": "string"
                      },
                      "enumerated_obligation_ids": {
                        "items": {
                          "pattern": "^[A-Za-z][A-Za-z0-9._:\\x2f\\x2d]*$",
                          "type": "string"
                        },
                        "minItems": 1,
                        "type": "array"
                      },
                      "nondeterminism": {
                        "additionalProperties": false,
                        "properties": {
                          "mode": {
                            "description": "Operation mode that selects the requested behavior.",
                            "enum": [
                              "total-order",
                              "partial-order",
                              "finite-traces"
                            ],
                            "type": "string"
                          },
                          "specification": {
                            "minLength": 1,
                            "type": "string"
                          }
                        },
                        "required": [
                          "mode",
                          "specification"
                        ],
                        "type": "object"
                      },
                      "result_evidence_id": {
                        "description": "Exact Evidence identifier for the result observation.",
                        "pattern": "^ev_[a-f0-9]{64}$",
                        "type": "string"
                      },
                      "status": {
                        "description": "Current lifecycle or verification status.",
                        "enum": [
                          "pass",
                          "fail",
                          "unknown",
                          "unsupported",
                          "skipped"
                        ],
                        "type": "string"
                      },
                      "verifier_id": {
                        "pattern": "^[A-Za-z][A-Za-z0-9._:\\x2f\\x2d]*$",
                        "type": "string"
                      }
                    },
                    "required": [
                      "verifier_id",
                      "claim_id",
                      "command",
                      "authority",
                      "status",
                      "result_evidence_id",
                      "enumerated_obligation_ids",
                      "nondeterminism"
                    ],
                    "type": "object"
                  },
                  {
                    "type": "null"
                  }
                ]
              }
            },
            "required": [
              "obligation_id",
              "owner",
              "parser_type",
              "original_cases",
              "fixtures",
              "verifier"
            ],
            "type": "object"
          },
          "type": "array"
        },
        "contradictions": {
          "items": {
            "additionalProperties": false,
            "properties": {
              "evidence_ids": {
                "items": {
                  "pattern": "^ev_[a-f0-9]{64}$",
                  "type": "string"
                },
                "minItems": 2,
                "type": "array"
              },
              "obligation_id": {
                "pattern": "^[A-Za-z][A-Za-z0-9._:\\x2f\\x2d]*$",
                "type": "string"
              }
            },
            "required": [
              "obligation_id",
              "evidence_ids"
            ],
            "type": "object"
          },
          "type": "array"
        }
      },
      "required": [
        "bindings",
        "contradictions"
      ],
      "type": "object"
    },
    "reviewed_obligations": {
      "items": {
        "additionalProperties": false,
        "properties": {
          "application_layer": {
            "enum": [
              "cli",
              "protocol",
              "electron",
              "persistence",
              "process",
              "runtime",
              "packaging",
              "native-abi",
              "application",
              "other"
            ],
            "type": "string"
          },
          "dependency_obligation_ids": {
            "items": {
              "pattern": "^[A-Za-z][A-Za-z0-9._:\\x2f\\x2d]*$",
              "type": "string"
            },
            "type": "array"
          },
          "disposition": {
            "enum": [
              "active",
              "blocked",
              "out-of-scope"
            ],
            "type": "string"
          },
          "family": {
            "minLength": 1,
            "type": "string"
          },
          "obligation_id": {
            "pattern": "^[A-Za-z][A-Za-z0-9._:\\x2f\\x2d]*$",
            "type": "string"
          },
          "obligation_version": {
            "maximum": 9007199254740991,
            "minimum": 1,
            "type": "integer"
          },
          "required": {
            "type": "boolean"
          },
          "required_case_kinds": {
            "items": {
              "enum": [
                "positive",
                "negative",
                "malformed",
                "cancellation",
                "teardown"
              ],
              "type": "string"
            },
            "minItems": 1,
            "type": "array"
          },
          "required_fixture_authority": {
            "enum": [
              "unit",
              "integration",
              "protocol",
              "renderer",
              "packaged-process",
              "native-abi",
              "live-observation",
              "external"
            ],
            "type": "string"
          },
          "required_next_evidence": {
            "items": {
              "minLength": 1,
              "type": "string"
            },
            "type": "array"
          },
          "required_original_authority": {
            "enum": [
              "static",
              "runtime",
              "process",
              "external"
            ],
            "type": "string"
          },
          "required_verifier_authority": {
            "enum": [
              "unit",
              "integration",
              "protocol",
              "renderer",
              "packaged-process",
              "native-abi",
              "live-observation",
              "external"
            ],
            "type": "string"
          },
          "requires_parser_type": {
            "type": "boolean"
          },
          "residual_unknown_ids": {
            "items": {
              "pattern": "^[A-Za-z][A-Za-z0-9._:\\x2f\\x2d]*$",
              "type": "string"
            },
            "type": "array"
          },
          "review_evidence_ids": {
            "description": "Ordered Evidence identifiers for the review observations.",
            "items": {
              "pattern": "^ev_[a-f0-9]{64}$",
              "type": "string"
            },
            "minItems": 1,
            "type": "array"
          },
          "target": {
            "additionalProperties": false,
            "properties": {
              "application_node_id": {
                "anyOf": [
                  {
                    "pattern": "^jag_node_[a-f0-9]{64}$",
                    "type": "string"
                  },
                  {
                    "type": "null"
                  }
                ]
              },
              "artifact_sha256": {
                "anyOf": [
                  {
                    "pattern": "^[a-f0-9]{64}$",
                    "type": "string"
                  },
                  {
                    "type": "null"
                  }
                ],
                "description": "Exact SHA-256 digest of artifact."
              },
              "location": {
                "minLength": 1,
                "type": "string"
              },
              "semantic_node_id": {
                "anyOf": [
                  {
                    "pattern": "^jsrg_node_[a-f0-9]{64}$",
                    "type": "string"
                  },
                  {
                    "type": "null"
                  }
                ]
              }
            },
            "required": [
              "artifact_sha256",
              "application_node_id",
              "semantic_node_id",
              "location"
            ],
            "type": "object"
          },
          "title": {
            "minLength": 1,
            "type": "string"
          },
          "unavailable_authority": {
            "items": {
              "minLength": 1,
              "type": "string"
            },
            "type": "array"
          }
        },
        "required": [
          "obligation_id",
          "obligation_version",
          "title",
          "application_layer",
          "family",
          "target",
          "required",
          "required_case_kinds",
          "required_original_authority",
          "required_fixture_authority",
          "required_verifier_authority",
          "requires_parser_type",
          "dependency_obligation_ids",
          "residual_unknown_ids",
          "unavailable_authority",
          "required_next_evidence",
          "disposition",
          "review_evidence_ids"
        ],
        "type": "object"
      },
      "type": "array"
    }
  },
  "required": [
    "evidence_bundle",
    "reviewed_obligations",
    "manifest"
  ],
  "type": "object"
}
```

</details>

**Output schema:** see [`tool-specs/build_reconstruction_obligation_ledger.json`](../tool-specs/build_reconstruction_obligation_ledger.json) (`outputSchema`).

---

## compare_application_versions

<a id="compareapplicationversions"></a>

**Title:** Compare Application Versions  
**Kind:** `application` · **Requires session:** false · **analysisOperation:** null  
**Providers:** rea-javascript-application-workflows  
**Effects set (true flags):** mutatesSession  
**MCP annotations:** `{"destructiveHint":false,"idempotentHint":true,"openWorldHint":false,"readOnlyHint":false}`

**Description (verbatim, as advertised to the agent):**

> Compare two authenticated JavaScript Application Graph versions supplied as inline Evidence or exact same-session retained references. Uses unique-only exact digest, module source digest, source-map identity, structural fingerprint, and non-module semantic-key tiers. Reports added, removed, changed, ambiguous, and unknown entities plus the complete matching changed_from graph without fuzzy or module-ordinal pairing.

**Input schema (verbatim, JSON Schema 2020-12):**

<details><summary>inputSchema for compare_application_versions</summary>

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "additionalProperties": false,
  "examples": [
    {
      "left": {
        "evidence_id": "ev_2a6371cd2a7665bdad6d37d9b3a69da558e9882a0696d195f1f1a7707f14b5e5",
        "kind": "retained-evidence"
      },
      "right": {
        "evidence_id": "ev_3ce65a02b9646af31ae60860daa94775bda12e25e480aa767459b20e60e8eec9",
        "kind": "retained-evidence"
      }
    }
  ],
  "properties": {
    "left": {
      "anyOf": [
        {
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
        {
          "additionalProperties": false,
          "properties": {
            "evidence_id": {
              "description": "Stable identifier of the recorded Evidence observation.",
              "pattern": "^ev_[a-f0-9]{64}$",
              "type": "string"
            },
            "kind": {
              "const": "retained-evidence",
              "type": "string"
            }
          },
          "required": [
            "kind",
            "evidence_id"
          ],
          "type": "object"
        }
      ],
      "description": "Left-hand input used for comparison or differential execution."
    },
    "left_native_observations": {
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
      "type": "array"
    },
    "right": {
      "anyOf": [
        {
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
        {
          "additionalProperties": false,
          "properties": {
            "evidence_id": {
              "description": "Stable identifier of the recorded Evidence observation.",
              "pattern": "^ev_[a-f0-9]{64}$",
              "type": "string"
            },
            "kind": {
              "const": "retained-evidence",
              "type": "string"
            }
          },
          "required": [
            "kind",
            "evidence_id"
          ],
          "type": "object"
        }
      ],
      "description": "Right-hand input used for comparison or differential execution."
    },
    "right_native_observations": {
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
      "type": "array"
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

**Output schema:** see [`tool-specs/compare_application_versions.json`](../tool-specs/compare_application_versions.json) (`outputSchema`).

---

## compare_javascript_export_shapes

<a id="comparejavascriptexportshapes"></a>

**Title:** Compare Javascript Export Shapes  
**Kind:** `application` · **Requires session:** false · **analysisOperation:** null  
**Providers:** rea-javascript-application-workflows  
**Effects set (true flags):** mutatesSession  
**MCP annotations:** `{"destructiveHint":false,"idempotentHint":true,"openWorldHint":false,"readOnlyHint":false}`

**Description (verbatim, as advertised to the agent):**

> Compare static return shapes for one exact module/export selector on each authenticated JavaScript Application Graph supplied as inline Evidence or exact same-session retained references. Variants pair only by reciprocal unique literal discriminants. Each retained variant lists observed return-property names even when values stay unknown. Presence (present, absent, or unknown-coverage) is separate from value resolution: a name present on only one paired shape is added or removed when parent-property coverage is complete on both sides, including when the static value is unresolved. Dynamic values, incomplete parent coverage, and unpaired variants remain unknown. Reports JSON Pointer changes without executing JavaScript; runtime behavior requires a separate agent-run probe.

**Input schema (verbatim, JSON Schema 2020-12):**

<details><summary>inputSchema for compare_javascript_export_shapes</summary>

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "additionalProperties": false,
  "examples": [
    {
      "left": {
        "evidence_id": "ev_4765fd4d9759fef74a86e517349e3cc8292dd9d17b2544d40eddc6c7693341a1",
        "kind": "retained-evidence"
      },
      "left_export_name": "default",
      "left_module_path": "parser.mjs",
      "right": {
        "evidence_id": "ev_63d875a91fea7479b1dc9d31ad7e7ee41bc5b7b15f0b3e687f5cae087c29a236",
        "kind": "retained-evidence"
      },
      "right_export_name": "default",
      "right_module_path": "parser.mjs"
    }
  ],
  "properties": {
    "left": {
      "anyOf": [
        {
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
        {
          "additionalProperties": false,
          "properties": {
            "evidence_id": {
              "description": "Stable identifier of the recorded Evidence observation.",
              "pattern": "^ev_[a-f0-9]{64}$",
              "type": "string"
            },
            "kind": {
              "const": "retained-evidence",
              "type": "string"
            }
          },
          "required": [
            "kind",
            "evidence_id"
          ],
          "type": "object"
        }
      ],
      "description": "Left-hand input used for comparison or differential execution."
    },
    "left_export_name": {
      "type": "string"
    },
    "left_module_path": {
      "description": "Local filesystem path for left module.",
      "minLength": 1,
      "type": "string"
    },
    "right": {
      "anyOf": [
        {
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
        {
          "additionalProperties": false,
          "properties": {
            "evidence_id": {
              "description": "Stable identifier of the recorded Evidence observation.",
              "pattern": "^ev_[a-f0-9]{64}$",
              "type": "string"
            },
            "kind": {
              "const": "retained-evidence",
              "type": "string"
            }
          },
          "required": [
            "kind",
            "evidence_id"
          ],
          "type": "object"
        }
      ],
      "description": "Right-hand input used for comparison or differential execution."
    },
    "right_export_name": {
      "type": "string"
    },
    "right_module_path": {
      "description": "Local filesystem path for right module.",
      "minLength": 1,
      "type": "string"
    }
  },
  "required": [
    "left_module_path",
    "left_export_name",
    "right_module_path",
    "right_export_name",
    "left",
    "right"
  ],
  "type": "object"
}
```

</details>

**Output schema:** see [`tool-specs/compare_javascript_export_shapes.json`](../tool-specs/compare_javascript_export_shapes.json) (`outputSchema`).

---

## compare_source_to_bundle

<a id="comparesourcetobundle"></a>

**Title:** Compare Source To Bundle  
**Kind:** `application` · **Requires session:** false · **analysisOperation:** null  
**Providers:** rea-javascript-application-workflows  
**Effects set (true flags):** mutatesSession  
**MCP annotations:** `{"destructiveHint":false,"idempotentHint":true,"openWorldHint":false,"readOnlyHint":false}`

**Description (verbatim, as advertised to the agent):**

> Compare a cryptographically committed HistoricalSourceGraph with authenticated JavaScript Application Graph Evidence supplied inline or by exact same-session retained reference. Uses explicit exact-digest, source-map path, current-path, suffix, and basename signals with stable weights. Classifies unchanged, modified, removed, split, merged, duplicated, and unknown; incomplete coverage and ambiguous weak signals never become absence or forced matches.

**Input schema (verbatim, JSON Schema 2020-12):**

<details><summary>inputSchema for compare_source_to_bundle</summary>

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "additionalProperties": false,
  "examples": [
    {
      "application": {
        "evidence_id": "ev_2a6371cd2a7665bdad6d37d9b3a69da558e9882a0696d195f1f1a7707f14b5e5",
        "kind": "retained-evidence"
      },
      "reference": {
        "authority": "historical-reference",
        "entries": [
          {
            "classifications": [
              "source"
            ],
            "kind": "directory",
            "limitations": [],
            "path": "src",
            "tree_state": "enumerated"
          },
          {
            "classifications": [
              "source"
            ],
            "content_state": "hashed",
            "kind": "file",
            "language": "TypeScript",
            "limitations": [],
            "path": "src/main.ts",
            "sha256": "2222222222222222222222222222222222222222222222222222222222222222",
            "size": 128
          }
        ],
        "exclusions": [],
        "inventory_state": "complete",
        "languages": [
          "TypeScript"
        ],
        "limitations": [],
        "manifests": [],
        "parse_failures": [],
        "provenance": {
          "caller": "contract-example",
          "importer": "rea",
          "importer_version": "1"
        },
        "relationships": [],
        "root_alias": "$REFERENCE_ROOT",
        "root_sha256": "683969414c3e674a368392213c78021322fb39609b0c57f346b22da6464b2110",
        "schema": "HistoricalSourceGraph",
        "vcs": {
          "dirty": null,
          "head": null,
          "kind": "none"
        }
      }
    }
  ],
  "properties": {
    "application": {
      "anyOf": [
        {
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
        {
          "additionalProperties": false,
          "properties": {
            "evidence_id": {
              "description": "Stable identifier of the recorded Evidence observation.",
              "pattern": "^ev_[a-f0-9]{64}$",
              "type": "string"
            },
            "kind": {
              "const": "retained-evidence",
              "type": "string"
            }
          },
          "required": [
            "kind",
            "evidence_id"
          ],
          "type": "object"
        }
      ]
    },
    "reference": {
      "additionalProperties": false,
      "properties": {
        "authority": {
          "const": "historical-reference",
          "type": "string"
        },
        "entries": {
          "items": {
            "anyOf": [
              {
                "anyOf": [
                  {
                    "additionalProperties": false,
                    "properties": {
                      "classifications": {
                        "items": {
                          "enum": [
                            "source",
                            "test",
                            "config",
                            "manifest",
                            "generated",
                            "vendor",
                            "documentation",
                            "unknown"
                          ],
                          "type": "string"
                        },
                        "minItems": 1,
                        "type": "array"
                      },
                      "content_state": {
                        "const": "hashed",
                        "type": "string"
                      },
                      "kind": {
                        "const": "file",
                        "type": "string"
                      },
                      "language": {
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
                      "limitations": {
                        "items": {
                          "minLength": 1,
                          "type": "string"
                        },
                        "type": "array"
                      },
                      "path": {
                        "description": "Local filesystem path used by this operation.",
                        "minLength": 1,
                        "type": "string"
                      },
                      "sha256": {
                        "pattern": "^[a-f0-9]{64}$",
                        "type": "string"
                      },
                      "size": {
                        "maximum": 9007199254740991,
                        "minimum": 0,
                        "type": "integer"
                      }
                    },
                    "required": [
                      "path",
                      "classifications",
                      "limitations",
                      "kind",
                      "language",
                      "sha256",
                      "size",
                      "content_state"
                    ],
                    "type": "object"
                  },
                  {
                    "additionalProperties": false,
                    "properties": {
                      "classifications": {
                        "items": {
                          "enum": [
                            "source",
                            "test",
                            "config",
                            "manifest",
                            "generated",
                            "vendor",
                            "documentation",
                            "unknown"
                          ],
                          "type": "string"
                        },
                        "minItems": 1,
                        "type": "array"
                      },
                      "content_state": {
                        "enum": [
                          "redacted-secret",
                          "excluded",
                          "unreadable",
                          "unknown"
                        ],
                        "type": "string"
                      },
                      "kind": {
                        "const": "file",
                        "type": "string"
                      },
                      "language": {
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
                      "limitations": {
                        "items": {
                          "minLength": 1,
                          "type": "string"
                        },
                        "type": "array"
                      },
                      "path": {
                        "description": "Local filesystem path used by this operation.",
                        "minLength": 1,
                        "type": "string"
                      },
                      "sha256": {
                        "type": "null"
                      },
                      "size": {
                        "anyOf": [
                          {
                            "maximum": 9007199254740991,
                            "minimum": 0,
                            "type": "integer"
                          },
                          {
                            "type": "null"
                          }
                        ]
                      }
                    },
                    "required": [
                      "path",
                      "classifications",
                      "limitations",
                      "kind",
                      "language",
                      "sha256",
                      "size",
                      "content_state"
                    ],
                    "type": "object"
                  }
                ]
              },
              {
                "additionalProperties": false,
                "properties": {
                  "classifications": {
                    "items": {
                      "enum": [
                        "source",
                        "test",
                        "config",
                        "manifest",
                        "generated",
                        "vendor",
                        "documentation",
                        "unknown"
                      ],
                      "type": "string"
                    },
                    "minItems": 1,
                    "type": "array"
                  },
                  "kind": {
                    "const": "directory",
                    "type": "string"
                  },
                  "limitations": {
                    "items": {
                      "minLength": 1,
                      "type": "string"
                    },
                    "type": "array"
                  },
                  "path": {
                    "description": "Local filesystem path used by this operation.",
                    "minLength": 1,
                    "type": "string"
                  },
                  "tree_state": {
                    "enum": [
                      "enumerated",
                      "partial",
                      "excluded",
                      "unreadable",
                      "unknown"
                    ],
                    "type": "string"
                  }
                },
                "required": [
                  "path",
                  "classifications",
                  "limitations",
                  "kind",
                  "tree_state"
                ],
                "type": "object"
              },
              {
                "anyOf": [
                  {
                    "additionalProperties": false,
                    "properties": {
                      "classifications": {
                        "items": {
                          "enum": [
                            "source",
                            "test",
                            "config",
                            "manifest",
                            "generated",
                            "vendor",
                            "documentation",
                            "unknown"
                          ],
                          "type": "string"
                        },
                        "minItems": 1,
                        "type": "array"
                      },
                      "kind": {
                        "const": "symlink",
                        "type": "string"
                      },
                      "limitations": {
                        "items": {
                          "minLength": 1,
                          "type": "string"
                        },
                        "type": "array"
                      },
                      "path": {
                        "description": "Local filesystem path used by this operation.",
                        "minLength": 1,
                        "type": "string"
                      },
                      "target": {
                        "minLength": 1,
                        "type": "string"
                      },
                      "target_state": {
                        "enum": [
                          "internal",
                          "external",
                          "missing"
                        ],
                        "type": "string"
                      }
                    },
                    "required": [
                      "path",
                      "classifications",
                      "limitations",
                      "kind",
                      "target",
                      "target_state"
                    ],
                    "type": "object"
                  },
                  {
                    "additionalProperties": false,
                    "properties": {
                      "classifications": {
                        "items": {
                          "enum": [
                            "source",
                            "test",
                            "config",
                            "manifest",
                            "generated",
                            "vendor",
                            "documentation",
                            "unknown"
                          ],
                          "type": "string"
                        },
                        "minItems": 1,
                        "type": "array"
                      },
                      "kind": {
                        "const": "symlink",
                        "type": "string"
                      },
                      "limitations": {
                        "items": {
                          "minLength": 1,
                          "type": "string"
                        },
                        "type": "array"
                      },
                      "path": {
                        "description": "Local filesystem path used by this operation.",
                        "minLength": 1,
                        "type": "string"
                      },
                      "target": {
                        "type": "null"
                      },
                      "target_state": {
                        "enum": [
                          "unreadable",
                          "unknown"
                        ],
                        "type": "string"
                      }
                    },
                    "required": [
                      "path",
                      "classifications",
                      "limitations",
                      "kind",
                      "target",
                      "target_state"
                    ],
                    "type": "object"
                  }
                ]
              },
              {
                "additionalProperties": false,
                "properties": {
                  "classifications": {
                    "items": {
                      "enum": [
                        "source",
                        "test",
                        "config",
                        "manifest",
                        "generated",
                        "vendor",
                        "documentation",
                        "unknown"
                      ],
                      "type": "string"
                    },
                    "minItems": 1,
                    "type": "array"
                  },
                  "kind": {
                    "const": "unknown",
                    "type": "string"
                  },
                  "limitations": {
                    "items": {
                      "minLength": 1,
                      "type": "string"
                    },
                    "type": "array"
                  },
                  "path": {
                    "description": "Local filesystem path used by this operation.",
                    "minLength": 1,
                    "type": "string"
                  }
                },
                "required": [
                  "path",
                  "classifications",
                  "limitations",
                  "kind"
                ],
                "type": "object"
              }
            ]
          },
          "type": "array"
        },
        "exclusions": {
          "items": {
            "oneOf": [
              {
                "additionalProperties": false,
                "properties": {
                  "entry_kind": {
                    "enum": [
                      "file",
                      "directory",
                      "symlink",
                      "other",
                      "unknown"
                    ],
                    "type": "string"
                  },
                  "path": {
                    "description": "Local filesystem path used by this operation.",
                    "minLength": 1,
                    "type": "string"
                  },
                  "pattern": {
                    "description": "Literal text or regular expression used to filter matching results.",
                    "minLength": 1,
                    "type": "string"
                  },
                  "reason": {
                    "enum": [
                      "configured-secret",
                      "project-ignored",
                      "default-ignored",
                      "caller-excluded"
                    ],
                    "type": "string"
                  }
                },
                "required": [
                  "path",
                  "reason",
                  "pattern"
                ],
                "type": "object"
              },
              {
                "additionalProperties": false,
                "properties": {
                  "entry_kind": {
                    "enum": [
                      "file",
                      "directory",
                      "symlink",
                      "other",
                      "unknown"
                    ],
                    "type": "string"
                  },
                  "path": {
                    "description": "Local filesystem path used by this operation.",
                    "minLength": 1,
                    "type": "string"
                  },
                  "reason": {
                    "enum": [
                      "symlink-escape",
                      "unreadable"
                    ],
                    "type": "string"
                  }
                },
                "required": [
                  "path",
                  "reason"
                ],
                "type": "object"
              }
            ]
          },
          "type": "array"
        },
        "inventory_state": {
          "enum": [
            "complete",
            "partial",
            "unknown"
          ],
          "type": "string"
        },
        "languages": {
          "items": {
            "minLength": 1,
            "type": "string"
          },
          "type": "array"
        },
        "limitations": {
          "items": {
            "minLength": 1,
            "type": "string"
          },
          "type": "array"
        },
        "manifests": {
          "items": {
            "minLength": 1,
            "type": "string"
          },
          "type": "array"
        },
        "parse_failures": {
          "items": {
            "additionalProperties": false,
            "properties": {
              "parser": {
                "minLength": 1,
                "type": "string"
              },
              "path": {
                "description": "Local filesystem path used by this operation.",
                "minLength": 1,
                "type": "string"
              },
              "reason": {
                "minLength": 1,
                "type": "string"
              }
            },
            "required": [
              "path",
              "parser",
              "reason"
            ],
            "type": "object"
          },
          "type": "array"
        },
        "provenance": {
          "additionalProperties": false,
          "properties": {
            "caller": {
              "minLength": 1,
              "pattern": "^[\\w .:@\\x2f+\\x2d]+$",
              "type": "string"
            },
            "importer": {
              "minLength": 1,
              "type": "string"
            },
            "importer_version": {
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
            "importer",
            "importer_version",
            "caller"
          ],
          "type": "object"
        },
        "relationships": {
          "items": {
            "additionalProperties": false,
            "properties": {
              "from_path": {
                "description": "Local filesystem path for from.",
                "minLength": 1,
                "type": "string"
              },
              "kind": {
                "enum": [
                  "imports",
                  "requires",
                  "references",
                  "declares-module"
                ],
                "type": "string"
              },
              "parse_state": {
                "enum": [
                  "parsed",
                  "partial",
                  "unknown"
                ],
                "type": "string"
              },
              "resolution": {
                "enum": [
                  "internal",
                  "external",
                  "unresolved",
                  "unknown"
                ],
                "type": "string"
              },
              "to": {
                "minLength": 1,
                "type": "string"
              }
            },
            "required": [
              "from_path",
              "to",
              "kind",
              "resolution",
              "parse_state"
            ],
            "type": "object"
          },
          "type": "array"
        },
        "root_alias": {
          "const": "$REFERENCE_ROOT",
          "type": "string"
        },
        "root_sha256": {
          "description": "Exact SHA-256 digest of root.",
          "pattern": "^[a-f0-9]{64}$",
          "type": "string"
        },
        "schema": {
          "const": "HistoricalSourceGraph",
          "type": "string"
        },
        "vcs": {
          "anyOf": [
            {
              "oneOf": [
                {
                  "additionalProperties": false,
                  "properties": {
                    "dirty": {
                      "anyOf": [
                        {
                          "type": "boolean"
                        },
                        {
                          "type": "null"
                        }
                      ]
                    },
                    "head": {
                      "pattern": "^(?:[a-f0-9]{40}|[a-f0-9]{64})$",
                      "type": "string"
                    },
                    "kind": {
                      "const": "git",
                      "type": "string"
                    }
                  },
                  "required": [
                    "kind",
                    "head",
                    "dirty"
                  ],
                  "type": "object"
                },
                {
                  "additionalProperties": false,
                  "properties": {
                    "dirty": {
                      "type": "null"
                    },
                    "head": {
                      "type": "null"
                    },
                    "kind": {
                      "const": "none",
                      "type": "string"
                    }
                  },
                  "required": [
                    "kind",
                    "head",
                    "dirty"
                  ],
                  "type": "object"
                },
                {
                  "additionalProperties": false,
                  "properties": {
                    "dirty": {
                      "type": "null"
                    },
                    "head": {
                      "type": "null"
                    },
                    "kind": {
                      "const": "unknown",
                      "type": "string"
                    }
                  },
                  "required": [
                    "kind",
                    "head",
                    "dirty"
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
        "schema",
        "authority",
        "root_alias",
        "root_sha256",
        "inventory_state",
        "entries",
        "relationships",
        "parse_failures",
        "exclusions",
        "languages",
        "manifests",
        "vcs",
        "provenance",
        "limitations"
      ],
      "type": "object"
    }
  },
  "required": [
    "reference",
    "application"
  ],
  "type": "object"
}
```

</details>

**Output schema:** see [`tool-specs/compare_source_to_bundle.json`](../tool-specs/compare_source_to_bundle.json) (`outputSchema`).

---

## evaluate_reconstruction_coverage

<a id="evaluatereconstructioncoverage"></a>

**Title:** Evaluate Reconstruction Coverage  
**Kind:** `application` · **Requires session:** false · **analysisOperation:** null  
**Providers:** rea-javascript-application-workflows  
**Effects set (true flags):** none (pure read)  
**MCP annotations:** `{"destructiveHint":false,"idempotentHint":true,"openWorldHint":false,"readOnlyHint":true}`

**Description (verbatim, as advertised to the agent):**

> Evaluate inline evidence-backed reconstruction coverage against one named boundary. Missing ownership or inventory is partial; stale, weak, truncated, skipped, unresolved, or conflicting tied verifier proof is unknown; contradictions, failed proof, missing owners, and authority routing fail closed.

**Input schema (verbatim, JSON Schema 2020-12):**

<details><summary>inputSchema for evaluate_reconstruction_coverage</summary>

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "additionalProperties": false,
  "examples": [
    {
      "boundary_id": "replacement.cli",
      "coverage": {
        "artifacts": [],
        "boundaries": [
          {
            "allowed_dispositions": [],
            "allowed_unknown_ids": [],
            "boundary_id": "replacement.cli",
            "required_claim_ids": [
              "claim.cli.help"
            ],
            "required_package_proof_kinds": [
              "clean-install",
              "authority-independence"
            ],
            "required_surface_ids": [
              "cli.help"
            ],
            "title": "CLI replacement"
          }
        ],
        "claims": [],
        "contradictions": [],
        "evidence_bundle": {
          "artifacts": [],
          "captures": [],
          "environments": [],
          "providers": [],
          "records": [],
          "scenarios": [],
          "unknowns": []
        },
        "owners": [],
        "package_proofs": [],
        "residual_unknown_ids": [],
        "surfaces": [],
        "verifier_contracts": [],
        "verifier_results": []
      }
    }
  ],
  "properties": {
    "boundary_id": {
      "description": "Exact reconstruction boundary identifier to evaluate.",
      "minLength": 1,
      "type": "string"
    },
    "coverage": {
      "additionalProperties": false,
      "description": "Exact reconstruction-coverage commitment to verify.",
      "properties": {
        "artifacts": {
          "items": {
            "additionalProperties": false,
            "properties": {
              "artifact_id": {
                "pattern": "^[A-Za-z][A-Za-z0-9._:\\x2f\\x2d]{0,199}$",
                "type": "string"
              },
              "artifact_sha256": {
                "description": "Exact SHA-256 digest of artifact.",
                "pattern": "^[a-f0-9]{64}$",
                "type": "string"
              },
              "environment_sha256": {
                "description": "Exact SHA-256 digest of environment.",
                "pattern": "^[a-f0-9]{64}$",
                "type": "string"
              },
              "evidence_ids": {
                "items": {
                  "pattern": "^ev_[a-f0-9]{64}$",
                  "type": "string"
                },
                "minItems": 1,
                "type": "array"
              },
              "version": {
                "minLength": 1,
                "type": "string"
              }
            },
            "required": [
              "artifact_id",
              "artifact_sha256",
              "version",
              "environment_sha256",
              "evidence_ids"
            ],
            "type": "object"
          },
          "type": "array"
        },
        "boundaries": {
          "items": {
            "additionalProperties": false,
            "properties": {
              "allowed_dispositions": {
                "items": {
                  "enum": [
                    "external",
                    "non-goal"
                  ],
                  "type": "string"
                },
                "type": "array"
              },
              "allowed_unknown_ids": {
                "items": {
                  "pattern": "^[A-Za-z][A-Za-z0-9._:\\x2f\\x2d]{0,199}$",
                  "type": "string"
                },
                "type": "array"
              },
              "boundary_id": {
                "description": "Exact reconstruction boundary identifier to evaluate.",
                "pattern": "^[A-Za-z][A-Za-z0-9._:\\x2f\\x2d]{0,199}$",
                "type": "string"
              },
              "required_claim_ids": {
                "items": {
                  "pattern": "^[A-Za-z][A-Za-z0-9._:\\x2f\\x2d]{0,199}$",
                  "type": "string"
                },
                "minItems": 1,
                "type": "array"
              },
              "required_package_proof_kinds": {
                "items": {
                  "enum": [
                    "build",
                    "clean-install",
                    "package-contents",
                    "runtime-routing",
                    "authority-independence"
                  ],
                  "type": "string"
                },
                "minItems": 1,
                "type": "array"
              },
              "required_surface_ids": {
                "items": {
                  "pattern": "^[A-Za-z][A-Za-z0-9._:\\x2f\\x2d]{0,199}$",
                  "type": "string"
                },
                "minItems": 1,
                "type": "array"
              },
              "title": {
                "minLength": 1,
                "type": "string"
              }
            },
            "required": [
              "boundary_id",
              "title",
              "required_surface_ids",
              "required_claim_ids",
              "required_package_proof_kinds",
              "allowed_dispositions",
              "allowed_unknown_ids"
            ],
            "type": "object"
          },
          "type": "array"
        },
        "claims": {
          "items": {
            "additionalProperties": false,
            "properties": {
              "claim_id": {
                "pattern": "^[A-Za-z][A-Za-z0-9._:\\x2f\\x2d]{0,199}$",
                "type": "string"
              },
              "kind": {
                "minLength": 1,
                "type": "string"
              },
              "required_authority": {
                "enum": [
                  "shipped-artifact",
                  "controlled-replay",
                  "live-observation",
                  "external"
                ],
                "type": "string"
              },
              "required_dimensions": {
                "items": {
                  "pattern": "^[A-Za-z][A-Za-z0-9._:\\x2f\\x2d]{0,199}$",
                  "type": "string"
                },
                "minItems": 1,
                "type": "array"
              },
              "surface_ids": {
                "items": {
                  "pattern": "^[A-Za-z][A-Za-z0-9._:\\x2f\\x2d]{0,199}$",
                  "type": "string"
                },
                "minItems": 1,
                "type": "array"
              },
              "title": {
                "minLength": 1,
                "type": "string"
              }
            },
            "required": [
              "claim_id",
              "title",
              "kind",
              "surface_ids",
              "required_dimensions",
              "required_authority"
            ],
            "type": "object"
          },
          "type": "array"
        },
        "contradictions": {
          "items": {
            "additionalProperties": false,
            "properties": {
              "claim_ids": {
                "items": {
                  "pattern": "^[A-Za-z][A-Za-z0-9._:\\x2f\\x2d]{0,199}$",
                  "type": "string"
                },
                "type": "array"
              },
              "contradiction_id": {
                "pattern": "^[A-Za-z][A-Za-z0-9._:\\x2f\\x2d]{0,199}$",
                "type": "string"
              },
              "evidence_ids": {
                "items": {
                  "pattern": "^ev_[a-f0-9]{64}$",
                  "type": "string"
                },
                "minItems": 2,
                "type": "array"
              },
              "status": {
                "description": "Current lifecycle or verification status.",
                "enum": [
                  "active",
                  "resolved"
                ],
                "type": "string"
              },
              "surface_ids": {
                "items": {
                  "pattern": "^[A-Za-z][A-Za-z0-9._:\\x2f\\x2d]{0,199}$",
                  "type": "string"
                },
                "type": "array"
              }
            },
            "required": [
              "contradiction_id",
              "status",
              "surface_ids",
              "claim_ids",
              "evidence_ids"
            ],
            "type": "object"
          },
          "type": "array"
        },
        "evidence_bundle": {
          "additionalProperties": false,
          "properties": {
            "artifacts": {
              "items": {
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
                      }
                    },
                    "required": [
                      "digest",
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
                      }
                    },
                    "required": [
                      "digest",
                      "format",
                      "architecture"
                    ],
                    "type": "object"
                  }
                ]
              },
              "type": "array"
            },
            "captures": {
              "items": {
                "additionalProperties": false,
                "properties": {
                  "evidence_id": {
                    "description": "Stable identifier of the recorded Evidence observation.",
                    "pattern": "^ev_[a-f0-9]{64}$",
                    "type": "string"
                  },
                  "predicate_type": {
                    "minLength": 1,
                    "type": "string"
                  }
                },
                "required": [
                  "evidence_id",
                  "predicate_type"
                ],
                "type": "object"
              },
              "type": "array"
            },
            "environments": {
              "items": {
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
              "type": "array"
            },
            "providers": {
              "items": {
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
              "type": "array"
            },
            "records": {
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
              "type": "array"
            },
            "scenarios": {
              "items": {
                "additionalProperties": false,
                "properties": {
                  "authority": {
                    "const": "controlled-replay",
                    "type": "string"
                  },
                  "evidence_id": {
                    "description": "Stable identifier of the recorded Evidence observation.",
                    "pattern": "^ev_[a-f0-9]{64}$",
                    "type": "string"
                  },
                  "operation": {
                    "minLength": 1,
                    "type": "string"
                  }
                },
                "required": [
                  "evidence_id",
                  "operation",
                  "authority"
                ],
                "type": "object"
              },
              "type": "array"
            },
            "unknowns": {
              "items": {
                "additionalProperties": false,
                "properties": {
                  "comparison_conclusion_scope": {
                    "additionalProperties": false,
                    "properties": {
                      "comparison_evidence_id": {
                        "description": "Exact Evidence identifier for the comparison observation.",
                        "pattern": "^ev_[a-f0-9]{64}$",
                        "type": "string"
                      },
                      "dimensions": {
                        "items": {
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
                        "minItems": 1,
                        "type": "array"
                      }
                    },
                    "required": [
                      "comparison_evidence_id",
                      "dimensions"
                    ],
                    "type": "object"
                  },
                  "contradicting_evidence_ids": {
                    "description": "Ordered Evidence identifiers for the contradicting observations.",
                    "items": {
                      "pattern": "^ev_[a-f0-9]{64}$",
                      "type": "string"
                    },
                    "type": "array"
                  },
                  "domain": {
                    "minLength": 1,
                    "type": "string"
                  },
                  "mutation_evidence_ids": {
                    "description": "Ordered Evidence identifiers for the mutation observations.",
                    "items": {
                      "pattern": "^ev_[a-f0-9]{64}$",
                      "type": "string"
                    },
                    "minItems": 1,
                    "type": "array"
                  },
                  "previous_revision_digest": {
                    "anyOf": [
                      {
                        "pattern": "^[a-f0-9]{64}$",
                        "type": "string"
                      },
                      {
                        "type": "null"
                      }
                    ]
                  },
                  "question": {
                    "description": "Concrete unresolved question to retain for later investigation.",
                    "minLength": 1,
                    "type": "string"
                  },
                  "recommended_probes": {
                    "items": {
                      "additionalProperties": false,
                      "properties": {
                        "operation": {
                          "minLength": 1,
                          "type": "string"
                        },
                        "rationale": {
                          "minLength": 1,
                          "type": "string"
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
                  "relationships": {
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
                  "required_authority": {
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
                  "required_confidence": {
                    "enum": [
                      "observed",
                      "derived",
                      "inferred"
                    ],
                    "type": "string"
                  },
                  "required_environment": {
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
                  "resolution": {
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
                                  "pattern": "^ev_[a-f0-9]{64}$",
                                  "type": "string"
                                },
                                "minItems": 1,
                                "type": "array"
                              },
                              "rationale": {
                                "minLength": 1,
                                "type": "string"
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
                                  "pattern": "^ev_[a-f0-9]{64}$",
                                  "type": "string"
                                },
                                "type": "array"
                              },
                              "rationale": {
                                "minLength": 1,
                                "type": "string"
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
                  "revision": {
                    "maximum": 9007199254740991,
                    "minimum": 1,
                    "type": "integer"
                  },
                  "revision_digest": {
                    "pattern": "^[a-f0-9]{64}$",
                    "type": "string"
                  },
                  "scope_digest": {
                    "anyOf": [
                      {
                        "pattern": "^[a-f0-9]{64}$",
                        "type": "string"
                      },
                      {
                        "type": "null"
                      }
                    ]
                  },
                  "severity": {
                    "enum": [
                      "low",
                      "medium",
                      "high",
                      "critical"
                    ],
                    "type": "string"
                  },
                  "status": {
                    "description": "Current lifecycle or verification status.",
                    "enum": [
                      "open",
                      "investigating",
                      "blocked",
                      "contradicted",
                      "resolved"
                    ],
                    "type": "string"
                  },
                  "supporting_evidence_ids": {
                    "description": "Ordered Evidence identifiers for the supporting observations.",
                    "items": {
                      "pattern": "^ev_[a-f0-9]{64}$",
                      "type": "string"
                    },
                    "type": "array"
                  },
                  "unknown_id": {
                    "description": "Exact residual-unknown identifier.",
                    "pattern": "^unk_[a-f0-9]{64}$",
                    "type": "string"
                  }
                },
                "required": [
                  "unknown_id",
                  "revision",
                  "previous_revision_digest",
                  "revision_digest",
                  "scope_digest",
                  "question",
                  "status",
                  "severity",
                  "domain",
                  "supporting_evidence_ids",
                  "contradicting_evidence_ids",
                  "required_authority",
                  "required_confidence",
                  "required_environment",
                  "recommended_probes",
                  "relationships",
                  "resolution",
                  "mutation_evidence_ids"
                ],
                "type": "object"
              },
              "type": "array"
            }
          },
          "required": [
            "artifacts",
            "providers",
            "environments",
            "scenarios",
            "captures",
            "unknowns",
            "records"
          ],
          "type": "object"
        },
        "owners": {
          "items": {
            "additionalProperties": false,
            "properties": {
              "ownership": {
                "oneOf": [
                  {
                    "additionalProperties": false,
                    "properties": {
                      "authority_route": {
                        "enum": [
                          "none",
                          "detected",
                          "unknown"
                        ],
                        "type": "string"
                      },
                      "disposition": {
                        "const": "implemented",
                        "type": "string"
                      },
                      "owner_export": {
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
                      "owner_path": {
                        "description": "Local filesystem path for owner.",
                        "minLength": 1,
                        "type": "string"
                      },
                      "owner_sha256": {
                        "description": "Exact SHA-256 digest of owner.",
                        "pattern": "^[a-f0-9]{64}$",
                        "type": "string"
                      },
                      "package_state": {
                        "enum": [
                          "distributed",
                          "missing",
                          "unknown"
                        ],
                        "type": "string"
                      },
                      "path_state": {
                        "enum": [
                          "present",
                          "missing",
                          "unknown"
                        ],
                        "type": "string"
                      }
                    },
                    "required": [
                      "disposition",
                      "owner_path",
                      "owner_export",
                      "owner_sha256",
                      "path_state",
                      "package_state",
                      "authority_route"
                    ],
                    "type": "object"
                  },
                  {
                    "additionalProperties": false,
                    "properties": {
                      "disposition": {
                        "enum": [
                          "external",
                          "non-goal"
                        ],
                        "type": "string"
                      },
                      "rationale": {
                        "minLength": 1,
                        "type": "string"
                      }
                    },
                    "required": [
                      "disposition",
                      "rationale"
                    ],
                    "type": "object"
                  }
                ]
              },
              "surface_id": {
                "pattern": "^[A-Za-z][A-Za-z0-9._:\\x2f\\x2d]{0,199}$",
                "type": "string"
              }
            },
            "required": [
              "surface_id",
              "ownership"
            ],
            "type": "object"
          },
          "type": "array"
        },
        "package_proofs": {
          "items": {
            "additionalProperties": false,
            "properties": {
              "artifact_sha256s": {
                "items": {
                  "pattern": "^[a-f0-9]{64}$",
                  "type": "string"
                },
                "minItems": 1,
                "type": "array"
              },
              "evidence_ids": {
                "items": {
                  "pattern": "^ev_[a-f0-9]{64}$",
                  "type": "string"
                },
                "minItems": 1,
                "type": "array"
              },
              "kind": {
                "enum": [
                  "build",
                  "clean-install",
                  "package-contents",
                  "runtime-routing",
                  "authority-independence"
                ],
                "type": "string"
              },
              "proof_id": {
                "pattern": "^[A-Za-z][A-Za-z0-9._:\\x2f\\x2d]{0,199}$",
                "type": "string"
              },
              "status": {
                "description": "Current lifecycle or verification status.",
                "enum": [
                  "pass",
                  "fail",
                  "unknown",
                  "unsupported",
                  "skipped"
                ],
                "type": "string"
              }
            },
            "required": [
              "proof_id",
              "kind",
              "status",
              "artifact_sha256s",
              "evidence_ids"
            ],
            "type": "object"
          },
          "type": "array"
        },
        "residual_unknown_ids": {
          "items": {
            "pattern": "^[A-Za-z][A-Za-z0-9._:\\x2f\\x2d]{0,199}$",
            "type": "string"
          },
          "type": "array"
        },
        "surfaces": {
          "items": {
            "additionalProperties": false,
            "properties": {
              "artifact_id": {
                "pattern": "^[A-Za-z][A-Za-z0-9._:\\x2f\\x2d]{0,199}$",
                "type": "string"
              },
              "authority": {
                "enum": [
                  "observed",
                  "derived",
                  "inferred",
                  "historical",
                  "external"
                ],
                "type": "string"
              },
              "dependency_surface_ids": {
                "items": {
                  "pattern": "^[A-Za-z][A-Za-z0-9._:\\x2f\\x2d]{0,199}$",
                  "type": "string"
                },
                "type": "array"
              },
              "evidence_ids": {
                "items": {
                  "pattern": "^ev_[a-f0-9]{64}$",
                  "type": "string"
                },
                "minItems": 1,
                "type": "array"
              },
              "family": {
                "minLength": 1,
                "type": "string"
              },
              "location": {
                "minLength": 1,
                "type": "string"
              },
              "occurrence_id": {
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
              "surface_id": {
                "pattern": "^[A-Za-z][A-Za-z0-9._:\\x2f\\x2d]{0,199}$",
                "type": "string"
              }
            },
            "required": [
              "surface_id",
              "family",
              "artifact_id",
              "occurrence_id",
              "location",
              "authority",
              "dependency_surface_ids",
              "evidence_ids"
            ],
            "type": "object"
          },
          "type": "array"
        },
        "verifier_contracts": {
          "items": {
            "additionalProperties": false,
            "properties": {
              "authority": {
                "enum": [
                  "shipped-artifact",
                  "controlled-replay",
                  "live-observation",
                  "external"
                ],
                "type": "string"
              },
              "claim_ids": {
                "items": {
                  "pattern": "^[A-Za-z][A-Za-z0-9._:\\x2f\\x2d]{0,199}$",
                  "type": "string"
                },
                "minItems": 1,
                "type": "array"
              },
              "contract_sha256": {
                "description": "Exact SHA-256 digest of contract.",
                "pattern": "^[a-f0-9]{64}$",
                "type": "string"
              },
              "dimensions": {
                "items": {
                  "pattern": "^[A-Za-z][A-Za-z0-9._:\\x2f\\x2d]{0,199}$",
                  "type": "string"
                },
                "minItems": 1,
                "type": "array"
              },
              "max_age_ms": {
                "description": "Maximum permitted age ms for this operation.",
                "maximum": 9007199254740991,
                "minimum": 1,
                "type": "integer"
              },
              "minimum_repeats": {
                "maximum": 9007199254740991,
                "minimum": 1,
                "type": "integer"
              },
              "normalization_removes_dimensions": {
                "const": false,
                "type": "boolean"
              },
              "normalization_sha256": {
                "description": "Exact SHA-256 digest of normalization.",
                "pattern": "^[a-f0-9]{64}$",
                "type": "string"
              },
              "verifier_id": {
                "pattern": "^[A-Za-z][A-Za-z0-9._:\\x2f\\x2d]{0,199}$",
                "type": "string"
              }
            },
            "required": [
              "verifier_id",
              "claim_ids",
              "dimensions",
              "authority",
              "max_age_ms",
              "minimum_repeats",
              "normalization_sha256",
              "normalization_removes_dimensions",
              "contract_sha256"
            ],
            "type": "object"
          },
          "type": "array"
        },
        "verifier_results": {
          "items": {
            "additionalProperties": false,
            "properties": {
              "artifact_sha256s": {
                "items": {
                  "pattern": "^[a-f0-9]{64}$",
                  "type": "string"
                },
                "minItems": 1,
                "type": "array"
              },
              "contract_sha256": {
                "description": "Exact SHA-256 digest of contract.",
                "pattern": "^[a-f0-9]{64}$",
                "type": "string"
              },
              "covered_claim_ids": {
                "items": {
                  "pattern": "^[A-Za-z][A-Za-z0-9._:\\x2f\\x2d]{0,199}$",
                  "type": "string"
                },
                "minItems": 1,
                "type": "array"
              },
              "covered_dimensions": {
                "items": {
                  "pattern": "^[A-Za-z][A-Za-z0-9._:\\x2f\\x2d]{0,199}$",
                  "type": "string"
                },
                "minItems": 1,
                "type": "array"
              },
              "evidence_ids": {
                "items": {
                  "pattern": "^ev_[a-f0-9]{64}$",
                  "type": "string"
                },
                "minItems": 1,
                "type": "array"
              },
              "normalization_sha256": {
                "description": "Exact SHA-256 digest of normalization.",
                "pattern": "^[a-f0-9]{64}$",
                "type": "string"
              },
              "observed_at": {
                "pattern": "^(?:(?:\\d\\d[2468][048]|\\d\\d[13579][26]|\\d\\d0[48]|[02468][048]00|[13579][26]00)-02-29|\\d{4}-(?:(?:0[13578]|1[02])-(?:0[1-9]|[12]\\d|3[01])|(?:0[469]|11)-(?:0[1-9]|[12]\\d|30)|(?:02)-(?:0[1-9]|1\\d|2[0-8])))T(?:(?:[01]\\d|2[0-3]):[0-5]\\d(?::[0-5]\\d(?:\\.\\d+)?)?(?:Z|(?:[+\\x2d](?:[01]\\d|2[0-3]):[0-5]\\d)))$",
                "type": "string"
              },
              "owner_sha256s": {
                "items": {
                  "pattern": "^[a-f0-9]{64}$",
                  "type": "string"
                },
                "type": "array"
              },
              "repeats": {
                "maximum": 9007199254740991,
                "minimum": 1,
                "type": "integer"
              },
              "status": {
                "description": "Current lifecycle or verification status.",
                "enum": [
                  "pass",
                  "fail",
                  "unknown",
                  "unsupported",
                  "truncated",
                  "skipped"
                ],
                "type": "string"
              },
              "verifier_id": {
                "pattern": "^[A-Za-z][A-Za-z0-9._:\\x2f\\x2d]{0,199}$",
                "type": "string"
              }
            },
            "required": [
              "verifier_id",
              "contract_sha256",
              "observed_at",
              "status",
              "covered_claim_ids",
              "covered_dimensions",
              "artifact_sha256s",
              "owner_sha256s",
              "normalization_sha256",
              "repeats",
              "evidence_ids"
            ],
            "type": "object"
          },
          "type": "array"
        }
      },
      "required": [
        "evidence_bundle",
        "artifacts",
        "surfaces",
        "owners",
        "claims",
        "verifier_contracts",
        "verifier_results",
        "residual_unknown_ids",
        "contradictions",
        "package_proofs",
        "boundaries"
      ],
      "type": "object"
    }
  },
  "required": [
    "coverage",
    "boundary_id"
  ],
  "type": "object"
}
```

</details>

**Output schema:** see [`tool-specs/evaluate_reconstruction_coverage.json`](../tool-specs/evaluate_reconstruction_coverage.json) (`outputSchema`).

---

## export_web_scripts

<a id="exportwebscripts"></a>

**Title:** Export Web Scripts  
**Kind:** `application` · **Requires session:** false · **analysisOperation:** null  
**Providers:** rea-web-script-export  
**Effects set (true flags):** NOT idempotent, mutatesSession, writesFilesystem  
**MCP annotations:** `{"destructiveHint":false,"idempotentHint":false,"openWorldHint":false,"readOnlyHint":false}`

**Description (verbatim, as advertised to the agent):**

> Export JavaScript bytes already retained in one local inspect_web_page or capture_browser_scenario JSON capture (normalized result or complete Evidence). Writes scripts and a digest-verified manifest into an absent absolute output_directory. Returns all source URLs, script or transaction/event references, unavailable states, and an analysis_input for analyze_javascript_application when any bytes were exported. Include script sources in inspect_web_page or select capture.network.response_body in scenarios. No refetch or execution. Safe unambiguous URL layouts preserve relative module paths; versions, query variants, inline scripts, and path collisions are isolated with explicit resolution limitations.

**Input schema (verbatim, JSON Schema 2020-12):**

<details><summary>inputSchema for export_web_scripts</summary>

```json
{
  "$defs": {
    "__schema0": {
      "$ref": "#/$defs/__schema1",
      "description": "Absolute filesystem path to saved inspect_web_page or capture_browser_scenario JSON, normalized result or complete Evidence"
    },
    "__schema1": {
      "minLength": 1,
      "pattern": "^[^\\x00]*$",
      "type": "string"
    },
    "__schema2": {
      "$ref": "#/$defs/__schema1",
      "description": "Absolute absent filesystem directory for verified scripts and manifest; parent directory must exist"
    }
  },
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "additionalProperties": false,
  "examples": [
    {
      "capture_path": "/analysis/capture.json",
      "output_directory": "/analysis/exported-scripts"
    }
  ],
  "properties": {
    "capture_path": {
      "$ref": "#/$defs/__schema0",
      "description": "Absolute filesystem path to saved inspect_web_page or capture_browser_scenario JSON, normalized result or complete Evidence"
    },
    "output_directory": {
      "$ref": "#/$defs/__schema2",
      "description": "Absolute absent filesystem directory for verified scripts and manifest; parent directory must exist"
    }
  },
  "required": [
    "capture_path",
    "output_directory"
  ],
  "type": "object"
}
```

</details>

**Output schema:** see [`tool-specs/export_web_scripts.json`](../tool-specs/export_web_scripts.json) (`outputSchema`).

---

## inspect_analysis_view

<a id="inspectanalysisview"></a>

**Title:** Inspect Analysis View  
**Kind:** `application` · **Requires session:** false · **analysisOperation:** null  
**Providers:** rea-analysis-view  
**Effects set (true flags):** mutatesSession  
**MCP annotations:** `{"destructiveHint":false,"idempotentHint":true,"openWorldHint":false,"readOnlyHint":false}`

**Description (verbatim, as advertised to the agent):**

> Inspect selected views of completed binary-layout, JavaScript application, native analyze_function, inspect_artifact, inventory_artifact, inspect_wasm_artifact, inspect_macho, decode_interface_builder, inspect_evm_interface, inspect_managed_artifact, inspect_managed_members, inspect_android_package, inspect_dart_aot or inspect_web_network_capture Evidence without repeating analysis. Historical capture summaries return identity and counts without bodies or archive inventories. Capture views page retained records: view {kind: "capture", detail: "preview" | "complete", offset: 0, limit: 20}; preview selects recorded headline fields and binary descriptors, complete returns exact records with all sidecars. Offsets follow the selected parent record order, preserving original producer ordinals. Paging never reopens the source or reruns the decoder. For inspect_pcap_capture parents, kind pcap pages endpoints, dns-queries, tls-sni, protocols, http-uris or unattributed-addresses. Select an exact query for dns-addresses, or a tshark/capinfos stream for UTF-16 diagnostics text. Page totals count retained facts; source coverage remains explicit. Qlog summaries keep profile/scope and counts; kind qlog pages traces, streams, loss-declarations, incomplete-records, contributions, ranges or final-sizes. Except traces, select trace_index; stream-specific facets also require exact stream_id and direction. Facts retain all-recorded-events-before-selection scope, and interval overlap or endpoint loss declarations do not prove retransmission or network loss. The api-surface view groups retained HAR requests by method, origin and format-rule path template; templated segments are inferences. It reads no headers or bodies and reports no query values. For a retained record use source: {kind: "retained-evidence", evidence_id: "<parent_evidence_id>"}. Use normalized_result.parent_evidence_id from a summary receipt. Source kind is required. Portable source uses {kind: "inline", evidence: <complete Evidence>}. For layout, JavaScript, inventory, WASM, Mach-O, Interface Builder, EVM, managed artifact, Android package and Dart AOT sources, request a summary with view: {kind: "summary"}; summary is a view kind and has no facet. The WASM summary gives validation, counts, WAT digest/length, tool profile and execution/network states without reading WAT text. Select a layout mitigations/linkage facet, one section/symbol/module, or a stable page. Module pages include assets, bundled and source modules; use node_id for ambiguous or unavailable paths. Inventory uses view: {kind: "inventory", collection: "occurrences", logical_paths: ["package.json"], offset: 0, limit: 64}. Inventory views page nodes, occurrences, edges or integrity contradictions; occurrence logical_paths matches exact recorded strings (omitted means all available, [] means none). source_complete distinguishes complete inventories from partial source records; page exhaustion does not prove absence in a partial source. WASM views use kind wasm and facet sections/imports/exports/candidates/glue/wat/headers/details/tool_profile; text facets use UTF-16 code units and source forms remain exact. Mach-O views use kind macho and facet entrypoints/architectures/build_metadata/load_commands/dependencies/imports/exports/segments/provenance; source_exhaustive false means unreturned rows may exist. Interface Builder views use kind interface-builder and collection documents/nodes/edges/coverage; nodes and edges accept an exact document relative_path. EVM summary returns all inferred interface candidates, carrier/decoded identities and explicit unknowns without hex or duplicate stdout. EVM views use kind evm and facet functions/bytecode_hex/stdout/stderr; function pages preserve the original candidate rows, and text offsets/limits count UTF-16 code units (hex has two characters per decoded byte). Exhausting candidate pages does not establish global interface completeness. Managed artifact summaries preserve complete identity/classification, metadata status, module/MVID, frameworks, coverage and limitations without unrelated inventories. Managed pages use kind managed and collection references/resources/attributes, retaining source coverage and build-local token scope; page exhaustion does not establish complete metadata. Managed member summaries keep identity, selection with unmatched names, coverage and per-collection counts; managed-members pages use collection types/exported_types/fields/methods/member_refs/call_edges/field_accesses/user_strings and carry the source selection and coverage. Android package summaries retain all declarations, engine identity and counts without decoded manifest text. Android manifest pages use kind android, facet manifest, offset and limit in UTF-16 code units; source_status preserves partial decoded coverage even when the retained text page is exhausted. Dart AOT summary preserves target/ABI/library identity, snapshot headers and pool lower bounds. String pages use kind dart-aot, collection package_uris/dart_uris/class_like_tokens; source coverage remains partial when the producer says partial. Native function Evidence requires kind native: view: {kind: "native", facet: "procedure"}. Facets select procedure, pseudocode, assembly, basic blocks, comments, callers/callees, references, unresolved calls, referenced strings/names, native API and high-pcode. Use nonnegative offset and a positive caller-selected limit (defaults 0 and 64); pseudocode uses UTF-16 code units, other native pages use rows. Returns artifact identity, parent Evidence ID, a distinct view digest, coverage, limitations and unknowns. Actual serialized size determines MCP transport admission; choose a smaller page or export the complete retained Evidence if needed.

**Input schema (verbatim, JSON Schema 2020-12):**

<details><summary>inputSchema for inspect_analysis_view</summary>

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "additionalProperties": false,
  "examples": [
    {
      "source": {
        "evidence_id": "ev_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "kind": "retained-evidence"
      },
      "view": {
        "collection": "occurrences",
        "kind": "inventory",
        "limit": 32,
        "logical_paths": [
          "package.json",
          "main.js"
        ],
        "offset": 0
      }
    },
    {
      "source": {
        "evidence_id": "ev_9e218c18bc6159ec9c8492a9130c286496fb1b6d9f03ec2f4ea3321ce2b15097",
        "kind": "retained-evidence"
      },
      "view": {
        "kind": "api-surface",
        "limit": 50,
        "offset": 0
      }
    },
    {
      "source": {
        "evidence_id": "ev_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "kind": "retained-evidence"
      },
      "view": {
        "kind": "summary"
      }
    },
    {
      "source": {
        "evidence_id": "ev_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "kind": "retained-evidence"
      },
      "view": {
        "collection": "sections",
        "kind": "item",
        "selector": {
          "name": ".text"
        }
      }
    },
    {
      "source": {
        "evidence_id": "ev_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "kind": "retained-evidence"
      },
      "view": {
        "facet": "value_flow_operations",
        "kind": "native",
        "limit": 32,
        "offset": 0
      }
    },
    {
      "source": {
        "evidence_id": "ev_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "kind": "retained-evidence"
      },
      "view": {
        "collection": "modules",
        "kind": "page",
        "limit": 32,
        "offset": 0
      }
    }
  ],
  "properties": {
    "source": {
      "oneOf": [
        {
          "additionalProperties": false,
          "properties": {
            "evidence_id": {
              "description": "Stable identifier of the recorded Evidence observation.",
              "pattern": "^ev_[a-f0-9]{64}$",
              "type": "string"
            },
            "kind": {
              "const": "retained-evidence",
              "type": "string"
            }
          },
          "required": [
            "kind",
            "evidence_id"
          ],
          "type": "object"
        },
        {
          "additionalProperties": false,
          "properties": {
            "evidence": {
              "additionalProperties": false,
              "description": "Evidence record produced by this operation.",
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
            "kind": {
              "const": "inline",
              "type": "string"
            }
          },
          "required": [
            "kind",
            "evidence"
          ],
          "type": "object"
        }
      ]
    },
    "view": {
      "oneOf": [
        {
          "additionalProperties": false,
          "properties": {
            "kind": {
              "const": "summary",
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
            "facet": {
              "enum": [
                "mitigations",
                "linkage"
              ],
              "type": "string"
            },
            "kind": {
              "const": "facet",
              "type": "string"
            }
          },
          "required": [
            "kind",
            "facet"
          ],
          "type": "object"
        },
        {
          "oneOf": [
            {
              "additionalProperties": false,
              "properties": {
                "collection": {
                  "const": "modules",
                  "type": "string"
                },
                "kind": {
                  "const": "item",
                  "type": "string"
                },
                "selector": {
                  "anyOf": [
                    {
                      "additionalProperties": false,
                      "properties": {
                        "path": {
                          "description": "Exact observed module path or original source-map reference from a module page; an empty reference is valid.",
                          "type": "string"
                        }
                      },
                      "required": [
                        "path"
                      ],
                      "type": "object"
                    },
                    {
                      "additionalProperties": false,
                      "properties": {
                        "node_id": {
                          "pattern": "^jag_node_[a-f0-9]{64}$",
                          "type": "string"
                        }
                      },
                      "required": [
                        "node_id"
                      ],
                      "type": "object"
                    }
                  ]
                }
              },
              "required": [
                "kind",
                "collection",
                "selector"
              ],
              "type": "object"
            },
            {
              "additionalProperties": false,
              "properties": {
                "collection": {
                  "enum": [
                    "sections",
                    "symbols"
                  ],
                  "type": "string"
                },
                "kind": {
                  "const": "item",
                  "type": "string"
                },
                "selector": {
                  "anyOf": [
                    {
                      "additionalProperties": false,
                      "properties": {
                        "index": {
                          "maximum": 9007199254740991,
                          "minimum": 0,
                          "type": "integer"
                        }
                      },
                      "required": [
                        "index"
                      ],
                      "type": "object"
                    },
                    {
                      "additionalProperties": false,
                      "properties": {
                        "name": {
                          "description": "Exact name used by this operation.",
                          "type": "string"
                        }
                      },
                      "required": [
                        "name"
                      ],
                      "type": "object"
                    }
                  ]
                }
              },
              "required": [
                "kind",
                "collection",
                "selector"
              ],
              "type": "object"
            }
          ]
        },
        {
          "additionalProperties": false,
          "properties": {
            "collection": {
              "enum": [
                "sections",
                "symbols",
                "modules"
              ],
              "type": "string"
            },
            "kind": {
              "const": "page",
              "type": "string"
            },
            "limit": {
              "exclusiveMinimum": 0,
              "maximum": 9007199254740991,
              "type": "integer"
            },
            "offset": {
              "maximum": 9007199254740991,
              "minimum": 0,
              "type": "integer"
            }
          },
          "required": [
            "kind",
            "collection",
            "offset",
            "limit"
          ],
          "type": "object"
        },
        {
          "additionalProperties": false,
          "properties": {
            "facet": {
              "enum": [
                "procedure",
                "pseudocode",
                "assembly",
                "basic_blocks",
                "comments",
                "callers",
                "callees",
                "incoming_references",
                "outgoing_references",
                "unresolved_calls",
                "referenced_strings",
                "referenced_names",
                "swift_string_literals",
                "swift_string_literal_omissions",
                "native_api",
                "value_flow_summary",
                "value_flow_operations",
                "value_flow_def_use",
                "value_flow_effects",
                "value_flow_parameters",
                "value_flow_parameter_uses"
              ],
              "type": "string"
            },
            "kind": {
              "const": "native",
              "type": "string"
            },
            "limit": {
              "default": 64,
              "exclusiveMinimum": 0,
              "maximum": 9007199254740991,
              "type": "integer"
            },
            "offset": {
              "default": 0,
              "maximum": 9007199254740991,
              "minimum": 0,
              "type": "integer"
            }
          },
          "required": [
            "kind",
            "facet"
          ],
          "type": "object"
        },
        {
          "oneOf": [
            {
              "additionalProperties": false,
              "properties": {
                "collection": {
                  "const": "occurrences",
                  "type": "string"
                },
                "kind": {
                  "const": "inventory",
                  "type": "string"
                },
                "limit": {
                  "default": 64,
                  "exclusiveMinimum": 0,
                  "maximum": 9007199254740991,
                  "type": "integer"
                },
                "logical_paths": {
                  "description": "Exact recorded logical paths. Omitted selects all available occurrences; an empty array selects none. This does not resolve filesystem paths.",
                  "items": {
                    "type": "string"
                  },
                  "type": "array"
                },
                "offset": {
                  "default": 0,
                  "maximum": 9007199254740991,
                  "minimum": 0,
                  "type": "integer"
                }
              },
              "required": [
                "kind",
                "collection"
              ],
              "type": "object"
            },
            {
              "additionalProperties": false,
              "properties": {
                "collection": {
                  "enum": [
                    "nodes",
                    "edges",
                    "integrity_contradictions"
                  ],
                  "type": "string"
                },
                "kind": {
                  "const": "inventory",
                  "type": "string"
                },
                "limit": {
                  "default": 64,
                  "exclusiveMinimum": 0,
                  "maximum": 9007199254740991,
                  "type": "integer"
                },
                "offset": {
                  "default": 0,
                  "maximum": 9007199254740991,
                  "minimum": 0,
                  "type": "integer"
                }
              },
              "required": [
                "kind",
                "collection"
              ],
              "type": "object"
            }
          ]
        },
        {
          "additionalProperties": false,
          "properties": {
            "facet": {
              "enum": [
                "sections",
                "imports",
                "exports",
                "candidates",
                "glue",
                "wat",
                "headers",
                "details",
                "tool_profile"
              ],
              "type": "string"
            },
            "kind": {
              "const": "wasm",
              "type": "string"
            },
            "limit": {
              "default": 64,
              "exclusiveMinimum": 0,
              "maximum": 9007199254740991,
              "type": "integer"
            },
            "offset": {
              "default": 0,
              "maximum": 9007199254740991,
              "minimum": 0,
              "type": "integer"
            }
          },
          "required": [
            "kind",
            "facet"
          ],
          "type": "object"
        },
        {
          "additionalProperties": false,
          "properties": {
            "facet": {
              "enum": [
                "entrypoints",
                "architectures",
                "build_metadata",
                "load_commands",
                "dependencies",
                "imports",
                "exports",
                "segments",
                "provenance"
              ],
              "type": "string"
            },
            "kind": {
              "const": "macho",
              "type": "string"
            },
            "limit": {
              "default": 64,
              "exclusiveMinimum": 0,
              "maximum": 9007199254740991,
              "type": "integer"
            },
            "offset": {
              "default": 0,
              "maximum": 9007199254740991,
              "minimum": 0,
              "type": "integer"
            }
          },
          "required": [
            "kind",
            "facet"
          ],
          "type": "object"
        },
        {
          "oneOf": [
            {
              "additionalProperties": false,
              "properties": {
                "collection": {
                  "enum": [
                    "nodes",
                    "edges"
                  ],
                  "type": "string"
                },
                "document": {
                  "description": "Exact documents[].relative_path; selects rows whose evidence names that archive.",
                  "minLength": 1,
                  "type": "string"
                },
                "kind": {
                  "const": "interface-builder",
                  "type": "string"
                },
                "limit": {
                  "default": 64,
                  "exclusiveMinimum": 0,
                  "maximum": 9007199254740991,
                  "type": "integer"
                },
                "offset": {
                  "default": 0,
                  "maximum": 9007199254740991,
                  "minimum": 0,
                  "type": "integer"
                }
              },
              "required": [
                "kind",
                "collection"
              ],
              "type": "object"
            },
            {
              "additionalProperties": false,
              "properties": {
                "collection": {
                  "enum": [
                    "documents",
                    "coverage"
                  ],
                  "type": "string"
                },
                "kind": {
                  "const": "interface-builder",
                  "type": "string"
                },
                "limit": {
                  "default": 64,
                  "exclusiveMinimum": 0,
                  "maximum": 9007199254740991,
                  "type": "integer"
                },
                "offset": {
                  "default": 0,
                  "maximum": 9007199254740991,
                  "minimum": 0,
                  "type": "integer"
                }
              },
              "required": [
                "kind",
                "collection"
              ],
              "type": "object"
            }
          ]
        },
        {
          "additionalProperties": false,
          "properties": {
            "facet": {
              "enum": [
                "functions",
                "bytecode_hex",
                "stdout",
                "stderr"
              ],
              "type": "string"
            },
            "kind": {
              "const": "evm",
              "type": "string"
            },
            "limit": {
              "default": 64,
              "exclusiveMinimum": 0,
              "maximum": 9007199254740991,
              "type": "integer"
            },
            "offset": {
              "default": 0,
              "maximum": 9007199254740991,
              "minimum": 0,
              "type": "integer"
            }
          },
          "required": [
            "kind",
            "facet"
          ],
          "type": "object"
        },
        {
          "additionalProperties": false,
          "properties": {
            "collection": {
              "enum": [
                "references",
                "resources",
                "attributes"
              ],
              "type": "string"
            },
            "kind": {
              "const": "managed",
              "type": "string"
            },
            "limit": {
              "default": 64,
              "exclusiveMinimum": 0,
              "maximum": 9007199254740991,
              "type": "integer"
            },
            "offset": {
              "default": 0,
              "maximum": 9007199254740991,
              "minimum": 0,
              "type": "integer"
            }
          },
          "required": [
            "kind",
            "collection"
          ],
          "type": "object"
        },
        {
          "additionalProperties": false,
          "properties": {
            "collection": {
              "enum": [
                "types",
                "exported_types",
                "fields",
                "methods",
                "member_refs",
                "call_edges",
                "field_accesses",
                "user_strings"
              ],
              "type": "string"
            },
            "kind": {
              "const": "managed-members",
              "type": "string"
            },
            "limit": {
              "default": 64,
              "exclusiveMinimum": 0,
              "maximum": 9007199254740991,
              "type": "integer"
            },
            "offset": {
              "default": 0,
              "maximum": 9007199254740991,
              "minimum": 0,
              "type": "integer"
            }
          },
          "required": [
            "kind",
            "collection"
          ],
          "type": "object"
        },
        {
          "additionalProperties": false,
          "properties": {
            "facet": {
              "const": "manifest",
              "type": "string"
            },
            "kind": {
              "const": "android",
              "type": "string"
            },
            "limit": {
              "exclusiveMinimum": 0,
              "maximum": 9007199254740991,
              "type": "integer"
            },
            "offset": {
              "default": 0,
              "maximum": 9007199254740991,
              "minimum": 0,
              "type": "integer"
            }
          },
          "required": [
            "kind",
            "facet",
            "limit"
          ],
          "type": "object"
        },
        {
          "additionalProperties": false,
          "properties": {
            "include_query_parameter_names": {
              "description": "Include distinct observed query parameter names and their original record ordinals; names do not establish required parameters or a complete API schema.",
              "type": "boolean"
            },
            "kind": {
              "const": "api-surface",
              "type": "string"
            },
            "limit": {
              "default": 50,
              "exclusiveMinimum": 0,
              "maximum": 9007199254740991,
              "type": "integer"
            },
            "offset": {
              "default": 0,
              "maximum": 9007199254740991,
              "minimum": 0,
              "type": "integer"
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
            "detail": {
              "default": "preview",
              "enum": [
                "preview",
                "complete"
              ],
              "type": "string"
            },
            "kind": {
              "const": "capture",
              "type": "string"
            },
            "limit": {
              "default": 64,
              "exclusiveMinimum": 0,
              "maximum": 9007199254740991,
              "type": "integer"
            },
            "offset": {
              "default": 0,
              "maximum": 9007199254740991,
              "minimum": 0,
              "type": "integer"
            }
          },
          "required": [
            "kind"
          ],
          "type": "object"
        },
        {
          "oneOf": [
            {
              "additionalProperties": false,
              "properties": {
                "facet": {
                  "const": "traces",
                  "type": "string"
                },
                "kind": {
                  "const": "qlog",
                  "type": "string"
                },
                "limit": {
                  "default": 64,
                  "exclusiveMinimum": 0,
                  "maximum": 9007199254740991,
                  "type": "integer"
                },
                "offset": {
                  "default": 0,
                  "maximum": 9007199254740991,
                  "minimum": 0,
                  "type": "integer"
                }
              },
              "required": [
                "kind",
                "facet"
              ],
              "type": "object"
            },
            {
              "additionalProperties": false,
              "properties": {
                "facet": {
                  "const": "streams",
                  "type": "string"
                },
                "kind": {
                  "const": "qlog",
                  "type": "string"
                },
                "limit": {
                  "default": 64,
                  "exclusiveMinimum": 0,
                  "maximum": 9007199254740991,
                  "type": "integer"
                },
                "offset": {
                  "default": 0,
                  "maximum": 9007199254740991,
                  "minimum": 0,
                  "type": "integer"
                },
                "trace_index": {
                  "maximum": 9007199254740991,
                  "minimum": 0,
                  "type": "integer"
                }
              },
              "required": [
                "kind",
                "trace_index",
                "facet"
              ],
              "type": "object"
            },
            {
              "additionalProperties": false,
              "properties": {
                "facet": {
                  "const": "loss-declarations",
                  "type": "string"
                },
                "kind": {
                  "const": "qlog",
                  "type": "string"
                },
                "limit": {
                  "default": 64,
                  "exclusiveMinimum": 0,
                  "maximum": 9007199254740991,
                  "type": "integer"
                },
                "offset": {
                  "default": 0,
                  "maximum": 9007199254740991,
                  "minimum": 0,
                  "type": "integer"
                },
                "trace_index": {
                  "maximum": 9007199254740991,
                  "minimum": 0,
                  "type": "integer"
                }
              },
              "required": [
                "kind",
                "trace_index",
                "facet"
              ],
              "type": "object"
            },
            {
              "additionalProperties": false,
              "properties": {
                "facet": {
                  "const": "incomplete-records",
                  "type": "string"
                },
                "kind": {
                  "const": "qlog",
                  "type": "string"
                },
                "limit": {
                  "default": 64,
                  "exclusiveMinimum": 0,
                  "maximum": 9007199254740991,
                  "type": "integer"
                },
                "offset": {
                  "default": 0,
                  "maximum": 9007199254740991,
                  "minimum": 0,
                  "type": "integer"
                },
                "trace_index": {
                  "maximum": 9007199254740991,
                  "minimum": 0,
                  "type": "integer"
                }
              },
              "required": [
                "kind",
                "trace_index",
                "facet"
              ],
              "type": "object"
            },
            {
              "additionalProperties": false,
              "properties": {
                "direction": {
                  "description": "Direction in which to traverse or compare relationships.",
                  "enum": [
                    "sent",
                    "received"
                  ],
                  "type": "string"
                },
                "facet": {
                  "const": "contributions",
                  "type": "string"
                },
                "kind": {
                  "const": "qlog",
                  "type": "string"
                },
                "limit": {
                  "default": 64,
                  "exclusiveMinimum": 0,
                  "maximum": 9007199254740991,
                  "type": "integer"
                },
                "offset": {
                  "default": 0,
                  "maximum": 9007199254740991,
                  "minimum": 0,
                  "type": "integer"
                },
                "stream_id": {
                  "pattern": "^(0|[1-9][0-9]*)$",
                  "type": "string"
                },
                "trace_index": {
                  "maximum": 9007199254740991,
                  "minimum": 0,
                  "type": "integer"
                }
              },
              "required": [
                "kind",
                "trace_index",
                "stream_id",
                "direction",
                "facet"
              ],
              "type": "object"
            },
            {
              "additionalProperties": false,
              "properties": {
                "direction": {
                  "description": "Direction in which to traverse or compare relationships.",
                  "enum": [
                    "sent",
                    "received"
                  ],
                  "type": "string"
                },
                "facet": {
                  "const": "ranges",
                  "type": "string"
                },
                "kind": {
                  "const": "qlog",
                  "type": "string"
                },
                "limit": {
                  "default": 64,
                  "exclusiveMinimum": 0,
                  "maximum": 9007199254740991,
                  "type": "integer"
                },
                "offset": {
                  "default": 0,
                  "maximum": 9007199254740991,
                  "minimum": 0,
                  "type": "integer"
                },
                "stream_id": {
                  "pattern": "^(0|[1-9][0-9]*)$",
                  "type": "string"
                },
                "trace_index": {
                  "maximum": 9007199254740991,
                  "minimum": 0,
                  "type": "integer"
                }
              },
              "required": [
                "kind",
                "trace_index",
                "stream_id",
                "direction",
                "facet"
              ],
              "type": "object"
            },
            {
              "additionalProperties": false,
              "properties": {
                "direction": {
                  "description": "Direction in which to traverse or compare relationships.",
                  "enum": [
                    "sent",
                    "received"
                  ],
                  "type": "string"
                },
                "facet": {
                  "const": "final-sizes",
                  "type": "string"
                },
                "kind": {
                  "const": "qlog",
                  "type": "string"
                },
                "limit": {
                  "default": 64,
                  "exclusiveMinimum": 0,
                  "maximum": 9007199254740991,
                  "type": "integer"
                },
                "offset": {
                  "default": 0,
                  "maximum": 9007199254740991,
                  "minimum": 0,
                  "type": "integer"
                },
                "stream_id": {
                  "pattern": "^(0|[1-9][0-9]*)$",
                  "type": "string"
                },
                "trace_index": {
                  "maximum": 9007199254740991,
                  "minimum": 0,
                  "type": "integer"
                }
              },
              "required": [
                "kind",
                "trace_index",
                "stream_id",
                "direction",
                "facet"
              ],
              "type": "object"
            }
          ]
        },
        {
          "oneOf": [
            {
              "additionalProperties": false,
              "properties": {
                "facet": {
                  "enum": [
                    "endpoints",
                    "dns-queries",
                    "tls-sni",
                    "protocols",
                    "http-uris",
                    "unattributed-addresses"
                  ],
                  "type": "string"
                },
                "kind": {
                  "const": "pcap",
                  "type": "string"
                },
                "limit": {
                  "default": 64,
                  "exclusiveMinimum": 0,
                  "maximum": 9007199254740991,
                  "type": "integer"
                },
                "offset": {
                  "default": 0,
                  "maximum": 9007199254740991,
                  "minimum": 0,
                  "type": "integer"
                }
              },
              "required": [
                "kind",
                "facet"
              ],
              "type": "object"
            },
            {
              "additionalProperties": false,
              "properties": {
                "facet": {
                  "const": "dns-addresses",
                  "type": "string"
                },
                "kind": {
                  "const": "pcap",
                  "type": "string"
                },
                "limit": {
                  "default": 64,
                  "exclusiveMinimum": 0,
                  "maximum": 9007199254740991,
                  "type": "integer"
                },
                "offset": {
                  "default": 0,
                  "maximum": 9007199254740991,
                  "minimum": 0,
                  "type": "integer"
                },
                "query": {
                  "description": "Non-empty feature or text query to investigate.",
                  "minLength": 1,
                  "type": "string"
                }
              },
              "required": [
                "kind",
                "facet",
                "query"
              ],
              "type": "object"
            },
            {
              "additionalProperties": false,
              "properties": {
                "facet": {
                  "const": "diagnostics",
                  "type": "string"
                },
                "kind": {
                  "const": "pcap",
                  "type": "string"
                },
                "limit": {
                  "default": 64,
                  "exclusiveMinimum": 0,
                  "maximum": 9007199254740991,
                  "type": "integer"
                },
                "offset": {
                  "default": 0,
                  "maximum": 9007199254740991,
                  "minimum": 0,
                  "type": "integer"
                },
                "stream": {
                  "enum": [
                    "tshark",
                    "capinfos"
                  ],
                  "type": "string"
                }
              },
              "required": [
                "kind",
                "facet",
                "stream"
              ],
              "type": "object"
            }
          ]
        },
        {
          "additionalProperties": false,
          "properties": {
            "collection": {
              "enum": [
                "package_uris",
                "dart_uris",
                "class_like_tokens"
              ],
              "type": "string"
            },
            "kind": {
              "const": "dart-aot",
              "type": "string"
            },
            "limit": {
              "default": 64,
              "exclusiveMinimum": 0,
              "maximum": 9007199254740991,
              "type": "integer"
            },
            "offset": {
              "default": 0,
              "maximum": 9007199254740991,
              "minimum": 0,
              "type": "integer"
            }
          },
          "required": [
            "kind",
            "collection"
          ],
          "type": "object"
        }
      ]
    }
  },
  "required": [
    "source",
    "view"
  ],
  "type": "object"
}
```

</details>

**Output schema:** see [`tool-specs/inspect_analysis_view.json`](../tool-specs/inspect_analysis_view.json) (`outputSchema`).

---

## project_android_application_graph

<a id="projectandroidapplicationgraph"></a>

**Title:** Project Android Application Graph  
**Kind:** `application` · **Requires session:** false · **analysisOperation:** null  
**Providers:** rea-android-application  
**Effects set (true flags):** mutatesSession  
**MCP annotations:** `{"destructiveHint":false,"idempotentHint":true,"openWorldHint":false,"readOnlyHint":false}`

**Description (verbatim, as advertised to the agent):**

> Project authenticated APK inventory_artifact Evidence into an execution-free Android application inventory. Reports exact component paths and hashes, runtime-family hints, and path-based bridge hypotheses without decoding DEX, executing the APK, or claiming observed runtime calls.

**Input schema (verbatim, JSON Schema 2020-12):**

<details><summary>inputSchema for project_android_application_graph</summary>

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "additionalProperties": false,
  "properties": {
    "inventory_evidence": {
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
    "inventory_evidence"
  ],
  "type": "object"
}
```

</details>

**Output schema:** see [`tool-specs/project_android_application_graph.json`](../tool-specs/project_android_application_graph.json) (`outputSchema`).

---

## project_apple_application_graph

<a id="projectappleapplicationgraph"></a>

**Title:** Project Apple Application Graph  
**Kind:** `application` · **Requires session:** false · **analysisOperation:** null  
**Providers:** rea-apple-application  
**Effects set (true flags):** mutatesSession  
**MCP annotations:** `{"destructiveHint":false,"idempotentHint":true,"openWorldHint":false,"readOnlyHint":false}`

**Description (verbatim, as advertised to the agent):**

> Project authenticated IPA, macOS .app directory, ZIP, or DMG inventory Evidence into an execution-free Apple application inventory. Reports application roots, nested bundles with path-convention roles (app extensions, XPC services, login items, privileged helpers, system extensions, frameworks), launchd plists, exact component paths and hashes, runtime-family hints, and path-based bridge hypotheses without parsing plist/CMS semantics or claiming observed runtime calls.

**Input schema (verbatim, JSON Schema 2020-12):**

<details><summary>inputSchema for project_apple_application_graph</summary>

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "additionalProperties": false,
  "properties": {
    "inventory_evidence": {
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
    "inventory_evidence"
  ],
  "type": "object"
}
```

</details>

**Output schema:** see [`tool-specs/project_apple_application_graph.json`](../tool-specs/project_apple_application_graph.json) (`outputSchema`).

---

## project_harmony_application_graph

<a id="projectharmonyapplicationgraph"></a>

**Title:** Project Harmony Application Graph  
**Kind:** `application` · **Requires session:** false · **analysisOperation:** null  
**Providers:** rea-javascript-application-workflows  
**Effects set (true flags):** mutatesSession  
**MCP annotations:** `{"destructiveHint":false,"idempotentHint":true,"openWorldHint":false,"readOnlyHint":false}`

**Description (verbatim, as advertised to the agent):**

> Project authenticated HarmonyOS HAP, HSP, or App Pack inventory Evidence into an execution-free application inventory. Reports packaging-model hints (Stage module.json versus FA config.json), exact component paths and hashes (manifests, Ark bytecode, resources, native libraries, JavaScript, signing), App Pack child packages, runtime-family hints, and path-based N-API bridge hypotheses without decoding Ark bytecode, parsing manifest semantics, or claiming observed runtime calls.

**Input schema (verbatim, JSON Schema 2020-12):**

<details><summary>inputSchema for project_harmony_application_graph</summary>

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "additionalProperties": false,
  "properties": {
    "inventory_evidence": {
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
    "inventory_evidence"
  ],
  "type": "object"
}
```

</details>

**Output schema:** see [`tool-specs/project_harmony_application_graph.json`](../tool-specs/project_harmony_application_graph.json) (`outputSchema`).

---

## recover_javascript_sources

<a id="recoverjavascriptsources"></a>

**Title:** Recover Javascript Sources  
**Kind:** `application` · **Requires session:** false · **analysisOperation:** null  
**Providers:** wakaru  
**Effects set (true flags):** NOT idempotent, launchesProcess, mutatesSession, writesFilesystem  
**MCP annotations:** `{"destructiveHint":false,"idempotentHint":false,"openWorldHint":true,"readOnlyHint":false}`

**Description (verbatim, as advertised to the agent):**

> Recover readable modules from local UTF-8 JavaScript scripts/bundles into an absent directory, using caller-supplied Wakaru ^1.13.0 (verified with 1.14.0) on Linux x64. Use additional_paths for related chunks; each input retains its own snapshot and provenance. Returns original/derived digests, extraction byte ranges, emitted source maps, warnings and analysis_input inline. Structural splitting may fall back to one module; original names and runtime equivalence remain unknown. No application code execution. Requires util-linux prlimit; one worker, 1 GiB address-space ceiling, 120-second deadline, 64 MiB total input, 128 MiB output, 10000 entries and 8 MiB per diagnostic/report stream.

**Input schema (verbatim, JSON Schema 2020-12):**

<details><summary>inputSchema for recover_javascript_sources</summary>

```json
{
  "$defs": {
    "__schema0": {
      "$ref": "#/$defs/__schema1",
      "description": "Absolute path to a UTF-8 JavaScript file; never executed"
    },
    "__schema1": {
      "minLength": 1,
      "pattern": "^[^\\x00]*$",
      "type": "string"
    },
    "__schema2": {
      "$ref": "#/$defs/__schema3",
      "description": "Additional absolute UTF-8 JavaScript files recovered together with path; each is snapshotted separately so imports can resolve across related chunks. All inputs share a 64 MiB total budget"
    },
    "__schema3": {
      "items": {
        "$ref": "#/$defs/__schema1"
      },
      "maxItems": 16,
      "type": "array"
    },
    "__schema4": {
      "$ref": "#/$defs/__schema1",
      "description": "Absolute absent output directory; parent must exist"
    },
    "__schema5": {
      "$ref": "#/$defs/__schema6",
      "default": "structural",
      "description": "Structural module boundaries, heuristic fallback, or finer inspection-only regions"
    },
    "__schema6": {
      "enum": [
        "structural",
        "heuristic",
        "inspection"
      ],
      "type": "string"
    },
    "__schema7": {
      "$ref": "#/$defs/__schema8",
      "default": "standard",
      "description": "Upstream syntax recovery level; runtime equivalence remains unverified"
    },
    "__schema8": {
      "enum": [
        "minimal",
        "standard",
        "aggressive"
      ],
      "type": "string"
    }
  },
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "additionalProperties": false,
  "examples": [
    {
      "output_directory": "/tmp/recovered-app",
      "path": "/tmp/web-scripts/app.js"
    },
    {
      "additional_paths": [
        "/tmp/web-scripts/runtime.js",
        "/tmp/web-scripts/shared.js",
        "/tmp/web-scripts/checkout.chunk.js"
      ],
      "output_directory": "/tmp/recovered-chunks",
      "path": "/tmp/web-scripts/main.js"
    }
  ],
  "properties": {
    "additional_paths": {
      "$ref": "#/$defs/__schema2",
      "description": "Additional absolute UTF-8 JavaScript files recovered together with path; each is snapshotted separately so imports can resolve across related chunks. All inputs share a 64 MiB total budget"
    },
    "extraction_mode": {
      "$ref": "#/$defs/__schema5",
      "description": "Structural module boundaries, heuristic fallback, or finer inspection-only regions"
    },
    "output_directory": {
      "$ref": "#/$defs/__schema4",
      "description": "Absolute absent output directory; parent must exist"
    },
    "path": {
      "$ref": "#/$defs/__schema0",
      "description": "Absolute path to a UTF-8 JavaScript file; never executed"
    },
    "rewrite_level": {
      "$ref": "#/$defs/__schema7",
      "description": "Upstream syntax recovery level; runtime equivalence remains unverified"
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

**Output schema:** see [`tool-specs/recover_javascript_sources.json`](../tool-specs/recover_javascript_sources.json) (`outputSchema`).

---

## trace_application_feature

<a id="traceapplicationfeature"></a>

**Title:** Trace Application Feature  
**Kind:** `application` · **Requires session:** false · **analysisOperation:** null  
**Providers:** rea-javascript-application-workflows  
**Effects set (true flags):** mutatesSession  
**MCP annotations:** `{"destructiveHint":false,"idempotentHint":true,"openWorldHint":false,"readOnlyHint":false}`

**Description (verbatim, as advertised to the agent):**

> Trace a typed literal seed through every reachable part of an authenticated JavaScript Application Graph supplied as inline Evidence or exact same-session retained references. Original static, native, passive-runtime, inferred, and unknown authorities remain distinct; native addon handoffs never open a provider or execute the application.

**Input schema (verbatim, JSON Schema 2020-12):**

<details><summary>inputSchema for trace_application_feature</summary>

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "additionalProperties": false,
  "examples": [
    {
      "application": {
        "evidence_id": "ev_2a6371cd2a7665bdad6d37d9b3a69da558e9882a0696d195f1f1a7707f14b5e5",
        "kind": "retained-evidence"
      },
      "direction": "both",
      "seed": {
        "case_sensitive": false,
        "kind": "module",
        "match": "exact",
        "value": "renderer.js"
      }
    }
  ],
  "properties": {
    "application": {
      "anyOf": [
        {
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
        {
          "additionalProperties": false,
          "properties": {
            "evidence_id": {
              "description": "Stable identifier of the recorded Evidence observation.",
              "pattern": "^ev_[a-f0-9]{64}$",
              "type": "string"
            },
            "kind": {
              "const": "retained-evidence",
              "type": "string"
            }
          },
          "required": [
            "kind",
            "evidence_id"
          ],
          "type": "object"
        }
      ]
    },
    "direction": {
      "default": "both",
      "description": "Direction in which to traverse or compare relationships.",
      "enum": [
        "outgoing",
        "incoming",
        "both"
      ],
      "type": "string"
    },
    "native_observations": {
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
      "type": "array"
    },
    "seed": {
      "anyOf": [
        {
          "additionalProperties": false,
          "properties": {
            "case_sensitive": {
              "default": false,
              "description": "Whether text matching distinguishes uppercase and lowercase.",
              "type": "boolean"
            },
            "kind": {
              "enum": [
                "node-id",
                "route",
                "string",
                "channel",
                "module",
                "native-export"
              ],
              "type": "string"
            },
            "match": {
              "anyOf": [
                {
                  "enum": [
                    "exact",
                    "contains"
                  ],
                  "type": "string"
                },
                {
                  "type": "null"
                }
              ],
              "default": null
            },
            "value": {
              "minLength": 1,
              "type": "string"
            }
          },
          "required": [
            "kind",
            "value"
          ],
          "type": "object"
        },
        {
          "additionalProperties": false,
          "properties": {
            "case_sensitive": {
              "default": false,
              "description": "Whether text matching distinguishes uppercase and lowercase.",
              "type": "boolean"
            },
            "kind": {
              "enum": [
                "route",
                "string",
                "channel",
                "module",
                "native-export"
              ],
              "type": "string"
            },
            "match": {
              "const": "exact",
              "type": "string"
            },
            "value": {
              "const": "",
              "type": "string"
            }
          },
          "required": [
            "kind",
            "value",
            "match"
          ],
          "type": "object"
        },
        {
          "anyOf": [
            {
              "additionalProperties": false,
              "properties": {
                "case_sensitive": {
                  "default": false,
                  "description": "Whether text matching distinguishes uppercase and lowercase.",
                  "type": "boolean"
                },
                "kind": {
                  "const": "api",
                  "type": "string"
                },
                "match": {
                  "anyOf": [
                    {
                      "enum": [
                        "exact",
                        "contains"
                      ],
                      "type": "string"
                    },
                    {
                      "type": "null"
                    }
                  ],
                  "default": null
                },
                "value": {
                  "minLength": 1,
                  "type": "string"
                }
              },
              "required": [
                "kind",
                "value"
              ],
              "type": "object"
            },
            {
              "additionalProperties": false,
              "properties": {
                "case_sensitive": {
                  "default": false,
                  "description": "Whether text matching distinguishes uppercase and lowercase.",
                  "type": "boolean"
                },
                "kind": {
                  "const": "api",
                  "type": "string"
                },
                "match": {
                  "const": "exact",
                  "type": "string"
                },
                "value": {
                  "const": "",
                  "type": "string"
                }
              },
              "required": [
                "kind",
                "value",
                "match"
              ],
              "type": "object"
            }
          ]
        },
        {
          "anyOf": [
            {
              "additionalProperties": false,
              "properties": {
                "case_sensitive": {
                  "default": false,
                  "description": "Whether text matching distinguishes uppercase and lowercase.",
                  "type": "boolean"
                },
                "entry_path": {
                  "description": "Local filesystem path for entry.",
                  "items": {
                    "type": "string"
                  },
                  "minItems": 1,
                  "type": "array"
                },
                "kind": {
                  "const": "api",
                  "type": "string"
                },
                "match": {
                  "anyOf": [
                    {
                      "enum": [
                        "exact",
                        "contains"
                      ],
                      "type": "string"
                    },
                    {
                      "type": "null"
                    }
                  ],
                  "default": null
                },
                "value": {
                  "minLength": 1,
                  "type": "string"
                }
              },
              "required": [
                "kind",
                "value",
                "entry_path"
              ],
              "type": "object"
            },
            {
              "additionalProperties": false,
              "properties": {
                "case_sensitive": {
                  "default": false,
                  "description": "Whether text matching distinguishes uppercase and lowercase.",
                  "type": "boolean"
                },
                "entry_path": {
                  "description": "Local filesystem path for entry.",
                  "items": {
                    "type": "string"
                  },
                  "minItems": 1,
                  "type": "array"
                },
                "kind": {
                  "const": "api",
                  "type": "string"
                },
                "match": {
                  "const": "exact",
                  "type": "string"
                },
                "value": {
                  "const": "",
                  "type": "string"
                }
              },
              "required": [
                "kind",
                "value",
                "match",
                "entry_path"
              ],
              "type": "object"
            }
          ]
        }
      ]
    }
  },
  "required": [
    "seed",
    "application"
  ],
  "type": "object"
}
```

</details>

**Output schema:** see [`tool-specs/trace_application_feature.json`](../tool-specs/trace_application_feature.json) (`outputSchema`).

---

## trace_javascript_semantics

<a id="tracejavascriptsemantics"></a>

**Title:** Trace Javascript Semantics  
**Kind:** `application` · **Requires session:** false · **analysisOperation:** null  
**Providers:** rea-javascript-application-workflows  
**Effects set (true flags):** mutatesSession  
**MCP annotations:** `{"destructiveHint":false,"idempotentHint":true,"openWorldHint":false,"readOnlyHint":false}`

**Description (verbatim, as advertised to the agent):**

> Trace static JavaScript data-flow, direct call/return, and closure relations from inline application Evidence or an exact same-session retained reference. Dynamic or unsupported semantics remain explicit unknowns; static reachability never claims runtime execution.

**Input schema (verbatim, JSON Schema 2020-12):**

<details><summary>inputSchema for trace_javascript_semantics</summary>

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "additionalProperties": false,
  "examples": [
    {
      "application": {
        "evidence_id": "ev_2a6371cd2a7665bdad6d37d9b3a69da558e9882a0696d195f1f1a7707f14b5e5",
        "kind": "retained-evidence"
      },
      "query": {
        "direction": "backward-provenance",
        "seed": {
          "kind": "semantic-node",
          "node_id": "jsrg_node_0000000000000000000000000000000000000000000000000000000000000000"
        }
      }
    }
  ],
  "properties": {
    "application": {
      "anyOf": [
        {
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
        {
          "additionalProperties": false,
          "properties": {
            "evidence_id": {
              "description": "Stable identifier of the recorded Evidence observation.",
              "pattern": "^ev_[a-f0-9]{64}$",
              "type": "string"
            },
            "kind": {
              "const": "retained-evidence",
              "type": "string"
            }
          },
          "required": [
            "kind",
            "evidence_id"
          ],
          "type": "object"
        }
      ]
    },
    "query": {
      "additionalProperties": false,
      "description": "Non-empty feature or text query to investigate.",
      "properties": {
        "allowed_relations": {
          "items": {
            "enum": [
              "acquires",
              "aggregates",
              "aliases",
              "argument-to-parameter",
              "awaits",
              "calls",
              "cancels-timer",
              "captures",
              "chains",
              "coerces",
              "connects-stdio",
              "consumed-by",
              "constructs-request",
              "creates-promise",
              "defaults",
              "defines",
              "destructures",
              "detaches-task",
              "dispatches-candidate",
              "forwards-signal",
              "listens-error",
              "listens-exit",
              "owns",
              "overrides",
              "parses",
              "reads",
              "reads-argv",
              "reads-config",
              "reads-environment",
              "reads-property",
              "registers-listener",
              "releases",
              "removes-listener",
              "returns-task",
              "returns-to-call",
              "schedules-timer",
              "spawns",
              "spreads",
              "supplies-argv",
              "supplies-env",
              "supplies-request-field",
              "validates",
              "writes",
              "writes-property"
            ],
            "type": "string"
          },
          "minItems": 1,
          "type": "array"
        },
        "direction": {
          "description": "Direction in which to traverse or compare relationships.",
          "enum": [
            "backward-provenance",
            "forward-influence",
            "callers",
            "ownership"
          ],
          "type": "string"
        },
        "expected": {
          "anyOf": [
            {
              "additionalProperties": false,
              "properties": {
                "classes": {
                  "items": {
                    "enum": [
                      "module",
                      "function",
                      "parameter",
                      "binding",
                      "expression",
                      "literal",
                      "property-slot",
                      "call-site",
                      "return-site",
                      "closure-capture",
                      "promise",
                      "task",
                      "event",
                      "listener",
                      "timer",
                      "child-process",
                      "stdio",
                      "signal",
                      "config-source",
                      "request",
                      "response",
                      "boundary",
                      "resource",
                      "unknown-frontier"
                    ],
                    "type": "string"
                  },
                  "minItems": 1,
                  "type": "array"
                },
                "role": {
                  "enum": [
                    "source",
                    "sink"
                  ],
                  "type": "string"
                }
              },
              "required": [
                "role",
                "classes"
              ],
              "type": "object"
            },
            {
              "type": "null"
            }
          ],
          "default": null
        },
        "include_ambiguous_dynamic_edges": {
          "default": false,
          "description": "Whether to include ambiguous dynamic edges in the result.",
          "type": "boolean"
        },
        "seed": {
          "oneOf": [
            {
              "additionalProperties": false,
              "properties": {
                "kind": {
                  "const": "semantic-node",
                  "type": "string"
                },
                "node_id": {
                  "pattern": "^jsrg_node_[a-f0-9]{64}$",
                  "type": "string"
                }
              },
              "required": [
                "kind",
                "node_id"
              ],
              "type": "object"
            },
            {
              "additionalProperties": false,
              "properties": {
                "kind": {
                  "const": "application-node",
                  "type": "string"
                },
                "node_id": {
                  "pattern": "^jag_node_[a-f0-9]{64}$",
                  "type": "string"
                }
              },
              "required": [
                "kind",
                "node_id"
              ],
              "type": "object"
            },
            {
              "additionalProperties": false,
              "properties": {
                "kind": {
                  "const": "literal",
                  "type": "string"
                },
                "value": {
                  "anyOf": [
                    {
                      "type": "string"
                    },
                    {
                      "type": "number"
                    },
                    {
                      "type": "boolean"
                    },
                    {
                      "type": "null"
                    }
                  ]
                }
              },
              "required": [
                "kind",
                "value"
              ],
              "type": "object"
            },
            {
              "additionalProperties": false,
              "properties": {
                "fingerprint_sha256": {
                  "description": "Exact SHA-256 digest of fingerprint.",
                  "pattern": "^[a-f0-9]{64}$",
                  "type": "string"
                },
                "kind": {
                  "const": "function",
                  "type": "string"
                }
              },
              "required": [
                "kind",
                "fingerprint_sha256"
              ],
              "type": "object"
            },
            {
              "additionalProperties": false,
              "properties": {
                "kind": {
                  "const": "property",
                  "type": "string"
                },
                "name": {
                  "description": "Exact name used by this operation.",
                  "minLength": 1,
                  "type": "string"
                }
              },
              "required": [
                "kind",
                "name"
              ],
              "type": "object"
            },
            {
              "additionalProperties": false,
              "properties": {
                "kind": {
                  "const": "endpoint",
                  "type": "string"
                },
                "value": {
                  "minLength": 1,
                  "type": "string"
                }
              },
              "required": [
                "kind",
                "value"
              ],
              "type": "object"
            },
            {
              "additionalProperties": false,
              "properties": {
                "kind": {
                  "const": "event",
                  "type": "string"
                },
                "name": {
                  "description": "Exact name used by this operation.",
                  "minLength": 1,
                  "type": "string"
                }
              },
              "required": [
                "kind",
                "name"
              ],
              "type": "object"
            },
            {
              "additionalProperties": false,
              "properties": {
                "field": {
                  "minLength": 1,
                  "type": "string"
                },
                "kind": {
                  "const": "boundary-field",
                  "type": "string"
                }
              },
              "required": [
                "kind",
                "field"
              ],
              "type": "object"
            }
          ]
        }
      },
      "required": [
        "seed",
        "direction"
      ],
      "type": "object"
    }
  },
  "required": [
    "application",
    "query"
  ],
  "type": "object"
}
```

</details>

**Output schema:** see [`tool-specs/trace_javascript_semantics.json`](../tool-specs/trace_javascript_semantics.json) (`outputSchema`).

---

## trace_web_module_imports

<a id="tracewebmoduleimports"></a>

**Title:** Trace Web Module Imports  
**Kind:** `application` · **Requires session:** false · **analysisOperation:** null  
**Providers:** rea-web-script-export  
**Effects set (true flags):** accessesNetwork, launchesProcess, mutatesSession, writesFilesystem  
**MCP annotations:** `{"destructiveHint":false,"idempotentHint":true,"openWorldHint":true,"readOnlyHint":false}`

**Description (verbatim, as advertised to the agent):**

> Trace one exported website script's outgoing native ES imports/re-exports, using exact URL and optional selected import-map context. Reads a local export_web_scripts manifest and verifies the selected source's SHA-256/size; returns source positions, native resolved URLs or exact errors, every matching captured candidate and explicit unknown execution. Query/fragment identities are preserved. Computed imports and bundler IDs remain unknown. Select importer_url for unknown inline/document-base context. Caller-supplied Chromium executes only a trusted REA resolver stub in an owned context with page requests locally fulfilled/blocked; no captured application execution or asset refetch. Requires absolute REA_BROWSER_EXECUTABLE for literal imports. 32 MiB manifest, 16 MiB source, 4 MiB map and 20-second native deadline; cleanup may extend the deadline.

**Input schema (verbatim, JSON Schema 2020-12):**

<details><summary>inputSchema for trace_web_module_imports</summary>

```json
{
  "$defs": {
    "__schema0": {
      "$ref": "#/$defs/__schema1",
      "description": "Absolute path to an export_web_scripts manifest"
    },
    "__schema1": {
      "minLength": 1,
      "pattern": "^[^\\x00]*$",
      "type": "string"
    },
    "__schema2": {
      "description": "Zero-based index in manifest.scripts",
      "maximum": 9007199254740991,
      "minimum": 0,
      "type": "integer"
    },
    "__schema3": {
      "$ref": "#/$defs/__schema4",
      "description": "Explicit HTTP(S) module URL; useful when captured inline/base context is unknown"
    },
    "__schema4": {
      "minLength": 1,
      "type": "string"
    },
    "__schema5": {
      "additionalProperties": false,
      "properties": {
        "base_url": {
          "description": "Explicit HTTP(S) base for the selected map",
          "minLength": 1,
          "type": "string"
        },
        "path": {
          "$ref": "#/$defs/__schema1",
          "description": "Absolute local import-map JSON path; no fetch"
        }
      },
      "required": [
        "path",
        "base_url"
      ],
      "type": "object"
    }
  },
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "additionalProperties": false,
  "examples": [
    {
      "import_map": {
        "base_url": "https://example.test/app/",
        "path": "/analysis/import-map.json"
      },
      "manifest_path": "/analysis/exported-scripts/manifest.json",
      "script_index": 0
    }
  ],
  "properties": {
    "import_map": {
      "$ref": "#/$defs/__schema5"
    },
    "importer_url": {
      "$ref": "#/$defs/__schema3",
      "description": "Explicit HTTP(S) module URL; useful when captured inline/base context is unknown"
    },
    "manifest_path": {
      "$ref": "#/$defs/__schema0",
      "description": "Absolute path to an export_web_scripts manifest"
    },
    "script_index": {
      "$ref": "#/$defs/__schema2",
      "description": "Zero-based index in manifest.scripts"
    }
  },
  "required": [
    "manifest_path",
    "script_index"
  ],
  "type": "object"
}
```

</details>

**Output schema:** see [`tool-specs/trace_web_module_imports.json`](../tool-specs/trace_web_module_imports.json) (`outputSchema`).

---

## trace_web_source_location

<a id="tracewebsourcelocation"></a>

**Title:** Trace Web Source Location  
**Kind:** `application` · **Requires session:** false · **analysisOperation:** null  
**Providers:** rea-web-script-export  
**Effects set (true flags):** launchesProcess, mutatesSession, writesFilesystem  
**MCP annotations:** `{"destructiveHint":false,"idempotentHint":true,"openWorldHint":true,"readOnlyHint":false}`

**Description (verbatim, as advertised to the agent):**

> Trace one generated position in an exported website script through an explicitly paired local source map. Verifies manifest, selected script and map SHA-256/byte identities; returns every equal-position mapping, reported source/root, resolved source URL, embedded sourcesContent and original position inline. One-based lines and zero-based UTF-16 columns; greatest generated position <= requested across lines. Duplicate sources and generated-only mappings remain distinct. Caller-selected pairing does not establish deployment authenticity or execution. Regular maps and inline indexed sections only; external section URLs are unsupported. No network access or application execution; uses the pinned upstream codec in an owned Node process with private temporary files, independent 192 MiB old-generation heap and 20-second deadline. 4 MiB map, 32 MiB reply; complete evidence or actionable resource failure. Cleanup may extend the deadline.

**Input schema (verbatim, JSON Schema 2020-12):**

<details><summary>inputSchema for trace_web_source_location</summary>

```json
{
  "$defs": {
    "__schema0": {
      "$ref": "#/$defs/__schema1",
      "description": "Absolute export_web_scripts manifest path"
    },
    "__schema1": {
      "minLength": 1,
      "pattern": "^[^\\x00]*$",
      "type": "string"
    },
    "__schema2": {
      "description": "Zero-based index in manifest.scripts",
      "maximum": 9007199254740991,
      "minimum": 0,
      "type": "integer"
    },
    "__schema3": {
      "additionalProperties": false,
      "properties": {
        "path": {
          "$ref": "#/$defs/__schema1",
          "description": "Absolute local source-map path; no fetch"
        },
        "url": {
          "description": "Explicit source-map URL context used to resolve original source names",
          "minLength": 1,
          "type": "string"
        }
      },
      "required": [
        "path",
        "url"
      ],
      "type": "object"
    },
    "__schema4": {
      "additionalProperties": false,
      "properties": {
        "column": {
          "maximum": 9007199254740991,
          "minimum": 0,
          "type": "integer"
        },
        "line": {
          "maximum": 9007199254740991,
          "minimum": 1,
          "type": "integer"
        }
      },
      "required": [
        "line",
        "column"
      ],
      "type": "object"
    }
  },
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "additionalProperties": false,
  "examples": [
    {
      "generated_position": {
        "column": 25,
        "line": 1
      },
      "manifest_path": "/analysis/scripts/manifest.json",
      "script_index": 0,
      "source_map": {
        "path": "/analysis/app.js.map",
        "url": "https://example.test/app.js.map"
      }
    }
  ],
  "properties": {
    "generated_position": {
      "$ref": "#/$defs/__schema4"
    },
    "manifest_path": {
      "$ref": "#/$defs/__schema0",
      "description": "Absolute export_web_scripts manifest path"
    },
    "script_index": {
      "$ref": "#/$defs/__schema2",
      "description": "Zero-based index in manifest.scripts"
    },
    "source_map": {
      "$ref": "#/$defs/__schema3"
    }
  },
  "required": [
    "manifest_path",
    "script_index",
    "source_map",
    "generated_position"
  ],
  "type": "object"
}
```

</details>

**Output schema:** see [`tool-specs/trace_web_source_location.json`](../tool-specs/trace_web_source_location.json) (`outputSchema`).

---

