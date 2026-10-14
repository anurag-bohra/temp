# Tool family: Artifact graph & format inspectors

Generated mechanically from `.cache/mcp-tool-catalog.json` (produced by `scripts/generate-mcp-tool-catalog.mjs`, which registers every tool through the MCP SDK and exports the advertised JSON Schema 2020-12 input/output schemas) and `docs/public/product-catalog.json` (family `artifact`, surface `artifact-provider`, 16 tools). Input schemas below are **verbatim**. Output schemas are verbatim in `tool-specs/<tool>.json` (field `outputSchema`) because several exceed 100 KB; the complete per-tool spec (description, effects, annotations, inputSchema, outputSchema) is in that file.

| Tool | Kind | Session? | Providers advertising it | CLI command |
|---|---|---|---|---|
| [`compare_wasm_interfaces`](#comparewasminterfaces) | application | no | (built-in / not provider-listed) | `rea compare-wasm-interfaces` |
| [`decode_interface_builder`](#decodeinterfacebuilder) | artifact-provider | no | rea-artifact-graph | `rea decode-interface-builder` |
| [`decode_signal_recording`](#decodesignalrecording) | artifact-provider | no | sigrok-recording | `rea decode-signal-recording` |
| [`extract_artifact`](#extractartifact) | artifact-provider | no | rea-artifact-graph | `rea extract-artifact` |
| [`inspect_artifact`](#inspectartifact) | artifact-provider | no | rea-artifact-graph | `rea inspect-artifact` |
| [`inspect_asset_catalog`](#inspectassetcatalog) | artifact-provider | no | rea-artifact-graph | `rea inspect-asset-catalog` |
| [`inspect_evm_interface`](#inspectevminterface) | artifact-provider | no | evmole-interface | `rea inspect-evm-interface` |
| [`inspect_go_binary`](#inspectgobinary) | artifact-provider | no | go-build-info | `rea inspect-go-binary` |
| [`inspect_keyed_archive`](#inspectkeyedarchive) | artifact-provider | no | rea-artifact-graph | `rea inspect-keyed-archive` |
| [`inspect_packet_capture`](#inspectpacketcapture) | artifact-provider | no | tshark-capture | `rea inspect-packet-capture` |
| [`inspect_packet_fields`](#inspectpacketfields) | artifact-provider | no | tshark-capture | `rea inspect-packet-fields` |
| [`inspect_rust_binary`](#inspectrustbinary) | artifact-provider | no | rust-auditable | `rea inspect-rust-binary` |
| [`inspect_signal_decoders`](#inspectsignaldecoders) | artifact-provider | no | sigrok-recording | `rea inspect-signal-decoders` |
| [`inspect_sqlite_database`](#inspectsqlitedatabase) | artifact-provider | no | sqlite | `rea inspect-sqlite-database` |
| [`inspect_wasm_artifact`](#inspectwasmartifact) | artifact-provider | no | wabt-artifact | `rea inspect-wasm-artifact` |
| [`trace_dylib_resolution`](#tracedylibresolution) | artifact-provider | no | rea-artifact-graph | `rea trace-dylib-resolution` |

## compare_wasm_interfaces

<a id="comparewasminterfaces"></a>

**Title:** Compare Wasm Interfaces  
**Kind:** `application` · **Requires session:** false · **analysisOperation:** null  
**Providers:** n/a  
**Effects set (true flags):** mutatesSession  
**MCP annotations:** `{"destructiveHint":false,"idempotentHint":true,"openWorldHint":false,"readOnlyHint":false}`

**Description (verbatim, as advertised to the agent):**

> Compare typed core WASM import/export names, kinds and exact signatures from two authenticated inspect_wasm_artifact Evidence records. Select imports, exports or both explicitly. Retained references resolve only in the current session; CLI accepts portable inline Evidence. Duplicate names, unsupported types and missing historical interface facets remain unknown. Preserve original module digests and every occurrence; no source acquisition, module execution or runtime-compatibility inference.

**Input schema (verbatim, JSON Schema 2020-12):**

<details><summary>inputSchema for compare_wasm_interfaces</summary>

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "additionalProperties": false,
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
      "description": "Exact complete inspect_wasm_artifact Evidence or retained session reference"
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
      "description": "Exact complete inspect_wasm_artifact Evidence or retained session reference"
    },
    "scope": {
      "description": "Explicit interface selection; static equality does not establish runtime compatibility",
      "enum": [
        "imports",
        "exports",
        "both"
      ],
      "type": "string"
    }
  },
  "required": [
    "left",
    "right",
    "scope"
  ],
  "type": "object"
}
```

</details>

**Output schema:** see [`tool-specs/compare_wasm_interfaces.json`](../tool-specs/compare_wasm_interfaces.json) (`outputSchema`).

---

## decode_interface_builder

<a id="decodeinterfacebuilder"></a>

**Title:** Decode Interface Builder  
**Kind:** `artifact-provider` · **Requires session:** false · **analysisOperation:** decode_interface_builder  
**Providers:** rea-artifact-graph  
**Effects set (true flags):** mutatesSession  
**MCP annotations:** `{"destructiveHint":false,"idempotentHint":true,"openWorldHint":false,"readOnlyHint":false}`

**Description (verbatim, as advertised to the agent):**

> Decode compiled storyboard and nib archives inside the active Apple app bundle, including keyed property lists and NIBArchive object tables, into a bounded object, hierarchy, and connection graph. This is static archive parsing; unrecognized archive classes and unresolved code handlers remain explicit unknowns. A full app graph is often several megabytes; detail summary retains it and returns documents with node, edge and coverage counts, then page rows, optionally one document's, with inspect_analysis_view kind interface-builder.

**Input schema (verbatim, JSON Schema 2020-12):**

<details><summary>inputSchema for decode_interface_builder</summary>

```json
{
  "$defs": {
    "__schema0": {
      "default": 64,
      "maximum": 64,
      "minimum": 1,
      "type": "integer"
    },
    "__schema1": {
      "default": 20000,
      "maximum": 20000,
      "minimum": 1,
      "type": "integer"
    },
    "__schema2": {
      "default": 40000,
      "maximum": 40000,
      "minimum": 1,
      "type": "integer"
    },
    "__schema3": {
      "$ref": "#/$defs/__schema4",
      "description": "Omitted or complete returns the complete decoded graph Evidence. summary retains that complete Evidence in this session and returns its inspect_analysis_view summary; use normalized_result.parent_evidence_id for interface-builder pages."
    },
    "__schema4": {
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
    {}
  ],
  "properties": {
    "detail": {
      "$ref": "#/$defs/__schema3",
      "description": "Omitted or complete returns the complete decoded graph Evidence. summary retains that complete Evidence in this session and returns its inspect_analysis_view summary; use normalized_result.parent_evidence_id for interface-builder pages."
    },
    "max_connections": {
      "$ref": "#/$defs/__schema2",
      "description": "Maximum permitted connections for this operation."
    },
    "max_documents": {
      "$ref": "#/$defs/__schema0",
      "description": "Maximum permitted documents for this operation."
    },
    "max_objects": {
      "$ref": "#/$defs/__schema1",
      "description": "Maximum permitted objects for this operation."
    }
  },
  "type": "object"
}
```

</details>

**Output schema:** see [`tool-specs/decode_interface_builder.json`](../tool-specs/decode_interface_builder.json) (`outputSchema`).

---

## decode_signal_recording

<a id="decodesignalrecording"></a>

**Title:** Decode Signal Recording  
**Kind:** `artifact-provider` · **Requires session:** false · **analysisOperation:** decode_signal_recording  
**Providers:** sigrok-recording  
**Effects set (true flags):** launchesProcess, mutatesSession, writesFilesystem  
**MCP annotations:** `{"destructiveHint":false,"idempotentHint":true,"openWorldHint":true,"readOnlyHint":false}`

**Description (verbatim, as advertised to the agent):**

> Decode an existing local logic/signal recording on Linux with sigrok-cli 0.7.2 and util-linux prlimit. Supply decoder stack, channels and options explicitly; optionally select input format and annotation classes. Return 50 literal output lines by default, with line_offset/line_limit paging; line_limit:null requests all remaining lines. Output windows count display lines, not annotations or samples, and do not shorten decoding. Preserve selected text, sample ranges, stderr, source/tool identity and coverage inline. Configure absolute REA_SIGROK_COMMAND. File-only analysis; no hardware acquisition or device communication. Empty output does not prove absence of traffic.

**Input schema (verbatim, JSON Schema 2020-12):**

<details><summary>inputSchema for decode_signal_recording</summary>

```json
{
  "$defs": {
    "__schema0": {
      "description": "Absolute local recording path",
      "minLength": 1,
      "pattern": "^[^\\x00]*$",
      "type": "string"
    },
    "__schema1": {
      "$ref": "#/$defs/__schema2",
      "description": "sigrok decoder stack, options and channel assignments, e.g. uart:rx=RX:baudrate=9600"
    },
    "__schema10": {
      "anyOf": [
        {
          "exclusiveMinimum": 0,
          "maximum": 9007199254740991,
          "type": "integer"
        },
        {
          "type": "null"
        }
      ]
    },
    "__schema2": {
      "maxLength": 8192,
      "minLength": 1,
      "type": "string"
    },
    "__schema3": {
      "$ref": "#/$defs/__schema4",
      "default": null,
      "description": "Explicit sigrok input format and options; omitted means autodetection"
    },
    "__schema4": {
      "anyOf": [
        {
          "$ref": "#/$defs/__schema2"
        },
        {
          "type": "null"
        }
      ]
    },
    "__schema5": {
      "$ref": "#/$defs/__schema6",
      "default": null,
      "description": "Optional annotation selection, e.g. uart=rx-data"
    },
    "__schema6": {
      "anyOf": [
        {
          "$ref": "#/$defs/__schema2"
        },
        {
          "type": "null"
        }
      ]
    },
    "__schema7": {
      "$ref": "#/$defs/__schema8",
      "default": 0,
      "description": "Skip this many literal LF-separated output lines; default 0"
    },
    "__schema8": {
      "maximum": 9007199254740991,
      "minimum": 0,
      "type": "integer"
    },
    "__schema9": {
      "$ref": "#/$defs/__schema10",
      "default": 50,
      "description": "Return at most this many output lines; default 50. Null explicitly returns all remaining lines within producer limits. Lines are not annotation counts."
    }
  },
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "additionalProperties": false,
  "examples": [
    {
      "annotations": "uart=rx-data",
      "decoders": "uart:rx=RX:baudrate=9600",
      "input_format": "vcd",
      "path": "/artifacts/uart.vcd"
    }
  ],
  "properties": {
    "annotations": {
      "$ref": "#/$defs/__schema5",
      "description": "Optional annotation selection, e.g. uart=rx-data"
    },
    "decoders": {
      "$ref": "#/$defs/__schema1",
      "description": "sigrok decoder stack, options and channel assignments, e.g. uart:rx=RX:baudrate=9600"
    },
    "input_format": {
      "$ref": "#/$defs/__schema3",
      "description": "Explicit sigrok input format and options; omitted means autodetection"
    },
    "line_limit": {
      "$ref": "#/$defs/__schema9",
      "description": "Return at most this many output lines; default 50. Null explicitly returns all remaining lines within producer limits. Lines are not annotation counts."
    },
    "line_offset": {
      "$ref": "#/$defs/__schema7",
      "description": "Skip this many literal LF-separated output lines; default 0"
    },
    "path": {
      "$ref": "#/$defs/__schema0",
      "description": "Absolute local recording path"
    }
  },
  "required": [
    "path",
    "decoders"
  ],
  "type": "object"
}
```

</details>

**Output schema:** see [`tool-specs/decode_signal_recording.json`](../tool-specs/decode_signal_recording.json) (`outputSchema`).

---

## extract_artifact

<a id="extractartifact"></a>

**Title:** Extract Artifact  
**Kind:** `artifact-provider` · **Requires session:** false · **analysisOperation:** extract_artifact  
**Providers:** rea-artifact-graph  
**Effects set (true flags):** NOT idempotent, launchesProcess, mutatesSession, writesFilesystem  
**MCP annotations:** `{"destructiveHint":false,"idempotentHint":false,"openWorldHint":true,"readOnlyHint":false}`

**Description (verbatim, as advertised to the agent):**

> Extract all regular files from the active archive or application package into a fresh temporary directory chosen by REA. The result includes its location. Rejects traversal and symlink escapes, never overwrites, and verifies cleanup. Integrity mismatches fail by default; record-and-continue extracts the observed bytes and returns each mismatch as an explicitly untrusted integrity contradiction.

**Input schema (verbatim, JSON Schema 2020-12):**

<details><summary>inputSchema for extract_artifact</summary>

```json
{
  "$defs": {
    "__schema0": {
      "default": "fail",
      "enum": [
        "fail",
        "record-and-continue"
      ],
      "type": "string"
    }
  },
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "additionalProperties": false,
  "examples": [
    {}
  ],
  "properties": {
    "integrity_policy": {
      "$ref": "#/$defs/__schema0"
    }
  },
  "type": "object"
}
```

</details>

**Output schema:** see [`tool-specs/extract_artifact.json`](../tool-specs/extract_artifact.json) (`outputSchema`).

---

## inspect_artifact

<a id="inspectartifact"></a>

**Title:** Inspect Artifact  
**Kind:** `artifact-provider` · **Requires session:** false · **analysisOperation:** inspect_artifact  
**Providers:** rea-artifact-graph  
**Effects set (true flags):** launchesProcess, mutatesSession, writesFilesystem  
**MCP annotations:** `{"destructiveHint":false,"idempotentHint":true,"openWorldHint":true,"readOnlyHint":false}`

**Description (verbatim, as advertised to the agent):**

> Inspect an active archive or application package in one call. By default returns the complete content-addressed artifact graph once, as the typed nested inventory Evidence, with root and integrity observations, integrity contradictions, hypotheses, unexplored branches, limitations, and next probes inline. Optional detail summary retains the complete inspection and returns its derived summary view; read exact paths or inventory pages with inspect_analysis_view using parent_evidence_id. This changes delivery, not inventory coverage. Read-only DMG mounting is used automatically on supported macOS hosts. Integrity mismatches fail by default; record-and-continue keeps mismatches explicitly untrusted. It does not extract files; use extract_artifact to materialize its regular contents.

**Input schema (verbatim, JSON Schema 2020-12):**

<details><summary>inputSchema for inspect_artifact</summary>

```json
{
  "$defs": {
    "__schema0": {
      "default": "fail",
      "enum": [
        "fail",
        "record-and-continue"
      ],
      "type": "string"
    },
    "__schema1": {
      "$ref": "#/$defs/__schema2",
      "description": "Omitted or complete returns the complete inspection Evidence. summary retains that complete Evidence in this session and returns its inspect_analysis_view summary; use normalized_result.parent_evidence_id for inventory views."
    },
    "__schema2": {
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
    {}
  ],
  "properties": {
    "detail": {
      "$ref": "#/$defs/__schema1",
      "description": "Omitted or complete returns the complete inspection Evidence. summary retains that complete Evidence in this session and returns its inspect_analysis_view summary; use normalized_result.parent_evidence_id for inventory views."
    },
    "integrity_policy": {
      "$ref": "#/$defs/__schema0"
    }
  },
  "type": "object"
}
```

</details>

**Output schema:** see [`tool-specs/inspect_artifact.json`](../tool-specs/inspect_artifact.json) (`outputSchema`).

---

## inspect_asset_catalog

<a id="inspectassetcatalog"></a>

**Title:** Inspect Asset Catalog  
**Kind:** `artifact-provider` · **Requires session:** false · **analysisOperation:** inspect_asset_catalog  
**Providers:** rea-artifact-graph  
**Effects set (true flags):** launchesProcess, mutatesSession  
**MCP annotations:** `{"destructiveHint":false,"idempotentHint":true,"openWorldHint":true,"readOnlyHint":false}`

**Description (verbatim, as advertised to the agent):**

> Inspect compiled Assets.car metadata in an active Apple app bundle. Returns stable paginated catalog and rendition records with raw assetutil metadata and catalog digests; rendition bytes are not extracted.

**Input schema (verbatim, JSON Schema 2020-12):**

<details><summary>inputSchema for inspect_asset_catalog</summary>

```json
{
  "$defs": {
    "__schema0": {
      "default": 0,
      "maximum": 9007199254740991,
      "minimum": 0,
      "type": "integer"
    },
    "__schema1": {
      "default": 1000,
      "maximum": 10000,
      "minimum": 1,
      "type": "integer"
    }
  },
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "additionalProperties": false,
  "examples": [
    {
      "limit": 1000,
      "offset": 0
    }
  ],
  "properties": {
    "limit": {
      "$ref": "#/$defs/__schema1"
    },
    "offset": {
      "$ref": "#/$defs/__schema0"
    }
  },
  "type": "object"
}
```

</details>

**Output schema:** see [`tool-specs/inspect_asset_catalog.json`](../tool-specs/inspect_asset_catalog.json) (`outputSchema`).

---

## inspect_evm_interface

<a id="inspectevminterface"></a>

**Title:** Inspect Evm Interface  
**Kind:** `artifact-provider` · **Requires session:** false · **analysisOperation:** inspect_evm_interface  
**Providers:** evmole-interface  
**Effects set (true flags):** launchesProcess, mutatesSession, writesFilesystem  
**MCP annotations:** `{"destructiveHint":false,"idempotentHint":true,"openWorldHint":true,"readOnlyHint":false}`

**Description (verbatim, as advertised to the agent):**

> Inspect explicit local flat EVM bytecode without target execution or chain/RPC access. Select raw or hex encoding explicitly. Omitted or complete detail returns original carrier and decoded identities, full bytecode and all inferred interface candidates inline. For all inferred selectors/offsets/arguments/mutability and identities without bytecode hex or duplicated stdout, select detail: "summary" on this first call: it retains unchanged complete Evidence and returns a distinct linked inspect_analysis_view summary. Read original function rows or bytecode_hex/stdout/stderr text pages using view kind evm and normalized_result.parent_evidence_id; original complete Evidence remains accessible. Bytecode kind, hardfork, deployed authenticity and discovery completeness stay unknown; summary coverage covers only producer-returned candidates. Unchanged bundled EVMole 0.9.3/WASM in an owned bounded worker is initially real-verified on Linux x64; EOF-style EF00 containers are unsupported. No signature lookup, wallet action or transaction broadcast.

**Input schema (verbatim, JSON Schema 2020-12):**

<details><summary>inputSchema for inspect_evm_interface</summary>

```json
{
  "$defs": {
    "__schema0": {
      "description": "Absolute path to caller-selected local bytecode carrier",
      "minLength": 1,
      "pattern": "^[^\\x00]*$",
      "type": "string"
    },
    "__schema1": {
      "description": "Raw bytes or UTF-8 hex with optional 0x prefix and outer ASCII whitespace",
      "enum": [
        "raw",
        "hex"
      ],
      "type": "string"
    },
    "__schema2": {
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
      "encoding": "hex",
      "path": "/artifacts/runtime.hex"
    },
    {
      "detail": "summary",
      "encoding": "hex",
      "path": "/artifacts/runtime.hex"
    }
  ],
  "properties": {
    "detail": {
      "$ref": "#/$defs/__schema2"
    },
    "encoding": {
      "$ref": "#/$defs/__schema1",
      "description": "Raw bytes or UTF-8 hex with optional 0x prefix and outer ASCII whitespace"
    },
    "path": {
      "$ref": "#/$defs/__schema0",
      "description": "Absolute path to caller-selected local bytecode carrier"
    }
  },
  "required": [
    "path",
    "encoding"
  ],
  "type": "object"
}
```

</details>

**Output schema:** see [`tool-specs/inspect_evm_interface.json`](../tool-specs/inspect_evm_interface.json) (`outputSchema`).

---

## inspect_go_binary

<a id="inspectgobinary"></a>

**Title:** Inspect Go Binary  
**Kind:** `artifact-provider` · **Requires session:** false · **analysisOperation:** inspect_go_binary  
**Providers:** go-build-info  
**Effects set (true flags):** mutatesSession  
**MCP annotations:** `{"destructiveHint":false,"idempotentHint":true,"openWorldHint":false,"readOnlyHint":false}`

**Description (verbatim, as advertised to the agent):**

> Inspect embedded Go compiler version, main module, dependency/replacement versions and build settings in an explicit local ELF, PE or thin Mach-O image. Returns original artifact SHA-256, exact build-info source ranges, raw framed module bytes and unparsed module-text lines inline as observed Evidence. Supports inline and historical pointer encodings without installing Go, opening a disassembler, executing the target, writing temporary files or accessing the network. Missing metadata is reported as unknown, not proof that an image is not Go. Does not recover functions, source mappings, types or runtime behavior. Resource guards bound files to 256 MiB, aggregate embedded strings to 1 MiB, structural table decoding to 16 MiB and complete inline metadata to 8 MiB; malformed, unsupported and oversized inputs receive typed failures rather than partial success.

**Input schema (verbatim, JSON Schema 2020-12):**

<details><summary>inputSchema for inspect_go_binary</summary>

```json
{
  "$defs": {
    "__schema0": {
      "description": "Absolute filesystem path to the selected executable or library",
      "minLength": 1,
      "pattern": "^[^\\x00]*$",
      "type": "string"
    }
  },
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "additionalProperties": false,
  "examples": [
    {
      "path": "/artifacts/application"
    }
  ],
  "properties": {
    "path": {
      "$ref": "#/$defs/__schema0",
      "description": "Absolute filesystem path to the selected executable or library"
    }
  },
  "required": [
    "path"
  ],
  "type": "object"
}
```

</details>

**Output schema:** see [`tool-specs/inspect_go_binary.json`](../tool-specs/inspect_go_binary.json) (`outputSchema`).

---

## inspect_keyed_archive

<a id="inspectkeyedarchive"></a>

**Title:** Inspect Keyed Archive  
**Kind:** `artifact-provider` · **Requires session:** false · **analysisOperation:** inspect_keyed_archive  
**Providers:** rea-artifact-graph  
**Effects set (true flags):** mutatesSession  
**MCP annotations:** `{"destructiveHint":false,"idempotentHint":true,"openWorldHint":false,"readOnlyHint":false}`

**Description (verbatim, as advertised to the agent):**

> Inspect one Foundation NSKeyedArchiver plist in the active app bundle as original object-table nodes, class descriptors, named roots, and UID edges. Preserves shared and cyclic references without instantiating classes. The path is relative to the bundle; root selection and object pagination preserve original identities.

**Input schema (verbatim, JSON Schema 2020-12):**

<details><summary>inputSchema for inspect_keyed_archive</summary>

```json
{
  "$defs": {
    "__schema0": {
      "default": ".",
      "minLength": 1,
      "type": "string"
    },
    "__schema1": {
      "type": "string"
    },
    "__schema2": {
      "default": 0,
      "maximum": 9007199254740991,
      "minimum": 0,
      "type": "integer"
    },
    "__schema3": {
      "default": 20000,
      "maximum": 20000,
      "minimum": 1,
      "type": "integer"
    }
  },
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "additionalProperties": false,
  "examples": [
    {
      "path": "Contents/Resources/Model.plist"
    }
  ],
  "properties": {
    "limit": {
      "$ref": "#/$defs/__schema3"
    },
    "offset": {
      "$ref": "#/$defs/__schema2"
    },
    "path": {
      "$ref": "#/$defs/__schema0",
      "description": "Local filesystem path used by this operation."
    },
    "root": {
      "$ref": "#/$defs/__schema1"
    }
  },
  "type": "object"
}
```

</details>

**Output schema:** see [`tool-specs/inspect_keyed_archive.json`](../tool-specs/inspect_keyed_archive.json) (`outputSchema`).

---

## inspect_packet_capture

<a id="inspectpacketcapture"></a>

**Title:** Inspect Packet Capture  
**Kind:** `artifact-provider` · **Requires session:** false · **analysisOperation:** inspect_packet_capture  
**Providers:** tshark-capture  
**Effects set (true flags):** launchesProcess, mutatesSession, writesFilesystem  
**MCP annotations:** `{"destructiveHint":false,"idempotentHint":true,"openWorldHint":true,"readOnlyHint":false}`

**Description (verbatim, as advertised to the agent):**

> Inspect caller-selected fields in an existing local packet capture with TShark 4.x. Return 50 matching frames by default, with match_offset/match_limit paging and coverage counts; match_limit:null requests all remaining matches. Preserve repeated values, frame numbers, display filter, decode-as rules and pass mode in inline Evidence with source/tool identity and diagnostics. Optional packet_limit counts input packets before filtering; output paging does not shorten dissection or two-pass reassembly. Requires Linux, util-linux prlimit, and absolute REA_TSHARK_COMMAND. File-only analysis; no live capture or device communication. Missing fields or no matches do not establish absence of device traffic.

**Input schema (verbatim, JSON Schema 2020-12):**

<details><summary>inputSchema for inspect_packet_capture</summary>

```json
{
  "$defs": {
    "__schema0": {
      "description": "Absolute local capture path",
      "minLength": 1,
      "pattern": "^[^\\x00]*$",
      "type": "string"
    },
    "__schema1": {
      "description": "TShark field names to return, e.g. ip.addr, usb.endpoint_address, btatt.opcode; frame.number is always included",
      "items": {
        "$ref": "#/$defs/__schema2"
      },
      "maxItems": 1024,
      "minItems": 1,
      "type": "array"
    },
    "__schema10": {
      "type": "boolean"
    },
    "__schema11": {
      "$ref": "#/$defs/__schema12",
      "default": 0,
      "description": "Skip this many matching packets after filtering; default 0"
    },
    "__schema12": {
      "maximum": 9007199254740991,
      "minimum": 0,
      "type": "integer"
    },
    "__schema13": {
      "$ref": "#/$defs/__schema14",
      "default": 50,
      "description": "Return at most this many matching packets after filtering; default 50. Null explicitly returns all remaining matches within producer resource limits."
    },
    "__schema14": {
      "anyOf": [
        {
          "exclusiveMinimum": 0,
          "maximum": 9007199254740991,
          "type": "integer"
        },
        {
          "type": "null"
        }
      ]
    },
    "__schema2": {
      "maxLength": 8192,
      "minLength": 1,
      "type": "string"
    },
    "__schema3": {
      "$ref": "#/$defs/__schema4",
      "default": null,
      "description": "Optional Wireshark display filter (-Y), applied within the read limit"
    },
    "__schema4": {
      "anyOf": [
        {
          "$ref": "#/$defs/__schema2"
        },
        {
          "type": "null"
        }
      ]
    },
    "__schema5": {
      "$ref": "#/$defs/__schema6",
      "default": [],
      "description": "Explicit TShark decode-as selections, e.g. tcp.port==8888,http"
    },
    "__schema6": {
      "items": {
        "$ref": "#/$defs/__schema2"
      },
      "maxItems": 1024,
      "type": "array"
    },
    "__schema7": {
      "$ref": "#/$defs/__schema8",
      "default": null,
      "description": "Maximum input packets to read before filtering; omitted scans to EOF within resource limits"
    },
    "__schema8": {
      "anyOf": [
        {
          "exclusiveMinimum": 0,
          "maximum": 2147483647,
          "type": "integer"
        },
        {
          "type": "null"
        }
      ]
    },
    "__schema9": {
      "$ref": "#/$defs/__schema10",
      "default": true,
      "description": "Use two-pass analysis for fields requiring later packets; false requests a single pass"
    }
  },
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "additionalProperties": false,
  "examples": [
    {
      "decode_as": [],
      "display_filter": "udp",
      "fields": [
        "ip.addr",
        "udp.port",
        "data.data"
      ],
      "packet_limit": null,
      "path": "/artifacts/device.pcapng",
      "two_pass": true
    }
  ],
  "properties": {
    "decode_as": {
      "$ref": "#/$defs/__schema5",
      "description": "Explicit TShark decode-as selections, e.g. tcp.port==8888,http"
    },
    "display_filter": {
      "$ref": "#/$defs/__schema3",
      "description": "Optional Wireshark display filter (-Y), applied within the read limit"
    },
    "fields": {
      "$ref": "#/$defs/__schema1",
      "description": "TShark field names to return, e.g. ip.addr, usb.endpoint_address, btatt.opcode; frame.number is always included"
    },
    "match_limit": {
      "$ref": "#/$defs/__schema13",
      "description": "Return at most this many matching packets after filtering; default 50. Null explicitly returns all remaining matches within producer resource limits."
    },
    "match_offset": {
      "$ref": "#/$defs/__schema11",
      "description": "Skip this many matching packets after filtering; default 0"
    },
    "packet_limit": {
      "$ref": "#/$defs/__schema7",
      "description": "Maximum input packets to read before filtering; omitted scans to EOF within resource limits"
    },
    "path": {
      "$ref": "#/$defs/__schema0",
      "description": "Absolute local capture path"
    },
    "two_pass": {
      "$ref": "#/$defs/__schema9",
      "description": "Use two-pass analysis for fields requiring later packets; false requests a single pass"
    }
  },
  "required": [
    "path",
    "fields"
  ],
  "type": "object"
}
```

</details>

**Output schema:** see [`tool-specs/inspect_packet_capture.json`](../tool-specs/inspect_packet_capture.json) (`outputSchema`).

---

## inspect_packet_fields

<a id="inspectpacketfields"></a>

**Title:** Inspect Packet Fields  
**Kind:** `artifact-provider` · **Requires session:** false · **analysisOperation:** inspect_packet_fields  
**Providers:** tshark-capture  
**Effects set (true flags):** launchesProcess, mutatesSession, writesFilesystem  
**MCP annotations:** `{"destructiveHint":false,"idempotentHint":true,"openWorldHint":true,"readOnlyHint":false}`

**Description (verbatim, as advertised to the agent):**

> Discover protocols or field names/types registered in the installed TShark 4.x. kind defaults to protocols; use fields and optional exact protocol abbreviation to select field definitions. query searches name/abbreviation/description by case-insensitive literal substring. Return 50 matches by default with offset/limit paging; null requests all remaining within resource limits. Preserve type/base/bitmask/description, duplicate registrations, source line numbers, coverage, tool identity and diagnostics. Linux, REA_TSHARK_COMMAND and prlimit required. No capture file, interface or binary target needed. Registrations describe tool capabilities, not observed traffic. Each call rereads the glossary; use selected fields with inspect_packet_capture.

**Input schema (verbatim, JSON Schema 2020-12):**

<details><summary>inputSchema for inspect_packet_fields</summary>

```json
{
  "$defs": {
    "__schema0": {
      "$ref": "#/$defs/__schema1",
      "default": "protocols",
      "description": "Return protocol registrations or field definitions; defaults to protocols"
    },
    "__schema1": {
      "enum": [
        "protocols",
        "fields"
      ],
      "type": "string"
    },
    "__schema2": {
      "$ref": "#/$defs/__schema3",
      "default": null,
      "description": "Exact protocol abbreviation; selects that protocol or its registered fields"
    },
    "__schema3": {
      "anyOf": [
        {
          "maxLength": 8192,
          "minLength": 1,
          "type": "string"
        },
        {
          "type": "null"
        }
      ]
    },
    "__schema4": {
      "$ref": "#/$defs/__schema5",
      "default": "",
      "description": "Case-insensitive literal substring in name, abbreviation or field description"
    },
    "__schema5": {
      "maxLength": 8192,
      "type": "string"
    },
    "__schema6": {
      "$ref": "#/$defs/__schema7",
      "default": 0,
      "description": "Number of matching records to skip; defaults to 0"
    },
    "__schema7": {
      "maximum": 9007199254740991,
      "minimum": 0,
      "type": "integer"
    },
    "__schema8": {
      "$ref": "#/$defs/__schema9",
      "default": 50,
      "description": "Maximum matches returned; null requests all remaining within the record budget"
    },
    "__schema9": {
      "anyOf": [
        {
          "exclusiveMinimum": 0,
          "maximum": 9007199254740991,
          "type": "integer"
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
      "query": "usb"
    },
    {
      "kind": "fields",
      "protocol": "usb",
      "query": "idVendor"
    }
  ],
  "properties": {
    "kind": {
      "$ref": "#/$defs/__schema0",
      "description": "Return protocol registrations or field definitions; defaults to protocols"
    },
    "limit": {
      "$ref": "#/$defs/__schema8",
      "description": "Maximum matches returned; null requests all remaining within the record budget"
    },
    "offset": {
      "$ref": "#/$defs/__schema6",
      "description": "Number of matching records to skip; defaults to 0"
    },
    "protocol": {
      "$ref": "#/$defs/__schema2",
      "description": "Exact protocol abbreviation; selects that protocol or its registered fields"
    },
    "query": {
      "$ref": "#/$defs/__schema4",
      "description": "Case-insensitive literal substring in name, abbreviation or field description"
    }
  },
  "type": "object"
}
```

</details>

**Output schema:** see [`tool-specs/inspect_packet_fields.json`](../tool-specs/inspect_packet_fields.json) (`outputSchema`).

---

## inspect_rust_binary

<a id="inspectrustbinary"></a>

**Title:** Inspect Rust Binary  
**Kind:** `artifact-provider` · **Requires session:** false · **analysisOperation:** inspect_rust_binary  
**Providers:** rust-auditable  
**Effects set (true flags):** mutatesSession  
**MCP annotations:** `{"destructiveHint":false,"idempotentHint":true,"openWorldHint":false,"readOnlyHint":false}`

**Description (verbatim, as advertised to the agent):**

> Inspect the cargo-auditable crate dependency list embedded in an explicit local ELF, PE or thin Mach-O image. Returns the artifact SHA-256, the .dep-v0 section file offset and size, compressed and uncompressed sizes, format version, packages in their original order, the root package index, and dependency edges by index. Reads zlib-compressed JSON without installing Rust, opening a disassembler, executing the target, writing temporary files or accessing the network. A missing section is null metadata with a limitation and is not proof that the binary has no dependencies. A rustc commit hash is reported only as an inference when a /rustc/<40-hex>/ path is present in read-only data. Resource guards bound files to 256 MiB, dependency sections to 1 MiB, inflated JSON to the smaller of 8 MiB and 64 times the compressed size, and the complete report to 8 MiB. Malformed, unsupported and oversized inputs receive typed failures rather than partial success.

**Input schema (verbatim, JSON Schema 2020-12):**

<details><summary>inputSchema for inspect_rust_binary</summary>

```json
{
  "$defs": {
    "__schema0": {
      "description": "Absolute filesystem path to the selected executable or library",
      "minLength": 1,
      "pattern": "^[^\\x00]*$",
      "type": "string"
    }
  },
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "additionalProperties": false,
  "examples": [
    {
      "path": "/artifacts/application"
    }
  ],
  "properties": {
    "path": {
      "$ref": "#/$defs/__schema0",
      "description": "Absolute filesystem path to the selected executable or library"
    }
  },
  "required": [
    "path"
  ],
  "type": "object"
}
```

</details>

**Output schema:** see [`tool-specs/inspect_rust_binary.json`](../tool-specs/inspect_rust_binary.json) (`outputSchema`).

---

## inspect_signal_decoders

<a id="inspectsignaldecoders"></a>

**Title:** Inspect Signal Decoders  
**Kind:** `artifact-provider` · **Requires session:** false · **analysisOperation:** inspect_signal_decoders  
**Providers:** sigrok-recording  
**Effects set (true flags):** launchesProcess, mutatesSession, writesFilesystem  
**MCP annotations:** `{"destructiveHint":false,"idempotentHint":true,"openWorldHint":true,"readOnlyHint":false}`

**Description (verbatim, as advertised to the agent):**

> Discover installed sigrok protocol decoders or inspect one decoder's channel/option help on Linux. Omit decoder to list ID/name pairs; supply its exact ID for literal help lines with source line numbers. query is a case-insensitive literal substring. Page matches with offset/limit (default 50; null returns all remaining). Reports tool identity, version, diagnostics and examined/matching coverage. Uses configured REA_SIGROK_COMMAND and prlimit; no recording, binary target, hardware scan or acquisition. Each call probes again; decoder modules are trusted, not fully fingerprinted. Use returned IDs/options with decode_signal_recording.

**Input schema (verbatim, JSON Schema 2020-12):**

<details><summary>inputSchema for inspect_signal_decoders</summary>

```json
{
  "$defs": {
    "__schema0": {
      "$ref": "#/$defs/__schema1",
      "default": null,
      "description": "Exact installed decoder ID for help; null searches the decoder catalog"
    },
    "__schema1": {
      "anyOf": [
        {
          "maxLength": 256,
          "pattern": "^[a-zA-Z0-9_+\\x2d]+$",
          "type": "string"
        },
        {
          "type": "null"
        }
      ]
    },
    "__schema2": {
      "$ref": "#/$defs/__schema3",
      "default": "",
      "description": "Case-insensitive literal substring in decoder ID/name or help lines; empty selects all"
    },
    "__schema3": {
      "maxLength": 8192,
      "type": "string"
    },
    "__schema4": {
      "$ref": "#/$defs/__schema5",
      "default": 0,
      "description": "Number of matching decoders or help lines to skip; defaults to 0"
    },
    "__schema5": {
      "maximum": 9007199254740991,
      "minimum": 0,
      "type": "integer"
    },
    "__schema6": {
      "$ref": "#/$defs/__schema7",
      "default": 50,
      "description": "Maximum matching decoders or help lines returned; null requests all remaining"
    },
    "__schema7": {
      "anyOf": [
        {
          "exclusiveMinimum": 0,
          "maximum": 9007199254740991,
          "type": "integer"
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
      "query": "uart"
    },
    {
      "decoder": "uart",
      "query": "baud"
    }
  ],
  "properties": {
    "decoder": {
      "$ref": "#/$defs/__schema0",
      "description": "Exact installed decoder ID for help; null searches the decoder catalog"
    },
    "limit": {
      "$ref": "#/$defs/__schema6",
      "description": "Maximum matching decoders or help lines returned; null requests all remaining"
    },
    "offset": {
      "$ref": "#/$defs/__schema4",
      "description": "Number of matching decoders or help lines to skip; defaults to 0"
    },
    "query": {
      "$ref": "#/$defs/__schema2",
      "description": "Case-insensitive literal substring in decoder ID/name or help lines; empty selects all"
    }
  },
  "type": "object"
}
```

</details>

**Output schema:** see [`tool-specs/inspect_signal_decoders.json`](../tool-specs/inspect_signal_decoders.json) (`outputSchema`).

---

## inspect_sqlite_database

<a id="inspectsqlitedatabase"></a>

**Title:** Inspect Sqlite Database  
**Kind:** `artifact-provider` · **Requires session:** false · **analysisOperation:** inspect_sqlite_database  
**Providers:** sqlite  
**Effects set (true flags):** launchesProcess, mutatesSession, writesFilesystem  
**MCP annotations:** `{"destructiveHint":false,"idempotentHint":true,"openWorldHint":true,"readOnlyHint":false}`

**Description (verbatim, as advertised to the agent):**

> Inspect an explicit local SQLite database snapshot and its existing sibling WAL without modifying source files or opening a native analysis provider. Requires Node.js 24.x >=24.15 or 26+ with native DatabaseSync.limits support, checked by the worker. Returns observed Evidence with database/WAL SHA-256 and a compact schema inventory. Selecting an exact ordinary table expands only its schema and samples rows (default 20, subject to byte and worker resource limits). Select exact columns in the requested order to avoid unrelated or large values; schema_scope=database explicitly expands the whole schema; returned rows retain 64-bit integers, text bytes and blobs with explicit truncation. No arbitrary SQL, view or virtual-table execution, extension loading, database repair, encryption support or live-snapshot atomicity claim. At most two inspections per provider are admitted; occupied capacity is retryable. An isolated temporary copy and owned worker enforce input, value/record, SQL-statement, JSON-reply, JavaScript-heap and deadline limits; overall native heap is not capped. Supply a quiescent snapshot for coherent database/WAL evidence.

**Input schema (verbatim, JSON Schema 2020-12):**

<details><summary>inputSchema for inspect_sqlite_database</summary>

```json
{
  "$defs": {
    "__schema0": {
      "description": "Absolute path to an offline SQLite database snapshot",
      "minLength": 1,
      "pattern": "^[^\\x00]*$",
      "type": "string"
    },
    "__schema1": {
      "$ref": "#/$defs/__schema2",
      "description": "Exact ordinary table name; views and virtual/shadow tables are not executed"
    },
    "__schema2": {
      "type": "string"
    },
    "__schema3": {
      "$ref": "#/$defs/__schema4",
      "description": "Exact row columns in caller-selected order; requires table. Omit to sample all visible columns."
    },
    "__schema4": {
      "items": {
        "$ref": "#/$defs/__schema5"
      },
      "minItems": 1,
      "type": "array"
    },
    "__schema5": {
      "type": "string"
    },
    "__schema6": {
      "$ref": "#/$defs/__schema7",
      "description": "Default: compact inventory without a table, or detailed selected-table schema with a table. Database explicitly expands all stored declarations and supported columns."
    },
    "__schema7": {
      "enum": [
        "inventory",
        "selected_table",
        "database"
      ],
      "type": "string"
    },
    "__schema8": {
      "$ref": "#/$defs/__schema9",
      "description": "Selected-table sample size, default 20; subject to byte and worker resource limits"
    },
    "__schema9": {
      "maximum": 9007199254740991,
      "minimum": 1,
      "type": "integer"
    }
  },
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "additionalProperties": false,
  "description": "When row_limit is provided, also provide table. When columns is provided, also provide table.",
  "examples": [
    {
      "path": "/artifacts/application.sqlite"
    },
    {
      "columns": [
        "key",
        "value"
      ],
      "path": "/artifacts/application.sqlite",
      "row_limit": 20,
      "table": "settings"
    },
    {
      "path": "/artifacts/application.sqlite",
      "schema_scope": "database"
    }
  ],
  "if": {
    "properties": {
      "schema_scope": {
        "const": "selected_table"
      }
    },
    "required": [
      "schema_scope"
    ]
  },
  "properties": {
    "columns": {
      "$ref": "#/$defs/__schema3",
      "description": "Exact row columns in caller-selected order; requires table. Omit to sample all visible columns."
    },
    "path": {
      "$ref": "#/$defs/__schema0",
      "description": "Absolute path to an offline SQLite database snapshot"
    },
    "row_limit": {
      "$ref": "#/$defs/__schema8",
      "description": "Selected-table sample size, default 20; subject to byte and worker resource limits"
    },
    "schema_scope": {
      "$ref": "#/$defs/__schema6",
      "description": "Default: compact inventory without a table, or detailed selected-table schema with a table. Database explicitly expands all stored declarations and supported columns."
    },
    "table": {
      "$ref": "#/$defs/__schema1",
      "description": "Exact ordinary table name; views and virtual/shadow tables are not executed"
    }
  },
  "required": [
    "path"
  ],
  "then": {
    "required": [
      "table"
    ]
  },
  "type": "object"
}
```

</details>

**Output schema:** see [`tool-specs/inspect_sqlite_database.json`](../tool-specs/inspect_sqlite_database.json) (`outputSchema`).

---

## inspect_wasm_artifact

<a id="inspectwasmartifact"></a>

**Title:** Inspect Wasm Artifact  
**Kind:** `artifact-provider` · **Requires session:** false · **analysisOperation:** inspect_wasm_artifact  
**Providers:** wabt-artifact  
**Effects set (true flags):** launchesProcess, mutatesSession, writesFilesystem  
**MCP annotations:** `{"destructiveHint":false,"idempotentHint":true,"openWorldHint":true,"readOnlyHint":false}`

**Description (verbatim, as advertised to the agent):**

> Validate an explicit local WASM artifact with caller-supplied WABT 1.0.42. Omitted or complete detail returns exact byte SHA-256, sections, upstream import/export WAT forms and decoded WAT inline as Evidence. For counts, validation and WAT identity without WAT text, pass detail: "summary" on this first call; it retains the complete original Evidence and returns the same typed summary as inspect_analysis_view, avoiding oversized complete delivery. Read exact imports/exports or WAT pages with inspect_analysis_view using normalized_result.parent_evidence_id. Delivery selection does not change analysis, provider inputs or source identity. Optionally associate selected JavaScript glue literals with explicit local candidates while preserving ambiguous URL/basename matches. Configure absolute REA_WABT_BIN_DIRECTORY. No installation, implicit fetch, WASM execution or original-source claim.

**Input schema (verbatim, JSON Schema 2020-12):**

<details><summary>inputSchema for inspect_wasm_artifact</summary>

```json
{
  "$defs": {
    "__schema0": {
      "$ref": "#/$defs/__schema1",
      "description": "Absolute selected local WASM artifact path"
    },
    "__schema1": {
      "minLength": 1,
      "pattern": "^[^\\x00]*$",
      "type": "string"
    },
    "__schema2": {
      "default": [],
      "items": {
        "$ref": "#/$defs/__schema1"
      },
      "maxItems": 16,
      "type": "array"
    },
    "__schema3": {
      "default": [],
      "items": {
        "$ref": "#/$defs/__schema1"
      },
      "maxItems": 16,
      "type": "array"
    },
    "__schema4": {
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
      "candidate_paths": [],
      "glue_paths": [],
      "path": "/artifacts/module.wasm"
    }
  ],
  "properties": {
    "candidate_paths": {
      "$ref": "#/$defs/__schema3"
    },
    "detail": {
      "$ref": "#/$defs/__schema4"
    },
    "glue_paths": {
      "$ref": "#/$defs/__schema2"
    },
    "path": {
      "$ref": "#/$defs/__schema0",
      "description": "Absolute selected local WASM artifact path"
    }
  },
  "required": [
    "path"
  ],
  "type": "object"
}
```

</details>

**Output schema:** see [`tool-specs/inspect_wasm_artifact.json`](../tool-specs/inspect_wasm_artifact.json) (`outputSchema`).

---

## trace_dylib_resolution

<a id="tracedylibresolution"></a>

**Title:** Trace Dylib Resolution  
**Kind:** `artifact-provider` · **Requires session:** false · **analysisOperation:** trace_dylib_resolution  
**Providers:** rea-artifact-graph  
**Effects set (true flags):** mutatesSession  
**MCP annotations:** `{"destructiveHint":false,"idempotentHint":true,"openWorldHint":false,"readOnlyHint":false}`

**Description (verbatim, as advertised to the agent):**

> Trace how dyld would resolve each Mach-O dylib load for the active Mach-O, or for every executable in the active .app bundle (the main app, XPC services, extensions, login items, helpers). Expands @executable_path, @loader_path, and @rpath through each process's LC_RPATH stack in dependents-first load order, and reports every candidate path with its outcome, the resolved image and digest, weak, re-export, and upward flags, and derived findings such as unresolved required loads or absent earlier @rpath candidates. Pure header parsing: nothing is executed, and absolute or system paths outside the analyzed root stay undetermined. Select roots or one architecture to narrow large bundles.

**Input schema (verbatim, JSON Schema 2020-12):**

<details><summary>inputSchema for trace_dylib_resolution</summary>

```json
{
  "$defs": {
    "__schema0": {
      "items": {
        "$ref": "#/$defs/__schema1"
      },
      "minItems": 1,
      "type": "array"
    },
    "__schema1": {
      "minLength": 1,
      "pattern": "^(?:[^\\x2f\\\\\\x00.][^\\x2f\\\\\\x00]*|\\.[^\\x2f\\\\\\x00.][^\\x2f\\\\\\x00]*|\\.\\.[^\\x2f\\\\\\x00]+)(?:\\x2f(?:[^\\x2f\\\\\\x00.][^\\x2f\\\\\\x00]*|\\.[^\\x2f\\\\\\x00.][^\\x2f\\\\\\x00]*|\\.\\.[^\\x2f\\\\\\x00]+))*$",
      "type": "string"
    },
    "__schema2": {
      "enum": [
        "arm64",
        "arm64e",
        "x86_64"
      ],
      "type": "string"
    }
  },
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "additionalProperties": false,
  "examples": [
    {
      "architecture": "arm64",
      "roots": [
        "Contents/MacOS/App"
      ]
    }
  ],
  "properties": {
    "architecture": {
      "$ref": "#/$defs/__schema2"
    },
    "roots": {
      "$ref": "#/$defs/__schema0"
    }
  },
  "type": "object"
}
```

</details>

**Output schema:** see [`tool-specs/trace_dylib_resolution.json`](../tool-specs/trace_dylib_resolution.json) (`outputSchema`).

---

