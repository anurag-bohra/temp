# Tool family: Managed PE/CLI (.NET)

Generated mechanically from `.cache/mcp-tool-catalog.json` (produced by `scripts/generate-mcp-tool-catalog.mjs`, which registers every tool through the MCP SDK and exports the advertised JSON Schema 2020-12 input/output schemas) and `docs/public/product-catalog.json` (family `managed`, surface `managed`, 7 tools). Input schemas below are **verbatim**. Output schemas are verbatim in `tool-specs/<tool>.json` (field `outputSchema`) because several exceed 100 KB; the complete per-tool spec (description, effects, annotations, inputSchema, outputSchema) is in that file.

| Tool | Kind | Session? | Providers advertising it | CLI command |
|---|---|---|---|---|
| [`compare_managed_members`](#comparemanagedmembers) | application | yes | rea-dotnet-workflows | `rea compare-managed-members` |
| [`import_managed_reconstruction`](#importmanagedreconstruction) | application | yes | rea-dotnet-workflows | `rea import-managed-reconstruction` |
| [`inspect_managed_artifact`](#inspectmanagedartifact) | managed-provider | no | rea-dotnet-static | `rea inspect-managed-artifact` |
| [`inspect_managed_members`](#inspectmanagedmembers) | managed-provider | no | rea-dotnet-static | `rea inspect-managed-members` |
| [`inspect_managed_native_boundaries`](#inspectmanagednativeboundaries) | managed-provider | no | rea-dotnet-static | `rea inspect-managed-native-boundaries` |
| [`project_managed_application_graph`](#projectmanagedapplicationgraph) | application | yes | rea-dotnet-workflows | `rea project-managed-application-graph` |
| [`verify_managed_native_boundaries`](#verifymanagednativeboundaries) | application | yes | rea-dotnet-workflows | `rea verify-managed-native-boundaries` |

## compare_managed_members

<a id="comparemanagedmembers"></a>

**Title:** Compare Managed Members  
**Kind:** `application` · **Requires session:** true · **analysisOperation:** null  
**Providers:** rea-dotnet-workflows  
**Effects set (true flags):** mutatesSession  
**MCP annotations:** `{"destructiveHint":false,"idempotentHint":true,"openWorldHint":false,"readOnlyHint":false}`

**Description (verbatim, as advertised to the agent):**

> Compare two authenticated inspect_managed_members Evidence records using unique-only tiers: exact declared type, name, and CIL/signature; exact declared type, name, and raw signature (decoded or not); exact declared type, name, and decoded structural method shape; then exact CIL/signature or decoded structural method shape alone, which never takes a member whose own declared type and name remain unpaired on the other side or whose declaring type is unresolved. Names alone are never a matching basis; a member whose signature was not decoded, or whose same-named counterpart's was not, stays unknown rather than added or removed. Metadata tokens remain build-local coordinates bound to each artifact SHA-256 and MVID, and the tuple digest does not itself remap them.

**Input schema (verbatim, JSON Schema 2020-12):**

<details><summary>inputSchema for compare_managed_members</summary>

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

**Output schema:** see [`tool-specs/compare_managed_members.json`](../tool-specs/compare_managed_members.json) (`outputSchema`).

---

## import_managed_reconstruction

<a id="importmanagedreconstruction"></a>

**Title:** Import Managed Reconstruction  
**Kind:** `application` · **Requires session:** true · **analysisOperation:** null  
**Providers:** rea-dotnet-workflows  
**Effects set (true flags):** mutatesSession  
**MCP annotations:** `{"destructiveHint":false,"idempotentHint":true,"openWorldHint":false,"readOnlyHint":false}`

**Description (verbatim, as advertised to the agent):**

> Import decompiler-produced managed reconstruction against authenticated inspect_managed_members Evidence. The workflow locks each method to artifact SHA-256, MVID, metadata token, signature hash, and the limited decoded-IL tuple hash, records the decompiler identity and options, and marks C# or pseudocode as analyst inference rather than canonical byte observation.

**Input schema (verbatim, JSON Schema 2020-12):**

<details><summary>inputSchema for import_managed_reconstruction</summary>

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "additionalProperties": false,
  "properties": {
    "decompiler": {
      "additionalProperties": false,
      "properties": {
        "executable_sha256": {
          "anyOf": [
            {
              "pattern": "^[a-f0-9]{64}$",
              "type": "string"
            },
            {
              "type": "null"
            }
          ],
          "default": null,
          "description": "Exact SHA-256 digest of executable."
        },
        "family": {
          "enum": [
            "ilspy",
            "dnspy",
            "dnlib",
            "mono-cecil",
            "other"
          ],
          "type": "string"
        },
        "name": {
          "description": "Exact name used by this operation.",
          "minLength": 1,
          "type": "string"
        },
        "options": {
          "default": [],
          "items": {
            "type": "string"
          },
          "type": "array"
        },
        "version": {
          "anyOf": [
            {
              "minLength": 1,
              "type": "string"
            },
            {
              "type": "null"
            }
          ],
          "default": null
        }
      },
      "required": [
        "name",
        "family"
      ],
      "type": "object"
    },
    "methods": {
      "items": {
        "additionalProperties": false,
        "properties": {
          "normalized_il_sha256": {
            "anyOf": [
              {
                "pattern": "^[a-f0-9]{64}$",
                "type": "string"
              },
              {
                "type": "null"
              }
            ],
            "description": "Exact SHA-256 digest of normalized il."
          },
          "reconstruction": {
            "additionalProperties": false,
            "properties": {
              "end_line": {
                "anyOf": [
                  {
                    "maximum": 9007199254740991,
                    "minimum": 1,
                    "type": "integer"
                  },
                  {
                    "type": "null"
                  }
                ]
              },
              "kind": {
                "enum": [
                  "decompiled-csharp",
                  "decompiled-il",
                  "semantic-pseudocode"
                ],
                "type": "string"
              },
              "language": {
                "enum": [
                  "csharp",
                  "il",
                  "pseudocode"
                ],
                "type": "string"
              },
              "source_path": {
                "anyOf": [
                  {
                    "minLength": 1,
                    "type": "string"
                  },
                  {
                    "type": "null"
                  }
                ],
                "description": "Local filesystem path for source."
              },
              "start_line": {
                "anyOf": [
                  {
                    "maximum": 9007199254740991,
                    "minimum": 1,
                    "type": "integer"
                  },
                  {
                    "type": "null"
                  }
                ]
              },
              "text": {
                "minLength": 1,
                "type": "string"
              },
              "text_sha256": {
                "description": "Exact SHA-256 digest of text.",
                "pattern": "^[a-f0-9]{64}$",
                "type": "string"
              }
            },
            "required": [
              "kind",
              "language",
              "text"
            ],
            "type": "object"
          },
          "signature_sha256": {
            "description": "Exact SHA-256 digest of signature.",
            "pattern": "^[a-f0-9]{64}$",
            "type": "string"
          },
          "token": {
            "pattern": "^0x[0-9a-f]{8}$",
            "type": "string"
          }
        },
        "required": [
          "token",
          "signature_sha256",
          "normalized_il_sha256",
          "reconstruction"
        ],
        "type": "object"
      },
      "minItems": 1,
      "type": "array"
    },
    "notes": {
      "default": [],
      "items": {
        "minLength": 1,
        "type": "string"
      },
      "type": "array"
    },
    "static_members": {
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
    }
  },
  "required": [
    "static_members",
    "decompiler",
    "methods"
  ],
  "type": "object"
}
```

</details>

**Output schema:** see [`tool-specs/import_managed_reconstruction.json`](../tool-specs/import_managed_reconstruction.json) (`outputSchema`).

---

## inspect_managed_artifact

<a id="inspectmanagedartifact"></a>

**Title:** Inspect Managed Artifact  
**Kind:** `managed-provider` · **Requires session:** false · **analysisOperation:** inspect_managed_artifact  
**Providers:** rea-dotnet-static  
**Effects set (true flags):** mutatesSession  
**MCP annotations:** `{"destructiveHint":false,"idempotentHint":true,"openWorldHint":false,"readOnlyHint":false}`

**Description (verbatim, as advertised to the agent):**

> Inspect an explicit PE/CLI path, or the selected managed target, without loading or executing target code. Omitted or complete detail returns complete metadata inventories with original coverage. Select detail: "summary" on the first call for complete identity, PE/CLI, classification with its evidence, module/MVID, assembly, frameworks, returned-collection counts, coverage/issues and limitations. It retains complete Evidence and returns a distinct linked inspect_analysis_view summary. Page original references/resources/attributes with view kind managed and normalized_result.parent_evidence_id. Counts cover producer-returned rows; partial, unavailable or malformed metadata remains explicit and tokens remain build-local.

**Input schema (verbatim, JSON Schema 2020-12):**

<details><summary>inputSchema for inspect_managed_artifact</summary>

```json
{
  "$defs": {
    "__schema0": {
      "description": "Explicit absolute managed PE/CLI path; omit to reuse the previously selected managed target",
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
      "path": "/tmp/Example.dll"
    },
    {
      "detail": "summary",
      "path": "/tmp/Example.dll"
    }
  ],
  "properties": {
    "detail": {
      "$ref": "#/$defs/__schema1"
    },
    "path": {
      "$ref": "#/$defs/__schema0",
      "description": "Explicit absolute managed PE/CLI path; omit to reuse the previously selected managed target"
    }
  },
  "type": "object"
}
```

</details>

**Output schema:** see [`tool-specs/inspect_managed_artifact.json`](../tool-specs/inspect_managed_artifact.json) (`outputSchema`).

---

## inspect_managed_members

<a id="inspectmanagedmembers"></a>

**Title:** Inspect Managed Members  
**Kind:** `managed-provider` · **Requires session:** false · **analysisOperation:** inspect_managed_members  
**Providers:** rea-dotnet-static  
**Effects set (true flags):** mutatesSession  
**MCP annotations:** `{"destructiveHint":false,"idempotentHint":true,"openWorldHint":false,"readOnlyHint":false}`

**Description (verbatim, as advertised to the agent):**

> Inspect PE/CLI metadata members, signatures, raw CIL hashes, decoded-instruction-tuple hashes, separately reported exception regions, call edges, field-access anchors, and the #US string literals that ldstr loads, without loading or executing target code. Select type_names to decode only the members of those exact declaring types and the literals their bodies load, which keeps large assemblies such as a base class library within the representation budget. Metadata tokens are reported as build-local coordinates bound to the artifact SHA-256 and MVID; the tuple hash does not resolve them or fully commit control flow. Omitted or complete detail returns every collection, including the assembly-wide member_refs and exported_types, which type_names does not narrow. Select detail: "summary" for identity, metadata status, selection with unmatched names, coverage/issues, limitations and per-collection counts; it retains complete Evidence and returns a linked inspect_analysis_view summary. Page original rows with view kind managed-members, normalized_result.parent_evidence_id and collection types/exported_types/fields/methods/member_refs/call_edges/field_accesses/user_strings.

**Input schema (verbatim, JSON Schema 2020-12):**

<details><summary>inputSchema for inspect_managed_members</summary>

```json
{
  "$defs": {
    "__schema0": {
      "description": "Explicit absolute managed PE/CLI path; omit to reuse the previously selected managed target",
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
    },
    "__schema2": {
      "description": "Inspect only the fields, methods, call edges, and field accesses declared by these exact type full names, and the user strings their method bodies load; omit to inspect every type. Unmatched names are reported in selection.unmatched_type_names.",
      "items": {
        "$ref": "#/$defs/__schema3"
      },
      "minItems": 1,
      "type": "array",
      "uniqueItems": true
    },
    "__schema3": {
      "description": "Exact declaring-type full_name: namespace-qualified for top-level types (System.Threading.Monitor); nested types report their bare name, so it selects every nested type of that name",
      "minLength": 1,
      "type": "string"
    }
  },
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "additionalProperties": false,
  "examples": [
    {},
    {
      "path": "/tmp/mscorlib.dll",
      "type_names": [
        "System.Threading.Monitor"
      ]
    },
    {
      "detail": "summary",
      "path": "/tmp/mscorlib.dll",
      "type_names": [
        "System.Threading.Monitor"
      ]
    }
  ],
  "properties": {
    "detail": {
      "$ref": "#/$defs/__schema1"
    },
    "path": {
      "$ref": "#/$defs/__schema0",
      "description": "Explicit absolute managed PE/CLI path; omit to reuse the previously selected managed target"
    },
    "type_names": {
      "$ref": "#/$defs/__schema2",
      "description": "Inspect only the fields, methods, call edges, and field accesses declared by these exact type full names, and the user strings their method bodies load; omit to inspect every type. Unmatched names are reported in selection.unmatched_type_names."
    }
  },
  "type": "object"
}
```

</details>

**Output schema:** see [`tool-specs/inspect_managed_members.json`](../tool-specs/inspect_managed_members.json) (`outputSchema`).

---

## inspect_managed_native_boundaries

<a id="inspectmanagednativeboundaries"></a>

**Title:** Inspect Managed Native Boundaries  
**Kind:** `managed-provider` · **Requires session:** false · **analysisOperation:** inspect_managed_native_boundaries  
**Providers:** rea-dotnet-static  
**Effects set (true flags):** mutatesSession  
**MCP annotations:** `{"destructiveHint":false,"idempotentHint":true,"openWorldHint":false,"readOnlyHint":false}`

**Description (verbatim, as advertised to the agent):**

> Inspect PE/CLI ModuleRef, ImplMap/PInvoke declarations, CLI native-header indicators, and non-IL method implementation flags without loading or executing target code. Results are managed declarations and degraded native-boundary observations, not verified native exports or addresses.

**Input schema (verbatim, JSON Schema 2020-12):**

<details><summary>inputSchema for inspect_managed_native_boundaries</summary>

```json
{
  "$defs": {
    "__schema0": {
      "description": "Explicit absolute managed PE/CLI path; omit to reuse the previously selected managed target",
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
    "path": {
      "$ref": "#/$defs/__schema0",
      "description": "Explicit absolute managed PE/CLI path; omit to reuse the previously selected managed target"
    }
  },
  "type": "object"
}
```

</details>

**Output schema:** see [`tool-specs/inspect_managed_native_boundaries.json`](../tool-specs/inspect_managed_native_boundaries.json) (`outputSchema`).

---

## project_managed_application_graph

<a id="projectmanagedapplicationgraph"></a>

**Title:** Project Managed Application Graph  
**Kind:** `application` · **Requires session:** true · **analysisOperation:** null  
**Providers:** rea-dotnet-workflows  
**Effects set (true flags):** mutatesSession  
**MCP annotations:** `{"destructiveHint":false,"idempotentHint":true,"openWorldHint":false,"readOnlyHint":false}`

**Description (verbatim, as advertised to the agent):**

> Project authenticated managed artifact, member, and native-boundary Evidence into the provider-neutral application graph without executing managed code, loading assemblies, or translating managed metadata tokens to native addresses. The graph preserves managed static observations as managed-specific nodes linked to source Evidence.

**Input schema (verbatim, JSON Schema 2020-12):**

<details><summary>inputSchema for project_managed_application_graph</summary>

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "additionalProperties": false,
  "description": "Provide a complete input group: managed_artifact + [managed_members] + [managed_native_boundaries]; managed_members + [managed_artifact] + [managed_native_boundaries]; managed_native_boundaries + [managed_artifact] + [managed_members].",
  "minProperties": 1,
  "properties": {
    "managed_artifact": {
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
    "managed_members": {
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
    "managed_native_boundaries": {
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
    }
  },
  "type": "object"
}
```

</details>

**Output schema:** see [`tool-specs/project_managed_application_graph.json`](../tool-specs/project_managed_application_graph.json) (`outputSchema`).

---

## verify_managed_native_boundaries

<a id="verifymanagednativeboundaries"></a>

**Title:** Verify Managed Native Boundaries  
**Kind:** `application` · **Requires session:** true · **analysisOperation:** null  
**Providers:** rea-dotnet-workflows  
**Effects set (true flags):** mutatesSession  
**MCP annotations:** `{"destructiveHint":false,"idempotentHint":true,"openWorldHint":false,"readOnlyHint":false}`

**Description (verbatim, as advertised to the agent):**

> Verify managed P/Invoke/native-boundary declarations against authenticated native export or function Evidence without executing managed code or translating managed metadata tokens into native addresses. The workflow preserves declaration-only, verified, inferred, contradicted, and unresolved states; a name candidate with missing managed or native module identity remains unresolved with its candidate evidence retained.

**Input schema (verbatim, JSON Schema 2020-12):**

<details><summary>inputSchema for verify_managed_native_boundaries</summary>

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "additionalProperties": false,
  "properties": {
    "managed_boundaries": {
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
    "native_observations": {
      "description": "Native function or export Evidence records",
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
    "managed_boundaries",
    "native_observations"
  ],
  "type": "object"
}
```

</details>

**Output schema:** see [`tool-specs/verify_managed_native_boundaries.json`](../tool-specs/verify_managed_native_boundaries.json) (`outputSchema`).

---

