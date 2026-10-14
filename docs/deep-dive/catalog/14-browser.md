# Tool family: Browser observation

Generated mechanically from `.cache/mcp-tool-catalog.json` (produced by `scripts/generate-mcp-tool-catalog.mjs`, which registers every tool through the MCP SDK and exports the advertised JSON Schema 2020-12 input/output schemas) and `docs/public/product-catalog.json` (family `browser`, surface `browser-provider`, 12 tools). Input schemas below are **verbatim**. Output schemas are verbatim in `tool-specs/<tool>.json` (field `outputSchema`) because several exceed 100 KB; the complete per-tool spec (description, effects, annotations, inputSchema, outputSchema) is in that file.

| Tool | Kind | Session? | Providers advertising it | CLI command |
|---|---|---|---|---|
| [`analyze_web_bundle`](#analyzewebbundle) | browser-provider | no | rea-cdp-browser | `rea analyze-web-bundle` |
| [`capture_browser_scenario`](#capturebrowserscenario) | browser-provider | no | rea-playwright-browser-scenario | `rea capture-browser-scenario` |
| [`capture_web_screenshot`](#capturewebscreenshot) | browser-provider | no | rea-cdp-browser | `rea capture-web-screenshot` |
| [`compare_web_captures`](#comparewebcaptures) | browser-provider | no | rea-cdp-browser | `rea compare-web-captures` |
| [`compare_web_screenshots`](#comparewebscreenshots) | browser-provider | no | rea-cdp-browser | `rea compare-web-screenshots` |
| [`discover_webmcp_tools`](#discoverwebmcptools) | browser-provider | no | rea-cdp-browser | `rea discover-webmcp-tools` |
| [`inspect_web_event_listeners`](#inspectwebeventlisteners) | browser-provider | no | rea-cdp-browser | `rea inspect-web-event-listeners` |
| [`inspect_web_network_capture`](#inspectwebnetworkcapture) | browser-provider | no | fiddler-saz, har-schema/lossless-json, mitmproxy-native-tnetstring | `rea inspect-web-network-capture` |
| [`inspect_web_page`](#inspectwebpage) | browser-provider | no | rea-cdp-browser | `rea inspect-web-page` |
| [`list_browser_targets`](#listbrowsertargets) | browser-provider | no | rea-cdp-browser | `rea list-browser-targets` |
| [`observe_web_execution`](#observewebexecution) | browser-provider | no | rea-cdp-browser | `rea observe-web-execution` |
| [`observe_web_session`](#observewebsession) | browser-provider | no | rea-cdp-browser | `rea observe-web-session` |

## analyze_web_bundle

<a id="analyzewebbundle"></a>

**Title:** Analyze Web Bundle  
**Kind:** `browser-provider` · **Requires session:** false · **analysisOperation:** null  
**Providers:** rea-cdp-browser  
**Effects set (true flags):** accessesNetwork, mutatesSession  
**MCP annotations:** `{"destructiveHint":false,"idempotentHint":true,"openWorldHint":true,"readOnlyHint":false}`

**Description (verbatim, as advertised to the agent):**

> Capture JavaScript source from one selected CDP page and statically derive a chunk graph, route and endpoint candidates, vendor fingerprints, page-declared WebMCP metadata, and optionally fetch source maps from the selected target origin or explicitly requested origins. JavaScript is parsed but never executed.

**Input schema (verbatim, JSON Schema 2020-12):**

<details><summary>inputSchema for analyze_web_bundle</summary>

```json
{
  "$defs": {
    "__schema0": {
      "description": "Literal loopback CDP endpoint: http://127.0.0.1:PORT, or ws://127.0.0.1:PORT/devtools/browser/ID.",
      "minLength": 1,
      "type": "string"
    },
    "__schema1": {
      "items": {
        "minLength": 1,
        "type": "string"
      },
      "type": "array"
    },
    "__schema10": {
      "const": true,
      "default": true,
      "type": "boolean"
    },
    "__schema11": {
      "default": false,
      "type": "boolean"
    },
    "__schema2": {
      "minLength": 1,
      "type": "string"
    },
    "__schema3": {
      "default": 500,
      "maximum": 9007199254740991,
      "minimum": 0,
      "type": "integer"
    },
    "__schema4": {
      "default": false,
      "type": "boolean"
    },
    "__schema5": {
      "default": false,
      "type": "boolean"
    },
    "__schema6": {
      "default": false,
      "type": "boolean"
    },
    "__schema7": {
      "default": false,
      "type": "boolean"
    },
    "__schema8": {
      "default": false,
      "type": "boolean"
    },
    "__schema9": {
      "default": false,
      "type": "boolean"
    }
  },
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "additionalProperties": false,
  "examples": [
    {
      "cdp_endpoint": "http://127.0.0.1:9222",
      "fetch_source_maps": false,
      "include_accessibility_text": false,
      "include_script_sources": true,
      "include_storage_keys": false,
      "observation_ms": 500,
      "target_id": "TARGET_ID_FROM_LIST_BROWSER_TARGETS"
    }
  ],
  "properties": {
    "allowed_origins": {
      "$ref": "#/$defs/__schema1"
    },
    "cdp_endpoint": {
      "$ref": "#/$defs/__schema0",
      "description": "Literal loopback CDP endpoint: http://127.0.0.1:PORT, or ws://127.0.0.1:PORT/devtools/browser/ID."
    },
    "fetch_source_maps": {
      "$ref": "#/$defs/__schema11"
    },
    "include_accessibility_text": {
      "$ref": "#/$defs/__schema4",
      "description": "Whether to include accessibility text in the result."
    },
    "include_console_text": {
      "$ref": "#/$defs/__schema5",
      "description": "Whether to include console text in the result."
    },
    "include_json_body_shapes": {
      "$ref": "#/$defs/__schema6",
      "description": "Whether to include json body shapes in the result."
    },
    "include_script_sources": {
      "$ref": "#/$defs/__schema10",
      "description": "Whether to include script sources in the result."
    },
    "include_storage_fingerprints": {
      "$ref": "#/$defs/__schema9",
      "description": "Whether to include storage fingerprints in the result."
    },
    "include_storage_keys": {
      "$ref": "#/$defs/__schema8",
      "description": "Whether to include storage keys in the result."
    },
    "include_websocket_shapes": {
      "$ref": "#/$defs/__schema7",
      "description": "Whether to include websocket shapes in the result."
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

**Output schema:** see [`tool-specs/analyze_web_bundle.json`](../tool-specs/analyze_web_bundle.json) (`outputSchema`).

---

## capture_browser_scenario

<a id="capturebrowserscenario"></a>

**Title:** Capture Browser Scenario  
**Kind:** `browser-provider` · **Requires session:** false · **analysisOperation:** null  
**Providers:** rea-playwright-browser-scenario  
**Effects set (true flags):** accessesNetwork, changesUiState, executesForeignCode, NOT idempotent, launchesProcess, mayDiscardData, mutatesSession, mutatesTarget, writesFilesystem  
**MCP annotations:** `{"destructiveHint":true,"idempotentHint":false,"openWorldHint":true,"readOnlyHint":false}`

**Description (verbatim, as advertised to the agent):**

> Run a controlled browser scenario when passive observation cannot exercise the application. Launch the selected executable or connect to a loopback CDP target, provide a start URL and actions, and select storage or artifacts when needed. Environment, empty storage, and a URL-only final capture are defaults. capture.network selects request_body, response_body, and header_values independently; selected content is returned inline with transaction and event references, byte digests, and explicit unavailable states. Credentials and declared secrets are redacted. Agents can run their own local fixture servers to control application responses. Actions run until completion or cancellation unless timeout_ms is set. Results are returned inline.

**Input schema (verbatim, JSON Schema 2020-12):**

<details><summary>inputSchema for capture_browser_scenario</summary>

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "additionalProperties": false,
  "examples": [
    {
      "actions": [
        {
          "action": "wait_for_timeout",
          "duration_ms": 250,
          "step_id": "settle"
        }
      ],
      "browser": {
        "executable_path": "/opt/chromium/chrome",
        "mode": "launch"
      },
      "start_url": {
        "query": [],
        "url": "https://app.example.test/"
      }
    }
  ],
  "properties": {
    "actions": {
      "description": "Required sequence of explicit browser actions.",
      "items": {
        "oneOf": [
          {
            "additionalProperties": false,
            "properties": {
              "action": {
                "const": "goto",
                "type": "string"
              },
              "destination": {
                "additionalProperties": false,
                "properties": {
                  "query": {
                    "default": [],
                    "description": "Non-empty feature or text query to investigate.",
                    "items": {
                      "additionalProperties": false,
                      "properties": {
                        "name": {
                          "description": "Exact name used by this operation.",
                          "minLength": 1,
                          "type": "string"
                        },
                        "value": {
                          "oneOf": [
                            {
                              "additionalProperties": false,
                              "properties": {
                                "source": {
                                  "const": "literal",
                                  "type": "string"
                                },
                                "value": {
                                  "type": "string"
                                }
                              },
                              "required": [
                                "source",
                                "value"
                              ],
                              "type": "object"
                            },
                            {
                              "additionalProperties": false,
                              "properties": {
                                "secret_id": {
                                  "pattern": "^[A-Za-z][A-Za-z0-9._\\x2d]*$",
                                  "type": "string"
                                },
                                "source": {
                                  "const": "secret",
                                  "type": "string"
                                }
                              },
                              "required": [
                                "source",
                                "secret_id"
                              ],
                              "type": "object"
                            }
                          ]
                        }
                      },
                      "required": [
                        "name",
                        "value"
                      ],
                      "type": "object"
                    },
                    "type": "array"
                  },
                  "url": {
                    "minLength": 1,
                    "type": "string"
                  }
                },
                "required": [
                  "url"
                ],
                "type": "object"
              },
              "step_id": {
                "pattern": "^[A-Za-z][A-Za-z0-9._\\x2d]*$",
                "type": "string"
              },
              "timeout_ms": {
                "description": "Optional action deadline in milliseconds; omitted means wait until completion or request cancellation.",
                "maximum": 9007199254740991,
                "minimum": 1,
                "type": "integer"
              },
              "wait_until": {
                "enum": [
                  "commit",
                  "domcontentloaded",
                  "load"
                ],
                "type": "string"
              }
            },
            "required": [
              "step_id",
              "action",
              "destination",
              "wait_until"
            ],
            "type": "object"
          },
          {
            "additionalProperties": false,
            "properties": {
              "action": {
                "const": "click",
                "type": "string"
              },
              "button": {
                "default": "left",
                "enum": [
                  "left",
                  "middle",
                  "right"
                ],
                "type": "string"
              },
              "click_count": {
                "default": 1,
                "exclusiveMinimum": 0,
                "maximum": 9007199254740991,
                "type": "integer"
              },
              "locator": {
                "oneOf": [
                  {
                    "additionalProperties": false,
                    "properties": {
                      "kind": {
                        "const": "test_id",
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
                        "const": "role",
                        "type": "string"
                      },
                      "name": {
                        "description": "Exact name used by this operation.",
                        "minLength": 1,
                        "type": "string"
                      },
                      "role": {
                        "enum": [
                          "button",
                          "checkbox",
                          "combobox",
                          "dialog",
                          "link",
                          "listbox",
                          "menuitem",
                          "option",
                          "radio",
                          "slider",
                          "spinbutton",
                          "switch",
                          "tab",
                          "textbox"
                        ],
                        "type": "string"
                      }
                    },
                    "required": [
                      "kind",
                      "role",
                      "name"
                    ],
                    "type": "object"
                  },
                  {
                    "additionalProperties": false,
                    "properties": {
                      "kind": {
                        "const": "css",
                        "type": "string"
                      },
                      "selector": {
                        "minLength": 1,
                        "type": "string"
                      }
                    },
                    "required": [
                      "kind",
                      "selector"
                    ],
                    "type": "object"
                  }
                ]
              },
              "step_id": {
                "pattern": "^[A-Za-z][A-Za-z0-9._\\x2d]*$",
                "type": "string"
              },
              "timeout_ms": {
                "description": "Optional action deadline in milliseconds; omitted means wait until completion or request cancellation.",
                "maximum": 9007199254740991,
                "minimum": 1,
                "type": "integer"
              }
            },
            "required": [
              "step_id",
              "action",
              "locator"
            ],
            "type": "object"
          },
          {
            "additionalProperties": false,
            "properties": {
              "action": {
                "const": "fill",
                "type": "string"
              },
              "locator": {
                "oneOf": [
                  {
                    "additionalProperties": false,
                    "properties": {
                      "kind": {
                        "const": "test_id",
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
                        "const": "role",
                        "type": "string"
                      },
                      "name": {
                        "description": "Exact name used by this operation.",
                        "minLength": 1,
                        "type": "string"
                      },
                      "role": {
                        "enum": [
                          "button",
                          "checkbox",
                          "combobox",
                          "dialog",
                          "link",
                          "listbox",
                          "menuitem",
                          "option",
                          "radio",
                          "slider",
                          "spinbutton",
                          "switch",
                          "tab",
                          "textbox"
                        ],
                        "type": "string"
                      }
                    },
                    "required": [
                      "kind",
                      "role",
                      "name"
                    ],
                    "type": "object"
                  },
                  {
                    "additionalProperties": false,
                    "properties": {
                      "kind": {
                        "const": "css",
                        "type": "string"
                      },
                      "selector": {
                        "minLength": 1,
                        "type": "string"
                      }
                    },
                    "required": [
                      "kind",
                      "selector"
                    ],
                    "type": "object"
                  }
                ]
              },
              "step_id": {
                "pattern": "^[A-Za-z][A-Za-z0-9._\\x2d]*$",
                "type": "string"
              },
              "timeout_ms": {
                "description": "Optional action deadline in milliseconds; omitted means wait until completion or request cancellation.",
                "maximum": 9007199254740991,
                "minimum": 1,
                "type": "integer"
              },
              "value": {
                "oneOf": [
                  {
                    "additionalProperties": false,
                    "properties": {
                      "source": {
                        "const": "literal",
                        "type": "string"
                      },
                      "value": {
                        "type": "string"
                      }
                    },
                    "required": [
                      "source",
                      "value"
                    ],
                    "type": "object"
                  },
                  {
                    "additionalProperties": false,
                    "properties": {
                      "secret_id": {
                        "pattern": "^[A-Za-z][A-Za-z0-9._\\x2d]*$",
                        "type": "string"
                      },
                      "source": {
                        "const": "secret",
                        "type": "string"
                      }
                    },
                    "required": [
                      "source",
                      "secret_id"
                    ],
                    "type": "object"
                  }
                ]
              }
            },
            "required": [
              "step_id",
              "action",
              "locator",
              "value"
            ],
            "type": "object"
          },
          {
            "additionalProperties": false,
            "properties": {
              "action": {
                "const": "press",
                "type": "string"
              },
              "key": {
                "minLength": 1,
                "type": "string"
              },
              "locator": {
                "oneOf": [
                  {
                    "additionalProperties": false,
                    "properties": {
                      "kind": {
                        "const": "test_id",
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
                        "const": "role",
                        "type": "string"
                      },
                      "name": {
                        "description": "Exact name used by this operation.",
                        "minLength": 1,
                        "type": "string"
                      },
                      "role": {
                        "enum": [
                          "button",
                          "checkbox",
                          "combobox",
                          "dialog",
                          "link",
                          "listbox",
                          "menuitem",
                          "option",
                          "radio",
                          "slider",
                          "spinbutton",
                          "switch",
                          "tab",
                          "textbox"
                        ],
                        "type": "string"
                      }
                    },
                    "required": [
                      "kind",
                      "role",
                      "name"
                    ],
                    "type": "object"
                  },
                  {
                    "additionalProperties": false,
                    "properties": {
                      "kind": {
                        "const": "css",
                        "type": "string"
                      },
                      "selector": {
                        "minLength": 1,
                        "type": "string"
                      }
                    },
                    "required": [
                      "kind",
                      "selector"
                    ],
                    "type": "object"
                  }
                ]
              },
              "step_id": {
                "pattern": "^[A-Za-z][A-Za-z0-9._\\x2d]*$",
                "type": "string"
              },
              "timeout_ms": {
                "description": "Optional action deadline in milliseconds; omitted means wait until completion or request cancellation.",
                "maximum": 9007199254740991,
                "minimum": 1,
                "type": "integer"
              }
            },
            "required": [
              "step_id",
              "action",
              "locator",
              "key"
            ],
            "type": "object"
          },
          {
            "additionalProperties": false,
            "properties": {
              "action": {
                "const": "select_option",
                "type": "string"
              },
              "locator": {
                "oneOf": [
                  {
                    "additionalProperties": false,
                    "properties": {
                      "kind": {
                        "const": "test_id",
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
                        "const": "role",
                        "type": "string"
                      },
                      "name": {
                        "description": "Exact name used by this operation.",
                        "minLength": 1,
                        "type": "string"
                      },
                      "role": {
                        "enum": [
                          "button",
                          "checkbox",
                          "combobox",
                          "dialog",
                          "link",
                          "listbox",
                          "menuitem",
                          "option",
                          "radio",
                          "slider",
                          "spinbutton",
                          "switch",
                          "tab",
                          "textbox"
                        ],
                        "type": "string"
                      }
                    },
                    "required": [
                      "kind",
                      "role",
                      "name"
                    ],
                    "type": "object"
                  },
                  {
                    "additionalProperties": false,
                    "properties": {
                      "kind": {
                        "const": "css",
                        "type": "string"
                      },
                      "selector": {
                        "minLength": 1,
                        "type": "string"
                      }
                    },
                    "required": [
                      "kind",
                      "selector"
                    ],
                    "type": "object"
                  }
                ]
              },
              "step_id": {
                "pattern": "^[A-Za-z][A-Za-z0-9._\\x2d]*$",
                "type": "string"
              },
              "timeout_ms": {
                "description": "Optional action deadline in milliseconds; omitted means wait until completion or request cancellation.",
                "maximum": 9007199254740991,
                "minimum": 1,
                "type": "integer"
              },
              "value": {
                "oneOf": [
                  {
                    "additionalProperties": false,
                    "properties": {
                      "source": {
                        "const": "literal",
                        "type": "string"
                      },
                      "value": {
                        "type": "string"
                      }
                    },
                    "required": [
                      "source",
                      "value"
                    ],
                    "type": "object"
                  },
                  {
                    "additionalProperties": false,
                    "properties": {
                      "secret_id": {
                        "pattern": "^[A-Za-z][A-Za-z0-9._\\x2d]*$",
                        "type": "string"
                      },
                      "source": {
                        "const": "secret",
                        "type": "string"
                      }
                    },
                    "required": [
                      "source",
                      "secret_id"
                    ],
                    "type": "object"
                  }
                ]
              }
            },
            "required": [
              "step_id",
              "action",
              "locator",
              "value"
            ],
            "type": "object"
          },
          {
            "additionalProperties": false,
            "properties": {
              "action": {
                "enum": [
                  "check",
                  "uncheck"
                ],
                "type": "string"
              },
              "locator": {
                "oneOf": [
                  {
                    "additionalProperties": false,
                    "properties": {
                      "kind": {
                        "const": "test_id",
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
                        "const": "role",
                        "type": "string"
                      },
                      "name": {
                        "description": "Exact name used by this operation.",
                        "minLength": 1,
                        "type": "string"
                      },
                      "role": {
                        "enum": [
                          "button",
                          "checkbox",
                          "combobox",
                          "dialog",
                          "link",
                          "listbox",
                          "menuitem",
                          "option",
                          "radio",
                          "slider",
                          "spinbutton",
                          "switch",
                          "tab",
                          "textbox"
                        ],
                        "type": "string"
                      }
                    },
                    "required": [
                      "kind",
                      "role",
                      "name"
                    ],
                    "type": "object"
                  },
                  {
                    "additionalProperties": false,
                    "properties": {
                      "kind": {
                        "const": "css",
                        "type": "string"
                      },
                      "selector": {
                        "minLength": 1,
                        "type": "string"
                      }
                    },
                    "required": [
                      "kind",
                      "selector"
                    ],
                    "type": "object"
                  }
                ]
              },
              "step_id": {
                "pattern": "^[A-Za-z][A-Za-z0-9._\\x2d]*$",
                "type": "string"
              },
              "timeout_ms": {
                "description": "Optional action deadline in milliseconds; omitted means wait until completion or request cancellation.",
                "maximum": 9007199254740991,
                "minimum": 1,
                "type": "integer"
              }
            },
            "required": [
              "step_id",
              "action",
              "locator"
            ],
            "type": "object"
          },
          {
            "additionalProperties": false,
            "properties": {
              "action": {
                "const": "wait_for",
                "type": "string"
              },
              "locator": {
                "oneOf": [
                  {
                    "additionalProperties": false,
                    "properties": {
                      "kind": {
                        "const": "test_id",
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
                        "const": "role",
                        "type": "string"
                      },
                      "name": {
                        "description": "Exact name used by this operation.",
                        "minLength": 1,
                        "type": "string"
                      },
                      "role": {
                        "enum": [
                          "button",
                          "checkbox",
                          "combobox",
                          "dialog",
                          "link",
                          "listbox",
                          "menuitem",
                          "option",
                          "radio",
                          "slider",
                          "spinbutton",
                          "switch",
                          "tab",
                          "textbox"
                        ],
                        "type": "string"
                      }
                    },
                    "required": [
                      "kind",
                      "role",
                      "name"
                    ],
                    "type": "object"
                  },
                  {
                    "additionalProperties": false,
                    "properties": {
                      "kind": {
                        "const": "css",
                        "type": "string"
                      },
                      "selector": {
                        "minLength": 1,
                        "type": "string"
                      }
                    },
                    "required": [
                      "kind",
                      "selector"
                    ],
                    "type": "object"
                  }
                ]
              },
              "state": {
                "enum": [
                  "attached",
                  "detached",
                  "visible",
                  "hidden"
                ],
                "type": "string"
              },
              "step_id": {
                "pattern": "^[A-Za-z][A-Za-z0-9._\\x2d]*$",
                "type": "string"
              },
              "timeout_ms": {
                "description": "Optional action deadline in milliseconds; omitted means wait until completion or request cancellation.",
                "maximum": 9007199254740991,
                "minimum": 1,
                "type": "integer"
              }
            },
            "required": [
              "step_id",
              "action",
              "locator",
              "state"
            ],
            "type": "object"
          },
          {
            "additionalProperties": false,
            "properties": {
              "action": {
                "const": "wait_for_timeout",
                "type": "string"
              },
              "duration_ms": {
                "description": "Wait this many milliseconds; the wait ends early on cancellation.",
                "maximum": 9007199254740991,
                "minimum": 1,
                "type": "integer"
              },
              "step_id": {
                "pattern": "^[A-Za-z][A-Za-z0-9._\\x2d]*$",
                "type": "string"
              }
            },
            "required": [
              "step_id",
              "action",
              "duration_ms"
            ],
            "type": "object"
          }
        ]
      },
      "minItems": 1,
      "type": "array"
    },
    "browser": {
      "description": "Required launch/connect selection. Launch uses the selected executable and an owned temporary profile; connect uses one loopback CDP endpoint and target.",
      "oneOf": [
        {
          "additionalProperties": false,
          "properties": {
            "executable_path": {
              "description": "Absolute local filesystem path for the browser executable; relative paths are rejected.",
              "minLength": 1,
              "pattern": "^[^\\x00]*$",
              "type": "string"
            },
            "headless": {
              "default": true,
              "description": "Run without a visible browser window; defaults to true and can be disabled when the host supports a display.",
              "type": "boolean"
            },
            "mode": {
              "const": "launch",
              "description": "Operation mode that selects the requested behavior.",
              "type": "string"
            }
          },
          "required": [
            "mode",
            "executable_path"
          ],
          "type": "object"
        },
        {
          "additionalProperties": false,
          "properties": {
            "cdp_endpoint": {
              "description": "Literal loopback Chrome DevTools Protocol endpoint.",
              "minLength": 1,
              "type": "string"
            },
            "mode": {
              "const": "connect",
              "description": "Operation mode that selects the requested behavior.",
              "type": "string"
            },
            "target_id": {
              "description": "Exact CDP target identifier selected from the endpoint's target listing.",
              "minLength": 1,
              "type": "string"
            }
          },
          "required": [
            "mode",
            "cdp_endpoint",
            "target_id"
          ],
          "type": "object"
        }
      ]
    },
    "capture": {
      "additionalProperties": false,
      "default": {
        "after_each_step": [],
        "at_end": [
          "url"
        ],
        "events": [],
        "network": {
          "header_values": false,
          "request_body": false,
          "response_body": false
        }
      },
      "description": "Optional retained artifacts and event families. Defaults to only a final sanitized URL; request screenshots, DOM, accessibility, history, storage, and event capture explicitly.",
      "properties": {
        "after_each_step": {
          "default": [],
          "items": {
            "enum": [
              "screenshot",
              "dom",
              "accessibility",
              "url",
              "history",
              "storage"
            ],
            "type": "string"
          },
          "type": "array"
        },
        "at_end": {
          "default": [
            "url"
          ],
          "items": {
            "enum": [
              "screenshot",
              "dom",
              "accessibility",
              "url",
              "history",
              "storage"
            ],
            "type": "string"
          },
          "type": "array"
        },
        "events": {
          "default": [],
          "items": {
            "enum": [
              "console",
              "page-errors",
              "network",
              "websockets",
              "frames",
              "workers",
              "popups",
              "downloads"
            ],
            "type": "string"
          },
          "type": "array"
        },
        "network": {
          "additionalProperties": false,
          "default": {
            "header_values": false,
            "request_body": false,
            "response_body": false
          },
          "properties": {
            "header_values": {
              "default": false,
              "type": "boolean"
            },
            "request_body": {
              "default": false,
              "type": "boolean"
            },
            "response_body": {
              "default": false,
              "type": "boolean"
            }
          },
          "type": "object"
        }
      },
      "type": "object"
    },
    "environment": {
      "additionalProperties": false,
      "default": {
        "color_scheme": "light",
        "locale": "en-US",
        "reduced_motion": "reduce",
        "service_workers": "block",
        "timezone": "UTC",
        "viewport": {
          "device_scale_factor": 1,
          "height": 720,
          "width": 1280
        }
      },
      "description": "Optional deterministic browser settings. Defaults to 1280x720, en-US, UTC, light mode, reduced motion, and blocked service workers.",
      "properties": {
        "color_scheme": {
          "default": "light",
          "enum": [
            "light",
            "dark",
            "no-preference"
          ],
          "type": "string"
        },
        "locale": {
          "default": "en-US",
          "minLength": 2,
          "pattern": "^[A-Za-z0-9]+(?:-[A-Za-z0-9]+)*$",
          "type": "string"
        },
        "reduced_motion": {
          "default": "reduce",
          "enum": [
            "reduce",
            "no-preference"
          ],
          "type": "string"
        },
        "service_workers": {
          "default": "block",
          "enum": [
            "allow",
            "block"
          ],
          "type": "string"
        },
        "timezone": {
          "default": "UTC",
          "minLength": 1,
          "pattern": "^[A-Za-z0-9_+\\x2d]+(?:\\x2f[A-Za-z0-9_+\\x2d]+)*$",
          "type": "string"
        },
        "viewport": {
          "additionalProperties": false,
          "default": {
            "device_scale_factor": 1,
            "height": 720,
            "width": 1280
          },
          "properties": {
            "device_scale_factor": {
              "default": 1,
              "exclusiveMinimum": 0,
              "type": "number"
            },
            "height": {
              "default": 720,
              "exclusiveMinimum": 0,
              "maximum": 9007199254740991,
              "type": "integer"
            },
            "width": {
              "default": 1280,
              "exclusiveMinimum": 0,
              "maximum": 9007199254740991,
              "type": "integer"
            }
          },
          "type": "object"
        }
      },
      "type": "object"
    },
    "secrets": {
      "default": [],
      "description": "Optional environment-variable references for values used in actions, URLs, storage, or replay, and for redacting matching observed text. Secret values are never supplied inline.",
      "items": {
        "additionalProperties": false,
        "properties": {
          "environment_variable": {
            "minLength": 1,
            "type": "string"
          },
          "secret_id": {
            "pattern": "^[A-Za-z][A-Za-z0-9._\\x2d]*$",
            "type": "string"
          }
        },
        "required": [
          "secret_id",
          "environment_variable"
        ],
        "type": "object"
      },
      "type": "array"
    },
    "start_url": {
      "additionalProperties": false,
      "description": "Required initial HTTP(S) URL. Query values must be declared separately as public literals or secret references.",
      "properties": {
        "query": {
          "default": [],
          "description": "Non-empty feature or text query to investigate.",
          "items": {
            "additionalProperties": false,
            "properties": {
              "name": {
                "description": "Exact name used by this operation.",
                "minLength": 1,
                "type": "string"
              },
              "value": {
                "oneOf": [
                  {
                    "additionalProperties": false,
                    "properties": {
                      "source": {
                        "const": "literal",
                        "type": "string"
                      },
                      "value": {
                        "type": "string"
                      }
                    },
                    "required": [
                      "source",
                      "value"
                    ],
                    "type": "object"
                  },
                  {
                    "additionalProperties": false,
                    "properties": {
                      "secret_id": {
                        "pattern": "^[A-Za-z][A-Za-z0-9._\\x2d]*$",
                        "type": "string"
                      },
                      "source": {
                        "const": "secret",
                        "type": "string"
                      }
                    },
                    "required": [
                      "source",
                      "secret_id"
                    ],
                    "type": "object"
                  }
                ]
              }
            },
            "required": [
              "name",
              "value"
            ],
            "type": "object"
          },
          "type": "array"
        },
        "url": {
          "minLength": 1,
          "type": "string"
        }
      },
      "required": [
        "url"
      ],
      "type": "object"
    },
    "storage": {
      "additionalProperties": false,
      "description": "Optional initial cookies, local storage, or session storage. Defaults to empty; every supplied value and origin must be declared and within the allowed origins.",
      "properties": {
        "cookies": {
          "items": {
            "additionalProperties": false,
            "properties": {
              "destination": {
                "additionalProperties": false,
                "properties": {
                  "query": {
                    "default": [],
                    "description": "Non-empty feature or text query to investigate.",
                    "items": {
                      "additionalProperties": false,
                      "properties": {
                        "name": {
                          "description": "Exact name used by this operation.",
                          "minLength": 1,
                          "type": "string"
                        },
                        "value": {
                          "oneOf": [
                            {
                              "additionalProperties": false,
                              "properties": {
                                "source": {
                                  "const": "literal",
                                  "type": "string"
                                },
                                "value": {
                                  "type": "string"
                                }
                              },
                              "required": [
                                "source",
                                "value"
                              ],
                              "type": "object"
                            },
                            {
                              "additionalProperties": false,
                              "properties": {
                                "secret_id": {
                                  "pattern": "^[A-Za-z][A-Za-z0-9._\\x2d]*$",
                                  "type": "string"
                                },
                                "source": {
                                  "const": "secret",
                                  "type": "string"
                                }
                              },
                              "required": [
                                "source",
                                "secret_id"
                              ],
                              "type": "object"
                            }
                          ]
                        }
                      },
                      "required": [
                        "name",
                        "value"
                      ],
                      "type": "object"
                    },
                    "type": "array"
                  },
                  "url": {
                    "minLength": 1,
                    "type": "string"
                  }
                },
                "required": [
                  "url"
                ],
                "type": "object"
              },
              "http_only": {
                "type": "boolean"
              },
              "name": {
                "description": "Exact name used by this operation.",
                "minLength": 1,
                "type": "string"
              },
              "same_site": {
                "enum": [
                  "Strict",
                  "Lax",
                  "None"
                ],
                "type": "string"
              },
              "secure": {
                "type": "boolean"
              },
              "value": {
                "oneOf": [
                  {
                    "additionalProperties": false,
                    "properties": {
                      "source": {
                        "const": "literal",
                        "type": "string"
                      },
                      "value": {
                        "type": "string"
                      }
                    },
                    "required": [
                      "source",
                      "value"
                    ],
                    "type": "object"
                  },
                  {
                    "additionalProperties": false,
                    "properties": {
                      "secret_id": {
                        "pattern": "^[A-Za-z][A-Za-z0-9._\\x2d]*$",
                        "type": "string"
                      },
                      "source": {
                        "const": "secret",
                        "type": "string"
                      }
                    },
                    "required": [
                      "source",
                      "secret_id"
                    ],
                    "type": "object"
                  }
                ]
              }
            },
            "required": [
              "name",
              "value",
              "destination",
              "http_only",
              "secure",
              "same_site"
            ],
            "type": "object"
          },
          "type": "array"
        },
        "local_storage": {
          "items": {
            "additionalProperties": false,
            "properties": {
              "entries": {
                "items": {
                  "additionalProperties": false,
                  "properties": {
                    "name": {
                      "description": "Exact name used by this operation.",
                      "minLength": 1,
                      "type": "string"
                    },
                    "value": {
                      "oneOf": [
                        {
                          "additionalProperties": false,
                          "properties": {
                            "source": {
                              "const": "literal",
                              "type": "string"
                            },
                            "value": {
                              "type": "string"
                            }
                          },
                          "required": [
                            "source",
                            "value"
                          ],
                          "type": "object"
                        },
                        {
                          "additionalProperties": false,
                          "properties": {
                            "secret_id": {
                              "pattern": "^[A-Za-z][A-Za-z0-9._\\x2d]*$",
                              "type": "string"
                            },
                            "source": {
                              "const": "secret",
                              "type": "string"
                            }
                          },
                          "required": [
                            "source",
                            "secret_id"
                          ],
                          "type": "object"
                        }
                      ]
                    }
                  },
                  "required": [
                    "name",
                    "value"
                  ],
                  "type": "object"
                },
                "type": "array"
              },
              "origin": {
                "minLength": 1,
                "type": "string"
              }
            },
            "required": [
              "origin",
              "entries"
            ],
            "type": "object"
          },
          "type": "array"
        },
        "session_storage": {
          "items": {
            "additionalProperties": false,
            "properties": {
              "entries": {
                "items": {
                  "additionalProperties": false,
                  "properties": {
                    "name": {
                      "description": "Exact name used by this operation.",
                      "minLength": 1,
                      "type": "string"
                    },
                    "value": {
                      "oneOf": [
                        {
                          "additionalProperties": false,
                          "properties": {
                            "source": {
                              "const": "literal",
                              "type": "string"
                            },
                            "value": {
                              "type": "string"
                            }
                          },
                          "required": [
                            "source",
                            "value"
                          ],
                          "type": "object"
                        },
                        {
                          "additionalProperties": false,
                          "properties": {
                            "secret_id": {
                              "pattern": "^[A-Za-z][A-Za-z0-9._\\x2d]*$",
                              "type": "string"
                            },
                            "source": {
                              "const": "secret",
                              "type": "string"
                            }
                          },
                          "required": [
                            "source",
                            "secret_id"
                          ],
                          "type": "object"
                        }
                      ]
                    }
                  },
                  "required": [
                    "name",
                    "value"
                  ],
                  "type": "object"
                },
                "type": "array"
              },
              "origin": {
                "minLength": 1,
                "type": "string"
              }
            },
            "required": [
              "origin",
              "entries"
            ],
            "type": "object"
          },
          "type": "array"
        }
      },
      "type": "object"
    }
  },
  "required": [
    "browser",
    "start_url",
    "actions"
  ],
  "type": "object"
}
```

</details>

**Output schema:** see [`tool-specs/capture_browser_scenario.json`](../tool-specs/capture_browser_scenario.json) (`outputSchema`).

---

## capture_web_screenshot

<a id="capturewebscreenshot"></a>

**Title:** Capture Web Screenshot  
**Kind:** `browser-provider` · **Requires session:** false · **analysisOperation:** null  
**Providers:** rea-cdp-browser  
**Effects set (true flags):** accessesNetwork, mutatesSession  
**MCP annotations:** `{"destructiveHint":false,"idempotentHint":true,"openWorldHint":true,"readOnlyHint":false}`

**Description (verbatim, as advertised to the agent):**

> Capture the current visible viewport of one configured page as an inline, content-addressed PNG artifact. The operation never scrolls, navigates, or evaluates page JavaScript.

**Input schema (verbatim, JSON Schema 2020-12):**

<details><summary>inputSchema for capture_web_screenshot</summary>

```json
{
  "$defs": {
    "__schema0": {
      "description": "Literal loopback CDP endpoint: http://127.0.0.1:PORT, or ws://127.0.0.1:PORT/devtools/browser/ID.",
      "minLength": 1,
      "type": "string"
    },
    "__schema1": {
      "items": {
        "minLength": 1,
        "type": "string"
      },
      "type": "array"
    },
    "__schema2": {
      "minLength": 1,
      "type": "string"
    }
  },
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "additionalProperties": false,
  "examples": [
    {
      "cdp_endpoint": "http://127.0.0.1:9222",
      "target_id": "TARGET_ID_FROM_LIST_BROWSER_TARGETS"
    }
  ],
  "properties": {
    "allowed_origins": {
      "$ref": "#/$defs/__schema1"
    },
    "cdp_endpoint": {
      "$ref": "#/$defs/__schema0",
      "description": "Literal loopback CDP endpoint: http://127.0.0.1:PORT, or ws://127.0.0.1:PORT/devtools/browser/ID."
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

**Output schema:** see [`tool-specs/capture_web_screenshot.json`](../tool-specs/capture_web_screenshot.json) (`outputSchema`).

---

## compare_web_captures

<a id="comparewebcaptures"></a>

**Title:** Compare Web Captures  
**Kind:** `browser-provider` · **Requires session:** false · **analysisOperation:** null  
**Providers:** rea-cdp-browser  
**Effects set (true flags):** mutatesSession  
**MCP annotations:** `{"destructiveHint":false,"idempotentHint":true,"openWorldHint":false,"readOnlyHint":false}`

**Description (verbatim, as advertised to the agent):**

> Compare passive web captures by providing before and after, each with the complete inspect_web_page normalized_result in inspection and an optional complete discover_webmcp_tools normalized_result in webmcp; or compare recorded scenarios by passing complete capture_browser_scenario normalized_result objects in before_scenario and after_scenario with an optional normalization policy. Use exactly one input group. Network comparison includes observed HTTP requests and WebSocket frame streams; same-URL connections are compared as an unordered collection of ordered streams, retaining connection counts without claiming stable identity between individual connections. Scenario comparison aligns exact step IDs, records deterministic literal normalization, and returns every artifact-level difference plus alignment failures inline. Missing or truncated evidence never proves equality.

**Input schema (verbatim, JSON Schema 2020-12):**

<details><summary>inputSchema for compare_web_captures</summary>

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "additionalProperties": false,
  "description": "Provide a complete input group: before + after; before_scenario + after_scenario + [normalization].",
  "examples": [
    {
      "after_scenario": {
        "browser": {
          "cleanup": "disconnected-external",
          "mode": "connect",
          "process_ownership": "external",
          "product": "Chromium",
          "version": "149"
        },
        "completeness": {
          "equality_eligible": true,
          "missing_sections": [],
          "status": "complete",
          "truncated_sections": []
        },
        "duration_ms": 10,
        "events": {
          "dropped": 0,
          "items": [],
          "retained": 0
        },
        "limitations": [],
        "scenario": {
          "action_count": 1,
          "event_families": [],
          "network_content": {
            "header_values": false,
            "request_body": false,
            "response_body": false
          },
          "secret_references": [],
          "start_origin": "https://app.example.test"
        },
        "steps": [
          {
            "action": "scenario_start",
            "after_url": {
              "origin": "https://app.example.test",
              "query_parameter_names": [],
              "redacted": false,
              "url": "https://app.example.test/"
            },
            "artifacts": {
              "accessibility": {
                "state": "not_requested"
              },
              "dom": {
                "state": "not_requested"
              },
              "history": {
                "state": "not_requested"
              },
              "screenshot": {
                "state": "not_requested"
              },
              "storage": {
                "state": "not_requested"
              },
              "url": {
                "state": "not_requested"
              }
            },
            "before_url": {
              "origin": "https://app.example.test",
              "query_parameter_names": [],
              "redacted": false,
              "url": "https://app.example.test/"
            },
            "completeness": {
              "equality_eligible": true,
              "missing_sections": [],
              "status": "complete",
              "truncated_sections": []
            },
            "elapsed_ms": 0,
            "error": null,
            "event_sequence_end": 0,
            "event_sequence_start": 1,
            "status": "completed",
            "step_id": "scenario_start",
            "step_index": 0
          },
          {
            "action": "click",
            "after_url": {
              "origin": "https://app.example.test",
              "query_parameter_names": [],
              "redacted": false,
              "url": "https://app.example.test/"
            },
            "artifacts": {
              "accessibility": {
                "state": "not_requested"
              },
              "dom": {
                "state": "not_requested"
              },
              "history": {
                "state": "not_requested"
              },
              "screenshot": {
                "state": "not_requested"
              },
              "storage": {
                "state": "not_requested"
              },
              "url": {
                "state": "not_requested"
              }
            },
            "before_url": {
              "origin": "https://app.example.test",
              "query_parameter_names": [],
              "redacted": false,
              "url": "https://app.example.test/"
            },
            "completeness": {
              "equality_eligible": true,
              "missing_sections": [],
              "status": "complete",
              "truncated_sections": []
            },
            "elapsed_ms": 10,
            "error": null,
            "event_sequence_end": 0,
            "event_sequence_start": 1,
            "status": "completed",
            "step_id": "open-settings",
            "step_index": 1
          }
        ]
      },
      "before_scenario": {
        "browser": {
          "cleanup": "disconnected-external",
          "mode": "connect",
          "process_ownership": "external",
          "product": "Chromium",
          "version": "149"
        },
        "completeness": {
          "equality_eligible": true,
          "missing_sections": [],
          "status": "complete",
          "truncated_sections": []
        },
        "duration_ms": 10,
        "events": {
          "dropped": 0,
          "items": [],
          "retained": 0
        },
        "limitations": [],
        "scenario": {
          "action_count": 1,
          "event_families": [],
          "network_content": {
            "header_values": false,
            "request_body": false,
            "response_body": false
          },
          "secret_references": [],
          "start_origin": "https://app.example.test"
        },
        "steps": [
          {
            "action": "scenario_start",
            "after_url": {
              "origin": "https://app.example.test",
              "query_parameter_names": [],
              "redacted": false,
              "url": "https://app.example.test/"
            },
            "artifacts": {
              "accessibility": {
                "state": "not_requested"
              },
              "dom": {
                "state": "not_requested"
              },
              "history": {
                "state": "not_requested"
              },
              "screenshot": {
                "state": "not_requested"
              },
              "storage": {
                "state": "not_requested"
              },
              "url": {
                "state": "not_requested"
              }
            },
            "before_url": {
              "origin": "https://app.example.test",
              "query_parameter_names": [],
              "redacted": false,
              "url": "https://app.example.test/"
            },
            "completeness": {
              "equality_eligible": true,
              "missing_sections": [],
              "status": "complete",
              "truncated_sections": []
            },
            "elapsed_ms": 0,
            "error": null,
            "event_sequence_end": 0,
            "event_sequence_start": 1,
            "status": "completed",
            "step_id": "scenario_start",
            "step_index": 0
          },
          {
            "action": "click",
            "after_url": {
              "origin": "https://app.example.test",
              "query_parameter_names": [],
              "redacted": false,
              "url": "https://app.example.test/"
            },
            "artifacts": {
              "accessibility": {
                "state": "not_requested"
              },
              "dom": {
                "state": "not_requested"
              },
              "history": {
                "state": "not_requested"
              },
              "screenshot": {
                "state": "not_requested"
              },
              "storage": {
                "state": "not_requested"
              },
              "url": {
                "state": "not_requested"
              }
            },
            "before_url": {
              "origin": "https://app.example.test",
              "query_parameter_names": [],
              "redacted": false,
              "url": "https://app.example.test/"
            },
            "completeness": {
              "equality_eligible": true,
              "missing_sections": [],
              "status": "complete",
              "truncated_sections": []
            },
            "elapsed_ms": 10,
            "error": null,
            "event_sequence_end": 0,
            "event_sequence_start": 1,
            "status": "completed",
            "step_id": "open-settings",
            "step_index": 1
          }
        ]
      },
      "normalization": {
        "rules": [
          {
            "artifacts": [
              "dom",
              "accessibility"
            ],
            "match": "build-123",
            "replacement": "[BUILD_ID]",
            "rule_id": "volatile-build-id"
          }
        ]
      }
    }
  ],
  "minProperties": 2,
  "properties": {
    "after": {
      "description": "The later or right-hand observation to compare.",
      "properties": {
        "inspection": {
          "description": "Complete normalized_result from inspect_web_page, including capture identity, observations, completeness, and limitations.",
          "properties": {
            "accessibility": {
              "properties": {
                "nodes": {
                  "items": {
                    "properties": {
                      "description": {
                        "anyOf": [
                          {
                            "type": "string"
                          },
                          {
                            "type": "null"
                          }
                        ]
                      },
                      "ignored": {
                        "type": "boolean"
                      },
                      "name": {
                        "anyOf": [
                          {
                            "type": "string"
                          },
                          {
                            "type": "null"
                          }
                        ],
                        "description": "Exact name used by this operation."
                      },
                      "node_id": {
                        "type": "string"
                      },
                      "parent_id": {
                        "anyOf": [
                          {
                            "type": "string"
                          },
                          {
                            "type": "null"
                          }
                        ]
                      },
                      "role": {
                        "anyOf": [
                          {
                            "type": "string"
                          },
                          {
                            "type": "null"
                          }
                        ]
                      },
                      "states": {
                        "default": [],
                        "items": {
                          "properties": {
                            "name": {
                              "description": "Exact name used by this operation.",
                              "type": "string"
                            },
                            "value": {
                              "anyOf": [
                                {
                                  "type": "boolean"
                                },
                                {
                                  "type": "number"
                                },
                                {
                                  "type": "string"
                                }
                              ]
                            }
                          },
                          "required": [
                            "name",
                            "value"
                          ],
                          "type": "object"
                        },
                        "type": "array"
                      }
                    },
                    "required": [
                      "node_id",
                      "parent_id",
                      "role",
                      "name",
                      "description",
                      "ignored"
                    ],
                    "type": "object"
                  },
                  "type": "array"
                },
                "text_capture": {
                  "properties": {
                    "excluded_fields": {
                      "maximum": 9007199254740991,
                      "minimum": 0,
                      "type": "integer"
                    },
                    "retained_bytes": {
                      "description": "Byte count for retained.",
                      "maximum": 9007199254740991,
                      "minimum": 0,
                      "type": "integer"
                    },
                    "status": {
                      "description": "Current lifecycle or verification status.",
                      "enum": [
                        "not_approved",
                        "included",
                        "unavailable"
                      ],
                      "type": "string"
                    }
                  },
                  "required": [
                    "status",
                    "retained_bytes",
                    "excluded_fields"
                  ],
                  "type": "object"
                },
                "total_nodes": {
                  "maximum": 9007199254740991,
                  "minimum": 0,
                  "type": "integer"
                }
              },
              "required": [
                "total_nodes",
                "text_capture",
                "nodes"
              ],
              "type": "object"
            },
            "browser": {
              "properties": {
                "js_version": {
                  "type": "string"
                },
                "product": {
                  "type": "string"
                },
                "protocol_version": {
                  "type": "string"
                },
                "revision": {
                  "type": "string"
                },
                "user_agent": {
                  "type": "string"
                }
              },
              "required": [
                "product",
                "protocol_version",
                "revision",
                "user_agent",
                "js_version"
              ],
              "type": "object"
            },
            "capture_window": {
              "properties": {
                "ended_at": {
                  "format": "date-time",
                  "pattern": "^(?:(?:\\d\\d[2468][048]|\\d\\d[13579][26]|\\d\\d0[48]|[02468][048]00|[13579][26]00)-02-29|\\d{4}-(?:(?:0[13578]|1[02])-(?:0[1-9]|[12]\\d|3[01])|(?:0[469]|11)-(?:0[1-9]|[12]\\d|30)|(?:02)-(?:0[1-9]|1\\d|2[0-8])))T(?:(?:[01]\\d|2[0-3]):[0-5]\\d(?::[0-5]\\d(?:\\.\\d+)?)?(?:Z))$",
                  "type": "string"
                },
                "observation_ms": {
                  "maximum": 9007199254740991,
                  "minimum": 0,
                  "type": "integer"
                },
                "started_at": {
                  "format": "date-time",
                  "pattern": "^(?:(?:\\d\\d[2468][048]|\\d\\d[13579][26]|\\d\\d0[48]|[02468][048]00|[13579][26]00)-02-29|\\d{4}-(?:(?:0[13578]|1[02])-(?:0[1-9]|[12]\\d|3[01])|(?:0[469]|11)-(?:0[1-9]|[12]\\d|30)|(?:02)-(?:0[1-9]|1\\d|2[0-8])))T(?:(?:[01]\\d|2[0-3]):[0-5]\\d(?::[0-5]\\d(?:\\.\\d+)?)?(?:Z))$",
                  "type": "string"
                }
              },
              "required": [
                "started_at",
                "ended_at",
                "observation_ms"
              ],
              "type": "object"
            },
            "completeness": {
              "properties": {
                "attach_limited_sections": {
                  "items": {
                    "enum": [
                      "frames",
                      "dom",
                      "accessibility",
                      "scripts",
                      "script_sources",
                      "resources",
                      "network_requests",
                      "network_initiators",
                      "console_events",
                      "console_text",
                      "websocket_connections",
                      "websocket_frames",
                      "websocket_shapes",
                      "json_body_shapes",
                      "workers",
                      "storage",
                      "storage_keys",
                      "metadata",
                      "webmcp_tools",
                      "screenshot",
                      "source_maps",
                      "timeline"
                    ],
                    "type": "string"
                  },
                  "type": "array"
                },
                "conditions": {
                  "items": {
                    "enum": [
                      "complete_within_window",
                      "policy_filtered",
                      "attach_limited",
                      "truncated"
                    ],
                    "type": "string"
                  },
                  "maxItems": 3,
                  "minItems": 1,
                  "type": "array"
                },
                "dropped_events": {
                  "properties": {
                    "console_events": {
                      "maximum": 9007199254740991,
                      "minimum": 0,
                      "type": "integer"
                    },
                    "network_requests": {
                      "maximum": 9007199254740991,
                      "minimum": 0,
                      "type": "integer"
                    },
                    "scripts": {
                      "maximum": 9007199254740991,
                      "minimum": 0,
                      "type": "integer"
                    },
                    "timeline_events": {
                      "maximum": 9007199254740991,
                      "minimum": 0,
                      "type": "integer"
                    },
                    "total": {
                      "maximum": 9007199254740991,
                      "minimum": 0,
                      "type": "integer"
                    },
                    "webmcp_tools": {
                      "maximum": 9007199254740991,
                      "minimum": 0,
                      "type": "integer"
                    },
                    "websocket_connections": {
                      "maximum": 9007199254740991,
                      "minimum": 0,
                      "type": "integer"
                    },
                    "websocket_frames": {
                      "maximum": 9007199254740991,
                      "minimum": 0,
                      "type": "integer"
                    }
                  },
                  "required": [
                    "scripts",
                    "network_requests",
                    "console_events",
                    "websocket_connections",
                    "websocket_frames",
                    "webmcp_tools",
                    "timeline_events",
                    "total"
                  ],
                  "type": "object"
                },
                "excluded": {
                  "items": {
                    "properties": {
                      "count": {
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
                      },
                      "reason": {
                        "enum": [
                          "disallowed_origin",
                          "unsupported_url",
                          "unattributed_origin",
                          "not_approved",
                          "out_of_target_scope",
                          "provider_unavailable",
                          "invalid_protocol_value",
                          "resource_budget_exhausted"
                        ],
                        "type": "string"
                      },
                      "section": {
                        "enum": [
                          "frames",
                          "dom",
                          "accessibility",
                          "scripts",
                          "script_sources",
                          "resources",
                          "network_requests",
                          "network_initiators",
                          "console_events",
                          "console_text",
                          "websocket_connections",
                          "websocket_frames",
                          "websocket_shapes",
                          "json_body_shapes",
                          "workers",
                          "storage",
                          "storage_keys",
                          "metadata",
                          "webmcp_tools",
                          "screenshot",
                          "source_maps",
                          "timeline"
                        ],
                        "type": "string"
                      }
                    },
                    "required": [
                      "section",
                      "reason",
                      "count"
                    ],
                    "type": "object"
                  },
                  "type": "array"
                },
                "policy_filtered_sections": {
                  "items": {
                    "enum": [
                      "frames",
                      "dom",
                      "accessibility",
                      "scripts",
                      "script_sources",
                      "resources",
                      "network_requests",
                      "network_initiators",
                      "console_events",
                      "console_text",
                      "websocket_connections",
                      "websocket_frames",
                      "websocket_shapes",
                      "json_body_shapes",
                      "workers",
                      "storage",
                      "storage_keys",
                      "metadata",
                      "webmcp_tools",
                      "screenshot",
                      "source_maps",
                      "timeline"
                    ],
                    "type": "string"
                  },
                  "type": "array"
                },
                "status": {
                  "description": "Current lifecycle or verification status.",
                  "enum": [
                    "complete_within_window",
                    "policy_filtered",
                    "attach_limited",
                    "truncated"
                  ],
                  "type": "string"
                },
                "truncated_sections": {
                  "items": {
                    "enum": [
                      "frames",
                      "dom",
                      "accessibility",
                      "scripts",
                      "script_sources",
                      "resources",
                      "network_requests",
                      "network_initiators",
                      "console_events",
                      "console_text",
                      "websocket_connections",
                      "websocket_frames",
                      "websocket_shapes",
                      "json_body_shapes",
                      "workers",
                      "storage",
                      "storage_keys",
                      "metadata",
                      "webmcp_tools",
                      "screenshot",
                      "source_maps",
                      "timeline"
                    ],
                    "type": "string"
                  },
                  "type": "array"
                },
                "unavailable_sections": {
                  "items": {
                    "enum": [
                      "frames",
                      "dom",
                      "accessibility",
                      "scripts",
                      "script_sources",
                      "resources",
                      "network_requests",
                      "network_initiators",
                      "console_events",
                      "console_text",
                      "websocket_connections",
                      "websocket_frames",
                      "websocket_shapes",
                      "json_body_shapes",
                      "workers",
                      "storage",
                      "storage_keys",
                      "metadata",
                      "webmcp_tools",
                      "screenshot",
                      "source_maps",
                      "timeline"
                    ],
                    "type": "string"
                  },
                  "type": "array"
                }
              },
              "required": [
                "status",
                "conditions",
                "policy_filtered_sections",
                "attach_limited_sections",
                "truncated_sections",
                "unavailable_sections",
                "excluded",
                "dropped_events"
              ],
              "type": "object"
            },
            "console": {
              "properties": {
                "coverage_started_at": {
                  "format": "date-time",
                  "pattern": "^(?:(?:\\d\\d[2468][048]|\\d\\d[13579][26]|\\d\\d0[48]|[02468][048]00|[13579][26]00)-02-29|\\d{4}-(?:(?:0[13578]|1[02])-(?:0[1-9]|[12]\\d|3[01])|(?:0[469]|11)-(?:0[1-9]|[12]\\d|30)|(?:02)-(?:0[1-9]|1\\d|2[0-8])))T(?:(?:[01]\\d|2[0-3]):[0-5]\\d(?::[0-5]\\d(?:\\.\\d+)?)?(?:Z))$",
                  "type": "string"
                },
                "events": {
                  "items": {
                    "properties": {
                      "argument_types": {
                        "items": {
                          "type": "string"
                        },
                        "type": "array"
                      },
                      "column": {
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
                      },
                      "line": {
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
                      },
                      "text_capture": {
                        "properties": {
                          "retained_bytes": {
                            "description": "Byte count for retained.",
                            "maximum": 9007199254740991,
                            "minimum": 0,
                            "type": "integer"
                          },
                          "status": {
                            "description": "Current lifecycle or verification status.",
                            "enum": [
                              "not_approved",
                              "included"
                            ],
                            "type": "string"
                          },
                          "values": {
                            "items": {
                              "properties": {
                                "argument_index": {
                                  "maximum": 9007199254740991,
                                  "minimum": 0,
                                  "type": "integer"
                                },
                                "text": {
                                  "type": "string"
                                },
                                "type": {
                                  "type": "string"
                                }
                              },
                              "required": [
                                "argument_index",
                                "type",
                                "text"
                              ],
                              "type": "object"
                            },
                            "type": "array"
                          }
                        },
                        "required": [
                          "status",
                          "values",
                          "retained_bytes"
                        ],
                        "type": "object"
                      },
                      "timestamp": {
                        "type": "number"
                      },
                      "type": {
                        "type": "string"
                      },
                      "url": {
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
                      "type",
                      "timestamp",
                      "argument_types",
                      "url",
                      "line",
                      "column",
                      "text_capture"
                    ],
                    "type": "object"
                  },
                  "type": "array"
                },
                "prior_activity_available": {
                  "const": false,
                  "type": "boolean"
                }
              },
              "required": [
                "events",
                "coverage_started_at",
                "prior_activity_available"
              ],
              "type": "object"
            },
            "dom": {
              "properties": {
                "nodes": {
                  "items": {
                    "properties": {
                      "attribute_names": {
                        "items": {
                          "type": "string"
                        },
                        "type": "array"
                      },
                      "index": {
                        "maximum": 9007199254740991,
                        "minimum": 0,
                        "type": "integer"
                      },
                      "node_name": {
                        "type": "string"
                      },
                      "node_type": {
                        "maximum": 9007199254740991,
                        "minimum": 0,
                        "type": "integer"
                      },
                      "node_value_length": {
                        "maximum": 9007199254740991,
                        "minimum": 0,
                        "type": "integer"
                      },
                      "parent_index": {
                        "maximum": 9007199254740991,
                        "minimum": -1,
                        "type": "integer"
                      }
                    },
                    "required": [
                      "index",
                      "parent_index",
                      "node_type",
                      "node_name",
                      "node_value_length",
                      "attribute_names"
                    ],
                    "type": "object"
                  },
                  "type": "array"
                },
                "total_nodes": {
                  "maximum": 9007199254740991,
                  "minimum": 0,
                  "type": "integer"
                }
              },
              "required": [
                "total_nodes",
                "nodes"
              ],
              "type": "object"
            },
            "frames": {
              "items": {
                "properties": {
                  "frame_id": {
                    "type": "string"
                  },
                  "origin": {
                    "anyOf": [
                      {
                        "type": "string"
                      },
                      {
                        "type": "null"
                      }
                    ]
                  },
                  "parent_frame_id": {
                    "anyOf": [
                      {
                        "type": "string"
                      },
                      {
                        "type": "null"
                      }
                    ]
                  },
                  "url": {
                    "type": "string"
                  }
                },
                "required": [
                  "frame_id",
                  "parent_frame_id",
                  "url",
                  "origin"
                ],
                "type": "object"
              },
              "type": "array"
            },
            "limitations": {
              "items": {
                "type": "string"
              },
              "type": "array"
            },
            "metadata": {
              "properties": {
                "agent_hints": {
                  "items": {
                    "properties": {
                      "declaration": {
                        "type": "string"
                      },
                      "mechanism": {
                        "enum": [
                          "link_rel",
                          "dom_link_rel",
                          "well_known_resource",
                          "response_header"
                        ],
                        "type": "string"
                      },
                      "trust": {
                        "const": "page-declared-untrusted",
                        "type": "string"
                      },
                      "url": {
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
                      "mechanism",
                      "declaration",
                      "url",
                      "trust"
                    ],
                    "type": "object"
                  },
                  "type": "array"
                },
                "dom_urls": {
                  "items": {
                    "properties": {
                      "attribute": {
                        "enum": [
                          "href",
                          "src",
                          "action",
                          "formaction",
                          "poster"
                        ],
                        "type": "string"
                      },
                      "destination_scope": {
                        "enum": [
                          "approved",
                          "outside_policy",
                          "unsupported"
                        ],
                        "type": "string"
                      },
                      "node_index": {
                        "maximum": 9007199254740991,
                        "minimum": 0,
                        "type": "integer"
                      },
                      "url": {
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
                      "node_index",
                      "attribute",
                      "url",
                      "destination_scope"
                    ],
                    "type": "object"
                  },
                  "type": "array"
                },
                "excluded_dom_urls": {
                  "maximum": 9007199254740991,
                  "minimum": 0,
                  "type": "integer"
                },
                "headers_allowlisted": {
                  "const": true,
                  "type": "boolean"
                },
                "responses": {
                  "items": {
                    "properties": {
                      "content_encoding": {
                        "anyOf": [
                          {
                            "type": "string"
                          },
                          {
                            "type": "null"
                          }
                        ]
                      },
                      "content_length": {
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
                      },
                      "csp": {
                        "properties": {
                          "directives": {
                            "items": {
                              "properties": {
                                "name": {
                                  "description": "Exact name used by this operation.",
                                  "type": "string"
                                },
                                "sources": {
                                  "items": {
                                    "properties": {
                                      "kind": {
                                        "enum": [
                                          "keyword",
                                          "scheme",
                                          "approved_origin",
                                          "external_origin",
                                          "other"
                                        ],
                                        "type": "string"
                                      },
                                      "value": {
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
                                      "kind",
                                      "value"
                                    ],
                                    "type": "object"
                                  },
                                  "type": "array"
                                }
                              },
                              "required": [
                                "name",
                                "sources"
                              ],
                              "type": "object"
                            },
                            "type": "array"
                          },
                          "hash_count": {
                            "maximum": 9007199254740991,
                            "minimum": 0,
                            "type": "integer"
                          },
                          "nonce_count": {
                            "maximum": 9007199254740991,
                            "minimum": 0,
                            "type": "integer"
                          }
                        },
                        "required": [
                          "directives",
                          "nonce_count",
                          "hash_count"
                        ],
                        "type": "object"
                      },
                      "links": {
                        "items": {
                          "properties": {
                            "as": {
                              "anyOf": [
                                {
                                  "type": "string"
                                },
                                {
                                  "type": "null"
                                }
                              ]
                            },
                            "crossorigin": {
                              "anyOf": [
                                {
                                  "type": "string"
                                },
                                {
                                  "type": "null"
                                }
                              ]
                            },
                            "destination_scope": {
                              "enum": [
                                "approved",
                                "outside_policy",
                                "unsupported"
                              ],
                              "type": "string"
                            },
                            "href": {
                              "anyOf": [
                                {
                                  "type": "string"
                                },
                                {
                                  "type": "null"
                                }
                              ]
                            },
                            "rel": {
                              "items": {
                                "type": "string"
                              },
                              "type": "array"
                            },
                            "type": {
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
                            "href",
                            "destination_scope",
                            "rel",
                            "as",
                            "type",
                            "crossorigin"
                          ],
                          "type": "object"
                        },
                        "type": "array"
                      },
                      "mime_type": {
                        "anyOf": [
                          {
                            "type": "string"
                          },
                          {
                            "type": "null"
                          }
                        ]
                      },
                      "policies": {
                        "properties": {
                          "coep": {
                            "anyOf": [
                              {
                                "type": "string"
                              },
                              {
                                "type": "null"
                              }
                            ]
                          },
                          "coop": {
                            "anyOf": [
                              {
                                "type": "string"
                              },
                              {
                                "type": "null"
                              }
                            ]
                          },
                          "corp": {
                            "anyOf": [
                              {
                                "type": "string"
                              },
                              {
                                "type": "null"
                              }
                            ]
                          },
                          "permissions_policy_features": {
                            "items": {
                              "type": "string"
                            },
                            "type": "array"
                          },
                          "referrer_policy": {
                            "anyOf": [
                              {
                                "type": "string"
                              },
                              {
                                "type": "null"
                              }
                            ]
                          },
                          "x_content_type_options": {
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
                          "coop",
                          "coep",
                          "corp",
                          "referrer_policy",
                          "x_content_type_options",
                          "permissions_policy_features"
                        ],
                        "type": "object"
                      },
                      "request_id": {
                        "type": "string"
                      },
                      "url": {
                        "type": "string"
                      }
                    },
                    "required": [
                      "request_id",
                      "url",
                      "mime_type",
                      "content_length",
                      "content_encoding",
                      "csp",
                      "links",
                      "policies"
                    ],
                    "type": "object"
                  },
                  "type": "array"
                }
              },
              "required": [
                "responses",
                "dom_urls",
                "agent_hints",
                "excluded_dom_urls",
                "headers_allowlisted"
              ],
              "type": "object"
            },
            "network": {
              "properties": {
                "coverage_started_at": {
                  "format": "date-time",
                  "pattern": "^(?:(?:\\d\\d[2468][048]|\\d\\d[13579][26]|\\d\\d0[48]|[02468][048]00|[13579][26]00)-02-29|\\d{4}-(?:(?:0[13578]|1[02])-(?:0[1-9]|[12]\\d|3[01])|(?:0[469]|11)-(?:0[1-9]|[12]\\d|30)|(?:02)-(?:0[1-9]|1\\d|2[0-8])))T(?:(?:[01]\\d|2[0-3]):[0-5]\\d(?::[0-5]\\d(?:\\.\\d+)?)?(?:Z))$",
                  "type": "string"
                },
                "prior_activity_available": {
                  "const": false,
                  "type": "boolean"
                },
                "requests": {
                  "items": {
                    "properties": {
                      "body_shapes": {
                        "properties": {
                          "request": {
                            "anyOf": [
                              {
                                "properties": {
                                  "max_depth_observed": {
                                    "description": "Maximum permitted depth observed for this operation.",
                                    "maximum": 9007199254740991,
                                    "minimum": 0,
                                    "type": "integer"
                                  },
                                  "node_count": {
                                    "maximum": 9007199254740991,
                                    "minimum": 1,
                                    "type": "integer"
                                  },
                                  "properties": {
                                    "items": {
                                      "properties": {
                                        "observations": {
                                          "maximum": 9007199254740991,
                                          "minimum": 1,
                                          "type": "integer"
                                        },
                                        "path": {
                                          "description": "Local filesystem path used by this operation.",
                                          "items": {
                                            "oneOf": [
                                              {
                                                "properties": {
                                                  "kind": {
                                                    "const": "property",
                                                    "type": "string"
                                                  },
                                                  "name": {
                                                    "description": "Exact name used by this operation.",
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
                                                "properties": {
                                                  "kind": {
                                                    "const": "array-element",
                                                    "type": "string"
                                                  }
                                                },
                                                "required": [
                                                  "kind"
                                                ],
                                                "type": "object"
                                              }
                                            ]
                                          },
                                          "minItems": 1,
                                          "type": "array"
                                        },
                                        "types": {
                                          "items": {
                                            "enum": [
                                              "object",
                                              "array",
                                              "string",
                                              "number",
                                              "boolean",
                                              "null"
                                            ],
                                            "type": "string"
                                          },
                                          "minItems": 1,
                                          "type": "array"
                                        }
                                      },
                                      "required": [
                                        "path",
                                        "types",
                                        "observations"
                                      ],
                                      "type": "object"
                                    },
                                    "type": "array"
                                  },
                                  "root_type": {
                                    "enum": [
                                      "object",
                                      "array",
                                      "string",
                                      "number",
                                      "boolean",
                                      "null"
                                    ],
                                    "type": "string"
                                  }
                                },
                                "required": [
                                  "root_type",
                                  "node_count",
                                  "max_depth_observed",
                                  "properties"
                                ],
                                "type": "object"
                              },
                              {
                                "type": "null"
                              }
                            ]
                          },
                          "response": {
                            "anyOf": [
                              {
                                "properties": {
                                  "max_depth_observed": {
                                    "description": "Maximum permitted depth observed for this operation.",
                                    "maximum": 9007199254740991,
                                    "minimum": 0,
                                    "type": "integer"
                                  },
                                  "node_count": {
                                    "maximum": 9007199254740991,
                                    "minimum": 1,
                                    "type": "integer"
                                  },
                                  "properties": {
                                    "items": {
                                      "properties": {
                                        "observations": {
                                          "maximum": 9007199254740991,
                                          "minimum": 1,
                                          "type": "integer"
                                        },
                                        "path": {
                                          "description": "Local filesystem path used by this operation.",
                                          "items": {
                                            "oneOf": [
                                              {
                                                "properties": {
                                                  "kind": {
                                                    "const": "property",
                                                    "type": "string"
                                                  },
                                                  "name": {
                                                    "description": "Exact name used by this operation.",
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
                                                "properties": {
                                                  "kind": {
                                                    "const": "array-element",
                                                    "type": "string"
                                                  }
                                                },
                                                "required": [
                                                  "kind"
                                                ],
                                                "type": "object"
                                              }
                                            ]
                                          },
                                          "minItems": 1,
                                          "type": "array"
                                        },
                                        "types": {
                                          "items": {
                                            "enum": [
                                              "object",
                                              "array",
                                              "string",
                                              "number",
                                              "boolean",
                                              "null"
                                            ],
                                            "type": "string"
                                          },
                                          "minItems": 1,
                                          "type": "array"
                                        }
                                      },
                                      "required": [
                                        "path",
                                        "types",
                                        "observations"
                                      ],
                                      "type": "object"
                                    },
                                    "type": "array"
                                  },
                                  "root_type": {
                                    "enum": [
                                      "object",
                                      "array",
                                      "string",
                                      "number",
                                      "boolean",
                                      "null"
                                    ],
                                    "type": "string"
                                  }
                                },
                                "required": [
                                  "root_type",
                                  "node_count",
                                  "max_depth_observed",
                                  "properties"
                                ],
                                "type": "object"
                              },
                              {
                                "type": "null"
                              }
                            ]
                          },
                          "status": {
                            "description": "Current lifecycle or verification status.",
                            "enum": [
                              "not_approved",
                              "included",
                              "partial",
                              "unavailable"
                            ],
                            "type": "string"
                          }
                        },
                        "required": [
                          "status",
                          "request",
                          "response"
                        ],
                        "type": "object"
                      },
                      "encoded_data_length": {
                        "anyOf": [
                          {
                            "minimum": 0,
                            "type": "number"
                          },
                          {
                            "type": "null"
                          }
                        ]
                      },
                      "initiator": {
                        "properties": {
                          "column": {
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
                          },
                          "line": {
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
                          },
                          "type": {
                            "type": "string"
                          },
                          "url": {
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
                          "type",
                          "url",
                          "line",
                          "column"
                        ],
                        "type": "object"
                      },
                      "method": {
                        "type": "string"
                      },
                      "mime_type": {
                        "anyOf": [
                          {
                            "type": "string"
                          },
                          {
                            "type": "null"
                          }
                        ]
                      },
                      "origin": {
                        "anyOf": [
                          {
                            "type": "string"
                          },
                          {
                            "type": "null"
                          }
                        ]
                      },
                      "redirects": {
                        "items": {
                          "properties": {
                            "encoded_data_length": {
                              "anyOf": [
                                {
                                  "minimum": 0,
                                  "type": "number"
                                },
                                {
                                  "type": "null"
                                }
                              ]
                            },
                            "method": {
                              "type": "string"
                            },
                            "mime_type": {
                              "anyOf": [
                                {
                                  "type": "string"
                                },
                                {
                                  "type": "null"
                                }
                              ]
                            },
                            "redirect_event_timestamp": {
                              "anyOf": [
                                {
                                  "type": "number"
                                },
                                {
                                  "type": "null"
                                }
                              ]
                            },
                            "request_timestamp": {
                              "anyOf": [
                                {
                                  "type": "number"
                                },
                                {
                                  "type": "null"
                                }
                              ]
                            },
                            "resource_type": {
                              "anyOf": [
                                {
                                  "type": "string"
                                },
                                {
                                  "type": "null"
                                }
                              ]
                            },
                            "response_url": {
                              "type": "string"
                            },
                            "status": {
                              "anyOf": [
                                {
                                  "type": "number"
                                },
                                {
                                  "type": "null"
                                }
                              ],
                              "description": "Current lifecycle or verification status."
                            },
                            "url": {
                              "type": "string"
                            }
                          },
                          "required": [
                            "url",
                            "response_url",
                            "method",
                            "resource_type",
                            "status",
                            "mime_type",
                            "encoded_data_length",
                            "request_timestamp",
                            "redirect_event_timestamp"
                          ],
                          "type": "object"
                        },
                        "type": "array"
                      },
                      "request_id": {
                        "type": "string"
                      },
                      "resource_type": {
                        "anyOf": [
                          {
                            "type": "string"
                          },
                          {
                            "type": "null"
                          }
                        ]
                      },
                      "status": {
                        "anyOf": [
                          {
                            "type": "number"
                          },
                          {
                            "type": "null"
                          }
                        ],
                        "description": "Current lifecycle or verification status."
                      },
                      "url": {
                        "type": "string"
                      }
                    },
                    "required": [
                      "request_id",
                      "url",
                      "origin",
                      "method",
                      "resource_type",
                      "status",
                      "mime_type",
                      "encoded_data_length",
                      "initiator",
                      "body_shapes"
                    ],
                    "type": "object"
                  },
                  "type": "array"
                },
                "websocket_connections": {
                  "items": {
                    "properties": {
                      "events": {
                        "items": {
                          "properties": {
                            "direction": {
                              "description": "Direction in which to traverse or compare relationships.",
                              "enum": [
                                "sent",
                                "received"
                              ],
                              "type": "string"
                            },
                            "opcode": {
                              "maximum": 9007199254740991,
                              "minimum": 0,
                              "type": "integer"
                            },
                            "payload_bytes": {
                              "anyOf": [
                                {
                                  "maximum": 9007199254740991,
                                  "minimum": 0,
                                  "type": "integer"
                                },
                                {
                                  "type": "null"
                                }
                              ],
                              "description": "Byte count for payload."
                            },
                            "payload_shape": {
                              "anyOf": [
                                {
                                  "properties": {
                                    "format": {
                                      "description": "Declared input artifact format.",
                                      "enum": [
                                        "json",
                                        "text",
                                        "binary"
                                      ],
                                      "type": "string"
                                    },
                                    "json_shape": {
                                      "anyOf": [
                                        {
                                          "properties": {
                                            "max_depth_observed": {
                                              "description": "Maximum permitted depth observed for this operation.",
                                              "maximum": 9007199254740991,
                                              "minimum": 0,
                                              "type": "integer"
                                            },
                                            "node_count": {
                                              "maximum": 9007199254740991,
                                              "minimum": 1,
                                              "type": "integer"
                                            },
                                            "properties": {
                                              "items": {
                                                "properties": {
                                                  "observations": {
                                                    "maximum": 9007199254740991,
                                                    "minimum": 1,
                                                    "type": "integer"
                                                  },
                                                  "path": {
                                                    "description": "Local filesystem path used by this operation.",
                                                    "items": {
                                                      "oneOf": [
                                                        {
                                                          "properties": {
                                                            "kind": {
                                                              "const": "property",
                                                              "type": "string"
                                                            },
                                                            "name": {
                                                              "description": "Exact name used by this operation.",
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
                                                          "properties": {
                                                            "kind": {
                                                              "const": "array-element",
                                                              "type": "string"
                                                            }
                                                          },
                                                          "required": [
                                                            "kind"
                                                          ],
                                                          "type": "object"
                                                        }
                                                      ]
                                                    },
                                                    "minItems": 1,
                                                    "type": "array"
                                                  },
                                                  "types": {
                                                    "items": {
                                                      "enum": [
                                                        "object",
                                                        "array",
                                                        "string",
                                                        "number",
                                                        "boolean",
                                                        "null"
                                                      ],
                                                      "type": "string"
                                                    },
                                                    "minItems": 1,
                                                    "type": "array"
                                                  }
                                                },
                                                "required": [
                                                  "path",
                                                  "types",
                                                  "observations"
                                                ],
                                                "type": "object"
                                              },
                                              "type": "array"
                                            },
                                            "root_type": {
                                              "enum": [
                                                "object",
                                                "array",
                                                "string",
                                                "number",
                                                "boolean",
                                                "null"
                                              ],
                                              "type": "string"
                                            }
                                          },
                                          "required": [
                                            "root_type",
                                            "node_count",
                                            "max_depth_observed",
                                            "properties"
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
                                    "format",
                                    "json_shape"
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
                            "direction",
                            "opcode",
                            "payload_bytes",
                            "payload_shape"
                          ],
                          "type": "object"
                        },
                        "type": "array"
                      },
                      "request_id": {
                        "type": "string"
                      },
                      "url": {
                        "type": "string"
                      }
                    },
                    "required": [
                      "request_id",
                      "url",
                      "events"
                    ],
                    "type": "object"
                  },
                  "type": "array"
                }
              },
              "required": [
                "requests",
                "websocket_connections",
                "coverage_started_at",
                "prior_activity_available"
              ],
              "type": "object"
            },
            "resources": {
              "items": {
                "properties": {
                  "content_size": {
                    "anyOf": [
                      {
                        "minimum": 0,
                        "type": "number"
                      },
                      {
                        "type": "null"
                      }
                    ]
                  },
                  "mime_type": {
                    "type": "string"
                  },
                  "origin": {
                    "anyOf": [
                      {
                        "type": "string"
                      },
                      {
                        "type": "null"
                      }
                    ]
                  },
                  "resource_key": {
                    "pattern": "^res_[a-f0-9]{64}$",
                    "type": "string"
                  },
                  "type": {
                    "type": "string"
                  },
                  "url": {
                    "type": "string"
                  }
                },
                "required": [
                  "resource_key",
                  "url",
                  "origin",
                  "type",
                  "mime_type",
                  "content_size"
                ],
                "type": "object"
              },
              "type": "array"
            },
            "scripts": {
              "properties": {
                "items": {
                  "items": {
                    "properties": {
                      "cdp_hash": {
                        "anyOf": [
                          {
                            "type": "string"
                          },
                          {
                            "type": "null"
                          }
                        ],
                        "description": "Producer-reported script hash; null when unavailable."
                      },
                      "frame_id": {
                        "anyOf": [
                          {
                            "type": "string"
                          },
                          {
                            "type": "null"
                          }
                        ],
                        "default": null
                      },
                      "is_module": {
                        "anyOf": [
                          {
                            "type": "boolean"
                          },
                          {
                            "type": "null"
                          }
                        ],
                        "description": "Producer-reported module classification; null when unavailable."
                      },
                      "language": {
                        "anyOf": [
                          {
                            "type": "string"
                          },
                          {
                            "type": "null"
                          }
                        ]
                      },
                      "length": {
                        "anyOf": [
                          {
                            "maximum": 9007199254740991,
                            "minimum": 0,
                            "type": "integer"
                          },
                          {
                            "type": "null"
                          }
                        ],
                        "description": "Producer-reported script length; null when unavailable."
                      },
                      "origin": {
                        "anyOf": [
                          {
                            "type": "string"
                          },
                          {
                            "type": "null"
                          }
                        ]
                      },
                      "resource_reconciliation": {
                        "oneOf": [
                          {
                            "properties": {
                              "resource_key": {
                                "type": "string"
                              },
                              "status": {
                                "const": "exact",
                                "description": "Current lifecycle or verification status.",
                                "type": "string"
                              }
                            },
                            "required": [
                              "status",
                              "resource_key"
                            ],
                            "type": "object"
                          },
                          {
                            "properties": {
                              "candidate_resource_keys": {
                                "items": {
                                  "type": "string"
                                },
                                "type": "array"
                              },
                              "status": {
                                "const": "ambiguous",
                                "description": "Current lifecycle or verification status.",
                                "type": "string"
                              }
                            },
                            "required": [
                              "status",
                              "candidate_resource_keys"
                            ],
                            "type": "object"
                          },
                          {
                            "properties": {
                              "reason": {
                                "const": "no_exact_sanitized_url",
                                "type": "string"
                              },
                              "status": {
                                "const": "unmatched",
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
                      "script_key": {
                        "pattern": "^scr_[a-f0-9]{64}(?:_[0-9]+)?$",
                        "type": "string"
                      },
                      "source": {
                        "oneOf": [
                          {
                            "properties": {
                              "included": {
                                "const": false,
                                "type": "boolean"
                              },
                              "reason": {
                                "type": "string"
                              }
                            },
                            "required": [
                              "included",
                              "reason"
                            ],
                            "type": "object"
                          },
                          {
                            "properties": {
                              "artifact": {
                                "properties": {
                                  "bytes": {
                                    "maximum": 9007199254740991,
                                    "minimum": 0,
                                    "type": "integer"
                                  },
                                  "charset": {
                                    "const": "utf-8",
                                    "type": "string"
                                  },
                                  "media_type": {
                                    "minLength": 1,
                                    "type": "string"
                                  },
                                  "sha256": {
                                    "pattern": "^[a-f0-9]{64}$",
                                    "type": "string"
                                  },
                                  "text": {
                                    "type": "string"
                                  }
                                },
                                "required": [
                                  "sha256",
                                  "bytes",
                                  "media_type",
                                  "charset",
                                  "text"
                                ],
                                "type": "object"
                              },
                              "included": {
                                "const": true,
                                "type": "boolean"
                              }
                            },
                            "required": [
                              "included",
                              "artifact"
                            ],
                            "type": "object"
                          }
                        ]
                      },
                      "source_map_url": {
                        "anyOf": [
                          {
                            "type": "string"
                          },
                          {
                            "type": "null"
                          }
                        ]
                      },
                      "url": {
                        "type": "string"
                      }
                    },
                    "required": [
                      "script_key",
                      "url",
                      "origin",
                      "cdp_hash",
                      "length",
                      "is_module",
                      "language",
                      "source_map_url",
                      "resource_reconciliation",
                      "source"
                    ],
                    "type": "object"
                  },
                  "type": "array"
                },
                "total": {
                  "maximum": 9007199254740991,
                  "minimum": 0,
                  "type": "integer"
                }
              },
              "required": [
                "total",
                "items"
              ],
              "type": "object"
            },
            "storage": {
              "properties": {
                "cache_names": {
                  "items": {
                    "type": "string"
                  },
                  "type": "array"
                },
                "content_fingerprints": {
                  "default": [],
                  "items": {
                    "properties": {
                      "complete": {
                        "type": "boolean"
                      },
                      "identity_sha256": {
                        "description": "Exact SHA-256 digest of identity.",
                        "pattern": "^[a-f0-9]{64}$",
                        "type": "string"
                      },
                      "scope": {
                        "enum": [
                          "cookie",
                          "local_storage",
                          "session_storage",
                          "indexed_db_schema",
                          "indexed_db_record",
                          "cache_entry"
                        ],
                        "type": "string"
                      },
                      "value_sha256": {
                        "anyOf": [
                          {
                            "pattern": "^[a-f0-9]{64}$",
                            "type": "string"
                          },
                          {
                            "type": "null"
                          }
                        ],
                        "description": "Exact SHA-256 digest of value."
                      }
                    },
                    "required": [
                      "scope",
                      "identity_sha256",
                      "value_sha256",
                      "complete"
                    ],
                    "type": "object"
                  },
                  "type": "array"
                },
                "fingerprint_algorithm": {
                  "const": "sha256",
                  "default": "sha256",
                  "type": "string"
                },
                "fingerprints_complete": {
                  "default": false,
                  "type": "boolean"
                },
                "indexed_db_names": {
                  "items": {
                    "type": "string"
                  },
                  "type": "array"
                },
                "local_storage_keys": {
                  "items": {
                    "type": "string"
                  },
                  "type": "array"
                },
                "origin": {
                  "type": "string"
                },
                "quota_bytes": {
                  "anyOf": [
                    {
                      "minimum": 0,
                      "type": "number"
                    },
                    {
                      "type": "null"
                    }
                  ],
                  "description": "Byte count for quota."
                },
                "session_storage_keys": {
                  "items": {
                    "type": "string"
                  },
                  "type": "array"
                },
                "usage_bytes": {
                  "anyOf": [
                    {
                      "minimum": 0,
                      "type": "number"
                    },
                    {
                      "type": "null"
                    }
                  ],
                  "description": "Byte count for usage."
                },
                "values_redacted": {
                  "const": true,
                  "type": "boolean"
                }
              },
              "required": [
                "origin",
                "usage_bytes",
                "quota_bytes",
                "local_storage_keys",
                "session_storage_keys",
                "indexed_db_names",
                "cache_names",
                "values_redacted"
              ],
              "type": "object"
            },
            "target": {
              "properties": {
                "attached": {
                  "anyOf": [
                    {
                      "type": "boolean"
                    },
                    {
                      "type": "null"
                    }
                  ],
                  "description": "Discovery-reported debugger attachment state; null means unknown"
                },
                "origin": {
                  "type": "string"
                },
                "target_id": {
                  "description": "Exact CDP target identifier selected from the endpoint's target listing.",
                  "type": "string"
                },
                "title": {
                  "type": "string"
                },
                "type": {
                  "type": "string"
                },
                "url": {
                  "type": "string"
                }
              },
              "required": [
                "target_id",
                "type",
                "title",
                "url",
                "origin",
                "attached"
              ],
              "type": "object"
            },
            "workers": {
              "items": {
                "properties": {
                  "attached": {
                    "type": "boolean"
                  },
                  "opener_target_id": {
                    "anyOf": [
                      {
                        "type": "string"
                      },
                      {
                        "type": "null"
                      }
                    ],
                    "default": null
                  },
                  "origin": {
                    "anyOf": [
                      {
                        "type": "string"
                      },
                      {
                        "type": "null"
                      }
                    ]
                  },
                  "parent_frame_id": {
                    "anyOf": [
                      {
                        "type": "string"
                      },
                      {
                        "type": "null"
                      }
                    ],
                    "default": null
                  },
                  "target_id": {
                    "description": "Exact CDP target identifier selected from the endpoint's target listing.",
                    "type": "string"
                  },
                  "type": {
                    "type": "string"
                  },
                  "url": {
                    "type": "string"
                  }
                },
                "required": [
                  "target_id",
                  "type",
                  "url",
                  "origin",
                  "attached"
                ],
                "type": "object"
              },
              "type": "array"
            }
          },
          "required": [
            "browser",
            "target",
            "capture_window",
            "completeness",
            "frames",
            "dom",
            "accessibility",
            "scripts",
            "resources",
            "network",
            "console",
            "workers",
            "metadata",
            "storage",
            "limitations"
          ],
          "type": "object"
        },
        "webmcp": {
          "anyOf": [
            {
              "properties": {
                "browser": {
                  "properties": {
                    "js_version": {
                      "type": "string"
                    },
                    "product": {
                      "type": "string"
                    },
                    "protocol_version": {
                      "type": "string"
                    },
                    "revision": {
                      "type": "string"
                    },
                    "user_agent": {
                      "type": "string"
                    }
                  },
                  "required": [
                    "product",
                    "protocol_version",
                    "revision",
                    "user_agent",
                    "js_version"
                  ],
                  "type": "object"
                },
                "completeness": {
                  "properties": {
                    "attach_limited_sections": {
                      "items": {
                        "enum": [
                          "frames",
                          "dom",
                          "accessibility",
                          "scripts",
                          "script_sources",
                          "resources",
                          "network_requests",
                          "network_initiators",
                          "console_events",
                          "console_text",
                          "websocket_connections",
                          "websocket_frames",
                          "websocket_shapes",
                          "json_body_shapes",
                          "workers",
                          "storage",
                          "storage_keys",
                          "metadata",
                          "webmcp_tools",
                          "screenshot",
                          "source_maps",
                          "timeline"
                        ],
                        "type": "string"
                      },
                      "type": "array"
                    },
                    "conditions": {
                      "items": {
                        "enum": [
                          "complete_within_window",
                          "policy_filtered",
                          "attach_limited",
                          "truncated"
                        ],
                        "type": "string"
                      },
                      "maxItems": 3,
                      "minItems": 1,
                      "type": "array"
                    },
                    "dropped_events": {
                      "properties": {
                        "console_events": {
                          "maximum": 9007199254740991,
                          "minimum": 0,
                          "type": "integer"
                        },
                        "network_requests": {
                          "maximum": 9007199254740991,
                          "minimum": 0,
                          "type": "integer"
                        },
                        "scripts": {
                          "maximum": 9007199254740991,
                          "minimum": 0,
                          "type": "integer"
                        },
                        "timeline_events": {
                          "maximum": 9007199254740991,
                          "minimum": 0,
                          "type": "integer"
                        },
                        "total": {
                          "maximum": 9007199254740991,
                          "minimum": 0,
                          "type": "integer"
                        },
                        "webmcp_tools": {
                          "maximum": 9007199254740991,
                          "minimum": 0,
                          "type": "integer"
                        },
                        "websocket_connections": {
                          "maximum": 9007199254740991,
                          "minimum": 0,
                          "type": "integer"
                        },
                        "websocket_frames": {
                          "maximum": 9007199254740991,
                          "minimum": 0,
                          "type": "integer"
                        }
                      },
                      "required": [
                        "scripts",
                        "network_requests",
                        "console_events",
                        "websocket_connections",
                        "websocket_frames",
                        "webmcp_tools",
                        "timeline_events",
                        "total"
                      ],
                      "type": "object"
                    },
                    "excluded": {
                      "items": {
                        "properties": {
                          "count": {
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
                          },
                          "reason": {
                            "enum": [
                              "disallowed_origin",
                              "unsupported_url",
                              "unattributed_origin",
                              "not_approved",
                              "out_of_target_scope",
                              "provider_unavailable",
                              "invalid_protocol_value",
                              "resource_budget_exhausted"
                            ],
                            "type": "string"
                          },
                          "section": {
                            "enum": [
                              "frames",
                              "dom",
                              "accessibility",
                              "scripts",
                              "script_sources",
                              "resources",
                              "network_requests",
                              "network_initiators",
                              "console_events",
                              "console_text",
                              "websocket_connections",
                              "websocket_frames",
                              "websocket_shapes",
                              "json_body_shapes",
                              "workers",
                              "storage",
                              "storage_keys",
                              "metadata",
                              "webmcp_tools",
                              "screenshot",
                              "source_maps",
                              "timeline"
                            ],
                            "type": "string"
                          }
                        },
                        "required": [
                          "section",
                          "reason",
                          "count"
                        ],
                        "type": "object"
                      },
                      "type": "array"
                    },
                    "policy_filtered_sections": {
                      "items": {
                        "enum": [
                          "frames",
                          "dom",
                          "accessibility",
                          "scripts",
                          "script_sources",
                          "resources",
                          "network_requests",
                          "network_initiators",
                          "console_events",
                          "console_text",
                          "websocket_connections",
                          "websocket_frames",
                          "websocket_shapes",
                          "json_body_shapes",
                          "workers",
                          "storage",
                          "storage_keys",
                          "metadata",
                          "webmcp_tools",
                          "screenshot",
                          "source_maps",
                          "timeline"
                        ],
                        "type": "string"
                      },
                      "type": "array"
                    },
                    "status": {
                      "description": "Current lifecycle or verification status.",
                      "enum": [
                        "complete_within_window",
                        "policy_filtered",
                        "attach_limited",
                        "truncated"
                      ],
                      "type": "string"
                    },
                    "truncated_sections": {
                      "items": {
                        "enum": [
                          "frames",
                          "dom",
                          "accessibility",
                          "scripts",
                          "script_sources",
                          "resources",
                          "network_requests",
                          "network_initiators",
                          "console_events",
                          "console_text",
                          "websocket_connections",
                          "websocket_frames",
                          "websocket_shapes",
                          "json_body_shapes",
                          "workers",
                          "storage",
                          "storage_keys",
                          "metadata",
                          "webmcp_tools",
                          "screenshot",
                          "source_maps",
                          "timeline"
                        ],
                        "type": "string"
                      },
                      "type": "array"
                    },
                    "unavailable_sections": {
                      "items": {
                        "enum": [
                          "frames",
                          "dom",
                          "accessibility",
                          "scripts",
                          "script_sources",
                          "resources",
                          "network_requests",
                          "network_initiators",
                          "console_events",
                          "console_text",
                          "websocket_connections",
                          "websocket_frames",
                          "websocket_shapes",
                          "json_body_shapes",
                          "workers",
                          "storage",
                          "storage_keys",
                          "metadata",
                          "webmcp_tools",
                          "screenshot",
                          "source_maps",
                          "timeline"
                        ],
                        "type": "string"
                      },
                      "type": "array"
                    }
                  },
                  "required": [
                    "status",
                    "conditions",
                    "policy_filtered_sections",
                    "attach_limited_sections",
                    "truncated_sections",
                    "unavailable_sections",
                    "excluded",
                    "dropped_events"
                  ],
                  "type": "object"
                },
                "limitations": {
                  "items": {
                    "type": "string"
                  },
                  "type": "array"
                },
                "status": {
                  "description": "Current lifecycle or verification status.",
                  "enum": [
                    "available",
                    "unavailable"
                  ],
                  "type": "string"
                },
                "target": {
                  "properties": {
                    "origin": {
                      "type": "string"
                    },
                    "target_id": {
                      "description": "Exact CDP target identifier selected from the endpoint's target listing.",
                      "type": "string"
                    },
                    "url": {
                      "type": "string"
                    }
                  },
                  "required": [
                    "target_id",
                    "url",
                    "origin"
                  ],
                  "type": "object"
                },
                "tools": {
                  "properties": {
                    "items": {
                      "items": {
                        "properties": {
                          "annotations": {
                            "properties": {
                              "autosubmit": {
                                "anyOf": [
                                  {
                                    "type": "boolean"
                                  },
                                  {
                                    "type": "null"
                                  }
                                ]
                              },
                              "consequential": {
                                "anyOf": [
                                  {
                                    "type": "boolean"
                                  },
                                  {
                                    "type": "null"
                                  }
                                ]
                              },
                              "read_only": {
                                "anyOf": [
                                  {
                                    "type": "boolean"
                                  },
                                  {
                                    "type": "null"
                                  }
                                ]
                              },
                              "untrusted_content": {
                                "anyOf": [
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
                              "read_only",
                              "untrusted_content",
                              "autosubmit"
                            ],
                            "type": "object"
                          },
                          "declaration_kind": {
                            "enum": [
                              "declarative",
                              "imperative"
                            ],
                            "type": "string"
                          },
                          "description": {
                            "type": "string"
                          },
                          "frame_id": {
                            "type": "string"
                          },
                          "frame_url": {
                            "type": "string"
                          },
                          "input_schema": {
                            "anyOf": [
                              {},
                              {
                                "type": "null"
                              }
                            ]
                          },
                          "input_schema_sha256": {
                            "anyOf": [
                              {
                                "pattern": "^[a-f0-9]{64}$",
                                "type": "string"
                              },
                              {
                                "type": "null"
                              }
                            ],
                            "description": "Exact SHA-256 digest of input schema."
                          },
                          "name": {
                            "description": "Exact name used by this operation.",
                            "type": "string"
                          },
                          "owner_origin": {
                            "type": "string"
                          },
                          "registration_source": {
                            "anyOf": [
                              {
                                "properties": {
                                  "column": {
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
                                  },
                                  "line": {
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
                                  },
                                  "url": {
                                    "type": "string"
                                  }
                                },
                                "required": [
                                  "url",
                                  "line",
                                  "column"
                                ],
                                "type": "object"
                              },
                              {
                                "type": "null"
                              }
                            ]
                          },
                          "tool_key": {
                            "pattern": "^webmcp_[a-f0-9]{64}$",
                            "type": "string"
                          },
                          "trust": {
                            "const": "page-declared-untrusted",
                            "type": "string"
                          }
                        },
                        "required": [
                          "tool_key",
                          "name",
                          "description",
                          "frame_id",
                          "frame_url",
                          "owner_origin",
                          "declaration_kind",
                          "input_schema",
                          "input_schema_sha256",
                          "annotations",
                          "registration_source",
                          "trust"
                        ],
                        "type": "object"
                      },
                      "type": "array"
                    },
                    "total": {
                      "maximum": 9007199254740991,
                      "minimum": 0,
                      "type": "integer"
                    }
                  },
                  "required": [
                    "total",
                    "items"
                  ],
                  "type": "object"
                }
              },
              "required": [
                "browser",
                "target",
                "status",
                "tools",
                "completeness",
                "limitations"
              ],
              "type": "object"
            },
            {
              "type": "null"
            }
          ],
          "description": "Complete normalized_result from discover_webmcp_tools for this capture, or null when it was not recorded."
        }
      },
      "required": [
        "inspection"
      ],
      "type": "object"
    },
    "after_scenario": {
      "additionalProperties": false,
      "description": "Later complete normalized_result from capture_browser_scenario.",
      "properties": {
        "browser": {
          "additionalProperties": false,
          "properties": {
            "cleanup": {
              "enum": [
                "terminated-owned-process",
                "disconnected-external"
              ],
              "type": "string"
            },
            "mode": {
              "description": "Operation mode that selects the requested behavior.",
              "enum": [
                "launch",
                "connect"
              ],
              "type": "string"
            },
            "process_ownership": {
              "enum": [
                "provider-owned",
                "external"
              ],
              "type": "string"
            },
            "product": {
              "minLength": 1,
              "type": "string"
            },
            "version": {
              "minLength": 1,
              "type": "string"
            }
          },
          "required": [
            "mode",
            "process_ownership",
            "cleanup",
            "product",
            "version"
          ],
          "type": "object"
        },
        "completeness": {
          "oneOf": [
            {
              "additionalProperties": false,
              "properties": {
                "equality_eligible": {
                  "const": true,
                  "type": "boolean"
                },
                "missing_sections": {
                  "items": {
                    "not": {}
                  },
                  "maxItems": 0,
                  "minItems": 0,
                  "type": "array"
                },
                "status": {
                  "const": "complete",
                  "description": "Current lifecycle or verification status.",
                  "type": "string"
                },
                "truncated_sections": {
                  "items": {
                    "not": {}
                  },
                  "maxItems": 0,
                  "minItems": 0,
                  "type": "array"
                }
              },
              "required": [
                "status",
                "equality_eligible",
                "missing_sections",
                "truncated_sections"
              ],
              "type": "object"
            },
            {
              "additionalProperties": false,
              "properties": {
                "equality_eligible": {
                  "const": false,
                  "type": "boolean"
                },
                "missing_sections": {
                  "items": {
                    "enum": [
                      "action",
                      "screenshot",
                      "dom",
                      "accessibility",
                      "url",
                      "history",
                      "storage",
                      "events",
                      "frames",
                      "workers",
                      "popups",
                      "websockets"
                    ],
                    "type": "string"
                  },
                  "minItems": 1,
                  "type": "array"
                },
                "status": {
                  "const": "incomplete",
                  "description": "Current lifecycle or verification status.",
                  "type": "string"
                },
                "truncated_sections": {
                  "items": {
                    "not": {}
                  },
                  "maxItems": 0,
                  "minItems": 0,
                  "type": "array"
                }
              },
              "required": [
                "status",
                "equality_eligible",
                "missing_sections",
                "truncated_sections"
              ],
              "type": "object"
            },
            {
              "additionalProperties": false,
              "properties": {
                "equality_eligible": {
                  "const": false,
                  "type": "boolean"
                },
                "missing_sections": {
                  "items": {
                    "enum": [
                      "action",
                      "screenshot",
                      "dom",
                      "accessibility",
                      "url",
                      "history",
                      "storage",
                      "events",
                      "frames",
                      "workers",
                      "popups",
                      "websockets"
                    ],
                    "type": "string"
                  },
                  "type": "array"
                },
                "status": {
                  "const": "truncated",
                  "description": "Current lifecycle or verification status.",
                  "type": "string"
                },
                "truncated_sections": {
                  "items": {
                    "enum": [
                      "action",
                      "screenshot",
                      "dom",
                      "accessibility",
                      "url",
                      "history",
                      "storage",
                      "events",
                      "frames",
                      "workers",
                      "popups",
                      "websockets"
                    ],
                    "type": "string"
                  },
                  "minItems": 1,
                  "type": "array"
                }
              },
              "required": [
                "status",
                "equality_eligible",
                "missing_sections",
                "truncated_sections"
              ],
              "type": "object"
            }
          ]
        },
        "duration_ms": {
          "maximum": 9007199254740991,
          "minimum": 0,
          "type": "integer"
        },
        "events": {
          "additionalProperties": false,
          "properties": {
            "dropped": {
              "maximum": 9007199254740991,
              "minimum": 0,
              "type": "integer"
            },
            "items": {
              "items": {
                "anyOf": [
                  {
                    "additionalProperties": false,
                    "properties": {
                      "kind": {
                        "const": "console",
                        "type": "string"
                      },
                      "level": {
                        "minLength": 1,
                        "type": "string"
                      },
                      "sequence": {
                        "maximum": 9007199254740991,
                        "minimum": 1,
                        "type": "integer"
                      },
                      "step_index": {
                        "maximum": 9007199254740991,
                        "minimum": 0,
                        "type": "integer"
                      },
                      "text": {
                        "type": "string"
                      },
                      "url": {
                        "anyOf": [
                          {
                            "properties": {
                              "origin": {
                                "anyOf": [
                                  {
                                    "type": "string"
                                  },
                                  {
                                    "type": "null"
                                  }
                                ]
                              },
                              "query_parameter_names": {
                                "items": {
                                  "type": "string"
                                },
                                "type": "array"
                              },
                              "redacted": {
                                "type": "boolean"
                              },
                              "url": {
                                "type": "string"
                              }
                            },
                            "required": [
                              "url",
                              "origin",
                              "query_parameter_names",
                              "redacted"
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
                      "sequence",
                      "step_index",
                      "kind",
                      "level",
                      "text",
                      "url"
                    ],
                    "type": "object"
                  },
                  {
                    "additionalProperties": false,
                    "properties": {
                      "kind": {
                        "const": "page-error",
                        "type": "string"
                      },
                      "message": {
                        "type": "string"
                      },
                      "sequence": {
                        "maximum": 9007199254740991,
                        "minimum": 1,
                        "type": "integer"
                      },
                      "stack": {
                        "anyOf": [
                          {
                            "type": "string"
                          },
                          {
                            "type": "null"
                          }
                        ]
                      },
                      "step_index": {
                        "maximum": 9007199254740991,
                        "minimum": 0,
                        "type": "integer"
                      }
                    },
                    "required": [
                      "sequence",
                      "step_index",
                      "kind",
                      "message",
                      "stack"
                    ],
                    "type": "object"
                  },
                  {
                    "additionalProperties": false,
                    "properties": {
                      "failure": {
                        "type": "null"
                      },
                      "header_names": {
                        "items": {
                          "type": "string"
                        },
                        "type": "array"
                      },
                      "kind": {
                        "const": "request",
                        "type": "string"
                      },
                      "method": {
                        "minLength": 1,
                        "type": "string"
                      },
                      "redirected_from_transaction_id": {
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
                      "redirected_from_transaction_state": {
                        "enum": [
                          "root",
                          "unknown"
                        ],
                        "type": "string"
                      },
                      "resource_type": {
                        "minLength": 1,
                        "type": "string"
                      },
                      "sequence": {
                        "maximum": 9007199254740991,
                        "minimum": 1,
                        "type": "integer"
                      },
                      "status": {
                        "description": "Current lifecycle or verification status.",
                        "type": "null"
                      },
                      "step_index": {
                        "maximum": 9007199254740991,
                        "minimum": 0,
                        "type": "integer"
                      },
                      "transaction_id": {
                        "minLength": 1,
                        "type": "string"
                      },
                      "url": {
                        "properties": {
                          "origin": {
                            "anyOf": [
                              {
                                "type": "string"
                              },
                              {
                                "type": "null"
                              }
                            ]
                          },
                          "query_parameter_names": {
                            "items": {
                              "type": "string"
                            },
                            "type": "array"
                          },
                          "redacted": {
                            "type": "boolean"
                          },
                          "url": {
                            "type": "string"
                          }
                        },
                        "required": [
                          "url",
                          "origin",
                          "query_parameter_names",
                          "redacted"
                        ],
                        "type": "object"
                      }
                    },
                    "required": [
                      "sequence",
                      "step_index",
                      "transaction_id",
                      "redirected_from_transaction_id",
                      "method",
                      "url",
                      "resource_type",
                      "header_names",
                      "kind",
                      "status",
                      "failure"
                    ],
                    "type": "object"
                  },
                  {
                    "additionalProperties": false,
                    "properties": {
                      "failure": {
                        "type": "null"
                      },
                      "header_names": {
                        "items": {
                          "type": "string"
                        },
                        "type": "array"
                      },
                      "kind": {
                        "const": "response",
                        "type": "string"
                      },
                      "method": {
                        "minLength": 1,
                        "type": "string"
                      },
                      "redirected_from_transaction_id": {
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
                      "redirected_from_transaction_state": {
                        "enum": [
                          "root",
                          "unknown"
                        ],
                        "type": "string"
                      },
                      "resource_type": {
                        "minLength": 1,
                        "type": "string"
                      },
                      "sequence": {
                        "maximum": 9007199254740991,
                        "minimum": 1,
                        "type": "integer"
                      },
                      "status": {
                        "description": "Current lifecycle or verification status.",
                        "maximum": 599,
                        "minimum": 100,
                        "type": "integer"
                      },
                      "step_index": {
                        "maximum": 9007199254740991,
                        "minimum": 0,
                        "type": "integer"
                      },
                      "transaction_id": {
                        "minLength": 1,
                        "type": "string"
                      },
                      "url": {
                        "properties": {
                          "origin": {
                            "anyOf": [
                              {
                                "type": "string"
                              },
                              {
                                "type": "null"
                              }
                            ]
                          },
                          "query_parameter_names": {
                            "items": {
                              "type": "string"
                            },
                            "type": "array"
                          },
                          "redacted": {
                            "type": "boolean"
                          },
                          "url": {
                            "type": "string"
                          }
                        },
                        "required": [
                          "url",
                          "origin",
                          "query_parameter_names",
                          "redacted"
                        ],
                        "type": "object"
                      }
                    },
                    "required": [
                      "sequence",
                      "step_index",
                      "transaction_id",
                      "redirected_from_transaction_id",
                      "method",
                      "url",
                      "resource_type",
                      "header_names",
                      "kind",
                      "status",
                      "failure"
                    ],
                    "type": "object"
                  },
                  {
                    "additionalProperties": false,
                    "properties": {
                      "failure": {
                        "minLength": 1,
                        "type": "string"
                      },
                      "header_names": {
                        "items": {
                          "type": "string"
                        },
                        "type": "array"
                      },
                      "kind": {
                        "const": "request-failed",
                        "type": "string"
                      },
                      "method": {
                        "minLength": 1,
                        "type": "string"
                      },
                      "redirected_from_transaction_id": {
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
                      "redirected_from_transaction_state": {
                        "enum": [
                          "root",
                          "unknown"
                        ],
                        "type": "string"
                      },
                      "resource_type": {
                        "minLength": 1,
                        "type": "string"
                      },
                      "sequence": {
                        "maximum": 9007199254740991,
                        "minimum": 1,
                        "type": "integer"
                      },
                      "status": {
                        "description": "Current lifecycle or verification status.",
                        "type": "null"
                      },
                      "step_index": {
                        "maximum": 9007199254740991,
                        "minimum": 0,
                        "type": "integer"
                      },
                      "transaction_id": {
                        "minLength": 1,
                        "type": "string"
                      },
                      "url": {
                        "properties": {
                          "origin": {
                            "anyOf": [
                              {
                                "type": "string"
                              },
                              {
                                "type": "null"
                              }
                            ]
                          },
                          "query_parameter_names": {
                            "items": {
                              "type": "string"
                            },
                            "type": "array"
                          },
                          "redacted": {
                            "type": "boolean"
                          },
                          "url": {
                            "type": "string"
                          }
                        },
                        "required": [
                          "url",
                          "origin",
                          "query_parameter_names",
                          "redacted"
                        ],
                        "type": "object"
                      }
                    },
                    "required": [
                      "sequence",
                      "step_index",
                      "transaction_id",
                      "redirected_from_transaction_id",
                      "method",
                      "url",
                      "resource_type",
                      "header_names",
                      "kind",
                      "status",
                      "failure"
                    ],
                    "type": "object"
                  },
                  {
                    "additionalProperties": false,
                    "properties": {
                      "failure": {
                        "type": "null"
                      },
                      "header_names": {
                        "items": {
                          "type": "string"
                        },
                        "type": "array"
                      },
                      "kind": {
                        "const": "request-finished",
                        "type": "string"
                      },
                      "method": {
                        "minLength": 1,
                        "type": "string"
                      },
                      "redirected_from_transaction_id": {
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
                      "redirected_from_transaction_state": {
                        "enum": [
                          "root",
                          "unknown"
                        ],
                        "type": "string"
                      },
                      "resource_type": {
                        "minLength": 1,
                        "type": "string"
                      },
                      "sequence": {
                        "maximum": 9007199254740991,
                        "minimum": 1,
                        "type": "integer"
                      },
                      "status": {
                        "description": "Current lifecycle or verification status.",
                        "type": "null"
                      },
                      "step_index": {
                        "maximum": 9007199254740991,
                        "minimum": 0,
                        "type": "integer"
                      },
                      "transaction_id": {
                        "minLength": 1,
                        "type": "string"
                      },
                      "url": {
                        "properties": {
                          "origin": {
                            "anyOf": [
                              {
                                "type": "string"
                              },
                              {
                                "type": "null"
                              }
                            ]
                          },
                          "query_parameter_names": {
                            "items": {
                              "type": "string"
                            },
                            "type": "array"
                          },
                          "redacted": {
                            "type": "boolean"
                          },
                          "url": {
                            "type": "string"
                          }
                        },
                        "required": [
                          "url",
                          "origin",
                          "query_parameter_names",
                          "redacted"
                        ],
                        "type": "object"
                      }
                    },
                    "required": [
                      "sequence",
                      "step_index",
                      "transaction_id",
                      "redirected_from_transaction_id",
                      "method",
                      "url",
                      "resource_type",
                      "header_names",
                      "kind",
                      "status",
                      "failure"
                    ],
                    "type": "object"
                  },
                  {
                    "additionalProperties": false,
                    "properties": {
                      "failure": {
                        "type": "null"
                      },
                      "header_names": {
                        "items": {
                          "type": "string"
                        },
                        "type": "array"
                      },
                      "kind": {
                        "const": "request-unfinished",
                        "type": "string"
                      },
                      "method": {
                        "minLength": 1,
                        "type": "string"
                      },
                      "reason": {
                        "enum": [
                          "capture-ended",
                          "cancelled"
                        ],
                        "type": "string"
                      },
                      "redirected_from_transaction_id": {
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
                      "redirected_from_transaction_state": {
                        "enum": [
                          "root",
                          "unknown"
                        ],
                        "type": "string"
                      },
                      "resource_type": {
                        "minLength": 1,
                        "type": "string"
                      },
                      "sequence": {
                        "maximum": 9007199254740991,
                        "minimum": 1,
                        "type": "integer"
                      },
                      "status": {
                        "description": "Current lifecycle or verification status.",
                        "type": "null"
                      },
                      "step_index": {
                        "maximum": 9007199254740991,
                        "minimum": 0,
                        "type": "integer"
                      },
                      "transaction_id": {
                        "minLength": 1,
                        "type": "string"
                      },
                      "url": {
                        "properties": {
                          "origin": {
                            "anyOf": [
                              {
                                "type": "string"
                              },
                              {
                                "type": "null"
                              }
                            ]
                          },
                          "query_parameter_names": {
                            "items": {
                              "type": "string"
                            },
                            "type": "array"
                          },
                          "redacted": {
                            "type": "boolean"
                          },
                          "url": {
                            "type": "string"
                          }
                        },
                        "required": [
                          "url",
                          "origin",
                          "query_parameter_names",
                          "redacted"
                        ],
                        "type": "object"
                      }
                    },
                    "required": [
                      "sequence",
                      "step_index",
                      "transaction_id",
                      "redirected_from_transaction_id",
                      "method",
                      "url",
                      "resource_type",
                      "header_names",
                      "kind",
                      "status",
                      "failure",
                      "reason"
                    ],
                    "type": "object"
                  },
                  {
                    "additionalProperties": false,
                    "properties": {
                      "body": {
                        "anyOf": [
                          {
                            "additionalProperties": false,
                            "properties": {
                              "state": {
                                "const": "not_requested",
                                "type": "string"
                              }
                            },
                            "required": [
                              "state"
                            ],
                            "type": "object"
                          },
                          {
                            "additionalProperties": false,
                            "properties": {
                              "state": {
                                "const": "not_exposed",
                                "type": "string"
                              }
                            },
                            "required": [
                              "state"
                            ],
                            "type": "object"
                          },
                          {
                            "additionalProperties": false,
                            "properties": {
                              "message": {
                                "minLength": 1,
                                "type": "string"
                              },
                              "reason": {
                                "enum": [
                                  "request-failed",
                                  "response-unfinished",
                                  "body-read-failed",
                                  "body-read-timeout",
                                  "cancelled",
                                  "capture-ended"
                                ],
                                "type": "string"
                              },
                              "state": {
                                "const": "unavailable",
                                "type": "string"
                              }
                            },
                            "required": [
                              "state",
                              "reason",
                              "message"
                            ],
                            "type": "object"
                          },
                          {
                            "additionalProperties": false,
                            "properties": {
                              "bytes": {
                                "maximum": 9007199254740991,
                                "minimum": 0,
                                "type": "integer"
                              },
                              "content": {
                                "type": "string"
                              },
                              "encoding": {
                                "const": "base64",
                                "type": "string"
                              },
                              "media_type": {
                                "anyOf": [
                                  {
                                    "type": "string"
                                  },
                                  {
                                    "type": "null"
                                  }
                                ]
                              },
                              "redacted": {
                                "type": "boolean"
                              },
                              "representation": {
                                "enum": [
                                  "browser-exposed-request-bytes",
                                  "playwright-response-body-bytes",
                                  "browser-decoded-response-bytes"
                                ],
                                "type": "string"
                              },
                              "sha256": {
                                "pattern": "^[a-f0-9]{64}$",
                                "type": "string"
                              },
                              "state": {
                                "const": "captured",
                                "type": "string"
                              }
                            },
                            "required": [
                              "state",
                              "representation",
                              "encoding",
                              "content",
                              "bytes",
                              "sha256",
                              "media_type",
                              "redacted"
                            ],
                            "type": "object"
                          }
                        ]
                      },
                      "headers": {
                        "anyOf": [
                          {
                            "additionalProperties": false,
                            "properties": {
                              "state": {
                                "const": "not_requested",
                                "type": "string"
                              }
                            },
                            "required": [
                              "state"
                            ],
                            "type": "object"
                          },
                          {
                            "additionalProperties": false,
                            "properties": {
                              "message": {
                                "minLength": 1,
                                "type": "string"
                              },
                              "state": {
                                "const": "unavailable",
                                "type": "string"
                              }
                            },
                            "required": [
                              "state",
                              "message"
                            ],
                            "type": "object"
                          },
                          {
                            "additionalProperties": false,
                            "properties": {
                              "items": {
                                "items": {
                                  "additionalProperties": false,
                                  "properties": {
                                    "name": {
                                      "description": "Exact name used by this operation.",
                                      "minLength": 1,
                                      "type": "string"
                                    },
                                    "redacted": {
                                      "type": "boolean"
                                    },
                                    "value": {
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
                                    "name",
                                    "value",
                                    "redacted"
                                  ],
                                  "type": "object"
                                },
                                "type": "array"
                              },
                              "state": {
                                "const": "captured",
                                "type": "string"
                              }
                            },
                            "required": [
                              "state",
                              "items"
                            ],
                            "type": "object"
                          }
                        ]
                      },
                      "kind": {
                        "const": "network-content",
                        "type": "string"
                      },
                      "phase": {
                        "description": "Current plan or execution phase of the operation.",
                        "enum": [
                          "request",
                          "response"
                        ],
                        "type": "string"
                      },
                      "sequence": {
                        "maximum": 9007199254740991,
                        "minimum": 1,
                        "type": "integer"
                      },
                      "source_event_sequence": {
                        "maximum": 9007199254740991,
                        "minimum": 1,
                        "type": "integer"
                      },
                      "step_index": {
                        "maximum": 9007199254740991,
                        "minimum": 0,
                        "type": "integer"
                      },
                      "transaction_id": {
                        "minLength": 1,
                        "type": "string"
                      }
                    },
                    "required": [
                      "sequence",
                      "step_index",
                      "kind",
                      "transaction_id",
                      "source_event_sequence",
                      "phase",
                      "headers",
                      "body"
                    ],
                    "type": "object"
                  },
                  {
                    "additionalProperties": false,
                    "properties": {
                      "kind": {
                        "enum": [
                          "websocket-opened",
                          "websocket-closed"
                        ],
                        "type": "string"
                      },
                      "sequence": {
                        "maximum": 9007199254740991,
                        "minimum": 1,
                        "type": "integer"
                      },
                      "step_index": {
                        "maximum": 9007199254740991,
                        "minimum": 0,
                        "type": "integer"
                      },
                      "url": {
                        "properties": {
                          "origin": {
                            "anyOf": [
                              {
                                "type": "string"
                              },
                              {
                                "type": "null"
                              }
                            ]
                          },
                          "query_parameter_names": {
                            "items": {
                              "type": "string"
                            },
                            "type": "array"
                          },
                          "redacted": {
                            "type": "boolean"
                          },
                          "url": {
                            "type": "string"
                          }
                        },
                        "required": [
                          "url",
                          "origin",
                          "query_parameter_names",
                          "redacted"
                        ],
                        "type": "object"
                      }
                    },
                    "required": [
                      "sequence",
                      "step_index",
                      "kind",
                      "url"
                    ],
                    "type": "object"
                  },
                  {
                    "additionalProperties": false,
                    "properties": {
                      "kind": {
                        "enum": [
                          "websocket-frame-sent",
                          "websocket-frame-received"
                        ],
                        "type": "string"
                      },
                      "payload_bytes": {
                        "description": "Byte count for payload.",
                        "maximum": 9007199254740991,
                        "minimum": 0,
                        "type": "integer"
                      },
                      "payload_text": {
                        "type": "string"
                      },
                      "payload_type": {
                        "const": "text",
                        "type": "string"
                      },
                      "sequence": {
                        "maximum": 9007199254740991,
                        "minimum": 1,
                        "type": "integer"
                      },
                      "step_index": {
                        "maximum": 9007199254740991,
                        "minimum": 0,
                        "type": "integer"
                      },
                      "truncated": {
                        "type": "boolean"
                      },
                      "url": {
                        "properties": {
                          "origin": {
                            "anyOf": [
                              {
                                "type": "string"
                              },
                              {
                                "type": "null"
                              }
                            ]
                          },
                          "query_parameter_names": {
                            "items": {
                              "type": "string"
                            },
                            "type": "array"
                          },
                          "redacted": {
                            "type": "boolean"
                          },
                          "url": {
                            "type": "string"
                          }
                        },
                        "required": [
                          "url",
                          "origin",
                          "query_parameter_names",
                          "redacted"
                        ],
                        "type": "object"
                      }
                    },
                    "required": [
                      "sequence",
                      "step_index",
                      "kind",
                      "url",
                      "payload_bytes",
                      "truncated",
                      "payload_type",
                      "payload_text"
                    ],
                    "type": "object"
                  },
                  {
                    "additionalProperties": false,
                    "properties": {
                      "kind": {
                        "enum": [
                          "websocket-frame-sent",
                          "websocket-frame-received"
                        ],
                        "type": "string"
                      },
                      "payload_bytes": {
                        "description": "Byte count for payload.",
                        "maximum": 9007199254740991,
                        "minimum": 0,
                        "type": "integer"
                      },
                      "payload_text": {
                        "type": "null"
                      },
                      "payload_type": {
                        "const": "binary",
                        "type": "string"
                      },
                      "sequence": {
                        "maximum": 9007199254740991,
                        "minimum": 1,
                        "type": "integer"
                      },
                      "step_index": {
                        "maximum": 9007199254740991,
                        "minimum": 0,
                        "type": "integer"
                      },
                      "truncated": {
                        "type": "boolean"
                      },
                      "url": {
                        "properties": {
                          "origin": {
                            "anyOf": [
                              {
                                "type": "string"
                              },
                              {
                                "type": "null"
                              }
                            ]
                          },
                          "query_parameter_names": {
                            "items": {
                              "type": "string"
                            },
                            "type": "array"
                          },
                          "redacted": {
                            "type": "boolean"
                          },
                          "url": {
                            "type": "string"
                          }
                        },
                        "required": [
                          "url",
                          "origin",
                          "query_parameter_names",
                          "redacted"
                        ],
                        "type": "object"
                      }
                    },
                    "required": [
                      "sequence",
                      "step_index",
                      "kind",
                      "url",
                      "payload_bytes",
                      "truncated",
                      "payload_type",
                      "payload_text"
                    ],
                    "type": "object"
                  },
                  {
                    "additionalProperties": false,
                    "properties": {
                      "kind": {
                        "enum": [
                          "frame-attached",
                          "frame-detached",
                          "frame-navigated",
                          "worker-created",
                          "worker-closed",
                          "popup-opened",
                          "popup-closed"
                        ],
                        "type": "string"
                      },
                      "name": {
                        "anyOf": [
                          {
                            "type": "string"
                          },
                          {
                            "type": "null"
                          }
                        ],
                        "description": "Exact name used by this operation."
                      },
                      "sequence": {
                        "maximum": 9007199254740991,
                        "minimum": 1,
                        "type": "integer"
                      },
                      "step_index": {
                        "maximum": 9007199254740991,
                        "minimum": 0,
                        "type": "integer"
                      },
                      "url": {
                        "anyOf": [
                          {
                            "properties": {
                              "origin": {
                                "anyOf": [
                                  {
                                    "type": "string"
                                  },
                                  {
                                    "type": "null"
                                  }
                                ]
                              },
                              "query_parameter_names": {
                                "items": {
                                  "type": "string"
                                },
                                "type": "array"
                              },
                              "redacted": {
                                "type": "boolean"
                              },
                              "url": {
                                "type": "string"
                              }
                            },
                            "required": [
                              "url",
                              "origin",
                              "query_parameter_names",
                              "redacted"
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
                      "sequence",
                      "step_index",
                      "kind",
                      "url",
                      "name"
                    ],
                    "type": "object"
                  },
                  {
                    "additionalProperties": false,
                    "properties": {
                      "kind": {
                        "const": "download-cancelled",
                        "type": "string"
                      },
                      "sequence": {
                        "maximum": 9007199254740991,
                        "minimum": 1,
                        "type": "integer"
                      },
                      "step_index": {
                        "maximum": 9007199254740991,
                        "minimum": 0,
                        "type": "integer"
                      },
                      "suggested_filename": {
                        "type": "string"
                      },
                      "url": {
                        "properties": {
                          "origin": {
                            "anyOf": [
                              {
                                "type": "string"
                              },
                              {
                                "type": "null"
                              }
                            ]
                          },
                          "query_parameter_names": {
                            "items": {
                              "type": "string"
                            },
                            "type": "array"
                          },
                          "redacted": {
                            "type": "boolean"
                          },
                          "url": {
                            "type": "string"
                          }
                        },
                        "required": [
                          "url",
                          "origin",
                          "query_parameter_names",
                          "redacted"
                        ],
                        "type": "object"
                      }
                    },
                    "required": [
                      "sequence",
                      "step_index",
                      "kind",
                      "suggested_filename",
                      "url"
                    ],
                    "type": "object"
                  }
                ]
              },
              "type": "array"
            },
            "retained": {
              "maximum": 9007199254740991,
              "minimum": 0,
              "type": "integer"
            }
          },
          "required": [
            "retained",
            "dropped",
            "items"
          ],
          "type": "object"
        },
        "limitations": {
          "items": {
            "minLength": 1,
            "type": "string"
          },
          "type": "array"
        },
        "scenario": {
          "additionalProperties": false,
          "properties": {
            "action_count": {
              "maximum": 9007199254740991,
              "minimum": 1,
              "type": "integer"
            },
            "event_families": {
              "items": {
                "enum": [
                  "console",
                  "page-errors",
                  "network",
                  "websockets",
                  "frames",
                  "workers",
                  "popups",
                  "downloads"
                ],
                "type": "string"
              },
              "type": "array"
            },
            "network_content": {
              "additionalProperties": false,
              "properties": {
                "header_values": {
                  "type": "boolean"
                },
                "request_body": {
                  "type": "boolean"
                },
                "response_body": {
                  "type": "boolean"
                }
              },
              "required": [
                "request_body",
                "response_body",
                "header_values"
              ],
              "type": "object"
            },
            "secret_references": {
              "items": {
                "minLength": 1,
                "type": "string"
              },
              "type": "array"
            },
            "start_origin": {
              "minLength": 1,
              "type": "string"
            }
          },
          "required": [
            "start_origin",
            "action_count",
            "secret_references",
            "network_content"
          ],
          "type": "object"
        },
        "steps": {
          "items": {
            "anyOf": [
              {
                "additionalProperties": false,
                "properties": {
                  "action": {
                    "minLength": 1,
                    "type": "string"
                  },
                  "after_url": {
                    "properties": {
                      "origin": {
                        "anyOf": [
                          {
                            "type": "string"
                          },
                          {
                            "type": "null"
                          }
                        ]
                      },
                      "query_parameter_names": {
                        "items": {
                          "type": "string"
                        },
                        "type": "array"
                      },
                      "redacted": {
                        "type": "boolean"
                      },
                      "url": {
                        "type": "string"
                      }
                    },
                    "required": [
                      "url",
                      "origin",
                      "query_parameter_names",
                      "redacted"
                    ],
                    "type": "object"
                  },
                  "artifacts": {
                    "additionalProperties": false,
                    "properties": {
                      "accessibility": {
                        "oneOf": [
                          {
                            "additionalProperties": false,
                            "properties": {
                              "state": {
                                "const": "captured",
                                "type": "string"
                              },
                              "value": {
                                "additionalProperties": false,
                                "properties": {
                                  "bytes": {
                                    "maximum": 9007199254740991,
                                    "minimum": 0,
                                    "type": "integer"
                                  },
                                  "sha256": {
                                    "pattern": "^[a-f0-9]{64}$",
                                    "type": "string"
                                  },
                                  "text": {
                                    "type": "string"
                                  }
                                },
                                "required": [
                                  "sha256",
                                  "bytes",
                                  "text"
                                ],
                                "type": "object"
                              }
                            },
                            "required": [
                              "state",
                              "value"
                            ],
                            "type": "object"
                          },
                          {
                            "additionalProperties": false,
                            "properties": {
                              "state": {
                                "const": "not_requested",
                                "type": "string"
                              }
                            },
                            "required": [
                              "state"
                            ],
                            "type": "object"
                          },
                          {
                            "additionalProperties": false,
                            "properties": {
                              "reason": {
                                "minLength": 1,
                                "type": "string"
                              },
                              "state": {
                                "const": "missing",
                                "type": "string"
                              }
                            },
                            "required": [
                              "state",
                              "reason"
                            ],
                            "type": "object"
                          },
                          {
                            "additionalProperties": false,
                            "properties": {
                              "observed": {
                                "maximum": 9007199254740991,
                                "minimum": 0,
                                "type": "integer"
                              },
                              "reason": {
                                "minLength": 1,
                                "type": "string"
                              },
                              "retained": {
                                "maximum": 9007199254740991,
                                "minimum": 0,
                                "type": "integer"
                              },
                              "state": {
                                "const": "truncated",
                                "type": "string"
                              }
                            },
                            "required": [
                              "state",
                              "observed",
                              "retained",
                              "reason"
                            ],
                            "type": "object"
                          }
                        ]
                      },
                      "dom": {
                        "oneOf": [
                          {
                            "additionalProperties": false,
                            "properties": {
                              "state": {
                                "const": "captured",
                                "type": "string"
                              },
                              "value": {
                                "additionalProperties": false,
                                "properties": {
                                  "bytes": {
                                    "maximum": 9007199254740991,
                                    "minimum": 0,
                                    "type": "integer"
                                  },
                                  "sha256": {
                                    "pattern": "^[a-f0-9]{64}$",
                                    "type": "string"
                                  },
                                  "text": {
                                    "type": "string"
                                  }
                                },
                                "required": [
                                  "sha256",
                                  "bytes",
                                  "text"
                                ],
                                "type": "object"
                              }
                            },
                            "required": [
                              "state",
                              "value"
                            ],
                            "type": "object"
                          },
                          {
                            "additionalProperties": false,
                            "properties": {
                              "state": {
                                "const": "not_requested",
                                "type": "string"
                              }
                            },
                            "required": [
                              "state"
                            ],
                            "type": "object"
                          },
                          {
                            "additionalProperties": false,
                            "properties": {
                              "reason": {
                                "minLength": 1,
                                "type": "string"
                              },
                              "state": {
                                "const": "missing",
                                "type": "string"
                              }
                            },
                            "required": [
                              "state",
                              "reason"
                            ],
                            "type": "object"
                          },
                          {
                            "additionalProperties": false,
                            "properties": {
                              "observed": {
                                "maximum": 9007199254740991,
                                "minimum": 0,
                                "type": "integer"
                              },
                              "reason": {
                                "minLength": 1,
                                "type": "string"
                              },
                              "retained": {
                                "maximum": 9007199254740991,
                                "minimum": 0,
                                "type": "integer"
                              },
                              "state": {
                                "const": "truncated",
                                "type": "string"
                              }
                            },
                            "required": [
                              "state",
                              "observed",
                              "retained",
                              "reason"
                            ],
                            "type": "object"
                          }
                        ]
                      },
                      "history": {
                        "oneOf": [
                          {
                            "additionalProperties": false,
                            "properties": {
                              "state": {
                                "const": "captured",
                                "type": "string"
                              },
                              "value": {
                                "additionalProperties": false,
                                "properties": {
                                  "current_url": {
                                    "properties": {
                                      "origin": {
                                        "anyOf": [
                                          {
                                            "type": "string"
                                          },
                                          {
                                            "type": "null"
                                          }
                                        ]
                                      },
                                      "query_parameter_names": {
                                        "items": {
                                          "type": "string"
                                        },
                                        "type": "array"
                                      },
                                      "redacted": {
                                        "type": "boolean"
                                      },
                                      "url": {
                                        "type": "string"
                                      }
                                    },
                                    "required": [
                                      "url",
                                      "origin",
                                      "query_parameter_names",
                                      "redacted"
                                    ],
                                    "type": "object"
                                  },
                                  "length": {
                                    "maximum": 9007199254740991,
                                    "minimum": 0,
                                    "type": "integer"
                                  },
                                  "navigation_entries": {
                                    "items": {
                                      "additionalProperties": false,
                                      "properties": {
                                        "name": {
                                          "description": "Exact name used by this operation.",
                                          "properties": {
                                            "origin": {
                                              "anyOf": [
                                                {
                                                  "type": "string"
                                                },
                                                {
                                                  "type": "null"
                                                }
                                              ]
                                            },
                                            "query_parameter_names": {
                                              "items": {
                                                "type": "string"
                                              },
                                              "type": "array"
                                            },
                                            "redacted": {
                                              "type": "boolean"
                                            },
                                            "url": {
                                              "type": "string"
                                            }
                                          },
                                          "required": [
                                            "url",
                                            "origin",
                                            "query_parameter_names",
                                            "redacted"
                                          ],
                                          "type": "object"
                                        },
                                        "type": {
                                          "enum": [
                                            "navigate",
                                            "reload",
                                            "back_forward",
                                            "prerender",
                                            "unknown"
                                          ],
                                          "type": "string"
                                        }
                                      },
                                      "required": [
                                        "type",
                                        "name"
                                      ],
                                      "type": "object"
                                    },
                                    "type": "array"
                                  }
                                },
                                "required": [
                                  "length",
                                  "current_url",
                                  "navigation_entries"
                                ],
                                "type": "object"
                              }
                            },
                            "required": [
                              "state",
                              "value"
                            ],
                            "type": "object"
                          },
                          {
                            "additionalProperties": false,
                            "properties": {
                              "state": {
                                "const": "not_requested",
                                "type": "string"
                              }
                            },
                            "required": [
                              "state"
                            ],
                            "type": "object"
                          },
                          {
                            "additionalProperties": false,
                            "properties": {
                              "reason": {
                                "minLength": 1,
                                "type": "string"
                              },
                              "state": {
                                "const": "missing",
                                "type": "string"
                              }
                            },
                            "required": [
                              "state",
                              "reason"
                            ],
                            "type": "object"
                          },
                          {
                            "additionalProperties": false,
                            "properties": {
                              "observed": {
                                "maximum": 9007199254740991,
                                "minimum": 0,
                                "type": "integer"
                              },
                              "reason": {
                                "minLength": 1,
                                "type": "string"
                              },
                              "retained": {
                                "maximum": 9007199254740991,
                                "minimum": 0,
                                "type": "integer"
                              },
                              "state": {
                                "const": "truncated",
                                "type": "string"
                              }
                            },
                            "required": [
                              "state",
                              "observed",
                              "retained",
                              "reason"
                            ],
                            "type": "object"
                          }
                        ]
                      },
                      "screenshot": {
                        "oneOf": [
                          {
                            "additionalProperties": false,
                            "properties": {
                              "state": {
                                "const": "captured",
                                "type": "string"
                              },
                              "value": {
                                "properties": {
                                  "bytes": {
                                    "maximum": 9007199254740991,
                                    "minimum": 1,
                                    "type": "integer"
                                  },
                                  "data_base64": {
                                    "type": "string"
                                  },
                                  "media_type": {
                                    "const": "image/png",
                                    "type": "string"
                                  },
                                  "sha256": {
                                    "pattern": "^[a-f0-9]{64}$",
                                    "type": "string"
                                  }
                                },
                                "required": [
                                  "sha256",
                                  "bytes",
                                  "media_type",
                                  "data_base64"
                                ],
                                "type": "object"
                              }
                            },
                            "required": [
                              "state",
                              "value"
                            ],
                            "type": "object"
                          },
                          {
                            "additionalProperties": false,
                            "properties": {
                              "state": {
                                "const": "not_requested",
                                "type": "string"
                              }
                            },
                            "required": [
                              "state"
                            ],
                            "type": "object"
                          },
                          {
                            "additionalProperties": false,
                            "properties": {
                              "reason": {
                                "minLength": 1,
                                "type": "string"
                              },
                              "state": {
                                "const": "missing",
                                "type": "string"
                              }
                            },
                            "required": [
                              "state",
                              "reason"
                            ],
                            "type": "object"
                          },
                          {
                            "additionalProperties": false,
                            "properties": {
                              "observed": {
                                "maximum": 9007199254740991,
                                "minimum": 0,
                                "type": "integer"
                              },
                              "reason": {
                                "minLength": 1,
                                "type": "string"
                              },
                              "retained": {
                                "maximum": 9007199254740991,
                                "minimum": 0,
                                "type": "integer"
                              },
                              "state": {
                                "const": "truncated",
                                "type": "string"
                              }
                            },
                            "required": [
                              "state",
                              "observed",
                              "retained",
                              "reason"
                            ],
                            "type": "object"
                          }
                        ]
                      },
                      "storage": {
                        "oneOf": [
                          {
                            "additionalProperties": false,
                            "properties": {
                              "state": {
                                "const": "captured",
                                "type": "string"
                              },
                              "value": {
                                "additionalProperties": false,
                                "properties": {
                                  "cookies": {
                                    "items": {
                                      "oneOf": [
                                        {
                                          "additionalProperties": false,
                                          "properties": {
                                            "domain": {
                                              "type": "string"
                                            },
                                            "http_only": {
                                              "type": "boolean"
                                            },
                                            "name": {
                                              "description": "Exact name used by this operation.",
                                              "type": "string"
                                            },
                                            "path": {
                                              "description": "Local filesystem path used by this operation.",
                                              "type": "string"
                                            },
                                            "same_site": {
                                              "enum": [
                                                "Strict",
                                                "Lax",
                                                "None"
                                              ],
                                              "type": "string"
                                            },
                                            "secure": {
                                              "type": "boolean"
                                            },
                                            "value_sha256": {
                                              "description": "Exact SHA-256 digest of value.",
                                              "pattern": "^[a-f0-9]{64}$",
                                              "type": "string"
                                            },
                                            "value_state": {
                                              "const": "hashed",
                                              "type": "string"
                                            }
                                          },
                                          "required": [
                                            "name",
                                            "domain",
                                            "path",
                                            "secure",
                                            "http_only",
                                            "same_site",
                                            "value_state",
                                            "value_sha256"
                                          ],
                                          "type": "object"
                                        },
                                        {
                                          "additionalProperties": false,
                                          "properties": {
                                            "domain": {
                                              "type": "string"
                                            },
                                            "http_only": {
                                              "type": "boolean"
                                            },
                                            "name": {
                                              "description": "Exact name used by this operation.",
                                              "type": "string"
                                            },
                                            "path": {
                                              "description": "Local filesystem path used by this operation.",
                                              "type": "string"
                                            },
                                            "same_site": {
                                              "enum": [
                                                "Strict",
                                                "Lax",
                                                "None"
                                              ],
                                              "type": "string"
                                            },
                                            "secure": {
                                              "type": "boolean"
                                            },
                                            "value_sha256": {
                                              "description": "Exact SHA-256 digest of value.",
                                              "type": "null"
                                            },
                                            "value_state": {
                                              "const": "redacted-secret",
                                              "type": "string"
                                            }
                                          },
                                          "required": [
                                            "name",
                                            "domain",
                                            "path",
                                            "secure",
                                            "http_only",
                                            "same_site",
                                            "value_state",
                                            "value_sha256"
                                          ],
                                          "type": "object"
                                        }
                                      ]
                                    },
                                    "type": "array"
                                  },
                                  "local_storage": {
                                    "items": {
                                      "oneOf": [
                                        {
                                          "additionalProperties": false,
                                          "properties": {
                                            "name": {
                                              "description": "Exact name used by this operation.",
                                              "type": "string"
                                            },
                                            "value_sha256": {
                                              "description": "Exact SHA-256 digest of value.",
                                              "pattern": "^[a-f0-9]{64}$",
                                              "type": "string"
                                            },
                                            "value_state": {
                                              "const": "hashed",
                                              "type": "string"
                                            }
                                          },
                                          "required": [
                                            "name",
                                            "value_state",
                                            "value_sha256"
                                          ],
                                          "type": "object"
                                        },
                                        {
                                          "additionalProperties": false,
                                          "properties": {
                                            "name": {
                                              "description": "Exact name used by this operation.",
                                              "type": "string"
                                            },
                                            "value_sha256": {
                                              "description": "Exact SHA-256 digest of value.",
                                              "type": "null"
                                            },
                                            "value_state": {
                                              "const": "redacted-secret",
                                              "type": "string"
                                            }
                                          },
                                          "required": [
                                            "name",
                                            "value_state",
                                            "value_sha256"
                                          ],
                                          "type": "object"
                                        }
                                      ]
                                    },
                                    "type": "array"
                                  },
                                  "session_storage": {
                                    "items": {
                                      "oneOf": [
                                        {
                                          "additionalProperties": false,
                                          "properties": {
                                            "name": {
                                              "description": "Exact name used by this operation.",
                                              "type": "string"
                                            },
                                            "value_sha256": {
                                              "description": "Exact SHA-256 digest of value.",
                                              "pattern": "^[a-f0-9]{64}$",
                                              "type": "string"
                                            },
                                            "value_state": {
                                              "const": "hashed",
                                              "type": "string"
                                            }
                                          },
                                          "required": [
                                            "name",
                                            "value_state",
                                            "value_sha256"
                                          ],
                                          "type": "object"
                                        },
                                        {
                                          "additionalProperties": false,
                                          "properties": {
                                            "name": {
                                              "description": "Exact name used by this operation.",
                                              "type": "string"
                                            },
                                            "value_sha256": {
                                              "description": "Exact SHA-256 digest of value.",
                                              "type": "null"
                                            },
                                            "value_state": {
                                              "const": "redacted-secret",
                                              "type": "string"
                                            }
                                          },
                                          "required": [
                                            "name",
                                            "value_state",
                                            "value_sha256"
                                          ],
                                          "type": "object"
                                        }
                                      ]
                                    },
                                    "type": "array"
                                  }
                                },
                                "required": [
                                  "cookies",
                                  "local_storage",
                                  "session_storage"
                                ],
                                "type": "object"
                              }
                            },
                            "required": [
                              "state",
                              "value"
                            ],
                            "type": "object"
                          },
                          {
                            "additionalProperties": false,
                            "properties": {
                              "state": {
                                "const": "not_requested",
                                "type": "string"
                              }
                            },
                            "required": [
                              "state"
                            ],
                            "type": "object"
                          },
                          {
                            "additionalProperties": false,
                            "properties": {
                              "reason": {
                                "minLength": 1,
                                "type": "string"
                              },
                              "state": {
                                "const": "missing",
                                "type": "string"
                              }
                            },
                            "required": [
                              "state",
                              "reason"
                            ],
                            "type": "object"
                          },
                          {
                            "additionalProperties": false,
                            "properties": {
                              "observed": {
                                "maximum": 9007199254740991,
                                "minimum": 0,
                                "type": "integer"
                              },
                              "reason": {
                                "minLength": 1,
                                "type": "string"
                              },
                              "retained": {
                                "maximum": 9007199254740991,
                                "minimum": 0,
                                "type": "integer"
                              },
                              "state": {
                                "const": "truncated",
                                "type": "string"
                              }
                            },
                            "required": [
                              "state",
                              "observed",
                              "retained",
                              "reason"
                            ],
                            "type": "object"
                          }
                        ]
                      },
                      "url": {
                        "oneOf": [
                          {
                            "additionalProperties": false,
                            "properties": {
                              "state": {
                                "const": "captured",
                                "type": "string"
                              },
                              "value": {
                                "properties": {
                                  "origin": {
                                    "anyOf": [
                                      {
                                        "type": "string"
                                      },
                                      {
                                        "type": "null"
                                      }
                                    ]
                                  },
                                  "query_parameter_names": {
                                    "items": {
                                      "type": "string"
                                    },
                                    "type": "array"
                                  },
                                  "redacted": {
                                    "type": "boolean"
                                  },
                                  "url": {
                                    "type": "string"
                                  }
                                },
                                "required": [
                                  "url",
                                  "origin",
                                  "query_parameter_names",
                                  "redacted"
                                ],
                                "type": "object"
                              }
                            },
                            "required": [
                              "state",
                              "value"
                            ],
                            "type": "object"
                          },
                          {
                            "additionalProperties": false,
                            "properties": {
                              "state": {
                                "const": "not_requested",
                                "type": "string"
                              }
                            },
                            "required": [
                              "state"
                            ],
                            "type": "object"
                          },
                          {
                            "additionalProperties": false,
                            "properties": {
                              "reason": {
                                "minLength": 1,
                                "type": "string"
                              },
                              "state": {
                                "const": "missing",
                                "type": "string"
                              }
                            },
                            "required": [
                              "state",
                              "reason"
                            ],
                            "type": "object"
                          },
                          {
                            "additionalProperties": false,
                            "properties": {
                              "observed": {
                                "maximum": 9007199254740991,
                                "minimum": 0,
                                "type": "integer"
                              },
                              "reason": {
                                "minLength": 1,
                                "type": "string"
                              },
                              "retained": {
                                "maximum": 9007199254740991,
                                "minimum": 0,
                                "type": "integer"
                              },
                              "state": {
                                "const": "truncated",
                                "type": "string"
                              }
                            },
                            "required": [
                              "state",
                              "observed",
                              "retained",
                              "reason"
                            ],
                            "type": "object"
                          }
                        ]
                      }
                    },
                    "required": [
                      "screenshot",
                      "dom",
                      "accessibility",
                      "url",
                      "history",
                      "storage"
                    ],
                    "type": "object"
                  },
                  "before_url": {
                    "properties": {
                      "origin": {
                        "anyOf": [
                          {
                            "type": "string"
                          },
                          {
                            "type": "null"
                          }
                        ]
                      },
                      "query_parameter_names": {
                        "items": {
                          "type": "string"
                        },
                        "type": "array"
                      },
                      "redacted": {
                        "type": "boolean"
                      },
                      "url": {
                        "type": "string"
                      }
                    },
                    "required": [
                      "url",
                      "origin",
                      "query_parameter_names",
                      "redacted"
                    ],
                    "type": "object"
                  },
                  "completeness": {
                    "oneOf": [
                      {
                        "additionalProperties": false,
                        "properties": {
                          "equality_eligible": {
                            "const": true,
                            "type": "boolean"
                          },
                          "missing_sections": {
                            "items": {
                              "not": {}
                            },
                            "maxItems": 0,
                            "minItems": 0,
                            "type": "array"
                          },
                          "status": {
                            "const": "complete",
                            "description": "Current lifecycle or verification status.",
                            "type": "string"
                          },
                          "truncated_sections": {
                            "items": {
                              "not": {}
                            },
                            "maxItems": 0,
                            "minItems": 0,
                            "type": "array"
                          }
                        },
                        "required": [
                          "status",
                          "equality_eligible",
                          "missing_sections",
                          "truncated_sections"
                        ],
                        "type": "object"
                      },
                      {
                        "additionalProperties": false,
                        "properties": {
                          "equality_eligible": {
                            "const": false,
                            "type": "boolean"
                          },
                          "missing_sections": {
                            "items": {
                              "enum": [
                                "action",
                                "screenshot",
                                "dom",
                                "accessibility",
                                "url",
                                "history",
                                "storage",
                                "events",
                                "frames",
                                "workers",
                                "popups",
                                "websockets"
                              ],
                              "type": "string"
                            },
                            "minItems": 1,
                            "type": "array"
                          },
                          "status": {
                            "const": "incomplete",
                            "description": "Current lifecycle or verification status.",
                            "type": "string"
                          },
                          "truncated_sections": {
                            "items": {
                              "not": {}
                            },
                            "maxItems": 0,
                            "minItems": 0,
                            "type": "array"
                          }
                        },
                        "required": [
                          "status",
                          "equality_eligible",
                          "missing_sections",
                          "truncated_sections"
                        ],
                        "type": "object"
                      },
                      {
                        "additionalProperties": false,
                        "properties": {
                          "equality_eligible": {
                            "const": false,
                            "type": "boolean"
                          },
                          "missing_sections": {
                            "items": {
                              "enum": [
                                "action",
                                "screenshot",
                                "dom",
                                "accessibility",
                                "url",
                                "history",
                                "storage",
                                "events",
                                "frames",
                                "workers",
                                "popups",
                                "websockets"
                              ],
                              "type": "string"
                            },
                            "type": "array"
                          },
                          "status": {
                            "const": "truncated",
                            "description": "Current lifecycle or verification status.",
                            "type": "string"
                          },
                          "truncated_sections": {
                            "items": {
                              "enum": [
                                "action",
                                "screenshot",
                                "dom",
                                "accessibility",
                                "url",
                                "history",
                                "storage",
                                "events",
                                "frames",
                                "workers",
                                "popups",
                                "websockets"
                              ],
                              "type": "string"
                            },
                            "minItems": 1,
                            "type": "array"
                          }
                        },
                        "required": [
                          "status",
                          "equality_eligible",
                          "missing_sections",
                          "truncated_sections"
                        ],
                        "type": "object"
                      }
                    ]
                  },
                  "elapsed_ms": {
                    "maximum": 9007199254740991,
                    "minimum": 0,
                    "type": "integer"
                  },
                  "error": {
                    "description": "Structured, caller-actionable error when the operation fails.",
                    "type": "null"
                  },
                  "event_sequence_end": {
                    "maximum": 9007199254740991,
                    "minimum": 0,
                    "type": "integer"
                  },
                  "event_sequence_start": {
                    "maximum": 9007199254740991,
                    "minimum": 1,
                    "type": "integer"
                  },
                  "status": {
                    "const": "completed",
                    "description": "Current lifecycle or verification status.",
                    "type": "string"
                  },
                  "step_id": {
                    "minLength": 1,
                    "type": "string"
                  },
                  "step_index": {
                    "maximum": 9007199254740991,
                    "minimum": 0,
                    "type": "integer"
                  }
                },
                "required": [
                  "step_index",
                  "step_id",
                  "action",
                  "elapsed_ms",
                  "before_url",
                  "after_url",
                  "event_sequence_start",
                  "event_sequence_end",
                  "artifacts",
                  "completeness",
                  "status",
                  "error"
                ],
                "type": "object"
              },
              {
                "additionalProperties": false,
                "properties": {
                  "action": {
                    "minLength": 1,
                    "type": "string"
                  },
                  "after_url": {
                    "properties": {
                      "origin": {
                        "anyOf": [
                          {
                            "type": "string"
                          },
                          {
                            "type": "null"
                          }
                        ]
                      },
                      "query_parameter_names": {
                        "items": {
                          "type": "string"
                        },
                        "type": "array"
                      },
                      "redacted": {
                        "type": "boolean"
                      },
                      "url": {
                        "type": "string"
                      }
                    },
                    "required": [
                      "url",
                      "origin",
                      "query_parameter_names",
                      "redacted"
                    ],
                    "type": "object"
                  },
                  "artifacts": {
                    "additionalProperties": false,
                    "properties": {
                      "accessibility": {
                        "oneOf": [
                          {
                            "additionalProperties": false,
                            "properties": {
                              "state": {
                                "const": "captured",
                                "type": "string"
                              },
                              "value": {
                                "additionalProperties": false,
                                "properties": {
                                  "bytes": {
                                    "maximum": 9007199254740991,
                                    "minimum": 0,
                                    "type": "integer"
                                  },
                                  "sha256": {
                                    "pattern": "^[a-f0-9]{64}$",
                                    "type": "string"
                                  },
                                  "text": {
                                    "type": "string"
                                  }
                                },
                                "required": [
                                  "sha256",
                                  "bytes",
                                  "text"
                                ],
                                "type": "object"
                              }
                            },
                            "required": [
                              "state",
                              "value"
                            ],
                            "type": "object"
                          },
                          {
                            "additionalProperties": false,
                            "properties": {
                              "state": {
                                "const": "not_requested",
                                "type": "string"
                              }
                            },
                            "required": [
                              "state"
                            ],
                            "type": "object"
                          },
                          {
                            "additionalProperties": false,
                            "properties": {
                              "reason": {
                                "minLength": 1,
                                "type": "string"
                              },
                              "state": {
                                "const": "missing",
                                "type": "string"
                              }
                            },
                            "required": [
                              "state",
                              "reason"
                            ],
                            "type": "object"
                          },
                          {
                            "additionalProperties": false,
                            "properties": {
                              "observed": {
                                "maximum": 9007199254740991,
                                "minimum": 0,
                                "type": "integer"
                              },
                              "reason": {
                                "minLength": 1,
                                "type": "string"
                              },
                              "retained": {
                                "maximum": 9007199254740991,
                                "minimum": 0,
                                "type": "integer"
                              },
                              "state": {
                                "const": "truncated",
                                "type": "string"
                              }
                            },
                            "required": [
                              "state",
                              "observed",
                              "retained",
                              "reason"
                            ],
                            "type": "object"
                          }
                        ]
                      },
                      "dom": {
                        "oneOf": [
                          {
                            "additionalProperties": false,
                            "properties": {
                              "state": {
                                "const": "captured",
                                "type": "string"
                              },
                              "value": {
                                "additionalProperties": false,
                                "properties": {
                                  "bytes": {
                                    "maximum": 9007199254740991,
                                    "minimum": 0,
                                    "type": "integer"
                                  },
                                  "sha256": {
                                    "pattern": "^[a-f0-9]{64}$",
                                    "type": "string"
                                  },
                                  "text": {
                                    "type": "string"
                                  }
                                },
                                "required": [
                                  "sha256",
                                  "bytes",
                                  "text"
                                ],
                                "type": "object"
                              }
                            },
                            "required": [
                              "state",
                              "value"
                            ],
                            "type": "object"
                          },
                          {
                            "additionalProperties": false,
                            "properties": {
                              "state": {
                                "const": "not_requested",
                                "type": "string"
                              }
                            },
                            "required": [
                              "state"
                            ],
                            "type": "object"
                          },
                          {
                            "additionalProperties": false,
                            "properties": {
                              "reason": {
                                "minLength": 1,
                                "type": "string"
                              },
                              "state": {
                                "const": "missing",
                                "type": "string"
                              }
                            },
                            "required": [
                              "state",
                              "reason"
                            ],
                            "type": "object"
                          },
                          {
                            "additionalProperties": false,
                            "properties": {
                              "observed": {
                                "maximum": 9007199254740991,
                                "minimum": 0,
                                "type": "integer"
                              },
                              "reason": {
                                "minLength": 1,
                                "type": "string"
                              },
                              "retained": {
                                "maximum": 9007199254740991,
                                "minimum": 0,
                                "type": "integer"
                              },
                              "state": {
                                "const": "truncated",
                                "type": "string"
                              }
                            },
                            "required": [
                              "state",
                              "observed",
                              "retained",
                              "reason"
                            ],
                            "type": "object"
                          }
                        ]
                      },
                      "history": {
                        "oneOf": [
                          {
                            "additionalProperties": false,
                            "properties": {
                              "state": {
                                "const": "captured",
                                "type": "string"
                              },
                              "value": {
                                "additionalProperties": false,
                                "properties": {
                                  "current_url": {
                                    "properties": {
                                      "origin": {
                                        "anyOf": [
                                          {
                                            "type": "string"
                                          },
                                          {
                                            "type": "null"
                                          }
                                        ]
                                      },
                                      "query_parameter_names": {
                                        "items": {
                                          "type": "string"
                                        },
                                        "type": "array"
                                      },
                                      "redacted": {
                                        "type": "boolean"
                                      },
                                      "url": {
                                        "type": "string"
                                      }
                                    },
                                    "required": [
                                      "url",
                                      "origin",
                                      "query_parameter_names",
                                      "redacted"
                                    ],
                                    "type": "object"
                                  },
                                  "length": {
                                    "maximum": 9007199254740991,
                                    "minimum": 0,
                                    "type": "integer"
                                  },
                                  "navigation_entries": {
                                    "items": {
                                      "additionalProperties": false,
                                      "properties": {
                                        "name": {
                                          "description": "Exact name used by this operation.",
                                          "properties": {
                                            "origin": {
                                              "anyOf": [
                                                {
                                                  "type": "string"
                                                },
                                                {
                                                  "type": "null"
                                                }
                                              ]
                                            },
                                            "query_parameter_names": {
                                              "items": {
                                                "type": "string"
                                              },
                                              "type": "array"
                                            },
                                            "redacted": {
                                              "type": "boolean"
                                            },
                                            "url": {
                                              "type": "string"
                                            }
                                          },
                                          "required": [
                                            "url",
                                            "origin",
                                            "query_parameter_names",
                                            "redacted"
                                          ],
                                          "type": "object"
                                        },
                                        "type": {
                                          "enum": [
                                            "navigate",
                                            "reload",
                                            "back_forward",
                                            "prerender",
                                            "unknown"
                                          ],
                                          "type": "string"
                                        }
                                      },
                                      "required": [
                                        "type",
                                        "name"
                                      ],
                                      "type": "object"
                                    },
                                    "type": "array"
                                  }
                                },
                                "required": [
                                  "length",
                                  "current_url",
                                  "navigation_entries"
                                ],
                                "type": "object"
                              }
                            },
                            "required": [
                              "state",
                              "value"
                            ],
                            "type": "object"
                          },
                          {
                            "additionalProperties": false,
                            "properties": {
                              "state": {
                                "const": "not_requested",
                                "type": "string"
                              }
                            },
                            "required": [
                              "state"
                            ],
                            "type": "object"
                          },
                          {
                            "additionalProperties": false,
                            "properties": {
                              "reason": {
                                "minLength": 1,
                                "type": "string"
                              },
                              "state": {
                                "const": "missing",
                                "type": "string"
                              }
                            },
                            "required": [
                              "state",
                              "reason"
                            ],
                            "type": "object"
                          },
                          {
                            "additionalProperties": false,
                            "properties": {
                              "observed": {
                                "maximum": 9007199254740991,
                                "minimum": 0,
                                "type": "integer"
                              },
                              "reason": {
                                "minLength": 1,
                                "type": "string"
                              },
                              "retained": {
                                "maximum": 9007199254740991,
                                "minimum": 0,
                                "type": "integer"
                              },
                              "state": {
                                "const": "truncated",
                                "type": "string"
                              }
                            },
                            "required": [
                              "state",
                              "observed",
                              "retained",
                              "reason"
                            ],
                            "type": "object"
                          }
                        ]
                      },
                      "screenshot": {
                        "oneOf": [
                          {
                            "additionalProperties": false,
                            "properties": {
                              "state": {
                                "const": "captured",
                                "type": "string"
                              },
                              "value": {
                                "properties": {
                                  "bytes": {
                                    "maximum": 9007199254740991,
                                    "minimum": 1,
                                    "type": "integer"
                                  },
                                  "data_base64": {
                                    "type": "string"
                                  },
                                  "media_type": {
                                    "const": "image/png",
                                    "type": "string"
                                  },
                                  "sha256": {
                                    "pattern": "^[a-f0-9]{64}$",
                                    "type": "string"
                                  }
                                },
                                "required": [
                                  "sha256",
                                  "bytes",
                                  "media_type",
                                  "data_base64"
                                ],
                                "type": "object"
                              }
                            },
                            "required": [
                              "state",
                              "value"
                            ],
                            "type": "object"
                          },
                          {
                            "additionalProperties": false,
                            "properties": {
                              "state": {
                                "const": "not_requested",
                                "type": "string"
                              }
                            },
                            "required": [
                              "state"
                            ],
                            "type": "object"
                          },
                          {
                            "additionalProperties": false,
                            "properties": {
                              "reason": {
                                "minLength": 1,
                                "type": "string"
                              },
                              "state": {
                                "const": "missing",
                                "type": "string"
                              }
                            },
                            "required": [
                              "state",
                              "reason"
                            ],
                            "type": "object"
                          },
                          {
                            "additionalProperties": false,
                            "properties": {
                              "observed": {
                                "maximum": 9007199254740991,
                                "minimum": 0,
                                "type": "integer"
                              },
                              "reason": {
                                "minLength": 1,
                                "type": "string"
                              },
                              "retained": {
                                "maximum": 9007199254740991,
                                "minimum": 0,
                                "type": "integer"
                              },
                              "state": {
                                "const": "truncated",
                                "type": "string"
                              }
                            },
                            "required": [
                              "state",
                              "observed",
                              "retained",
                              "reason"
                            ],
                            "type": "object"
                          }
                        ]
                      },
                      "storage": {
                        "oneOf": [
                          {
                            "additionalProperties": false,
                            "properties": {
                              "state": {
                                "const": "captured",
                                "type": "string"
                              },
                              "value": {
                                "additionalProperties": false,
                                "properties": {
                                  "cookies": {
                                    "items": {
                                      "oneOf": [
                                        {
                                          "additionalProperties": false,
                                          "properties": {
                                            "domain": {
                                              "type": "string"
                                            },
                                            "http_only": {
                                              "type": "boolean"
                                            },
                                            "name": {
                                              "description": "Exact name used by this operation.",
                                              "type": "string"
                                            },
                                            "path": {
                                              "description": "Local filesystem path used by this operation.",
                                              "type": "string"
                                            },
                                            "same_site": {
                                              "enum": [
                                                "Strict",
                                                "Lax",
                                                "None"
                                              ],
                                              "type": "string"
                                            },
                                            "secure": {
                                              "type": "boolean"
                                            },
                                            "value_sha256": {
                                              "description": "Exact SHA-256 digest of value.",
                                              "pattern": "^[a-f0-9]{64}$",
                                              "type": "string"
                                            },
                                            "value_state": {
                                              "const": "hashed",
                                              "type": "string"
                                            }
                                          },
                                          "required": [
                                            "name",
                                            "domain",
                                            "path",
                                            "secure",
                                            "http_only",
                                            "same_site",
                                            "value_state",
                                            "value_sha256"
                                          ],
                                          "type": "object"
                                        },
                                        {
                                          "additionalProperties": false,
                                          "properties": {
                                            "domain": {
                                              "type": "string"
                                            },
                                            "http_only": {
                                              "type": "boolean"
                                            },
                                            "name": {
                                              "description": "Exact name used by this operation.",
                                              "type": "string"
                                            },
                                            "path": {
                                              "description": "Local filesystem path used by this operation.",
                                              "type": "string"
                                            },
                                            "same_site": {
                                              "enum": [
                                                "Strict",
                                                "Lax",
                                                "None"
                                              ],
                                              "type": "string"
                                            },
                                            "secure": {
                                              "type": "boolean"
                                            },
                                            "value_sha256": {
                                              "description": "Exact SHA-256 digest of value.",
                                              "type": "null"
                                            },
                                            "value_state": {
                                              "const": "redacted-secret",
                                              "type": "string"
                                            }
                                          },
                                          "required": [
                                            "name",
                                            "domain",
                                            "path",
                                            "secure",
                                            "http_only",
                                            "same_site",
                                            "value_state",
                                            "value_sha256"
                                          ],
                                          "type": "object"
                                        }
                                      ]
                                    },
                                    "type": "array"
                                  },
                                  "local_storage": {
                                    "items": {
                                      "oneOf": [
                                        {
                                          "additionalProperties": false,
                                          "properties": {
                                            "name": {
                                              "description": "Exact name used by this operation.",
                                              "type": "string"
                                            },
                                            "value_sha256": {
                                              "description": "Exact SHA-256 digest of value.",
                                              "pattern": "^[a-f0-9]{64}$",
                                              "type": "string"
                                            },
                                            "value_state": {
                                              "const": "hashed",
                                              "type": "string"
                                            }
                                          },
                                          "required": [
                                            "name",
                                            "value_state",
                                            "value_sha256"
                                          ],
                                          "type": "object"
                                        },
                                        {
                                          "additionalProperties": false,
                                          "properties": {
                                            "name": {
                                              "description": "Exact name used by this operation.",
                                              "type": "string"
                                            },
                                            "value_sha256": {
                                              "description": "Exact SHA-256 digest of value.",
                                              "type": "null"
                                            },
                                            "value_state": {
                                              "const": "redacted-secret",
                                              "type": "string"
                                            }
                                          },
                                          "required": [
                                            "name",
                                            "value_state",
                                            "value_sha256"
                                          ],
                                          "type": "object"
                                        }
                                      ]
                                    },
                                    "type": "array"
                                  },
                                  "session_storage": {
                                    "items": {
                                      "oneOf": [
                                        {
                                          "additionalProperties": false,
                                          "properties": {
                                            "name": {
                                              "description": "Exact name used by this operation.",
                                              "type": "string"
                                            },
                                            "value_sha256": {
                                              "description": "Exact SHA-256 digest of value.",
                                              "pattern": "^[a-f0-9]{64}$",
                                              "type": "string"
                                            },
                                            "value_state": {
                                              "const": "hashed",
                                              "type": "string"
                                            }
                                          },
                                          "required": [
                                            "name",
                                            "value_state",
                                            "value_sha256"
                                          ],
                                          "type": "object"
                                        },
                                        {
                                          "additionalProperties": false,
                                          "properties": {
                                            "name": {
                                              "description": "Exact name used by this operation.",
                                              "type": "string"
                                            },
                                            "value_sha256": {
                                              "description": "Exact SHA-256 digest of value.",
                                              "type": "null"
                                            },
                                            "value_state": {
                                              "const": "redacted-secret",
                                              "type": "string"
                                            }
                                          },
                                          "required": [
                                            "name",
                                            "value_state",
                                            "value_sha256"
                                          ],
                                          "type": "object"
                                        }
                                      ]
                                    },
                                    "type": "array"
                                  }
                                },
                                "required": [
                                  "cookies",
                                  "local_storage",
                                  "session_storage"
                                ],
                                "type": "object"
                              }
                            },
                            "required": [
                              "state",
                              "value"
                            ],
                            "type": "object"
                          },
                          {
                            "additionalProperties": false,
                            "properties": {
                              "state": {
                                "const": "not_requested",
                                "type": "string"
                              }
                            },
                            "required": [
                              "state"
                            ],
                            "type": "object"
                          },
                          {
                            "additionalProperties": false,
                            "properties": {
                              "reason": {
                                "minLength": 1,
                                "type": "string"
                              },
                              "state": {
                                "const": "missing",
                                "type": "string"
                              }
                            },
                            "required": [
                              "state",
                              "reason"
                            ],
                            "type": "object"
                          },
                          {
                            "additionalProperties": false,
                            "properties": {
                              "observed": {
                                "maximum": 9007199254740991,
                                "minimum": 0,
                                "type": "integer"
                              },
                              "reason": {
                                "minLength": 1,
                                "type": "string"
                              },
                              "retained": {
                                "maximum": 9007199254740991,
                                "minimum": 0,
                                "type": "integer"
                              },
                              "state": {
                                "const": "truncated",
                                "type": "string"
                              }
                            },
                            "required": [
                              "state",
                              "observed",
                              "retained",
                              "reason"
                            ],
                            "type": "object"
                          }
                        ]
                      },
                      "url": {
                        "oneOf": [
                          {
                            "additionalProperties": false,
                            "properties": {
                              "state": {
                                "const": "captured",
                                "type": "string"
                              },
                              "value": {
                                "properties": {
                                  "origin": {
                                    "anyOf": [
                                      {
                                        "type": "string"
                                      },
                                      {
                                        "type": "null"
                                      }
                                    ]
                                  },
                                  "query_parameter_names": {
                                    "items": {
                                      "type": "string"
                                    },
                                    "type": "array"
                                  },
                                  "redacted": {
                                    "type": "boolean"
                                  },
                                  "url": {
                                    "type": "string"
                                  }
                                },
                                "required": [
                                  "url",
                                  "origin",
                                  "query_parameter_names",
                                  "redacted"
                                ],
                                "type": "object"
                              }
                            },
                            "required": [
                              "state",
                              "value"
                            ],
                            "type": "object"
                          },
                          {
                            "additionalProperties": false,
                            "properties": {
                              "state": {
                                "const": "not_requested",
                                "type": "string"
                              }
                            },
                            "required": [
                              "state"
                            ],
                            "type": "object"
                          },
                          {
                            "additionalProperties": false,
                            "properties": {
                              "reason": {
                                "minLength": 1,
                                "type": "string"
                              },
                              "state": {
                                "const": "missing",
                                "type": "string"
                              }
                            },
                            "required": [
                              "state",
                              "reason"
                            ],
                            "type": "object"
                          },
                          {
                            "additionalProperties": false,
                            "properties": {
                              "observed": {
                                "maximum": 9007199254740991,
                                "minimum": 0,
                                "type": "integer"
                              },
                              "reason": {
                                "minLength": 1,
                                "type": "string"
                              },
                              "retained": {
                                "maximum": 9007199254740991,
                                "minimum": 0,
                                "type": "integer"
                              },
                              "state": {
                                "const": "truncated",
                                "type": "string"
                              }
                            },
                            "required": [
                              "state",
                              "observed",
                              "retained",
                              "reason"
                            ],
                            "type": "object"
                          }
                        ]
                      }
                    },
                    "required": [
                      "screenshot",
                      "dom",
                      "accessibility",
                      "url",
                      "history",
                      "storage"
                    ],
                    "type": "object"
                  },
                  "before_url": {
                    "properties": {
                      "origin": {
                        "anyOf": [
                          {
                            "type": "string"
                          },
                          {
                            "type": "null"
                          }
                        ]
                      },
                      "query_parameter_names": {
                        "items": {
                          "type": "string"
                        },
                        "type": "array"
                      },
                      "redacted": {
                        "type": "boolean"
                      },
                      "url": {
                        "type": "string"
                      }
                    },
                    "required": [
                      "url",
                      "origin",
                      "query_parameter_names",
                      "redacted"
                    ],
                    "type": "object"
                  },
                  "completeness": {
                    "oneOf": [
                      {
                        "additionalProperties": false,
                        "properties": {
                          "equality_eligible": {
                            "const": true,
                            "type": "boolean"
                          },
                          "missing_sections": {
                            "items": {
                              "not": {}
                            },
                            "maxItems": 0,
                            "minItems": 0,
                            "type": "array"
                          },
                          "status": {
                            "const": "complete",
                            "description": "Current lifecycle or verification status.",
                            "type": "string"
                          },
                          "truncated_sections": {
                            "items": {
                              "not": {}
                            },
                            "maxItems": 0,
                            "minItems": 0,
                            "type": "array"
                          }
                        },
                        "required": [
                          "status",
                          "equality_eligible",
                          "missing_sections",
                          "truncated_sections"
                        ],
                        "type": "object"
                      },
                      {
                        "additionalProperties": false,
                        "properties": {
                          "equality_eligible": {
                            "const": false,
                            "type": "boolean"
                          },
                          "missing_sections": {
                            "items": {
                              "enum": [
                                "action",
                                "screenshot",
                                "dom",
                                "accessibility",
                                "url",
                                "history",
                                "storage",
                                "events",
                                "frames",
                                "workers",
                                "popups",
                                "websockets"
                              ],
                              "type": "string"
                            },
                            "minItems": 1,
                            "type": "array"
                          },
                          "status": {
                            "const": "incomplete",
                            "description": "Current lifecycle or verification status.",
                            "type": "string"
                          },
                          "truncated_sections": {
                            "items": {
                              "not": {}
                            },
                            "maxItems": 0,
                            "minItems": 0,
                            "type": "array"
                          }
                        },
                        "required": [
                          "status",
                          "equality_eligible",
                          "missing_sections",
                          "truncated_sections"
                        ],
                        "type": "object"
                      },
                      {
                        "additionalProperties": false,
                        "properties": {
                          "equality_eligible": {
                            "const": false,
                            "type": "boolean"
                          },
                          "missing_sections": {
                            "items": {
                              "enum": [
                                "action",
                                "screenshot",
                                "dom",
                                "accessibility",
                                "url",
                                "history",
                                "storage",
                                "events",
                                "frames",
                                "workers",
                                "popups",
                                "websockets"
                              ],
                              "type": "string"
                            },
                            "type": "array"
                          },
                          "status": {
                            "const": "truncated",
                            "description": "Current lifecycle or verification status.",
                            "type": "string"
                          },
                          "truncated_sections": {
                            "items": {
                              "enum": [
                                "action",
                                "screenshot",
                                "dom",
                                "accessibility",
                                "url",
                                "history",
                                "storage",
                                "events",
                                "frames",
                                "workers",
                                "popups",
                                "websockets"
                              ],
                              "type": "string"
                            },
                            "minItems": 1,
                            "type": "array"
                          }
                        },
                        "required": [
                          "status",
                          "equality_eligible",
                          "missing_sections",
                          "truncated_sections"
                        ],
                        "type": "object"
                      }
                    ]
                  },
                  "elapsed_ms": {
                    "maximum": 9007199254740991,
                    "minimum": 0,
                    "type": "integer"
                  },
                  "error": {
                    "description": "Structured, caller-actionable error when the operation fails.",
                    "type": "string"
                  },
                  "event_sequence_end": {
                    "maximum": 9007199254740991,
                    "minimum": 0,
                    "type": "integer"
                  },
                  "event_sequence_start": {
                    "maximum": 9007199254740991,
                    "minimum": 1,
                    "type": "integer"
                  },
                  "status": {
                    "description": "Current lifecycle or verification status.",
                    "enum": [
                      "failed",
                      "cancelled"
                    ],
                    "type": "string"
                  },
                  "step_id": {
                    "minLength": 1,
                    "type": "string"
                  },
                  "step_index": {
                    "maximum": 9007199254740991,
                    "minimum": 0,
                    "type": "integer"
                  }
                },
                "required": [
                  "step_index",
                  "step_id",
                  "action",
                  "elapsed_ms",
                  "before_url",
                  "after_url",
                  "event_sequence_start",
                  "event_sequence_end",
                  "artifacts",
                  "completeness",
                  "status",
                  "error"
                ],
                "type": "object"
              }
            ]
          },
          "minItems": 1,
          "type": "array"
        }
      },
      "required": [
        "browser",
        "scenario",
        "duration_ms",
        "steps",
        "events",
        "completeness",
        "limitations"
      ],
      "type": "object"
    },
    "before": {
      "description": "The earlier or left-hand observation to compare.",
      "properties": {
        "inspection": {
          "description": "Complete normalized_result from inspect_web_page, including capture identity, observations, completeness, and limitations.",
          "properties": {
            "accessibility": {
              "properties": {
                "nodes": {
                  "items": {
                    "properties": {
                      "description": {
                        "anyOf": [
                          {
                            "type": "string"
                          },
                          {
                            "type": "null"
                          }
                        ]
                      },
                      "ignored": {
                        "type": "boolean"
                      },
                      "name": {
                        "anyOf": [
                          {
                            "type": "string"
                          },
                          {
                            "type": "null"
                          }
                        ],
                        "description": "Exact name used by this operation."
                      },
                      "node_id": {
                        "type": "string"
                      },
                      "parent_id": {
                        "anyOf": [
                          {
                            "type": "string"
                          },
                          {
                            "type": "null"
                          }
                        ]
                      },
                      "role": {
                        "anyOf": [
                          {
                            "type": "string"
                          },
                          {
                            "type": "null"
                          }
                        ]
                      },
                      "states": {
                        "default": [],
                        "items": {
                          "properties": {
                            "name": {
                              "description": "Exact name used by this operation.",
                              "type": "string"
                            },
                            "value": {
                              "anyOf": [
                                {
                                  "type": "boolean"
                                },
                                {
                                  "type": "number"
                                },
                                {
                                  "type": "string"
                                }
                              ]
                            }
                          },
                          "required": [
                            "name",
                            "value"
                          ],
                          "type": "object"
                        },
                        "type": "array"
                      }
                    },
                    "required": [
                      "node_id",
                      "parent_id",
                      "role",
                      "name",
                      "description",
                      "ignored"
                    ],
                    "type": "object"
                  },
                  "type": "array"
                },
                "text_capture": {
                  "properties": {
                    "excluded_fields": {
                      "maximum": 9007199254740991,
                      "minimum": 0,
                      "type": "integer"
                    },
                    "retained_bytes": {
                      "description": "Byte count for retained.",
                      "maximum": 9007199254740991,
                      "minimum": 0,
                      "type": "integer"
                    },
                    "status": {
                      "description": "Current lifecycle or verification status.",
                      "enum": [
                        "not_approved",
                        "included",
                        "unavailable"
                      ],
                      "type": "string"
                    }
                  },
                  "required": [
                    "status",
                    "retained_bytes",
                    "excluded_fields"
                  ],
                  "type": "object"
                },
                "total_nodes": {
                  "maximum": 9007199254740991,
                  "minimum": 0,
                  "type": "integer"
                }
              },
              "required": [
                "total_nodes",
                "text_capture",
                "nodes"
              ],
              "type": "object"
            },
            "browser": {
              "properties": {
                "js_version": {
                  "type": "string"
                },
                "product": {
                  "type": "string"
                },
                "protocol_version": {
                  "type": "string"
                },
                "revision": {
                  "type": "string"
                },
                "user_agent": {
                  "type": "string"
                }
              },
              "required": [
                "product",
                "protocol_version",
                "revision",
                "user_agent",
                "js_version"
              ],
              "type": "object"
            },
            "capture_window": {
              "properties": {
                "ended_at": {
                  "format": "date-time",
                  "pattern": "^(?:(?:\\d\\d[2468][048]|\\d\\d[13579][26]|\\d\\d0[48]|[02468][048]00|[13579][26]00)-02-29|\\d{4}-(?:(?:0[13578]|1[02])-(?:0[1-9]|[12]\\d|3[01])|(?:0[469]|11)-(?:0[1-9]|[12]\\d|30)|(?:02)-(?:0[1-9]|1\\d|2[0-8])))T(?:(?:[01]\\d|2[0-3]):[0-5]\\d(?::[0-5]\\d(?:\\.\\d+)?)?(?:Z))$",
                  "type": "string"
                },
                "observation_ms": {
                  "maximum": 9007199254740991,
                  "minimum": 0,
                  "type": "integer"
                },
                "started_at": {
                  "format": "date-time",
                  "pattern": "^(?:(?:\\d\\d[2468][048]|\\d\\d[13579][26]|\\d\\d0[48]|[02468][048]00|[13579][26]00)-02-29|\\d{4}-(?:(?:0[13578]|1[02])-(?:0[1-9]|[12]\\d|3[01])|(?:0[469]|11)-(?:0[1-9]|[12]\\d|30)|(?:02)-(?:0[1-9]|1\\d|2[0-8])))T(?:(?:[01]\\d|2[0-3]):[0-5]\\d(?::[0-5]\\d(?:\\.\\d+)?)?(?:Z))$",
                  "type": "string"
                }
              },
              "required": [
                "started_at",
                "ended_at",
                "observation_ms"
              ],
              "type": "object"
            },
            "completeness": {
              "properties": {
                "attach_limited_sections": {
                  "items": {
                    "enum": [
                      "frames",
                      "dom",
                      "accessibility",
                      "scripts",
                      "script_sources",
                      "resources",
                      "network_requests",
                      "network_initiators",
                      "console_events",
                      "console_text",
                      "websocket_connections",
                      "websocket_frames",
                      "websocket_shapes",
                      "json_body_shapes",
                      "workers",
                      "storage",
                      "storage_keys",
                      "metadata",
                      "webmcp_tools",
                      "screenshot",
                      "source_maps",
                      "timeline"
                    ],
                    "type": "string"
                  },
                  "type": "array"
                },
                "conditions": {
                  "items": {
                    "enum": [
                      "complete_within_window",
                      "policy_filtered",
                      "attach_limited",
                      "truncated"
                    ],
                    "type": "string"
                  },
                  "maxItems": 3,
                  "minItems": 1,
                  "type": "array"
                },
                "dropped_events": {
                  "properties": {
                    "console_events": {
                      "maximum": 9007199254740991,
                      "minimum": 0,
                      "type": "integer"
                    },
                    "network_requests": {
                      "maximum": 9007199254740991,
                      "minimum": 0,
                      "type": "integer"
                    },
                    "scripts": {
                      "maximum": 9007199254740991,
                      "minimum": 0,
                      "type": "integer"
                    },
                    "timeline_events": {
                      "maximum": 9007199254740991,
                      "minimum": 0,
                      "type": "integer"
                    },
                    "total": {
                      "maximum": 9007199254740991,
                      "minimum": 0,
                      "type": "integer"
                    },
                    "webmcp_tools": {
                      "maximum": 9007199254740991,
                      "minimum": 0,
                      "type": "integer"
                    },
                    "websocket_connections": {
                      "maximum": 9007199254740991,
                      "minimum": 0,
                      "type": "integer"
                    },
                    "websocket_frames": {
                      "maximum": 9007199254740991,
                      "minimum": 0,
                      "type": "integer"
                    }
                  },
                  "required": [
                    "scripts",
                    "network_requests",
                    "console_events",
                    "websocket_connections",
                    "websocket_frames",
                    "webmcp_tools",
                    "timeline_events",
                    "total"
                  ],
                  "type": "object"
                },
                "excluded": {
                  "items": {
                    "properties": {
                      "count": {
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
                      },
                      "reason": {
                        "enum": [
                          "disallowed_origin",
                          "unsupported_url",
                          "unattributed_origin",
                          "not_approved",
                          "out_of_target_scope",
                          "provider_unavailable",
                          "invalid_protocol_value",
                          "resource_budget_exhausted"
                        ],
                        "type": "string"
                      },
                      "section": {
                        "enum": [
                          "frames",
                          "dom",
                          "accessibility",
                          "scripts",
                          "script_sources",
                          "resources",
                          "network_requests",
                          "network_initiators",
                          "console_events",
                          "console_text",
                          "websocket_connections",
                          "websocket_frames",
                          "websocket_shapes",
                          "json_body_shapes",
                          "workers",
                          "storage",
                          "storage_keys",
                          "metadata",
                          "webmcp_tools",
                          "screenshot",
                          "source_maps",
                          "timeline"
                        ],
                        "type": "string"
                      }
                    },
                    "required": [
                      "section",
                      "reason",
                      "count"
                    ],
                    "type": "object"
                  },
                  "type": "array"
                },
                "policy_filtered_sections": {
                  "items": {
                    "enum": [
                      "frames",
                      "dom",
                      "accessibility",
                      "scripts",
                      "script_sources",
                      "resources",
                      "network_requests",
                      "network_initiators",
                      "console_events",
                      "console_text",
                      "websocket_connections",
                      "websocket_frames",
                      "websocket_shapes",
                      "json_body_shapes",
                      "workers",
                      "storage",
                      "storage_keys",
                      "metadata",
                      "webmcp_tools",
                      "screenshot",
                      "source_maps",
                      "timeline"
                    ],
                    "type": "string"
                  },
                  "type": "array"
                },
                "status": {
                  "description": "Current lifecycle or verification status.",
                  "enum": [
                    "complete_within_window",
                    "policy_filtered",
                    "attach_limited",
                    "truncated"
                  ],
                  "type": "string"
                },
                "truncated_sections": {
                  "items": {
                    "enum": [
                      "frames",
                      "dom",
                      "accessibility",
                      "scripts",
                      "script_sources",
                      "resources",
                      "network_requests",
                      "network_initiators",
                      "console_events",
                      "console_text",
                      "websocket_connections",
                      "websocket_frames",
                      "websocket_shapes",
                      "json_body_shapes",
                      "workers",
                      "storage",
                      "storage_keys",
                      "metadata",
                      "webmcp_tools",
                      "screenshot",
                      "source_maps",
                      "timeline"
                    ],
                    "type": "string"
                  },
                  "type": "array"
                },
                "unavailable_sections": {
                  "items": {
                    "enum": [
                      "frames",
                      "dom",
                      "accessibility",
                      "scripts",
                      "script_sources",
                      "resources",
                      "network_requests",
                      "network_initiators",
                      "console_events",
                      "console_text",
                      "websocket_connections",
                      "websocket_frames",
                      "websocket_shapes",
                      "json_body_shapes",
                      "workers",
                      "storage",
                      "storage_keys",
                      "metadata",
                      "webmcp_tools",
                      "screenshot",
                      "source_maps",
                      "timeline"
                    ],
                    "type": "string"
                  },
                  "type": "array"
                }
              },
              "required": [
                "status",
                "conditions",
                "policy_filtered_sections",
                "attach_limited_sections",
                "truncated_sections",
                "unavailable_sections",
                "excluded",
                "dropped_events"
              ],
              "type": "object"
            },
            "console": {
              "properties": {
                "coverage_started_at": {
                  "format": "date-time",
                  "pattern": "^(?:(?:\\d\\d[2468][048]|\\d\\d[13579][26]|\\d\\d0[48]|[02468][048]00|[13579][26]00)-02-29|\\d{4}-(?:(?:0[13578]|1[02])-(?:0[1-9]|[12]\\d|3[01])|(?:0[469]|11)-(?:0[1-9]|[12]\\d|30)|(?:02)-(?:0[1-9]|1\\d|2[0-8])))T(?:(?:[01]\\d|2[0-3]):[0-5]\\d(?::[0-5]\\d(?:\\.\\d+)?)?(?:Z))$",
                  "type": "string"
                },
                "events": {
                  "items": {
                    "properties": {
                      "argument_types": {
                        "items": {
                          "type": "string"
                        },
                        "type": "array"
                      },
                      "column": {
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
                      },
                      "line": {
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
                      },
                      "text_capture": {
                        "properties": {
                          "retained_bytes": {
                            "description": "Byte count for retained.",
                            "maximum": 9007199254740991,
                            "minimum": 0,
                            "type": "integer"
                          },
                          "status": {
                            "description": "Current lifecycle or verification status.",
                            "enum": [
                              "not_approved",
                              "included"
                            ],
                            "type": "string"
                          },
                          "values": {
                            "items": {
                              "properties": {
                                "argument_index": {
                                  "maximum": 9007199254740991,
                                  "minimum": 0,
                                  "type": "integer"
                                },
                                "text": {
                                  "type": "string"
                                },
                                "type": {
                                  "type": "string"
                                }
                              },
                              "required": [
                                "argument_index",
                                "type",
                                "text"
                              ],
                              "type": "object"
                            },
                            "type": "array"
                          }
                        },
                        "required": [
                          "status",
                          "values",
                          "retained_bytes"
                        ],
                        "type": "object"
                      },
                      "timestamp": {
                        "type": "number"
                      },
                      "type": {
                        "type": "string"
                      },
                      "url": {
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
                      "type",
                      "timestamp",
                      "argument_types",
                      "url",
                      "line",
                      "column",
                      "text_capture"
                    ],
                    "type": "object"
                  },
                  "type": "array"
                },
                "prior_activity_available": {
                  "const": false,
                  "type": "boolean"
                }
              },
              "required": [
                "events",
                "coverage_started_at",
                "prior_activity_available"
              ],
              "type": "object"
            },
            "dom": {
              "properties": {
                "nodes": {
                  "items": {
                    "properties": {
                      "attribute_names": {
                        "items": {
                          "type": "string"
                        },
                        "type": "array"
                      },
                      "index": {
                        "maximum": 9007199254740991,
                        "minimum": 0,
                        "type": "integer"
                      },
                      "node_name": {
                        "type": "string"
                      },
                      "node_type": {
                        "maximum": 9007199254740991,
                        "minimum": 0,
                        "type": "integer"
                      },
                      "node_value_length": {
                        "maximum": 9007199254740991,
                        "minimum": 0,
                        "type": "integer"
                      },
                      "parent_index": {
                        "maximum": 9007199254740991,
                        "minimum": -1,
                        "type": "integer"
                      }
                    },
                    "required": [
                      "index",
                      "parent_index",
                      "node_type",
                      "node_name",
                      "node_value_length",
                      "attribute_names"
                    ],
                    "type": "object"
                  },
                  "type": "array"
                },
                "total_nodes": {
                  "maximum": 9007199254740991,
                  "minimum": 0,
                  "type": "integer"
                }
              },
              "required": [
                "total_nodes",
                "nodes"
              ],
              "type": "object"
            },
            "frames": {
              "items": {
                "properties": {
                  "frame_id": {
                    "type": "string"
                  },
                  "origin": {
                    "anyOf": [
                      {
                        "type": "string"
                      },
                      {
                        "type": "null"
                      }
                    ]
                  },
                  "parent_frame_id": {
                    "anyOf": [
                      {
                        "type": "string"
                      },
                      {
                        "type": "null"
                      }
                    ]
                  },
                  "url": {
                    "type": "string"
                  }
                },
                "required": [
                  "frame_id",
                  "parent_frame_id",
                  "url",
                  "origin"
                ],
                "type": "object"
              },
              "type": "array"
            },
            "limitations": {
              "items": {
                "type": "string"
              },
              "type": "array"
            },
            "metadata": {
              "properties": {
                "agent_hints": {
                  "items": {
                    "properties": {
                      "declaration": {
                        "type": "string"
                      },
                      "mechanism": {
                        "enum": [
                          "link_rel",
                          "dom_link_rel",
                          "well_known_resource",
                          "response_header"
                        ],
                        "type": "string"
                      },
                      "trust": {
                        "const": "page-declared-untrusted",
                        "type": "string"
                      },
                      "url": {
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
                      "mechanism",
                      "declaration",
                      "url",
                      "trust"
                    ],
                    "type": "object"
                  },
                  "type": "array"
                },
                "dom_urls": {
                  "items": {
                    "properties": {
                      "attribute": {
                        "enum": [
                          "href",
                          "src",
                          "action",
                          "formaction",
                          "poster"
                        ],
                        "type": "string"
                      },
                      "destination_scope": {
                        "enum": [
                          "approved",
                          "outside_policy",
                          "unsupported"
                        ],
                        "type": "string"
                      },
                      "node_index": {
                        "maximum": 9007199254740991,
                        "minimum": 0,
                        "type": "integer"
                      },
                      "url": {
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
                      "node_index",
                      "attribute",
                      "url",
                      "destination_scope"
                    ],
                    "type": "object"
                  },
                  "type": "array"
                },
                "excluded_dom_urls": {
                  "maximum": 9007199254740991,
                  "minimum": 0,
                  "type": "integer"
                },
                "headers_allowlisted": {
                  "const": true,
                  "type": "boolean"
                },
                "responses": {
                  "items": {
                    "properties": {
                      "content_encoding": {
                        "anyOf": [
                          {
                            "type": "string"
                          },
                          {
                            "type": "null"
                          }
                        ]
                      },
                      "content_length": {
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
                      },
                      "csp": {
                        "properties": {
                          "directives": {
                            "items": {
                              "properties": {
                                "name": {
                                  "description": "Exact name used by this operation.",
                                  "type": "string"
                                },
                                "sources": {
                                  "items": {
                                    "properties": {
                                      "kind": {
                                        "enum": [
                                          "keyword",
                                          "scheme",
                                          "approved_origin",
                                          "external_origin",
                                          "other"
                                        ],
                                        "type": "string"
                                      },
                                      "value": {
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
                                      "kind",
                                      "value"
                                    ],
                                    "type": "object"
                                  },
                                  "type": "array"
                                }
                              },
                              "required": [
                                "name",
                                "sources"
                              ],
                              "type": "object"
                            },
                            "type": "array"
                          },
                          "hash_count": {
                            "maximum": 9007199254740991,
                            "minimum": 0,
                            "type": "integer"
                          },
                          "nonce_count": {
                            "maximum": 9007199254740991,
                            "minimum": 0,
                            "type": "integer"
                          }
                        },
                        "required": [
                          "directives",
                          "nonce_count",
                          "hash_count"
                        ],
                        "type": "object"
                      },
                      "links": {
                        "items": {
                          "properties": {
                            "as": {
                              "anyOf": [
                                {
                                  "type": "string"
                                },
                                {
                                  "type": "null"
                                }
                              ]
                            },
                            "crossorigin": {
                              "anyOf": [
                                {
                                  "type": "string"
                                },
                                {
                                  "type": "null"
                                }
                              ]
                            },
                            "destination_scope": {
                              "enum": [
                                "approved",
                                "outside_policy",
                                "unsupported"
                              ],
                              "type": "string"
                            },
                            "href": {
                              "anyOf": [
                                {
                                  "type": "string"
                                },
                                {
                                  "type": "null"
                                }
                              ]
                            },
                            "rel": {
                              "items": {
                                "type": "string"
                              },
                              "type": "array"
                            },
                            "type": {
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
                            "href",
                            "destination_scope",
                            "rel",
                            "as",
                            "type",
                            "crossorigin"
                          ],
                          "type": "object"
                        },
                        "type": "array"
                      },
                      "mime_type": {
                        "anyOf": [
                          {
                            "type": "string"
                          },
                          {
                            "type": "null"
                          }
                        ]
                      },
                      "policies": {
                        "properties": {
                          "coep": {
                            "anyOf": [
                              {
                                "type": "string"
                              },
                              {
                                "type": "null"
                              }
                            ]
                          },
                          "coop": {
                            "anyOf": [
                              {
                                "type": "string"
                              },
                              {
                                "type": "null"
                              }
                            ]
                          },
                          "corp": {
                            "anyOf": [
                              {
                                "type": "string"
                              },
                              {
                                "type": "null"
                              }
                            ]
                          },
                          "permissions_policy_features": {
                            "items": {
                              "type": "string"
                            },
                            "type": "array"
                          },
                          "referrer_policy": {
                            "anyOf": [
                              {
                                "type": "string"
                              },
                              {
                                "type": "null"
                              }
                            ]
                          },
                          "x_content_type_options": {
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
                          "coop",
                          "coep",
                          "corp",
                          "referrer_policy",
                          "x_content_type_options",
                          "permissions_policy_features"
                        ],
                        "type": "object"
                      },
                      "request_id": {
                        "type": "string"
                      },
                      "url": {
                        "type": "string"
                      }
                    },
                    "required": [
                      "request_id",
                      "url",
                      "mime_type",
                      "content_length",
                      "content_encoding",
                      "csp",
                      "links",
                      "policies"
                    ],
                    "type": "object"
                  },
                  "type": "array"
                }
              },
              "required": [
                "responses",
                "dom_urls",
                "agent_hints",
                "excluded_dom_urls",
                "headers_allowlisted"
              ],
              "type": "object"
            },
            "network": {
              "properties": {
                "coverage_started_at": {
                  "format": "date-time",
                  "pattern": "^(?:(?:\\d\\d[2468][048]|\\d\\d[13579][26]|\\d\\d0[48]|[02468][048]00|[13579][26]00)-02-29|\\d{4}-(?:(?:0[13578]|1[02])-(?:0[1-9]|[12]\\d|3[01])|(?:0[469]|11)-(?:0[1-9]|[12]\\d|30)|(?:02)-(?:0[1-9]|1\\d|2[0-8])))T(?:(?:[01]\\d|2[0-3]):[0-5]\\d(?::[0-5]\\d(?:\\.\\d+)?)?(?:Z))$",
                  "type": "string"
                },
                "prior_activity_available": {
                  "const": false,
                  "type": "boolean"
                },
                "requests": {
                  "items": {
                    "properties": {
                      "body_shapes": {
                        "properties": {
                          "request": {
                            "anyOf": [
                              {
                                "properties": {
                                  "max_depth_observed": {
                                    "description": "Maximum permitted depth observed for this operation.",
                                    "maximum": 9007199254740991,
                                    "minimum": 0,
                                    "type": "integer"
                                  },
                                  "node_count": {
                                    "maximum": 9007199254740991,
                                    "minimum": 1,
                                    "type": "integer"
                                  },
                                  "properties": {
                                    "items": {
                                      "properties": {
                                        "observations": {
                                          "maximum": 9007199254740991,
                                          "minimum": 1,
                                          "type": "integer"
                                        },
                                        "path": {
                                          "description": "Local filesystem path used by this operation.",
                                          "items": {
                                            "oneOf": [
                                              {
                                                "properties": {
                                                  "kind": {
                                                    "const": "property",
                                                    "type": "string"
                                                  },
                                                  "name": {
                                                    "description": "Exact name used by this operation.",
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
                                                "properties": {
                                                  "kind": {
                                                    "const": "array-element",
                                                    "type": "string"
                                                  }
                                                },
                                                "required": [
                                                  "kind"
                                                ],
                                                "type": "object"
                                              }
                                            ]
                                          },
                                          "minItems": 1,
                                          "type": "array"
                                        },
                                        "types": {
                                          "items": {
                                            "enum": [
                                              "object",
                                              "array",
                                              "string",
                                              "number",
                                              "boolean",
                                              "null"
                                            ],
                                            "type": "string"
                                          },
                                          "minItems": 1,
                                          "type": "array"
                                        }
                                      },
                                      "required": [
                                        "path",
                                        "types",
                                        "observations"
                                      ],
                                      "type": "object"
                                    },
                                    "type": "array"
                                  },
                                  "root_type": {
                                    "enum": [
                                      "object",
                                      "array",
                                      "string",
                                      "number",
                                      "boolean",
                                      "null"
                                    ],
                                    "type": "string"
                                  }
                                },
                                "required": [
                                  "root_type",
                                  "node_count",
                                  "max_depth_observed",
                                  "properties"
                                ],
                                "type": "object"
                              },
                              {
                                "type": "null"
                              }
                            ]
                          },
                          "response": {
                            "anyOf": [
                              {
                                "properties": {
                                  "max_depth_observed": {
                                    "description": "Maximum permitted depth observed for this operation.",
                                    "maximum": 9007199254740991,
                                    "minimum": 0,
                                    "type": "integer"
                                  },
                                  "node_count": {
                                    "maximum": 9007199254740991,
                                    "minimum": 1,
                                    "type": "integer"
                                  },
                                  "properties": {
                                    "items": {
                                      "properties": {
                                        "observations": {
                                          "maximum": 9007199254740991,
                                          "minimum": 1,
                                          "type": "integer"
                                        },
                                        "path": {
                                          "description": "Local filesystem path used by this operation.",
                                          "items": {
                                            "oneOf": [
                                              {
                                                "properties": {
                                                  "kind": {
                                                    "const": "property",
                                                    "type": "string"
                                                  },
                                                  "name": {
                                                    "description": "Exact name used by this operation.",
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
                                                "properties": {
                                                  "kind": {
                                                    "const": "array-element",
                                                    "type": "string"
                                                  }
                                                },
                                                "required": [
                                                  "kind"
                                                ],
                                                "type": "object"
                                              }
                                            ]
                                          },
                                          "minItems": 1,
                                          "type": "array"
                                        },
                                        "types": {
                                          "items": {
                                            "enum": [
                                              "object",
                                              "array",
                                              "string",
                                              "number",
                                              "boolean",
                                              "null"
                                            ],
                                            "type": "string"
                                          },
                                          "minItems": 1,
                                          "type": "array"
                                        }
                                      },
                                      "required": [
                                        "path",
                                        "types",
                                        "observations"
                                      ],
                                      "type": "object"
                                    },
                                    "type": "array"
                                  },
                                  "root_type": {
                                    "enum": [
                                      "object",
                                      "array",
                                      "string",
                                      "number",
                                      "boolean",
                                      "null"
                                    ],
                                    "type": "string"
                                  }
                                },
                                "required": [
                                  "root_type",
                                  "node_count",
                                  "max_depth_observed",
                                  "properties"
                                ],
                                "type": "object"
                              },
                              {
                                "type": "null"
                              }
                            ]
                          },
                          "status": {
                            "description": "Current lifecycle or verification status.",
                            "enum": [
                              "not_approved",
                              "included",
                              "partial",
                              "unavailable"
                            ],
                            "type": "string"
                          }
                        },
                        "required": [
                          "status",
                          "request",
                          "response"
                        ],
                        "type": "object"
                      },
                      "encoded_data_length": {
                        "anyOf": [
                          {
                            "minimum": 0,
                            "type": "number"
                          },
                          {
                            "type": "null"
                          }
                        ]
                      },
                      "initiator": {
                        "properties": {
                          "column": {
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
                          },
                          "line": {
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
                          },
                          "type": {
                            "type": "string"
                          },
                          "url": {
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
                          "type",
                          "url",
                          "line",
                          "column"
                        ],
                        "type": "object"
                      },
                      "method": {
                        "type": "string"
                      },
                      "mime_type": {
                        "anyOf": [
                          {
                            "type": "string"
                          },
                          {
                            "type": "null"
                          }
                        ]
                      },
                      "origin": {
                        "anyOf": [
                          {
                            "type": "string"
                          },
                          {
                            "type": "null"
                          }
                        ]
                      },
                      "redirects": {
                        "items": {
                          "properties": {
                            "encoded_data_length": {
                              "anyOf": [
                                {
                                  "minimum": 0,
                                  "type": "number"
                                },
                                {
                                  "type": "null"
                                }
                              ]
                            },
                            "method": {
                              "type": "string"
                            },
                            "mime_type": {
                              "anyOf": [
                                {
                                  "type": "string"
                                },
                                {
                                  "type": "null"
                                }
                              ]
                            },
                            "redirect_event_timestamp": {
                              "anyOf": [
                                {
                                  "type": "number"
                                },
                                {
                                  "type": "null"
                                }
                              ]
                            },
                            "request_timestamp": {
                              "anyOf": [
                                {
                                  "type": "number"
                                },
                                {
                                  "type": "null"
                                }
                              ]
                            },
                            "resource_type": {
                              "anyOf": [
                                {
                                  "type": "string"
                                },
                                {
                                  "type": "null"
                                }
                              ]
                            },
                            "response_url": {
                              "type": "string"
                            },
                            "status": {
                              "anyOf": [
                                {
                                  "type": "number"
                                },
                                {
                                  "type": "null"
                                }
                              ],
                              "description": "Current lifecycle or verification status."
                            },
                            "url": {
                              "type": "string"
                            }
                          },
                          "required": [
                            "url",
                            "response_url",
                            "method",
                            "resource_type",
                            "status",
                            "mime_type",
                            "encoded_data_length",
                            "request_timestamp",
                            "redirect_event_timestamp"
                          ],
                          "type": "object"
                        },
                        "type": "array"
                      },
                      "request_id": {
                        "type": "string"
                      },
                      "resource_type": {
                        "anyOf": [
                          {
                            "type": "string"
                          },
                          {
                            "type": "null"
                          }
                        ]
                      },
                      "status": {
                        "anyOf": [
                          {
                            "type": "number"
                          },
                          {
                            "type": "null"
                          }
                        ],
                        "description": "Current lifecycle or verification status."
                      },
                      "url": {
                        "type": "string"
                      }
                    },
                    "required": [
                      "request_id",
                      "url",
                      "origin",
                      "method",
                      "resource_type",
                      "status",
                      "mime_type",
                      "encoded_data_length",
                      "initiator",
                      "body_shapes"
                    ],
                    "type": "object"
                  },
                  "type": "array"
                },
                "websocket_connections": {
                  "items": {
                    "properties": {
                      "events": {
                        "items": {
                          "properties": {
                            "direction": {
                              "description": "Direction in which to traverse or compare relationships.",
                              "enum": [
                                "sent",
                                "received"
                              ],
                              "type": "string"
                            },
                            "opcode": {
                              "maximum": 9007199254740991,
                              "minimum": 0,
                              "type": "integer"
                            },
                            "payload_bytes": {
                              "anyOf": [
                                {
                                  "maximum": 9007199254740991,
                                  "minimum": 0,
                                  "type": "integer"
                                },
                                {
                                  "type": "null"
                                }
                              ],
                              "description": "Byte count for payload."
                            },
                            "payload_shape": {
                              "anyOf": [
                                {
                                  "properties": {
                                    "format": {
                                      "description": "Declared input artifact format.",
                                      "enum": [
                                        "json",
                                        "text",
                                        "binary"
                                      ],
                                      "type": "string"
                                    },
                                    "json_shape": {
                                      "anyOf": [
                                        {
                                          "properties": {
                                            "max_depth_observed": {
                                              "description": "Maximum permitted depth observed for this operation.",
                                              "maximum": 9007199254740991,
                                              "minimum": 0,
                                              "type": "integer"
                                            },
                                            "node_count": {
                                              "maximum": 9007199254740991,
                                              "minimum": 1,
                                              "type": "integer"
                                            },
                                            "properties": {
                                              "items": {
                                                "properties": {
                                                  "observations": {
                                                    "maximum": 9007199254740991,
                                                    "minimum": 1,
                                                    "type": "integer"
                                                  },
                                                  "path": {
                                                    "description": "Local filesystem path used by this operation.",
                                                    "items": {
                                                      "oneOf": [
                                                        {
                                                          "properties": {
                                                            "kind": {
                                                              "const": "property",
                                                              "type": "string"
                                                            },
                                                            "name": {
                                                              "description": "Exact name used by this operation.",
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
                                                          "properties": {
                                                            "kind": {
                                                              "const": "array-element",
                                                              "type": "string"
                                                            }
                                                          },
                                                          "required": [
                                                            "kind"
                                                          ],
                                                          "type": "object"
                                                        }
                                                      ]
                                                    },
                                                    "minItems": 1,
                                                    "type": "array"
                                                  },
                                                  "types": {
                                                    "items": {
                                                      "enum": [
                                                        "object",
                                                        "array",
                                                        "string",
                                                        "number",
                                                        "boolean",
                                                        "null"
                                                      ],
                                                      "type": "string"
                                                    },
                                                    "minItems": 1,
                                                    "type": "array"
                                                  }
                                                },
                                                "required": [
                                                  "path",
                                                  "types",
                                                  "observations"
                                                ],
                                                "type": "object"
                                              },
                                              "type": "array"
                                            },
                                            "root_type": {
                                              "enum": [
                                                "object",
                                                "array",
                                                "string",
                                                "number",
                                                "boolean",
                                                "null"
                                              ],
                                              "type": "string"
                                            }
                                          },
                                          "required": [
                                            "root_type",
                                            "node_count",
                                            "max_depth_observed",
                                            "properties"
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
                                    "format",
                                    "json_shape"
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
                            "direction",
                            "opcode",
                            "payload_bytes",
                            "payload_shape"
                          ],
                          "type": "object"
                        },
                        "type": "array"
                      },
                      "request_id": {
                        "type": "string"
                      },
                      "url": {
                        "type": "string"
                      }
                    },
                    "required": [
                      "request_id",
                      "url",
                      "events"
                    ],
                    "type": "object"
                  },
                  "type": "array"
                }
              },
              "required": [
                "requests",
                "websocket_connections",
                "coverage_started_at",
                "prior_activity_available"
              ],
              "type": "object"
            },
            "resources": {
              "items": {
                "properties": {
                  "content_size": {
                    "anyOf": [
                      {
                        "minimum": 0,
                        "type": "number"
                      },
                      {
                        "type": "null"
                      }
                    ]
                  },
                  "mime_type": {
                    "type": "string"
                  },
                  "origin": {
                    "anyOf": [
                      {
                        "type": "string"
                      },
                      {
                        "type": "null"
                      }
                    ]
                  },
                  "resource_key": {
                    "pattern": "^res_[a-f0-9]{64}$",
                    "type": "string"
                  },
                  "type": {
                    "type": "string"
                  },
                  "url": {
                    "type": "string"
                  }
                },
                "required": [
                  "resource_key",
                  "url",
                  "origin",
                  "type",
                  "mime_type",
                  "content_size"
                ],
                "type": "object"
              },
              "type": "array"
            },
            "scripts": {
              "properties": {
                "items": {
                  "items": {
                    "properties": {
                      "cdp_hash": {
                        "anyOf": [
                          {
                            "type": "string"
                          },
                          {
                            "type": "null"
                          }
                        ],
                        "description": "Producer-reported script hash; null when unavailable."
                      },
                      "frame_id": {
                        "anyOf": [
                          {
                            "type": "string"
                          },
                          {
                            "type": "null"
                          }
                        ],
                        "default": null
                      },
                      "is_module": {
                        "anyOf": [
                          {
                            "type": "boolean"
                          },
                          {
                            "type": "null"
                          }
                        ],
                        "description": "Producer-reported module classification; null when unavailable."
                      },
                      "language": {
                        "anyOf": [
                          {
                            "type": "string"
                          },
                          {
                            "type": "null"
                          }
                        ]
                      },
                      "length": {
                        "anyOf": [
                          {
                            "maximum": 9007199254740991,
                            "minimum": 0,
                            "type": "integer"
                          },
                          {
                            "type": "null"
                          }
                        ],
                        "description": "Producer-reported script length; null when unavailable."
                      },
                      "origin": {
                        "anyOf": [
                          {
                            "type": "string"
                          },
                          {
                            "type": "null"
                          }
                        ]
                      },
                      "resource_reconciliation": {
                        "oneOf": [
                          {
                            "properties": {
                              "resource_key": {
                                "type": "string"
                              },
                              "status": {
                                "const": "exact",
                                "description": "Current lifecycle or verification status.",
                                "type": "string"
                              }
                            },
                            "required": [
                              "status",
                              "resource_key"
                            ],
                            "type": "object"
                          },
                          {
                            "properties": {
                              "candidate_resource_keys": {
                                "items": {
                                  "type": "string"
                                },
                                "type": "array"
                              },
                              "status": {
                                "const": "ambiguous",
                                "description": "Current lifecycle or verification status.",
                                "type": "string"
                              }
                            },
                            "required": [
                              "status",
                              "candidate_resource_keys"
                            ],
                            "type": "object"
                          },
                          {
                            "properties": {
                              "reason": {
                                "const": "no_exact_sanitized_url",
                                "type": "string"
                              },
                              "status": {
                                "const": "unmatched",
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
                      "script_key": {
                        "pattern": "^scr_[a-f0-9]{64}(?:_[0-9]+)?$",
                        "type": "string"
                      },
                      "source": {
                        "oneOf": [
                          {
                            "properties": {
                              "included": {
                                "const": false,
                                "type": "boolean"
                              },
                              "reason": {
                                "type": "string"
                              }
                            },
                            "required": [
                              "included",
                              "reason"
                            ],
                            "type": "object"
                          },
                          {
                            "properties": {
                              "artifact": {
                                "properties": {
                                  "bytes": {
                                    "maximum": 9007199254740991,
                                    "minimum": 0,
                                    "type": "integer"
                                  },
                                  "charset": {
                                    "const": "utf-8",
                                    "type": "string"
                                  },
                                  "media_type": {
                                    "minLength": 1,
                                    "type": "string"
                                  },
                                  "sha256": {
                                    "pattern": "^[a-f0-9]{64}$",
                                    "type": "string"
                                  },
                                  "text": {
                                    "type": "string"
                                  }
                                },
                                "required": [
                                  "sha256",
                                  "bytes",
                                  "media_type",
                                  "charset",
                                  "text"
                                ],
                                "type": "object"
                              },
                              "included": {
                                "const": true,
                                "type": "boolean"
                              }
                            },
                            "required": [
                              "included",
                              "artifact"
                            ],
                            "type": "object"
                          }
                        ]
                      },
                      "source_map_url": {
                        "anyOf": [
                          {
                            "type": "string"
                          },
                          {
                            "type": "null"
                          }
                        ]
                      },
                      "url": {
                        "type": "string"
                      }
                    },
                    "required": [
                      "script_key",
                      "url",
                      "origin",
                      "cdp_hash",
                      "length",
                      "is_module",
                      "language",
                      "source_map_url",
                      "resource_reconciliation",
                      "source"
                    ],
                    "type": "object"
                  },
                  "type": "array"
                },
                "total": {
                  "maximum": 9007199254740991,
                  "minimum": 0,
                  "type": "integer"
                }
              },
              "required": [
                "total",
                "items"
              ],
              "type": "object"
            },
            "storage": {
              "properties": {
                "cache_names": {
                  "items": {
                    "type": "string"
                  },
                  "type": "array"
                },
                "content_fingerprints": {
                  "default": [],
                  "items": {
                    "properties": {
                      "complete": {
                        "type": "boolean"
                      },
                      "identity_sha256": {
                        "description": "Exact SHA-256 digest of identity.",
                        "pattern": "^[a-f0-9]{64}$",
                        "type": "string"
                      },
                      "scope": {
                        "enum": [
                          "cookie",
                          "local_storage",
                          "session_storage",
                          "indexed_db_schema",
                          "indexed_db_record",
                          "cache_entry"
                        ],
                        "type": "string"
                      },
                      "value_sha256": {
                        "anyOf": [
                          {
                            "pattern": "^[a-f0-9]{64}$",
                            "type": "string"
                          },
                          {
                            "type": "null"
                          }
                        ],
                        "description": "Exact SHA-256 digest of value."
                      }
                    },
                    "required": [
                      "scope",
                      "identity_sha256",
                      "value_sha256",
                      "complete"
                    ],
                    "type": "object"
                  },
                  "type": "array"
                },
                "fingerprint_algorithm": {
                  "const": "sha256",
                  "default": "sha256",
                  "type": "string"
                },
                "fingerprints_complete": {
                  "default": false,
                  "type": "boolean"
                },
                "indexed_db_names": {
                  "items": {
                    "type": "string"
                  },
                  "type": "array"
                },
                "local_storage_keys": {
                  "items": {
                    "type": "string"
                  },
                  "type": "array"
                },
                "origin": {
                  "type": "string"
                },
                "quota_bytes": {
                  "anyOf": [
                    {
                      "minimum": 0,
                      "type": "number"
                    },
                    {
                      "type": "null"
                    }
                  ],
                  "description": "Byte count for quota."
                },
                "session_storage_keys": {
                  "items": {
                    "type": "string"
                  },
                  "type": "array"
                },
                "usage_bytes": {
                  "anyOf": [
                    {
                      "minimum": 0,
                      "type": "number"
                    },
                    {
                      "type": "null"
                    }
                  ],
                  "description": "Byte count for usage."
                },
                "values_redacted": {
                  "const": true,
                  "type": "boolean"
                }
              },
              "required": [
                "origin",
                "usage_bytes",
                "quota_bytes",
                "local_storage_keys",
                "session_storage_keys",
                "indexed_db_names",
                "cache_names",
                "values_redacted"
              ],
              "type": "object"
            },
            "target": {
              "properties": {
                "attached": {
                  "anyOf": [
                    {
                      "type": "boolean"
                    },
                    {
                      "type": "null"
                    }
                  ],
                  "description": "Discovery-reported debugger attachment state; null means unknown"
                },
                "origin": {
                  "type": "string"
                },
                "target_id": {
                  "description": "Exact CDP target identifier selected from the endpoint's target listing.",
                  "type": "string"
                },
                "title": {
                  "type": "string"
                },
                "type": {
                  "type": "string"
                },
                "url": {
                  "type": "string"
                }
              },
              "required": [
                "target_id",
                "type",
                "title",
                "url",
                "origin",
                "attached"
              ],
              "type": "object"
            },
            "workers": {
              "items": {
                "properties": {
                  "attached": {
                    "type": "boolean"
                  },
                  "opener_target_id": {
                    "anyOf": [
                      {
                        "type": "string"
                      },
                      {
                        "type": "null"
                      }
                    ],
                    "default": null
                  },
                  "origin": {
                    "anyOf": [
                      {
                        "type": "string"
                      },
                      {
                        "type": "null"
                      }
                    ]
                  },
                  "parent_frame_id": {
                    "anyOf": [
                      {
                        "type": "string"
                      },
                      {
                        "type": "null"
                      }
                    ],
                    "default": null
                  },
                  "target_id": {
                    "description": "Exact CDP target identifier selected from the endpoint's target listing.",
                    "type": "string"
                  },
                  "type": {
                    "type": "string"
                  },
                  "url": {
                    "type": "string"
                  }
                },
                "required": [
                  "target_id",
                  "type",
                  "url",
                  "origin",
                  "attached"
                ],
                "type": "object"
              },
              "type": "array"
            }
          },
          "required": [
            "browser",
            "target",
            "capture_window",
            "completeness",
            "frames",
            "dom",
            "accessibility",
            "scripts",
            "resources",
            "network",
            "console",
            "workers",
            "metadata",
            "storage",
            "limitations"
          ],
          "type": "object"
        },
        "webmcp": {
          "anyOf": [
            {
              "properties": {
                "browser": {
                  "properties": {
                    "js_version": {
                      "type": "string"
                    },
                    "product": {
                      "type": "string"
                    },
                    "protocol_version": {
                      "type": "string"
                    },
                    "revision": {
                      "type": "string"
                    },
                    "user_agent": {
                      "type": "string"
                    }
                  },
                  "required": [
                    "product",
                    "protocol_version",
                    "revision",
                    "user_agent",
                    "js_version"
                  ],
                  "type": "object"
                },
                "completeness": {
                  "properties": {
                    "attach_limited_sections": {
                      "items": {
                        "enum": [
                          "frames",
                          "dom",
                          "accessibility",
                          "scripts",
                          "script_sources",
                          "resources",
                          "network_requests",
                          "network_initiators",
                          "console_events",
                          "console_text",
                          "websocket_connections",
                          "websocket_frames",
                          "websocket_shapes",
                          "json_body_shapes",
                          "workers",
                          "storage",
                          "storage_keys",
                          "metadata",
                          "webmcp_tools",
                          "screenshot",
                          "source_maps",
                          "timeline"
                        ],
                        "type": "string"
                      },
                      "type": "array"
                    },
                    "conditions": {
                      "items": {
                        "enum": [
                          "complete_within_window",
                          "policy_filtered",
                          "attach_limited",
                          "truncated"
                        ],
                        "type": "string"
                      },
                      "maxItems": 3,
                      "minItems": 1,
                      "type": "array"
                    },
                    "dropped_events": {
                      "properties": {
                        "console_events": {
                          "maximum": 9007199254740991,
                          "minimum": 0,
                          "type": "integer"
                        },
                        "network_requests": {
                          "maximum": 9007199254740991,
                          "minimum": 0,
                          "type": "integer"
                        },
                        "scripts": {
                          "maximum": 9007199254740991,
                          "minimum": 0,
                          "type": "integer"
                        },
                        "timeline_events": {
                          "maximum": 9007199254740991,
                          "minimum": 0,
                          "type": "integer"
                        },
                        "total": {
                          "maximum": 9007199254740991,
                          "minimum": 0,
                          "type": "integer"
                        },
                        "webmcp_tools": {
                          "maximum": 9007199254740991,
                          "minimum": 0,
                          "type": "integer"
                        },
                        "websocket_connections": {
                          "maximum": 9007199254740991,
                          "minimum": 0,
                          "type": "integer"
                        },
                        "websocket_frames": {
                          "maximum": 9007199254740991,
                          "minimum": 0,
                          "type": "integer"
                        }
                      },
                      "required": [
                        "scripts",
                        "network_requests",
                        "console_events",
                        "websocket_connections",
                        "websocket_frames",
                        "webmcp_tools",
                        "timeline_events",
                        "total"
                      ],
                      "type": "object"
                    },
                    "excluded": {
                      "items": {
                        "properties": {
                          "count": {
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
                          },
                          "reason": {
                            "enum": [
                              "disallowed_origin",
                              "unsupported_url",
                              "unattributed_origin",
                              "not_approved",
                              "out_of_target_scope",
                              "provider_unavailable",
                              "invalid_protocol_value",
                              "resource_budget_exhausted"
                            ],
                            "type": "string"
                          },
                          "section": {
                            "enum": [
                              "frames",
                              "dom",
                              "accessibility",
                              "scripts",
                              "script_sources",
                              "resources",
                              "network_requests",
                              "network_initiators",
                              "console_events",
                              "console_text",
                              "websocket_connections",
                              "websocket_frames",
                              "websocket_shapes",
                              "json_body_shapes",
                              "workers",
                              "storage",
                              "storage_keys",
                              "metadata",
                              "webmcp_tools",
                              "screenshot",
                              "source_maps",
                              "timeline"
                            ],
                            "type": "string"
                          }
                        },
                        "required": [
                          "section",
                          "reason",
                          "count"
                        ],
                        "type": "object"
                      },
                      "type": "array"
                    },
                    "policy_filtered_sections": {
                      "items": {
                        "enum": [
                          "frames",
                          "dom",
                          "accessibility",
                          "scripts",
                          "script_sources",
                          "resources",
                          "network_requests",
                          "network_initiators",
                          "console_events",
                          "console_text",
                          "websocket_connections",
                          "websocket_frames",
                          "websocket_shapes",
                          "json_body_shapes",
                          "workers",
                          "storage",
                          "storage_keys",
                          "metadata",
                          "webmcp_tools",
                          "screenshot",
                          "source_maps",
                          "timeline"
                        ],
                        "type": "string"
                      },
                      "type": "array"
                    },
                    "status": {
                      "description": "Current lifecycle or verification status.",
                      "enum": [
                        "complete_within_window",
                        "policy_filtered",
                        "attach_limited",
                        "truncated"
                      ],
                      "type": "string"
                    },
                    "truncated_sections": {
                      "items": {
                        "enum": [
                          "frames",
                          "dom",
                          "accessibility",
                          "scripts",
                          "script_sources",
                          "resources",
                          "network_requests",
                          "network_initiators",
                          "console_events",
                          "console_text",
                          "websocket_connections",
                          "websocket_frames",
                          "websocket_shapes",
                          "json_body_shapes",
                          "workers",
                          "storage",
                          "storage_keys",
                          "metadata",
                          "webmcp_tools",
                          "screenshot",
                          "source_maps",
                          "timeline"
                        ],
                        "type": "string"
                      },
                      "type": "array"
                    },
                    "unavailable_sections": {
                      "items": {
                        "enum": [
                          "frames",
                          "dom",
                          "accessibility",
                          "scripts",
                          "script_sources",
                          "resources",
                          "network_requests",
                          "network_initiators",
                          "console_events",
                          "console_text",
                          "websocket_connections",
                          "websocket_frames",
                          "websocket_shapes",
                          "json_body_shapes",
                          "workers",
                          "storage",
                          "storage_keys",
                          "metadata",
                          "webmcp_tools",
                          "screenshot",
                          "source_maps",
                          "timeline"
                        ],
                        "type": "string"
                      },
                      "type": "array"
                    }
                  },
                  "required": [
                    "status",
                    "conditions",
                    "policy_filtered_sections",
                    "attach_limited_sections",
                    "truncated_sections",
                    "unavailable_sections",
                    "excluded",
                    "dropped_events"
                  ],
                  "type": "object"
                },
                "limitations": {
                  "items": {
                    "type": "string"
                  },
                  "type": "array"
                },
                "status": {
                  "description": "Current lifecycle or verification status.",
                  "enum": [
                    "available",
                    "unavailable"
                  ],
                  "type": "string"
                },
                "target": {
                  "properties": {
                    "origin": {
                      "type": "string"
                    },
                    "target_id": {
                      "description": "Exact CDP target identifier selected from the endpoint's target listing.",
                      "type": "string"
                    },
                    "url": {
                      "type": "string"
                    }
                  },
                  "required": [
                    "target_id",
                    "url",
                    "origin"
                  ],
                  "type": "object"
                },
                "tools": {
                  "properties": {
                    "items": {
                      "items": {
                        "properties": {
                          "annotations": {
                            "properties": {
                              "autosubmit": {
                                "anyOf": [
                                  {
                                    "type": "boolean"
                                  },
                                  {
                                    "type": "null"
                                  }
                                ]
                              },
                              "consequential": {
                                "anyOf": [
                                  {
                                    "type": "boolean"
                                  },
                                  {
                                    "type": "null"
                                  }
                                ]
                              },
                              "read_only": {
                                "anyOf": [
                                  {
                                    "type": "boolean"
                                  },
                                  {
                                    "type": "null"
                                  }
                                ]
                              },
                              "untrusted_content": {
                                "anyOf": [
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
                              "read_only",
                              "untrusted_content",
                              "autosubmit"
                            ],
                            "type": "object"
                          },
                          "declaration_kind": {
                            "enum": [
                              "declarative",
                              "imperative"
                            ],
                            "type": "string"
                          },
                          "description": {
                            "type": "string"
                          },
                          "frame_id": {
                            "type": "string"
                          },
                          "frame_url": {
                            "type": "string"
                          },
                          "input_schema": {
                            "anyOf": [
                              {},
                              {
                                "type": "null"
                              }
                            ]
                          },
                          "input_schema_sha256": {
                            "anyOf": [
                              {
                                "pattern": "^[a-f0-9]{64}$",
                                "type": "string"
                              },
                              {
                                "type": "null"
                              }
                            ],
                            "description": "Exact SHA-256 digest of input schema."
                          },
                          "name": {
                            "description": "Exact name used by this operation.",
                            "type": "string"
                          },
                          "owner_origin": {
                            "type": "string"
                          },
                          "registration_source": {
                            "anyOf": [
                              {
                                "properties": {
                                  "column": {
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
                                  },
                                  "line": {
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
                                  },
                                  "url": {
                                    "type": "string"
                                  }
                                },
                                "required": [
                                  "url",
                                  "line",
                                  "column"
                                ],
                                "type": "object"
                              },
                              {
                                "type": "null"
                              }
                            ]
                          },
                          "tool_key": {
                            "pattern": "^webmcp_[a-f0-9]{64}$",
                            "type": "string"
                          },
                          "trust": {
                            "const": "page-declared-untrusted",
                            "type": "string"
                          }
                        },
                        "required": [
                          "tool_key",
                          "name",
                          "description",
                          "frame_id",
                          "frame_url",
                          "owner_origin",
                          "declaration_kind",
                          "input_schema",
                          "input_schema_sha256",
                          "annotations",
                          "registration_source",
                          "trust"
                        ],
                        "type": "object"
                      },
                      "type": "array"
                    },
                    "total": {
                      "maximum": 9007199254740991,
                      "minimum": 0,
                      "type": "integer"
                    }
                  },
                  "required": [
                    "total",
                    "items"
                  ],
                  "type": "object"
                }
              },
              "required": [
                "browser",
                "target",
                "status",
                "tools",
                "completeness",
                "limitations"
              ],
              "type": "object"
            },
            {
              "type": "null"
            }
          ],
          "description": "Complete normalized_result from discover_webmcp_tools for this capture, or null when it was not recorded."
        }
      },
      "required": [
        "inspection"
      ],
      "type": "object"
    },
    "before_scenario": {
      "additionalProperties": false,
      "description": "Earlier complete normalized_result from capture_browser_scenario.",
      "properties": {
        "browser": {
          "additionalProperties": false,
          "properties": {
            "cleanup": {
              "enum": [
                "terminated-owned-process",
                "disconnected-external"
              ],
              "type": "string"
            },
            "mode": {
              "description": "Operation mode that selects the requested behavior.",
              "enum": [
                "launch",
                "connect"
              ],
              "type": "string"
            },
            "process_ownership": {
              "enum": [
                "provider-owned",
                "external"
              ],
              "type": "string"
            },
            "product": {
              "minLength": 1,
              "type": "string"
            },
            "version": {
              "minLength": 1,
              "type": "string"
            }
          },
          "required": [
            "mode",
            "process_ownership",
            "cleanup",
            "product",
            "version"
          ],
          "type": "object"
        },
        "completeness": {
          "oneOf": [
            {
              "additionalProperties": false,
              "properties": {
                "equality_eligible": {
                  "const": true,
                  "type": "boolean"
                },
                "missing_sections": {
                  "items": {
                    "not": {}
                  },
                  "maxItems": 0,
                  "minItems": 0,
                  "type": "array"
                },
                "status": {
                  "const": "complete",
                  "description": "Current lifecycle or verification status.",
                  "type": "string"
                },
                "truncated_sections": {
                  "items": {
                    "not": {}
                  },
                  "maxItems": 0,
                  "minItems": 0,
                  "type": "array"
                }
              },
              "required": [
                "status",
                "equality_eligible",
                "missing_sections",
                "truncated_sections"
              ],
              "type": "object"
            },
            {
              "additionalProperties": false,
              "properties": {
                "equality_eligible": {
                  "const": false,
                  "type": "boolean"
                },
                "missing_sections": {
                  "items": {
                    "enum": [
                      "action",
                      "screenshot",
                      "dom",
                      "accessibility",
                      "url",
                      "history",
                      "storage",
                      "events",
                      "frames",
                      "workers",
                      "popups",
                      "websockets"
                    ],
                    "type": "string"
                  },
                  "minItems": 1,
                  "type": "array"
                },
                "status": {
                  "const": "incomplete",
                  "description": "Current lifecycle or verification status.",
                  "type": "string"
                },
                "truncated_sections": {
                  "items": {
                    "not": {}
                  },
                  "maxItems": 0,
                  "minItems": 0,
                  "type": "array"
                }
              },
              "required": [
                "status",
                "equality_eligible",
                "missing_sections",
                "truncated_sections"
              ],
              "type": "object"
            },
            {
              "additionalProperties": false,
              "properties": {
                "equality_eligible": {
                  "const": false,
                  "type": "boolean"
                },
                "missing_sections": {
                  "items": {
                    "enum": [
                      "action",
                      "screenshot",
                      "dom",
                      "accessibility",
                      "url",
                      "history",
                      "storage",
                      "events",
                      "frames",
                      "workers",
                      "popups",
                      "websockets"
                    ],
                    "type": "string"
                  },
                  "type": "array"
                },
                "status": {
                  "const": "truncated",
                  "description": "Current lifecycle or verification status.",
                  "type": "string"
                },
                "truncated_sections": {
                  "items": {
                    "enum": [
                      "action",
                      "screenshot",
                      "dom",
                      "accessibility",
                      "url",
                      "history",
                      "storage",
                      "events",
                      "frames",
                      "workers",
                      "popups",
                      "websockets"
                    ],
                    "type": "string"
                  },
                  "minItems": 1,
                  "type": "array"
                }
              },
              "required": [
                "status",
                "equality_eligible",
                "missing_sections",
                "truncated_sections"
              ],
              "type": "object"
            }
          ]
        },
        "duration_ms": {
          "maximum": 9007199254740991,
          "minimum": 0,
          "type": "integer"
        },
        "events": {
          "additionalProperties": false,
          "properties": {
            "dropped": {
              "maximum": 9007199254740991,
              "minimum": 0,
              "type": "integer"
            },
            "items": {
              "items": {
                "anyOf": [
                  {
                    "additionalProperties": false,
                    "properties": {
                      "kind": {
                        "const": "console",
                        "type": "string"
                      },
                      "level": {
                        "minLength": 1,
                        "type": "string"
                      },
                      "sequence": {
                        "maximum": 9007199254740991,
                        "minimum": 1,
                        "type": "integer"
                      },
                      "step_index": {
                        "maximum": 9007199254740991,
                        "minimum": 0,
                        "type": "integer"
                      },
                      "text": {
                        "type": "string"
                      },
                      "url": {
                        "anyOf": [
                          {
                            "properties": {
                              "origin": {
                                "anyOf": [
                                  {
                                    "type": "string"
                                  },
                                  {
                                    "type": "null"
                                  }
                                ]
                              },
                              "query_parameter_names": {
                                "items": {
                                  "type": "string"
                                },
                                "type": "array"
                              },
                              "redacted": {
                                "type": "boolean"
                              },
                              "url": {
                                "type": "string"
                              }
                            },
                            "required": [
                              "url",
                              "origin",
                              "query_parameter_names",
                              "redacted"
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
                      "sequence",
                      "step_index",
                      "kind",
                      "level",
                      "text",
                      "url"
                    ],
                    "type": "object"
                  },
                  {
                    "additionalProperties": false,
                    "properties": {
                      "kind": {
                        "const": "page-error",
                        "type": "string"
                      },
                      "message": {
                        "type": "string"
                      },
                      "sequence": {
                        "maximum": 9007199254740991,
                        "minimum": 1,
                        "type": "integer"
                      },
                      "stack": {
                        "anyOf": [
                          {
                            "type": "string"
                          },
                          {
                            "type": "null"
                          }
                        ]
                      },
                      "step_index": {
                        "maximum": 9007199254740991,
                        "minimum": 0,
                        "type": "integer"
                      }
                    },
                    "required": [
                      "sequence",
                      "step_index",
                      "kind",
                      "message",
                      "stack"
                    ],
                    "type": "object"
                  },
                  {
                    "additionalProperties": false,
                    "properties": {
                      "failure": {
                        "type": "null"
                      },
                      "header_names": {
                        "items": {
                          "type": "string"
                        },
                        "type": "array"
                      },
                      "kind": {
                        "const": "request",
                        "type": "string"
                      },
                      "method": {
                        "minLength": 1,
                        "type": "string"
                      },
                      "redirected_from_transaction_id": {
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
                      "redirected_from_transaction_state": {
                        "enum": [
                          "root",
                          "unknown"
                        ],
                        "type": "string"
                      },
                      "resource_type": {
                        "minLength": 1,
                        "type": "string"
                      },
                      "sequence": {
                        "maximum": 9007199254740991,
                        "minimum": 1,
                        "type": "integer"
                      },
                      "status": {
                        "description": "Current lifecycle or verification status.",
                        "type": "null"
                      },
                      "step_index": {
                        "maximum": 9007199254740991,
                        "minimum": 0,
                        "type": "integer"
                      },
                      "transaction_id": {
                        "minLength": 1,
                        "type": "string"
                      },
                      "url": {
                        "properties": {
                          "origin": {
                            "anyOf": [
                              {
                                "type": "string"
                              },
                              {
                                "type": "null"
                              }
                            ]
                          },
                          "query_parameter_names": {
                            "items": {
                              "type": "string"
                            },
                            "type": "array"
                          },
                          "redacted": {
                            "type": "boolean"
                          },
                          "url": {
                            "type": "string"
                          }
                        },
                        "required": [
                          "url",
                          "origin",
                          "query_parameter_names",
                          "redacted"
                        ],
                        "type": "object"
                      }
                    },
                    "required": [
                      "sequence",
                      "step_index",
                      "transaction_id",
                      "redirected_from_transaction_id",
                      "method",
                      "url",
                      "resource_type",
                      "header_names",
                      "kind",
                      "status",
                      "failure"
                    ],
                    "type": "object"
                  },
                  {
                    "additionalProperties": false,
                    "properties": {
                      "failure": {
                        "type": "null"
                      },
                      "header_names": {
                        "items": {
                          "type": "string"
                        },
                        "type": "array"
                      },
                      "kind": {
                        "const": "response",
                        "type": "string"
                      },
                      "method": {
                        "minLength": 1,
                        "type": "string"
                      },
                      "redirected_from_transaction_id": {
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
                      "redirected_from_transaction_state": {
                        "enum": [
                          "root",
                          "unknown"
                        ],
                        "type": "string"
                      },
                      "resource_type": {
                        "minLength": 1,
                        "type": "string"
                      },
                      "sequence": {
                        "maximum": 9007199254740991,
                        "minimum": 1,
                        "type": "integer"
                      },
                      "status": {
                        "description": "Current lifecycle or verification status.",
                        "maximum": 599,
                        "minimum": 100,
                        "type": "integer"
                      },
                      "step_index": {
                        "maximum": 9007199254740991,
                        "minimum": 0,
                        "type": "integer"
                      },
                      "transaction_id": {
                        "minLength": 1,
                        "type": "string"
                      },
                      "url": {
                        "properties": {
                          "origin": {
                            "anyOf": [
                              {
                                "type": "string"
                              },
                              {
                                "type": "null"
                              }
                            ]
                          },
                          "query_parameter_names": {
                            "items": {
                              "type": "string"
                            },
                            "type": "array"
                          },
                          "redacted": {
                            "type": "boolean"
                          },
                          "url": {
                            "type": "string"
                          }
                        },
                        "required": [
                          "url",
                          "origin",
                          "query_parameter_names",
                          "redacted"
                        ],
                        "type": "object"
                      }
                    },
                    "required": [
                      "sequence",
                      "step_index",
                      "transaction_id",
                      "redirected_from_transaction_id",
                      "method",
                      "url",
                      "resource_type",
                      "header_names",
                      "kind",
                      "status",
                      "failure"
                    ],
                    "type": "object"
                  },
                  {
                    "additionalProperties": false,
                    "properties": {
                      "failure": {
                        "minLength": 1,
                        "type": "string"
                      },
                      "header_names": {
                        "items": {
                          "type": "string"
                        },
                        "type": "array"
                      },
                      "kind": {
                        "const": "request-failed",
                        "type": "string"
                      },
                      "method": {
                        "minLength": 1,
                        "type": "string"
                      },
                      "redirected_from_transaction_id": {
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
                      "redirected_from_transaction_state": {
                        "enum": [
                          "root",
                          "unknown"
                        ],
                        "type": "string"
                      },
                      "resource_type": {
                        "minLength": 1,
                        "type": "string"
                      },
                      "sequence": {
                        "maximum": 9007199254740991,
                        "minimum": 1,
                        "type": "integer"
                      },
                      "status": {
                        "description": "Current lifecycle or verification status.",
                        "type": "null"
                      },
                      "step_index": {
                        "maximum": 9007199254740991,
                        "minimum": 0,
                        "type": "integer"
                      },
                      "transaction_id": {
                        "minLength": 1,
                        "type": "string"
                      },
                      "url": {
                        "properties": {
                          "origin": {
                            "anyOf": [
                              {
                                "type": "string"
                              },
                              {
                                "type": "null"
                              }
                            ]
                          },
                          "query_parameter_names": {
                            "items": {
                              "type": "string"
                            },
                            "type": "array"
                          },
                          "redacted": {
                            "type": "boolean"
                          },
                          "url": {
                            "type": "string"
                          }
                        },
                        "required": [
                          "url",
                          "origin",
                          "query_parameter_names",
                          "redacted"
                        ],
                        "type": "object"
                      }
                    },
                    "required": [
                      "sequence",
                      "step_index",
                      "transaction_id",
                      "redirected_from_transaction_id",
                      "method",
                      "url",
                      "resource_type",
                      "header_names",
                      "kind",
                      "status",
                      "failure"
                    ],
                    "type": "object"
                  },
                  {
                    "additionalProperties": false,
                    "properties": {
                      "failure": {
                        "type": "null"
                      },
                      "header_names": {
                        "items": {
                          "type": "string"
                        },
                        "type": "array"
                      },
                      "kind": {
                        "const": "request-finished",
                        "type": "string"
                      },
                      "method": {
                        "minLength": 1,
                        "type": "string"
                      },
                      "redirected_from_transaction_id": {
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
                      "redirected_from_transaction_state": {
                        "enum": [
                          "root",
                          "unknown"
                        ],
                        "type": "string"
                      },
                      "resource_type": {
                        "minLength": 1,
                        "type": "string"
                      },
                      "sequence": {
                        "maximum": 9007199254740991,
                        "minimum": 1,
                        "type": "integer"
                      },
                      "status": {
                        "description": "Current lifecycle or verification status.",
                        "type": "null"
                      },
                      "step_index": {
                        "maximum": 9007199254740991,
                        "minimum": 0,
                        "type": "integer"
                      },
                      "transaction_id": {
                        "minLength": 1,
                        "type": "string"
                      },
                      "url": {
                        "properties": {
                          "origin": {
                            "anyOf": [
                              {
                                "type": "string"
                              },
                              {
                                "type": "null"
                              }
                            ]
                          },
                          "query_parameter_names": {
                            "items": {
                              "type": "string"
                            },
                            "type": "array"
                          },
                          "redacted": {
                            "type": "boolean"
                          },
                          "url": {
                            "type": "string"
                          }
                        },
                        "required": [
                          "url",
                          "origin",
                          "query_parameter_names",
                          "redacted"
                        ],
                        "type": "object"
                      }
                    },
                    "required": [
                      "sequence",
                      "step_index",
                      "transaction_id",
                      "redirected_from_transaction_id",
                      "method",
                      "url",
                      "resource_type",
                      "header_names",
                      "kind",
                      "status",
                      "failure"
                    ],
                    "type": "object"
                  },
                  {
                    "additionalProperties": false,
                    "properties": {
                      "failure": {
                        "type": "null"
                      },
                      "header_names": {
                        "items": {
                          "type": "string"
                        },
                        "type": "array"
                      },
                      "kind": {
                        "const": "request-unfinished",
                        "type": "string"
                      },
                      "method": {
                        "minLength": 1,
                        "type": "string"
                      },
                      "reason": {
                        "enum": [
                          "capture-ended",
                          "cancelled"
                        ],
                        "type": "string"
                      },
                      "redirected_from_transaction_id": {
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
                      "redirected_from_transaction_state": {
                        "enum": [
                          "root",
                          "unknown"
                        ],
                        "type": "string"
                      },
                      "resource_type": {
                        "minLength": 1,
                        "type": "string"
                      },
                      "sequence": {
                        "maximum": 9007199254740991,
                        "minimum": 1,
                        "type": "integer"
                      },
                      "status": {
                        "description": "Current lifecycle or verification status.",
                        "type": "null"
                      },
                      "step_index": {
                        "maximum": 9007199254740991,
                        "minimum": 0,
                        "type": "integer"
                      },
                      "transaction_id": {
                        "minLength": 1,
                        "type": "string"
                      },
                      "url": {
                        "properties": {
                          "origin": {
                            "anyOf": [
                              {
                                "type": "string"
                              },
                              {
                                "type": "null"
                              }
                            ]
                          },
                          "query_parameter_names": {
                            "items": {
                              "type": "string"
                            },
                            "type": "array"
                          },
                          "redacted": {
                            "type": "boolean"
                          },
                          "url": {
                            "type": "string"
                          }
                        },
                        "required": [
                          "url",
                          "origin",
                          "query_parameter_names",
                          "redacted"
                        ],
                        "type": "object"
                      }
                    },
                    "required": [
                      "sequence",
                      "step_index",
                      "transaction_id",
                      "redirected_from_transaction_id",
                      "method",
                      "url",
                      "resource_type",
                      "header_names",
                      "kind",
                      "status",
                      "failure",
                      "reason"
                    ],
                    "type": "object"
                  },
                  {
                    "additionalProperties": false,
                    "properties": {
                      "body": {
                        "anyOf": [
                          {
                            "additionalProperties": false,
                            "properties": {
                              "state": {
                                "const": "not_requested",
                                "type": "string"
                              }
                            },
                            "required": [
                              "state"
                            ],
                            "type": "object"
                          },
                          {
                            "additionalProperties": false,
                            "properties": {
                              "state": {
                                "const": "not_exposed",
                                "type": "string"
                              }
                            },
                            "required": [
                              "state"
                            ],
                            "type": "object"
                          },
                          {
                            "additionalProperties": false,
                            "properties": {
                              "message": {
                                "minLength": 1,
                                "type": "string"
                              },
                              "reason": {
                                "enum": [
                                  "request-failed",
                                  "response-unfinished",
                                  "body-read-failed",
                                  "body-read-timeout",
                                  "cancelled",
                                  "capture-ended"
                                ],
                                "type": "string"
                              },
                              "state": {
                                "const": "unavailable",
                                "type": "string"
                              }
                            },
                            "required": [
                              "state",
                              "reason",
                              "message"
                            ],
                            "type": "object"
                          },
                          {
                            "additionalProperties": false,
                            "properties": {
                              "bytes": {
                                "maximum": 9007199254740991,
                                "minimum": 0,
                                "type": "integer"
                              },
                              "content": {
                                "type": "string"
                              },
                              "encoding": {
                                "const": "base64",
                                "type": "string"
                              },
                              "media_type": {
                                "anyOf": [
                                  {
                                    "type": "string"
                                  },
                                  {
                                    "type": "null"
                                  }
                                ]
                              },
                              "redacted": {
                                "type": "boolean"
                              },
                              "representation": {
                                "enum": [
                                  "browser-exposed-request-bytes",
                                  "playwright-response-body-bytes",
                                  "browser-decoded-response-bytes"
                                ],
                                "type": "string"
                              },
                              "sha256": {
                                "pattern": "^[a-f0-9]{64}$",
                                "type": "string"
                              },
                              "state": {
                                "const": "captured",
                                "type": "string"
                              }
                            },
                            "required": [
                              "state",
                              "representation",
                              "encoding",
                              "content",
                              "bytes",
                              "sha256",
                              "media_type",
                              "redacted"
                            ],
                            "type": "object"
                          }
                        ]
                      },
                      "headers": {
                        "anyOf": [
                          {
                            "additionalProperties": false,
                            "properties": {
                              "state": {
                                "const": "not_requested",
                                "type": "string"
                              }
                            },
                            "required": [
                              "state"
                            ],
                            "type": "object"
                          },
                          {
                            "additionalProperties": false,
                            "properties": {
                              "message": {
                                "minLength": 1,
                                "type": "string"
                              },
                              "state": {
                                "const": "unavailable",
                                "type": "string"
                              }
                            },
                            "required": [
                              "state",
                              "message"
                            ],
                            "type": "object"
                          },
                          {
                            "additionalProperties": false,
                            "properties": {
                              "items": {
                                "items": {
                                  "additionalProperties": false,
                                  "properties": {
                                    "name": {
                                      "description": "Exact name used by this operation.",
                                      "minLength": 1,
                                      "type": "string"
                                    },
                                    "redacted": {
                                      "type": "boolean"
                                    },
                                    "value": {
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
                                    "name",
                                    "value",
                                    "redacted"
                                  ],
                                  "type": "object"
                                },
                                "type": "array"
                              },
                              "state": {
                                "const": "captured",
                                "type": "string"
                              }
                            },
                            "required": [
                              "state",
                              "items"
                            ],
                            "type": "object"
                          }
                        ]
                      },
                      "kind": {
                        "const": "network-content",
                        "type": "string"
                      },
                      "phase": {
                        "description": "Current plan or execution phase of the operation.",
                        "enum": [
                          "request",
                          "response"
                        ],
                        "type": "string"
                      },
                      "sequence": {
                        "maximum": 9007199254740991,
                        "minimum": 1,
                        "type": "integer"
                      },
                      "source_event_sequence": {
                        "maximum": 9007199254740991,
                        "minimum": 1,
                        "type": "integer"
                      },
                      "step_index": {
                        "maximum": 9007199254740991,
                        "minimum": 0,
                        "type": "integer"
                      },
                      "transaction_id": {
                        "minLength": 1,
                        "type": "string"
                      }
                    },
                    "required": [
                      "sequence",
                      "step_index",
                      "kind",
                      "transaction_id",
                      "source_event_sequence",
                      "phase",
                      "headers",
                      "body"
                    ],
                    "type": "object"
                  },
                  {
                    "additionalProperties": false,
                    "properties": {
                      "kind": {
                        "enum": [
                          "websocket-opened",
                          "websocket-closed"
                        ],
                        "type": "string"
                      },
                      "sequence": {
                        "maximum": 9007199254740991,
                        "minimum": 1,
                        "type": "integer"
                      },
                      "step_index": {
                        "maximum": 9007199254740991,
                        "minimum": 0,
                        "type": "integer"
                      },
                      "url": {
                        "properties": {
                          "origin": {
                            "anyOf": [
                              {
                                "type": "string"
                              },
                              {
                                "type": "null"
                              }
                            ]
                          },
                          "query_parameter_names": {
                            "items": {
                              "type": "string"
                            },
                            "type": "array"
                          },
                          "redacted": {
                            "type": "boolean"
                          },
                          "url": {
                            "type": "string"
                          }
                        },
                        "required": [
                          "url",
                          "origin",
                          "query_parameter_names",
                          "redacted"
                        ],
                        "type": "object"
                      }
                    },
                    "required": [
                      "sequence",
                      "step_index",
                      "kind",
                      "url"
                    ],
                    "type": "object"
                  },
                  {
                    "additionalProperties": false,
                    "properties": {
                      "kind": {
                        "enum": [
                          "websocket-frame-sent",
                          "websocket-frame-received"
                        ],
                        "type": "string"
                      },
                      "payload_bytes": {
                        "description": "Byte count for payload.",
                        "maximum": 9007199254740991,
                        "minimum": 0,
                        "type": "integer"
                      },
                      "payload_text": {
                        "type": "string"
                      },
                      "payload_type": {
                        "const": "text",
                        "type": "string"
                      },
                      "sequence": {
                        "maximum": 9007199254740991,
                        "minimum": 1,
                        "type": "integer"
                      },
                      "step_index": {
                        "maximum": 9007199254740991,
                        "minimum": 0,
                        "type": "integer"
                      },
                      "truncated": {
                        "type": "boolean"
                      },
                      "url": {
                        "properties": {
                          "origin": {
                            "anyOf": [
                              {
                                "type": "string"
                              },
                              {
                                "type": "null"
                              }
                            ]
                          },
                          "query_parameter_names": {
                            "items": {
                              "type": "string"
                            },
                            "type": "array"
                          },
                          "redacted": {
                            "type": "boolean"
                          },
                          "url": {
                            "type": "string"
                          }
                        },
                        "required": [
                          "url",
                          "origin",
                          "query_parameter_names",
                          "redacted"
                        ],
                        "type": "object"
                      }
                    },
                    "required": [
                      "sequence",
                      "step_index",
                      "kind",
                      "url",
                      "payload_bytes",
                      "truncated",
                      "payload_type",
                      "payload_text"
                    ],
                    "type": "object"
                  },
                  {
                    "additionalProperties": false,
                    "properties": {
                      "kind": {
                        "enum": [
                          "websocket-frame-sent",
                          "websocket-frame-received"
                        ],
                        "type": "string"
                      },
                      "payload_bytes": {
                        "description": "Byte count for payload.",
                        "maximum": 9007199254740991,
                        "minimum": 0,
                        "type": "integer"
                      },
                      "payload_text": {
                        "type": "null"
                      },
                      "payload_type": {
                        "const": "binary",
                        "type": "string"
                      },
                      "sequence": {
                        "maximum": 9007199254740991,
                        "minimum": 1,
                        "type": "integer"
                      },
                      "step_index": {
                        "maximum": 9007199254740991,
                        "minimum": 0,
                        "type": "integer"
                      },
                      "truncated": {
                        "type": "boolean"
                      },
                      "url": {
                        "properties": {
                          "origin": {
                            "anyOf": [
                              {
                                "type": "string"
                              },
                              {
                                "type": "null"
                              }
                            ]
                          },
                          "query_parameter_names": {
                            "items": {
                              "type": "string"
                            },
                            "type": "array"
                          },
                          "redacted": {
                            "type": "boolean"
                          },
                          "url": {
                            "type": "string"
                          }
                        },
                        "required": [
                          "url",
                          "origin",
                          "query_parameter_names",
                          "redacted"
                        ],
                        "type": "object"
                      }
                    },
                    "required": [
                      "sequence",
                      "step_index",
                      "kind",
                      "url",
                      "payload_bytes",
                      "truncated",
                      "payload_type",
                      "payload_text"
                    ],
                    "type": "object"
                  },
                  {
                    "additionalProperties": false,
                    "properties": {
                      "kind": {
                        "enum": [
                          "frame-attached",
                          "frame-detached",
                          "frame-navigated",
                          "worker-created",
                          "worker-closed",
                          "popup-opened",
                          "popup-closed"
                        ],
                        "type": "string"
                      },
                      "name": {
                        "anyOf": [
                          {
                            "type": "string"
                          },
                          {
                            "type": "null"
                          }
                        ],
                        "description": "Exact name used by this operation."
                      },
                      "sequence": {
                        "maximum": 9007199254740991,
                        "minimum": 1,
                        "type": "integer"
                      },
                      "step_index": {
                        "maximum": 9007199254740991,
                        "minimum": 0,
                        "type": "integer"
                      },
                      "url": {
                        "anyOf": [
                          {
                            "properties": {
                              "origin": {
                                "anyOf": [
                                  {
                                    "type": "string"
                                  },
                                  {
                                    "type": "null"
                                  }
                                ]
                              },
                              "query_parameter_names": {
                                "items": {
                                  "type": "string"
                                },
                                "type": "array"
                              },
                              "redacted": {
                                "type": "boolean"
                              },
                              "url": {
                                "type": "string"
                              }
                            },
                            "required": [
                              "url",
                              "origin",
                              "query_parameter_names",
                              "redacted"
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
                      "sequence",
                      "step_index",
                      "kind",
                      "url",
                      "name"
                    ],
                    "type": "object"
                  },
                  {
                    "additionalProperties": false,
                    "properties": {
                      "kind": {
                        "const": "download-cancelled",
                        "type": "string"
                      },
                      "sequence": {
                        "maximum": 9007199254740991,
                        "minimum": 1,
                        "type": "integer"
                      },
                      "step_index": {
                        "maximum": 9007199254740991,
                        "minimum": 0,
                        "type": "integer"
                      },
                      "suggested_filename": {
                        "type": "string"
                      },
                      "url": {
                        "properties": {
                          "origin": {
                            "anyOf": [
                              {
                                "type": "string"
                              },
                              {
                                "type": "null"
                              }
                            ]
                          },
                          "query_parameter_names": {
                            "items": {
                              "type": "string"
                            },
                            "type": "array"
                          },
                          "redacted": {
                            "type": "boolean"
                          },
                          "url": {
                            "type": "string"
                          }
                        },
                        "required": [
                          "url",
                          "origin",
                          "query_parameter_names",
                          "redacted"
                        ],
                        "type": "object"
                      }
                    },
                    "required": [
                      "sequence",
                      "step_index",
                      "kind",
                      "suggested_filename",
                      "url"
                    ],
                    "type": "object"
                  }
                ]
              },
              "type": "array"
            },
            "retained": {
              "maximum": 9007199254740991,
              "minimum": 0,
              "type": "integer"
            }
          },
          "required": [
            "retained",
            "dropped",
            "items"
          ],
          "type": "object"
        },
        "limitations": {
          "items": {
            "minLength": 1,
            "type": "string"
          },
          "type": "array"
        },
        "scenario": {
          "additionalProperties": false,
          "properties": {
            "action_count": {
              "maximum": 9007199254740991,
              "minimum": 1,
              "type": "integer"
            },
            "event_families": {
              "items": {
                "enum": [
                  "console",
                  "page-errors",
                  "network",
                  "websockets",
                  "frames",
                  "workers",
                  "popups",
                  "downloads"
                ],
                "type": "string"
              },
              "type": "array"
            },
            "network_content": {
              "additionalProperties": false,
              "properties": {
                "header_values": {
                  "type": "boolean"
                },
                "request_body": {
                  "type": "boolean"
                },
                "response_body": {
                  "type": "boolean"
                }
              },
              "required": [
                "request_body",
                "response_body",
                "header_values"
              ],
              "type": "object"
            },
            "secret_references": {
              "items": {
                "minLength": 1,
                "type": "string"
              },
              "type": "array"
            },
            "start_origin": {
              "minLength": 1,
              "type": "string"
            }
          },
          "required": [
            "start_origin",
            "action_count",
            "secret_references",
            "network_content"
          ],
          "type": "object"
        },
        "steps": {
          "items": {
            "anyOf": [
              {
                "additionalProperties": false,
                "properties": {
                  "action": {
                    "minLength": 1,
                    "type": "string"
                  },
                  "after_url": {
                    "properties": {
                      "origin": {
                        "anyOf": [
                          {
                            "type": "string"
                          },
                          {
                            "type": "null"
                          }
                        ]
                      },
                      "query_parameter_names": {
                        "items": {
                          "type": "string"
                        },
                        "type": "array"
                      },
                      "redacted": {
                        "type": "boolean"
                      },
                      "url": {
                        "type": "string"
                      }
                    },
                    "required": [
                      "url",
                      "origin",
                      "query_parameter_names",
                      "redacted"
                    ],
                    "type": "object"
                  },
                  "artifacts": {
                    "additionalProperties": false,
                    "properties": {
                      "accessibility": {
                        "oneOf": [
                          {
                            "additionalProperties": false,
                            "properties": {
                              "state": {
                                "const": "captured",
                                "type": "string"
                              },
                              "value": {
                                "additionalProperties": false,
                                "properties": {
                                  "bytes": {
                                    "maximum": 9007199254740991,
                                    "minimum": 0,
                                    "type": "integer"
                                  },
                                  "sha256": {
                                    "pattern": "^[a-f0-9]{64}$",
                                    "type": "string"
                                  },
                                  "text": {
                                    "type": "string"
                                  }
                                },
                                "required": [
                                  "sha256",
                                  "bytes",
                                  "text"
                                ],
                                "type": "object"
                              }
                            },
                            "required": [
                              "state",
                              "value"
                            ],
                            "type": "object"
                          },
                          {
                            "additionalProperties": false,
                            "properties": {
                              "state": {
                                "const": "not_requested",
                                "type": "string"
                              }
                            },
                            "required": [
                              "state"
                            ],
                            "type": "object"
                          },
                          {
                            "additionalProperties": false,
                            "properties": {
                              "reason": {
                                "minLength": 1,
                                "type": "string"
                              },
                              "state": {
                                "const": "missing",
                                "type": "string"
                              }
                            },
                            "required": [
                              "state",
                              "reason"
                            ],
                            "type": "object"
                          },
                          {
                            "additionalProperties": false,
                            "properties": {
                              "observed": {
                                "maximum": 9007199254740991,
                                "minimum": 0,
                                "type": "integer"
                              },
                              "reason": {
                                "minLength": 1,
                                "type": "string"
                              },
                              "retained": {
                                "maximum": 9007199254740991,
                                "minimum": 0,
                                "type": "integer"
                              },
                              "state": {
                                "const": "truncated",
                                "type": "string"
                              }
                            },
                            "required": [
                              "state",
                              "observed",
                              "retained",
                              "reason"
                            ],
                            "type": "object"
                          }
                        ]
                      },
                      "dom": {
                        "oneOf": [
                          {
                            "additionalProperties": false,
                            "properties": {
                              "state": {
                                "const": "captured",
                                "type": "string"
                              },
                              "value": {
                                "additionalProperties": false,
                                "properties": {
                                  "bytes": {
                                    "maximum": 9007199254740991,
                                    "minimum": 0,
                                    "type": "integer"
                                  },
                                  "sha256": {
                                    "pattern": "^[a-f0-9]{64}$",
                                    "type": "string"
                                  },
                                  "text": {
                                    "type": "string"
                                  }
                                },
                                "required": [
                                  "sha256",
                                  "bytes",
                                  "text"
                                ],
                                "type": "object"
                              }
                            },
                            "required": [
                              "state",
                              "value"
                            ],
                            "type": "object"
                          },
                          {
                            "additionalProperties": false,
                            "properties": {
                              "state": {
                                "const": "not_requested",
                                "type": "string"
                              }
                            },
                            "required": [
                              "state"
                            ],
                            "type": "object"
                          },
                          {
                            "additionalProperties": false,
                            "properties": {
                              "reason": {
                                "minLength": 1,
                                "type": "string"
                              },
                              "state": {
                                "const": "missing",
                                "type": "string"
                              }
                            },
                            "required": [
                              "state",
                              "reason"
                            ],
                            "type": "object"
                          },
                          {
                            "additionalProperties": false,
                            "properties": {
                              "observed": {
                                "maximum": 9007199254740991,
                                "minimum": 0,
                                "type": "integer"
                              },
                              "reason": {
                                "minLength": 1,
                                "type": "string"
                              },
                              "retained": {
                                "maximum": 9007199254740991,
                                "minimum": 0,
                                "type": "integer"
                              },
                              "state": {
                                "const": "truncated",
                                "type": "string"
                              }
                            },
                            "required": [
                              "state",
                              "observed",
                              "retained",
                              "reason"
                            ],
                            "type": "object"
                          }
                        ]
                      },
                      "history": {
                        "oneOf": [
                          {
                            "additionalProperties": false,
                            "properties": {
                              "state": {
                                "const": "captured",
                                "type": "string"
                              },
                              "value": {
                                "additionalProperties": false,
                                "properties": {
                                  "current_url": {
                                    "properties": {
                                      "origin": {
                                        "anyOf": [
                                          {
                                            "type": "string"
                                          },
                                          {
                                            "type": "null"
                                          }
                                        ]
                                      },
                                      "query_parameter_names": {
                                        "items": {
                                          "type": "string"
                                        },
                                        "type": "array"
                                      },
                                      "redacted": {
                                        "type": "boolean"
                                      },
                                      "url": {
                                        "type": "string"
                                      }
                                    },
                                    "required": [
                                      "url",
                                      "origin",
                                      "query_parameter_names",
                                      "redacted"
                                    ],
                                    "type": "object"
                                  },
                                  "length": {
                                    "maximum": 9007199254740991,
                                    "minimum": 0,
                                    "type": "integer"
                                  },
                                  "navigation_entries": {
                                    "items": {
                                      "additionalProperties": false,
                                      "properties": {
                                        "name": {
                                          "description": "Exact name used by this operation.",
                                          "properties": {
                                            "origin": {
                                              "anyOf": [
                                                {
                                                  "type": "string"
                                                },
                                                {
                                                  "type": "null"
                                                }
                                              ]
                                            },
                                            "query_parameter_names": {
                                              "items": {
                                                "type": "string"
                                              },
                                              "type": "array"
                                            },
                                            "redacted": {
                                              "type": "boolean"
                                            },
                                            "url": {
                                              "type": "string"
                                            }
                                          },
                                          "required": [
                                            "url",
                                            "origin",
                                            "query_parameter_names",
                                            "redacted"
                                          ],
                                          "type": "object"
                                        },
                                        "type": {
                                          "enum": [
                                            "navigate",
                                            "reload",
                                            "back_forward",
                                            "prerender",
                                            "unknown"
                                          ],
                                          "type": "string"
                                        }
                                      },
                                      "required": [
                                        "type",
                                        "name"
                                      ],
                                      "type": "object"
                                    },
                                    "type": "array"
                                  }
                                },
                                "required": [
                                  "length",
                                  "current_url",
                                  "navigation_entries"
                                ],
                                "type": "object"
                              }
                            },
                            "required": [
                              "state",
                              "value"
                            ],
                            "type": "object"
                          },
                          {
                            "additionalProperties": false,
                            "properties": {
                              "state": {
                                "const": "not_requested",
                                "type": "string"
                              }
                            },
                            "required": [
                              "state"
                            ],
                            "type": "object"
                          },
                          {
                            "additionalProperties": false,
                            "properties": {
                              "reason": {
                                "minLength": 1,
                                "type": "string"
                              },
                              "state": {
                                "const": "missing",
                                "type": "string"
                              }
                            },
                            "required": [
                              "state",
                              "reason"
                            ],
                            "type": "object"
                          },
                          {
                            "additionalProperties": false,
                            "properties": {
                              "observed": {
                                "maximum": 9007199254740991,
                                "minimum": 0,
                                "type": "integer"
                              },
                              "reason": {
                                "minLength": 1,
                                "type": "string"
                              },
                              "retained": {
                                "maximum": 9007199254740991,
                                "minimum": 0,
                                "type": "integer"
                              },
                              "state": {
                                "const": "truncated",
                                "type": "string"
                              }
                            },
                            "required": [
                              "state",
                              "observed",
                              "retained",
                              "reason"
                            ],
                            "type": "object"
                          }
                        ]
                      },
                      "screenshot": {
                        "oneOf": [
                          {
                            "additionalProperties": false,
                            "properties": {
                              "state": {
                                "const": "captured",
                                "type": "string"
                              },
                              "value": {
                                "properties": {
                                  "bytes": {
                                    "maximum": 9007199254740991,
                                    "minimum": 1,
                                    "type": "integer"
                                  },
                                  "data_base64": {
                                    "type": "string"
                                  },
                                  "media_type": {
                                    "const": "image/png",
                                    "type": "string"
                                  },
                                  "sha256": {
                                    "pattern": "^[a-f0-9]{64}$",
                                    "type": "string"
                                  }
                                },
                                "required": [
                                  "sha256",
                                  "bytes",
                                  "media_type",
                                  "data_base64"
                                ],
                                "type": "object"
                              }
                            },
                            "required": [
                              "state",
                              "value"
                            ],
                            "type": "object"
                          },
                          {
                            "additionalProperties": false,
                            "properties": {
                              "state": {
                                "const": "not_requested",
                                "type": "string"
                              }
                            },
                            "required": [
                              "state"
                            ],
                            "type": "object"
                          },
                          {
                            "additionalProperties": false,
                            "properties": {
                              "reason": {
                                "minLength": 1,
                                "type": "string"
                              },
                              "state": {
                                "const": "missing",
                                "type": "string"
                              }
                            },
                            "required": [
                              "state",
                              "reason"
                            ],
                            "type": "object"
                          },
                          {
                            "additionalProperties": false,
                            "properties": {
                              "observed": {
                                "maximum": 9007199254740991,
                                "minimum": 0,
                                "type": "integer"
                              },
                              "reason": {
                                "minLength": 1,
                                "type": "string"
                              },
                              "retained": {
                                "maximum": 9007199254740991,
                                "minimum": 0,
                                "type": "integer"
                              },
                              "state": {
                                "const": "truncated",
                                "type": "string"
                              }
                            },
                            "required": [
                              "state",
                              "observed",
                              "retained",
                              "reason"
                            ],
                            "type": "object"
                          }
                        ]
                      },
                      "storage": {
                        "oneOf": [
                          {
                            "additionalProperties": false,
                            "properties": {
                              "state": {
                                "const": "captured",
                                "type": "string"
                              },
                              "value": {
                                "additionalProperties": false,
                                "properties": {
                                  "cookies": {
                                    "items": {
                                      "oneOf": [
                                        {
                                          "additionalProperties": false,
                                          "properties": {
                                            "domain": {
                                              "type": "string"
                                            },
                                            "http_only": {
                                              "type": "boolean"
                                            },
                                            "name": {
                                              "description": "Exact name used by this operation.",
                                              "type": "string"
                                            },
                                            "path": {
                                              "description": "Local filesystem path used by this operation.",
                                              "type": "string"
                                            },
                                            "same_site": {
                                              "enum": [
                                                "Strict",
                                                "Lax",
                                                "None"
                                              ],
                                              "type": "string"
                                            },
                                            "secure": {
                                              "type": "boolean"
                                            },
                                            "value_sha256": {
                                              "description": "Exact SHA-256 digest of value.",
                                              "pattern": "^[a-f0-9]{64}$",
                                              "type": "string"
                                            },
                                            "value_state": {
                                              "const": "hashed",
                                              "type": "string"
                                            }
                                          },
                                          "required": [
                                            "name",
                                            "domain",
                                            "path",
                                            "secure",
                                            "http_only",
                                            "same_site",
                                            "value_state",
                                            "value_sha256"
                                          ],
                                          "type": "object"
                                        },
                                        {
                                          "additionalProperties": false,
                                          "properties": {
                                            "domain": {
                                              "type": "string"
                                            },
                                            "http_only": {
                                              "type": "boolean"
                                            },
                                            "name": {
                                              "description": "Exact name used by this operation.",
                                              "type": "string"
                                            },
                                            "path": {
                                              "description": "Local filesystem path used by this operation.",
                                              "type": "string"
                                            },
                                            "same_site": {
                                              "enum": [
                                                "Strict",
                                                "Lax",
                                                "None"
                                              ],
                                              "type": "string"
                                            },
                                            "secure": {
                                              "type": "boolean"
                                            },
                                            "value_sha256": {
                                              "description": "Exact SHA-256 digest of value.",
                                              "type": "null"
                                            },
                                            "value_state": {
                                              "const": "redacted-secret",
                                              "type": "string"
                                            }
                                          },
                                          "required": [
                                            "name",
                                            "domain",
                                            "path",
                                            "secure",
                                            "http_only",
                                            "same_site",
                                            "value_state",
                                            "value_sha256"
                                          ],
                                          "type": "object"
                                        }
                                      ]
                                    },
                                    "type": "array"
                                  },
                                  "local_storage": {
                                    "items": {
                                      "oneOf": [
                                        {
                                          "additionalProperties": false,
                                          "properties": {
                                            "name": {
                                              "description": "Exact name used by this operation.",
                                              "type": "string"
                                            },
                                            "value_sha256": {
                                              "description": "Exact SHA-256 digest of value.",
                                              "pattern": "^[a-f0-9]{64}$",
                                              "type": "string"
                                            },
                                            "value_state": {
                                              "const": "hashed",
                                              "type": "string"
                                            }
                                          },
                                          "required": [
                                            "name",
                                            "value_state",
                                            "value_sha256"
                                          ],
                                          "type": "object"
                                        },
                                        {
                                          "additionalProperties": false,
                                          "properties": {
                                            "name": {
                                              "description": "Exact name used by this operation.",
                                              "type": "string"
                                            },
                                            "value_sha256": {
                                              "description": "Exact SHA-256 digest of value.",
                                              "type": "null"
                                            },
                                            "value_state": {
                                              "const": "redacted-secret",
                                              "type": "string"
                                            }
                                          },
                                          "required": [
                                            "name",
                                            "value_state",
                                            "value_sha256"
                                          ],
                                          "type": "object"
                                        }
                                      ]
                                    },
                                    "type": "array"
                                  },
                                  "session_storage": {
                                    "items": {
                                      "oneOf": [
                                        {
                                          "additionalProperties": false,
                                          "properties": {
                                            "name": {
                                              "description": "Exact name used by this operation.",
                                              "type": "string"
                                            },
                                            "value_sha256": {
                                              "description": "Exact SHA-256 digest of value.",
                                              "pattern": "^[a-f0-9]{64}$",
                                              "type": "string"
                                            },
                                            "value_state": {
                                              "const": "hashed",
                                              "type": "string"
                                            }
                                          },
                                          "required": [
                                            "name",
                                            "value_state",
                                            "value_sha256"
                                          ],
                                          "type": "object"
                                        },
                                        {
                                          "additionalProperties": false,
                                          "properties": {
                                            "name": {
                                              "description": "Exact name used by this operation.",
                                              "type": "string"
                                            },
                                            "value_sha256": {
                                              "description": "Exact SHA-256 digest of value.",
                                              "type": "null"
                                            },
                                            "value_state": {
                                              "const": "redacted-secret",
                                              "type": "string"
                                            }
                                          },
                                          "required": [
                                            "name",
                                            "value_state",
                                            "value_sha256"
                                          ],
                                          "type": "object"
                                        }
                                      ]
                                    },
                                    "type": "array"
                                  }
                                },
                                "required": [
                                  "cookies",
                                  "local_storage",
                                  "session_storage"
                                ],
                                "type": "object"
                              }
                            },
                            "required": [
                              "state",
                              "value"
                            ],
                            "type": "object"
                          },
                          {
                            "additionalProperties": false,
                            "properties": {
                              "state": {
                                "const": "not_requested",
                                "type": "string"
                              }
                            },
                            "required": [
                              "state"
                            ],
                            "type": "object"
                          },
                          {
                            "additionalProperties": false,
                            "properties": {
                              "reason": {
                                "minLength": 1,
                                "type": "string"
                              },
                              "state": {
                                "const": "missing",
                                "type": "string"
                              }
                            },
                            "required": [
                              "state",
                              "reason"
                            ],
                            "type": "object"
                          },
                          {
                            "additionalProperties": false,
                            "properties": {
                              "observed": {
                                "maximum": 9007199254740991,
                                "minimum": 0,
                                "type": "integer"
                              },
                              "reason": {
                                "minLength": 1,
                                "type": "string"
                              },
                              "retained": {
                                "maximum": 9007199254740991,
                                "minimum": 0,
                                "type": "integer"
                              },
                              "state": {
                                "const": "truncated",
                                "type": "string"
                              }
                            },
                            "required": [
                              "state",
                              "observed",
                              "retained",
                              "reason"
                            ],
                            "type": "object"
                          }
                        ]
                      },
                      "url": {
                        "oneOf": [
                          {
                            "additionalProperties": false,
                            "properties": {
                              "state": {
                                "const": "captured",
                                "type": "string"
                              },
                              "value": {
                                "properties": {
                                  "origin": {
                                    "anyOf": [
                                      {
                                        "type": "string"
                                      },
                                      {
                                        "type": "null"
                                      }
                                    ]
                                  },
                                  "query_parameter_names": {
                                    "items": {
                                      "type": "string"
                                    },
                                    "type": "array"
                                  },
                                  "redacted": {
                                    "type": "boolean"
                                  },
                                  "url": {
                                    "type": "string"
                                  }
                                },
                                "required": [
                                  "url",
                                  "origin",
                                  "query_parameter_names",
                                  "redacted"
                                ],
                                "type": "object"
                              }
                            },
                            "required": [
                              "state",
                              "value"
                            ],
                            "type": "object"
                          },
                          {
                            "additionalProperties": false,
                            "properties": {
                              "state": {
                                "const": "not_requested",
                                "type": "string"
                              }
                            },
                            "required": [
                              "state"
                            ],
                            "type": "object"
                          },
                          {
                            "additionalProperties": false,
                            "properties": {
                              "reason": {
                                "minLength": 1,
                                "type": "string"
                              },
                              "state": {
                                "const": "missing",
                                "type": "string"
                              }
                            },
                            "required": [
                              "state",
                              "reason"
                            ],
                            "type": "object"
                          },
                          {
                            "additionalProperties": false,
                            "properties": {
                              "observed": {
                                "maximum": 9007199254740991,
                                "minimum": 0,
                                "type": "integer"
                              },
                              "reason": {
                                "minLength": 1,
                                "type": "string"
                              },
                              "retained": {
                                "maximum": 9007199254740991,
                                "minimum": 0,
                                "type": "integer"
                              },
                              "state": {
                                "const": "truncated",
                                "type": "string"
                              }
                            },
                            "required": [
                              "state",
                              "observed",
                              "retained",
                              "reason"
                            ],
                            "type": "object"
                          }
                        ]
                      }
                    },
                    "required": [
                      "screenshot",
                      "dom",
                      "accessibility",
                      "url",
                      "history",
                      "storage"
                    ],
                    "type": "object"
                  },
                  "before_url": {
                    "properties": {
                      "origin": {
                        "anyOf": [
                          {
                            "type": "string"
                          },
                          {
                            "type": "null"
                          }
                        ]
                      },
                      "query_parameter_names": {
                        "items": {
                          "type": "string"
                        },
                        "type": "array"
                      },
                      "redacted": {
                        "type": "boolean"
                      },
                      "url": {
                        "type": "string"
                      }
                    },
                    "required": [
                      "url",
                      "origin",
                      "query_parameter_names",
                      "redacted"
                    ],
                    "type": "object"
                  },
                  "completeness": {
                    "oneOf": [
                      {
                        "additionalProperties": false,
                        "properties": {
                          "equality_eligible": {
                            "const": true,
                            "type": "boolean"
                          },
                          "missing_sections": {
                            "items": {
                              "not": {}
                            },
                            "maxItems": 0,
                            "minItems": 0,
                            "type": "array"
                          },
                          "status": {
                            "const": "complete",
                            "description": "Current lifecycle or verification status.",
                            "type": "string"
                          },
                          "truncated_sections": {
                            "items": {
                              "not": {}
                            },
                            "maxItems": 0,
                            "minItems": 0,
                            "type": "array"
                          }
                        },
                        "required": [
                          "status",
                          "equality_eligible",
                          "missing_sections",
                          "truncated_sections"
                        ],
                        "type": "object"
                      },
                      {
                        "additionalProperties": false,
                        "properties": {
                          "equality_eligible": {
                            "const": false,
                            "type": "boolean"
                          },
                          "missing_sections": {
                            "items": {
                              "enum": [
                                "action",
                                "screenshot",
                                "dom",
                                "accessibility",
                                "url",
                                "history",
                                "storage",
                                "events",
                                "frames",
                                "workers",
                                "popups",
                                "websockets"
                              ],
                              "type": "string"
                            },
                            "minItems": 1,
                            "type": "array"
                          },
                          "status": {
                            "const": "incomplete",
                            "description": "Current lifecycle or verification status.",
                            "type": "string"
                          },
                          "truncated_sections": {
                            "items": {
                              "not": {}
                            },
                            "maxItems": 0,
                            "minItems": 0,
                            "type": "array"
                          }
                        },
                        "required": [
                          "status",
                          "equality_eligible",
                          "missing_sections",
                          "truncated_sections"
                        ],
                        "type": "object"
                      },
                      {
                        "additionalProperties": false,
                        "properties": {
                          "equality_eligible": {
                            "const": false,
                            "type": "boolean"
                          },
                          "missing_sections": {
                            "items": {
                              "enum": [
                                "action",
                                "screenshot",
                                "dom",
                                "accessibility",
                                "url",
                                "history",
                                "storage",
                                "events",
                                "frames",
                                "workers",
                                "popups",
                                "websockets"
                              ],
                              "type": "string"
                            },
                            "type": "array"
                          },
                          "status": {
                            "const": "truncated",
                            "description": "Current lifecycle or verification status.",
                            "type": "string"
                          },
                          "truncated_sections": {
                            "items": {
                              "enum": [
                                "action",
                                "screenshot",
                                "dom",
                                "accessibility",
                                "url",
                                "history",
                                "storage",
                                "events",
                                "frames",
                                "workers",
                                "popups",
                                "websockets"
                              ],
                              "type": "string"
                            },
                            "minItems": 1,
                            "type": "array"
                          }
                        },
                        "required": [
                          "status",
                          "equality_eligible",
                          "missing_sections",
                          "truncated_sections"
                        ],
                        "type": "object"
                      }
                    ]
                  },
                  "elapsed_ms": {
                    "maximum": 9007199254740991,
                    "minimum": 0,
                    "type": "integer"
                  },
                  "error": {
                    "description": "Structured, caller-actionable error when the operation fails.",
                    "type": "null"
                  },
                  "event_sequence_end": {
                    "maximum": 9007199254740991,
                    "minimum": 0,
                    "type": "integer"
                  },
                  "event_sequence_start": {
                    "maximum": 9007199254740991,
                    "minimum": 1,
                    "type": "integer"
                  },
                  "status": {
                    "const": "completed",
                    "description": "Current lifecycle or verification status.",
                    "type": "string"
                  },
                  "step_id": {
                    "minLength": 1,
                    "type": "string"
                  },
                  "step_index": {
                    "maximum": 9007199254740991,
                    "minimum": 0,
                    "type": "integer"
                  }
                },
                "required": [
                  "step_index",
                  "step_id",
                  "action",
                  "elapsed_ms",
                  "before_url",
                  "after_url",
                  "event_sequence_start",
                  "event_sequence_end",
                  "artifacts",
                  "completeness",
                  "status",
                  "error"
                ],
                "type": "object"
              },
              {
                "additionalProperties": false,
                "properties": {
                  "action": {
                    "minLength": 1,
                    "type": "string"
                  },
                  "after_url": {
                    "properties": {
                      "origin": {
                        "anyOf": [
                          {
                            "type": "string"
                          },
                          {
                            "type": "null"
                          }
                        ]
                      },
                      "query_parameter_names": {
                        "items": {
                          "type": "string"
                        },
                        "type": "array"
                      },
                      "redacted": {
                        "type": "boolean"
                      },
                      "url": {
                        "type": "string"
                      }
                    },
                    "required": [
                      "url",
                      "origin",
                      "query_parameter_names",
                      "redacted"
                    ],
                    "type": "object"
                  },
                  "artifacts": {
                    "additionalProperties": false,
                    "properties": {
                      "accessibility": {
                        "oneOf": [
                          {
                            "additionalProperties": false,
                            "properties": {
                              "state": {
                                "const": "captured",
                                "type": "string"
                              },
                              "value": {
                                "additionalProperties": false,
                                "properties": {
                                  "bytes": {
                                    "maximum": 9007199254740991,
                                    "minimum": 0,
                                    "type": "integer"
                                  },
                                  "sha256": {
                                    "pattern": "^[a-f0-9]{64}$",
                                    "type": "string"
                                  },
                                  "text": {
                                    "type": "string"
                                  }
                                },
                                "required": [
                                  "sha256",
                                  "bytes",
                                  "text"
                                ],
                                "type": "object"
                              }
                            },
                            "required": [
                              "state",
                              "value"
                            ],
                            "type": "object"
                          },
                          {
                            "additionalProperties": false,
                            "properties": {
                              "state": {
                                "const": "not_requested",
                                "type": "string"
                              }
                            },
                            "required": [
                              "state"
                            ],
                            "type": "object"
                          },
                          {
                            "additionalProperties": false,
                            "properties": {
                              "reason": {
                                "minLength": 1,
                                "type": "string"
                              },
                              "state": {
                                "const": "missing",
                                "type": "string"
                              }
                            },
                            "required": [
                              "state",
                              "reason"
                            ],
                            "type": "object"
                          },
                          {
                            "additionalProperties": false,
                            "properties": {
                              "observed": {
                                "maximum": 9007199254740991,
                                "minimum": 0,
                                "type": "integer"
                              },
                              "reason": {
                                "minLength": 1,
                                "type": "string"
                              },
                              "retained": {
                                "maximum": 9007199254740991,
                                "minimum": 0,
                                "type": "integer"
                              },
                              "state": {
                                "const": "truncated",
                                "type": "string"
                              }
                            },
                            "required": [
                              "state",
                              "observed",
                              "retained",
                              "reason"
                            ],
                            "type": "object"
                          }
                        ]
                      },
                      "dom": {
                        "oneOf": [
                          {
                            "additionalProperties": false,
                            "properties": {
                              "state": {
                                "const": "captured",
                                "type": "string"
                              },
                              "value": {
                                "additionalProperties": false,
                                "properties": {
                                  "bytes": {
                                    "maximum": 9007199254740991,
                                    "minimum": 0,
                                    "type": "integer"
                                  },
                                  "sha256": {
                                    "pattern": "^[a-f0-9]{64}$",
                                    "type": "string"
                                  },
                                  "text": {
                                    "type": "string"
                                  }
                                },
                                "required": [
                                  "sha256",
                                  "bytes",
                                  "text"
                                ],
                                "type": "object"
                              }
                            },
                            "required": [
                              "state",
                              "value"
                            ],
                            "type": "object"
                          },
                          {
                            "additionalProperties": false,
                            "properties": {
                              "state": {
                                "const": "not_requested",
                                "type": "string"
                              }
                            },
                            "required": [
                              "state"
                            ],
                            "type": "object"
                          },
                          {
                            "additionalProperties": false,
                            "properties": {
                              "reason": {
                                "minLength": 1,
                                "type": "string"
                              },
                              "state": {
                                "const": "missing",
                                "type": "string"
                              }
                            },
                            "required": [
                              "state",
                              "reason"
                            ],
                            "type": "object"
                          },
                          {
                            "additionalProperties": false,
                            "properties": {
                              "observed": {
                                "maximum": 9007199254740991,
                                "minimum": 0,
                                "type": "integer"
                              },
                              "reason": {
                                "minLength": 1,
                                "type": "string"
                              },
                              "retained": {
                                "maximum": 9007199254740991,
                                "minimum": 0,
                                "type": "integer"
                              },
                              "state": {
                                "const": "truncated",
                                "type": "string"
                              }
                            },
                            "required": [
                              "state",
                              "observed",
                              "retained",
                              "reason"
                            ],
                            "type": "object"
                          }
                        ]
                      },
                      "history": {
                        "oneOf": [
                          {
                            "additionalProperties": false,
                            "properties": {
                              "state": {
                                "const": "captured",
                                "type": "string"
                              },
                              "value": {
                                "additionalProperties": false,
                                "properties": {
                                  "current_url": {
                                    "properties": {
                                      "origin": {
                                        "anyOf": [
                                          {
                                            "type": "string"
                                          },
                                          {
                                            "type": "null"
                                          }
                                        ]
                                      },
                                      "query_parameter_names": {
                                        "items": {
                                          "type": "string"
                                        },
                                        "type": "array"
                                      },
                                      "redacted": {
                                        "type": "boolean"
                                      },
                                      "url": {
                                        "type": "string"
                                      }
                                    },
                                    "required": [
                                      "url",
                                      "origin",
                                      "query_parameter_names",
                                      "redacted"
                                    ],
                                    "type": "object"
                                  },
                                  "length": {
                                    "maximum": 9007199254740991,
                                    "minimum": 0,
                                    "type": "integer"
                                  },
                                  "navigation_entries": {
                                    "items": {
                                      "additionalProperties": false,
                                      "properties": {
                                        "name": {
                                          "description": "Exact name used by this operation.",
                                          "properties": {
                                            "origin": {
                                              "anyOf": [
                                                {
                                                  "type": "string"
                                                },
                                                {
                                                  "type": "null"
                                                }
                                              ]
                                            },
                                            "query_parameter_names": {
                                              "items": {
                                                "type": "string"
                                              },
                                              "type": "array"
                                            },
                                            "redacted": {
                                              "type": "boolean"
                                            },
                                            "url": {
                                              "type": "string"
                                            }
                                          },
                                          "required": [
                                            "url",
                                            "origin",
                                            "query_parameter_names",
                                            "redacted"
                                          ],
                                          "type": "object"
                                        },
                                        "type": {
                                          "enum": [
                                            "navigate",
                                            "reload",
                                            "back_forward",
                                            "prerender",
                                            "unknown"
                                          ],
                                          "type": "string"
                                        }
                                      },
                                      "required": [
                                        "type",
                                        "name"
                                      ],
                                      "type": "object"
                                    },
                                    "type": "array"
                                  }
                                },
                                "required": [
                                  "length",
                                  "current_url",
                                  "navigation_entries"
                                ],
                                "type": "object"
                              }
                            },
                            "required": [
                              "state",
                              "value"
                            ],
                            "type": "object"
                          },
                          {
                            "additionalProperties": false,
                            "properties": {
                              "state": {
                                "const": "not_requested",
                                "type": "string"
                              }
                            },
                            "required": [
                              "state"
                            ],
                            "type": "object"
                          },
                          {
                            "additionalProperties": false,
                            "properties": {
                              "reason": {
                                "minLength": 1,
                                "type": "string"
                              },
                              "state": {
                                "const": "missing",
                                "type": "string"
                              }
                            },
                            "required": [
                              "state",
                              "reason"
                            ],
                            "type": "object"
                          },
                          {
                            "additionalProperties": false,
                            "properties": {
                              "observed": {
                                "maximum": 9007199254740991,
                                "minimum": 0,
                                "type": "integer"
                              },
                              "reason": {
                                "minLength": 1,
                                "type": "string"
                              },
                              "retained": {
                                "maximum": 9007199254740991,
                                "minimum": 0,
                                "type": "integer"
                              },
                              "state": {
                                "const": "truncated",
                                "type": "string"
                              }
                            },
                            "required": [
                              "state",
                              "observed",
                              "retained",
                              "reason"
                            ],
                            "type": "object"
                          }
                        ]
                      },
                      "screenshot": {
                        "oneOf": [
                          {
                            "additionalProperties": false,
                            "properties": {
                              "state": {
                                "const": "captured",
                                "type": "string"
                              },
                              "value": {
                                "properties": {
                                  "bytes": {
                                    "maximum": 9007199254740991,
                                    "minimum": 1,
                                    "type": "integer"
                                  },
                                  "data_base64": {
                                    "type": "string"
                                  },
                                  "media_type": {
                                    "const": "image/png",
                                    "type": "string"
                                  },
                                  "sha256": {
                                    "pattern": "^[a-f0-9]{64}$",
                                    "type": "string"
                                  }
                                },
                                "required": [
                                  "sha256",
                                  "bytes",
                                  "media_type",
                                  "data_base64"
                                ],
                                "type": "object"
                              }
                            },
                            "required": [
                              "state",
                              "value"
                            ],
                            "type": "object"
                          },
                          {
                            "additionalProperties": false,
                            "properties": {
                              "state": {
                                "const": "not_requested",
                                "type": "string"
                              }
                            },
                            "required": [
                              "state"
                            ],
                            "type": "object"
                          },
                          {
                            "additionalProperties": false,
                            "properties": {
                              "reason": {
                                "minLength": 1,
                                "type": "string"
                              },
                              "state": {
                                "const": "missing",
                                "type": "string"
                              }
                            },
                            "required": [
                              "state",
                              "reason"
                            ],
                            "type": "object"
                          },
                          {
                            "additionalProperties": false,
                            "properties": {
                              "observed": {
                                "maximum": 9007199254740991,
                                "minimum": 0,
                                "type": "integer"
                              },
                              "reason": {
                                "minLength": 1,
                                "type": "string"
                              },
                              "retained": {
                                "maximum": 9007199254740991,
                                "minimum": 0,
                                "type": "integer"
                              },
                              "state": {
                                "const": "truncated",
                                "type": "string"
                              }
                            },
                            "required": [
                              "state",
                              "observed",
                              "retained",
                              "reason"
                            ],
                            "type": "object"
                          }
                        ]
                      },
                      "storage": {
                        "oneOf": [
                          {
                            "additionalProperties": false,
                            "properties": {
                              "state": {
                                "const": "captured",
                                "type": "string"
                              },
                              "value": {
                                "additionalProperties": false,
                                "properties": {
                                  "cookies": {
                                    "items": {
                                      "oneOf": [
                                        {
                                          "additionalProperties": false,
                                          "properties": {
                                            "domain": {
                                              "type": "string"
                                            },
                                            "http_only": {
                                              "type": "boolean"
                                            },
                                            "name": {
                                              "description": "Exact name used by this operation.",
                                              "type": "string"
                                            },
                                            "path": {
                                              "description": "Local filesystem path used by this operation.",
                                              "type": "string"
                                            },
                                            "same_site": {
                                              "enum": [
                                                "Strict",
                                                "Lax",
                                                "None"
                                              ],
                                              "type": "string"
                                            },
                                            "secure": {
                                              "type": "boolean"
                                            },
                                            "value_sha256": {
                                              "description": "Exact SHA-256 digest of value.",
                                              "pattern": "^[a-f0-9]{64}$",
                                              "type": "string"
                                            },
                                            "value_state": {
                                              "const": "hashed",
                                              "type": "string"
                                            }
                                          },
                                          "required": [
                                            "name",
                                            "domain",
                                            "path",
                                            "secure",
                                            "http_only",
                                            "same_site",
                                            "value_state",
                                            "value_sha256"
                                          ],
                                          "type": "object"
                                        },
                                        {
                                          "additionalProperties": false,
                                          "properties": {
                                            "domain": {
                                              "type": "string"
                                            },
                                            "http_only": {
                                              "type": "boolean"
                                            },
                                            "name": {
                                              "description": "Exact name used by this operation.",
                                              "type": "string"
                                            },
                                            "path": {
                                              "description": "Local filesystem path used by this operation.",
                                              "type": "string"
                                            },
                                            "same_site": {
                                              "enum": [
                                                "Strict",
                                                "Lax",
                                                "None"
                                              ],
                                              "type": "string"
                                            },
                                            "secure": {
                                              "type": "boolean"
                                            },
                                            "value_sha256": {
                                              "description": "Exact SHA-256 digest of value.",
                                              "type": "null"
                                            },
                                            "value_state": {
                                              "const": "redacted-secret",
                                              "type": "string"
                                            }
                                          },
                                          "required": [
                                            "name",
                                            "domain",
                                            "path",
                                            "secure",
                                            "http_only",
                                            "same_site",
                                            "value_state",
                                            "value_sha256"
                                          ],
                                          "type": "object"
                                        }
                                      ]
                                    },
                                    "type": "array"
                                  },
                                  "local_storage": {
                                    "items": {
                                      "oneOf": [
                                        {
                                          "additionalProperties": false,
                                          "properties": {
                                            "name": {
                                              "description": "Exact name used by this operation.",
                                              "type": "string"
                                            },
                                            "value_sha256": {
                                              "description": "Exact SHA-256 digest of value.",
                                              "pattern": "^[a-f0-9]{64}$",
                                              "type": "string"
                                            },
                                            "value_state": {
                                              "const": "hashed",
                                              "type": "string"
                                            }
                                          },
                                          "required": [
                                            "name",
                                            "value_state",
                                            "value_sha256"
                                          ],
                                          "type": "object"
                                        },
                                        {
                                          "additionalProperties": false,
                                          "properties": {
                                            "name": {
                                              "description": "Exact name used by this operation.",
                                              "type": "string"
                                            },
                                            "value_sha256": {
                                              "description": "Exact SHA-256 digest of value.",
                                              "type": "null"
                                            },
                                            "value_state": {
                                              "const": "redacted-secret",
                                              "type": "string"
                                            }
                                          },
                                          "required": [
                                            "name",
                                            "value_state",
                                            "value_sha256"
                                          ],
                                          "type": "object"
                                        }
                                      ]
                                    },
                                    "type": "array"
                                  },
                                  "session_storage": {
                                    "items": {
                                      "oneOf": [
                                        {
                                          "additionalProperties": false,
                                          "properties": {
                                            "name": {
                                              "description": "Exact name used by this operation.",
                                              "type": "string"
                                            },
                                            "value_sha256": {
                                              "description": "Exact SHA-256 digest of value.",
                                              "pattern": "^[a-f0-9]{64}$",
                                              "type": "string"
                                            },
                                            "value_state": {
                                              "const": "hashed",
                                              "type": "string"
                                            }
                                          },
                                          "required": [
                                            "name",
                                            "value_state",
                                            "value_sha256"
                                          ],
                                          "type": "object"
                                        },
                                        {
                                          "additionalProperties": false,
                                          "properties": {
                                            "name": {
                                              "description": "Exact name used by this operation.",
                                              "type": "string"
                                            },
                                            "value_sha256": {
                                              "description": "Exact SHA-256 digest of value.",
                                              "type": "null"
                                            },
                                            "value_state": {
                                              "const": "redacted-secret",
                                              "type": "string"
                                            }
                                          },
                                          "required": [
                                            "name",
                                            "value_state",
                                            "value_sha256"
                                          ],
                                          "type": "object"
                                        }
                                      ]
                                    },
                                    "type": "array"
                                  }
                                },
                                "required": [
                                  "cookies",
                                  "local_storage",
                                  "session_storage"
                                ],
                                "type": "object"
                              }
                            },
                            "required": [
                              "state",
                              "value"
                            ],
                            "type": "object"
                          },
                          {
                            "additionalProperties": false,
                            "properties": {
                              "state": {
                                "const": "not_requested",
                                "type": "string"
                              }
                            },
                            "required": [
                              "state"
                            ],
                            "type": "object"
                          },
                          {
                            "additionalProperties": false,
                            "properties": {
                              "reason": {
                                "minLength": 1,
                                "type": "string"
                              },
                              "state": {
                                "const": "missing",
                                "type": "string"
                              }
                            },
                            "required": [
                              "state",
                              "reason"
                            ],
                            "type": "object"
                          },
                          {
                            "additionalProperties": false,
                            "properties": {
                              "observed": {
                                "maximum": 9007199254740991,
                                "minimum": 0,
                                "type": "integer"
                              },
                              "reason": {
                                "minLength": 1,
                                "type": "string"
                              },
                              "retained": {
                                "maximum": 9007199254740991,
                                "minimum": 0,
                                "type": "integer"
                              },
                              "state": {
                                "const": "truncated",
                                "type": "string"
                              }
                            },
                            "required": [
                              "state",
                              "observed",
                              "retained",
                              "reason"
                            ],
                            "type": "object"
                          }
                        ]
                      },
                      "url": {
                        "oneOf": [
                          {
                            "additionalProperties": false,
                            "properties": {
                              "state": {
                                "const": "captured",
                                "type": "string"
                              },
                              "value": {
                                "properties": {
                                  "origin": {
                                    "anyOf": [
                                      {
                                        "type": "string"
                                      },
                                      {
                                        "type": "null"
                                      }
                                    ]
                                  },
                                  "query_parameter_names": {
                                    "items": {
                                      "type": "string"
                                    },
                                    "type": "array"
                                  },
                                  "redacted": {
                                    "type": "boolean"
                                  },
                                  "url": {
                                    "type": "string"
                                  }
                                },
                                "required": [
                                  "url",
                                  "origin",
                                  "query_parameter_names",
                                  "redacted"
                                ],
                                "type": "object"
                              }
                            },
                            "required": [
                              "state",
                              "value"
                            ],
                            "type": "object"
                          },
                          {
                            "additionalProperties": false,
                            "properties": {
                              "state": {
                                "const": "not_requested",
                                "type": "string"
                              }
                            },
                            "required": [
                              "state"
                            ],
                            "type": "object"
                          },
                          {
                            "additionalProperties": false,
                            "properties": {
                              "reason": {
                                "minLength": 1,
                                "type": "string"
                              },
                              "state": {
                                "const": "missing",
                                "type": "string"
                              }
                            },
                            "required": [
                              "state",
                              "reason"
                            ],
                            "type": "object"
                          },
                          {
                            "additionalProperties": false,
                            "properties": {
                              "observed": {
                                "maximum": 9007199254740991,
                                "minimum": 0,
                                "type": "integer"
                              },
                              "reason": {
                                "minLength": 1,
                                "type": "string"
                              },
                              "retained": {
                                "maximum": 9007199254740991,
                                "minimum": 0,
                                "type": "integer"
                              },
                              "state": {
                                "const": "truncated",
                                "type": "string"
                              }
                            },
                            "required": [
                              "state",
                              "observed",
                              "retained",
                              "reason"
                            ],
                            "type": "object"
                          }
                        ]
                      }
                    },
                    "required": [
                      "screenshot",
                      "dom",
                      "accessibility",
                      "url",
                      "history",
                      "storage"
                    ],
                    "type": "object"
                  },
                  "before_url": {
                    "properties": {
                      "origin": {
                        "anyOf": [
                          {
                            "type": "string"
                          },
                          {
                            "type": "null"
                          }
                        ]
                      },
                      "query_parameter_names": {
                        "items": {
                          "type": "string"
                        },
                        "type": "array"
                      },
                      "redacted": {
                        "type": "boolean"
                      },
                      "url": {
                        "type": "string"
                      }
                    },
                    "required": [
                      "url",
                      "origin",
                      "query_parameter_names",
                      "redacted"
                    ],
                    "type": "object"
                  },
                  "completeness": {
                    "oneOf": [
                      {
                        "additionalProperties": false,
                        "properties": {
                          "equality_eligible": {
                            "const": true,
                            "type": "boolean"
                          },
                          "missing_sections": {
                            "items": {
                              "not": {}
                            },
                            "maxItems": 0,
                            "minItems": 0,
                            "type": "array"
                          },
                          "status": {
                            "const": "complete",
                            "description": "Current lifecycle or verification status.",
                            "type": "string"
                          },
                          "truncated_sections": {
                            "items": {
                              "not": {}
                            },
                            "maxItems": 0,
                            "minItems": 0,
                            "type": "array"
                          }
                        },
                        "required": [
                          "status",
                          "equality_eligible",
                          "missing_sections",
                          "truncated_sections"
                        ],
                        "type": "object"
                      },
                      {
                        "additionalProperties": false,
                        "properties": {
                          "equality_eligible": {
                            "const": false,
                            "type": "boolean"
                          },
                          "missing_sections": {
                            "items": {
                              "enum": [
                                "action",
                                "screenshot",
                                "dom",
                                "accessibility",
                                "url",
                                "history",
                                "storage",
                                "events",
                                "frames",
                                "workers",
                                "popups",
                                "websockets"
                              ],
                              "type": "string"
                            },
                            "minItems": 1,
                            "type": "array"
                          },
                          "status": {
                            "const": "incomplete",
                            "description": "Current lifecycle or verification status.",
                            "type": "string"
                          },
                          "truncated_sections": {
                            "items": {
                              "not": {}
                            },
                            "maxItems": 0,
                            "minItems": 0,
                            "type": "array"
                          }
                        },
                        "required": [
                          "status",
                          "equality_eligible",
                          "missing_sections",
                          "truncated_sections"
                        ],
                        "type": "object"
                      },
                      {
                        "additionalProperties": false,
                        "properties": {
                          "equality_eligible": {
                            "const": false,
                            "type": "boolean"
                          },
                          "missing_sections": {
                            "items": {
                              "enum": [
                                "action",
                                "screenshot",
                                "dom",
                                "accessibility",
                                "url",
                                "history",
                                "storage",
                                "events",
                                "frames",
                                "workers",
                                "popups",
                                "websockets"
                              ],
                              "type": "string"
                            },
                            "type": "array"
                          },
                          "status": {
                            "const": "truncated",
                            "description": "Current lifecycle or verification status.",
                            "type": "string"
                          },
                          "truncated_sections": {
                            "items": {
                              "enum": [
                                "action",
                                "screenshot",
                                "dom",
                                "accessibility",
                                "url",
                                "history",
                                "storage",
                                "events",
                                "frames",
                                "workers",
                                "popups",
                                "websockets"
                              ],
                              "type": "string"
                            },
                            "minItems": 1,
                            "type": "array"
                          }
                        },
                        "required": [
                          "status",
                          "equality_eligible",
                          "missing_sections",
                          "truncated_sections"
                        ],
                        "type": "object"
                      }
                    ]
                  },
                  "elapsed_ms": {
                    "maximum": 9007199254740991,
                    "minimum": 0,
                    "type": "integer"
                  },
                  "error": {
                    "description": "Structured, caller-actionable error when the operation fails.",
                    "type": "string"
                  },
                  "event_sequence_end": {
                    "maximum": 9007199254740991,
                    "minimum": 0,
                    "type": "integer"
                  },
                  "event_sequence_start": {
                    "maximum": 9007199254740991,
                    "minimum": 1,
                    "type": "integer"
                  },
                  "status": {
                    "description": "Current lifecycle or verification status.",
                    "enum": [
                      "failed",
                      "cancelled"
                    ],
                    "type": "string"
                  },
                  "step_id": {
                    "minLength": 1,
                    "type": "string"
                  },
                  "step_index": {
                    "maximum": 9007199254740991,
                    "minimum": 0,
                    "type": "integer"
                  }
                },
                "required": [
                  "step_index",
                  "step_id",
                  "action",
                  "elapsed_ms",
                  "before_url",
                  "after_url",
                  "event_sequence_start",
                  "event_sequence_end",
                  "artifacts",
                  "completeness",
                  "status",
                  "error"
                ],
                "type": "object"
              }
            ]
          },
          "minItems": 1,
          "type": "array"
        }
      },
      "required": [
        "browser",
        "scenario",
        "duration_ms",
        "steps",
        "events",
        "completeness",
        "limitations"
      ],
      "type": "object"
    },
    "normalization": {
      "additionalProperties": false,
      "default": {
        "rules": []
      },
      "description": "Exact-literal rules committed in the comparison result.",
      "properties": {
        "rules": {
          "default": [],
          "items": {
            "additionalProperties": false,
            "properties": {
              "artifacts": {
                "description": "Artifact families whose durable string fields use this rule.",
                "items": {
                  "enum": [
                    "action_state",
                    "dom",
                    "accessibility",
                    "url",
                    "history",
                    "storage",
                    "events"
                  ],
                  "type": "string"
                },
                "minItems": 1,
                "type": "array"
              },
              "match": {
                "description": "Exact public literal to replace; regular expressions are not used.",
                "minLength": 1,
                "type": "string"
              },
              "replacement": {
                "description": "Recorded replacement text used in normalized comparison.",
                "type": "string"
              },
              "rule_id": {
                "description": "Stable rule identity; rules execute in rule_id order.",
                "minLength": 1,
                "type": "string"
              }
            },
            "required": [
              "rule_id",
              "artifacts",
              "match",
              "replacement"
            ],
            "type": "object"
          },
          "type": "array"
        }
      },
      "type": "object"
    }
  },
  "type": "object"
}
```

</details>

**Output schema:** see [`tool-specs/compare_web_captures.json`](../tool-specs/compare_web_captures.json) (`outputSchema`).

---

## compare_web_screenshots

<a id="comparewebscreenshots"></a>

**Title:** Compare Web Screenshots  
**Kind:** `browser-provider` · **Requires session:** false · **analysisOperation:** null  
**Providers:** rea-cdp-browser  
**Effects set (true flags):** mutatesSession  
**MCP annotations:** `{"destructiveHint":false,"idempotentHint":true,"openWorldHint":false,"readOnlyHint":false}`

**Description (verbatim, as advertised to the agent):**

> Compare two self-verifying PNG screenshot artifacts with local pixel metrics. Returns exact changed-pixel ratios and channel deltas without OCR or external services.

**Input schema (verbatim, JSON Schema 2020-12):**

<details><summary>inputSchema for compare_web_screenshots</summary>

```json
{
  "$defs": {
    "__schema0": {
      "properties": {
        "bytes": {
          "$ref": "#/$defs/__schema2"
        },
        "data_base64": {
          "$ref": "#/$defs/__schema4"
        },
        "media_type": {
          "$ref": "#/$defs/__schema3"
        },
        "sha256": {
          "$ref": "#/$defs/__schema1"
        }
      },
      "required": [
        "sha256",
        "bytes",
        "media_type",
        "data_base64"
      ],
      "type": "object"
    },
    "__schema1": {
      "pattern": "^[a-f0-9]{64}$",
      "type": "string"
    },
    "__schema2": {
      "maximum": 9007199254740991,
      "minimum": 1,
      "type": "integer"
    },
    "__schema3": {
      "const": "image/png",
      "type": "string"
    },
    "__schema4": {
      "type": "string"
    },
    "__schema5": {
      "default": 0,
      "maximum": 255,
      "minimum": 0,
      "type": "integer"
    }
  },
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "additionalProperties": false,
  "examples": [
    {
      "after": {
        "bytes": 70,
        "data_base64": "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8/5+hHgAHggJ/PzWvWQAAAABJRU5ErkJggg==",
        "media_type": "image/png",
        "sha256": "153cf6c9a526a63053a37b10234c2fd85df38887c2dc0a800d90abfa6631d01c"
      },
      "before": {
        "bytes": 70,
        "data_base64": "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8/5+hHgAHggJ/PzWvWQAAAABJRU5ErkJggg==",
        "media_type": "image/png",
        "sha256": "153cf6c9a526a63053a37b10234c2fd85df38887c2dc0a800d90abfa6631d01c"
      },
      "channel_threshold": 0
    }
  ],
  "properties": {
    "after": {
      "$ref": "#/$defs/__schema0",
      "description": "The later or right-hand observation to compare."
    },
    "before": {
      "$ref": "#/$defs/__schema0",
      "description": "The earlier or left-hand observation to compare."
    },
    "channel_threshold": {
      "$ref": "#/$defs/__schema5"
    }
  },
  "required": [
    "before",
    "after"
  ],
  "type": "object"
}
```

</details>

**Output schema:** see [`tool-specs/compare_web_screenshots.json`](../tool-specs/compare_web_screenshots.json) (`outputSchema`).

---

## discover_webmcp_tools

<a id="discoverwebmcptools"></a>

**Title:** Discover Webmcp Tools  
**Kind:** `browser-provider` · **Requires session:** false · **analysisOperation:** null  
**Providers:** rea-cdp-browser  
**Effects set (true flags):** accessesNetwork, mutatesSession  
**MCP annotations:** `{"destructiveHint":false,"idempotentHint":true,"openWorldHint":true,"readOnlyHint":false}`

**Description (verbatim, as advertised to the agent):**

> Passively inventory every page-registered WebMCP tool and its complete structural input-schema summary using the experimental CDP WebMCP domain. Metadata is page-declared-untrusted; REA never registers or invokes discovered tools.

**Input schema (verbatim, JSON Schema 2020-12):**

<details><summary>inputSchema for discover_webmcp_tools</summary>

```json
{
  "$defs": {
    "__schema0": {
      "description": "Literal loopback CDP endpoint: http://127.0.0.1:PORT, or ws://127.0.0.1:PORT/devtools/browser/ID.",
      "minLength": 1,
      "type": "string"
    },
    "__schema1": {
      "items": {
        "minLength": 1,
        "type": "string"
      },
      "type": "array"
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
    }
  },
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "additionalProperties": false,
  "examples": [
    {
      "cdp_endpoint": "http://127.0.0.1:9222",
      "observation_ms": 100,
      "target_id": "TARGET_ID_FROM_LIST_BROWSER_TARGETS"
    }
  ],
  "properties": {
    "allowed_origins": {
      "$ref": "#/$defs/__schema1"
    },
    "cdp_endpoint": {
      "$ref": "#/$defs/__schema0",
      "description": "Literal loopback CDP endpoint: http://127.0.0.1:PORT, or ws://127.0.0.1:PORT/devtools/browser/ID."
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

**Output schema:** see [`tool-specs/discover_webmcp_tools.json`](../tool-specs/discover_webmcp_tools.json) (`outputSchema`).

---

## inspect_web_event_listeners

<a id="inspectwebeventlisteners"></a>

**Title:** Inspect Web Event Listeners  
**Kind:** `browser-provider` · **Requires session:** false · **analysisOperation:** null  
**Providers:** rea-cdp-browser  
**Effects set (true flags):** accessesNetwork, mutatesSession  
**MCP annotations:** `{"destructiveHint":false,"idempotentHint":true,"openWorldHint":true,"readOnlyHint":false}`

**Description (verbatim, as advertised to the agent):**

> Inspect listeners registered directly on the first main-document CSS match in one selected CDP page. Returns event flags, native callback locations, source ownership and exact script text/digests inline. Does not dispatch events, evaluate JavaScript or invoke handlers. Delegated ancestor/framework listeners and execution history remain unknown. Releases REA's object group and transport, preserving the external page.

**Input schema (verbatim, JSON Schema 2020-12):**

<details><summary>inputSchema for inspect_web_event_listeners</summary>

```json
{
  "$defs": {
    "__schema0": {
      "minLength": 1,
      "type": "string"
    },
    "__schema1": {
      "items": {
        "minLength": 1,
        "type": "string"
      },
      "type": "array"
    },
    "__schema2": {
      "minLength": 1,
      "type": "string"
    },
    "__schema3": {
      "minLength": 1,
      "type": "string"
    }
  },
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "additionalProperties": false,
  "examples": [
    {
      "cdp_endpoint": "http://127.0.0.1:9222",
      "selector": "#submit",
      "target_id": "TARGET_ID_FROM_LIST_BROWSER_TARGETS"
    }
  ],
  "properties": {
    "allowed_origins": {
      "$ref": "#/$defs/__schema1"
    },
    "cdp_endpoint": {
      "$ref": "#/$defs/__schema0",
      "description": "Literal loopback Chrome DevTools Protocol endpoint."
    },
    "selector": {
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
    "selector"
  ],
  "type": "object"
}
```

</details>

**Output schema:** see [`tool-specs/inspect_web_event_listeners.json`](../tool-specs/inspect_web_event_listeners.json) (`outputSchema`).

---

## inspect_web_network_capture

<a id="inspectwebnetworkcapture"></a>

**Title:** Inspect Web Network Capture  
**Kind:** `browser-provider` · **Requires session:** false · **analysisOperation:** null  
**Providers:** fiddler-saz, har-schema/lossless-json, mitmproxy-native-tnetstring  
**Effects set (true flags):** launchesProcess, mutatesSession, writesFilesystem  
**MCP annotations:** `{"destructiveHint":false,"idempotentHint":true,"openWorldHint":true,"readOnlyHint":false}`

**Description (verbatim, as advertised to the agent):**

> Request detail summary for capture identity and counts; then page retained records with inspect_analysis_view kind capture (preview or complete), avoiding repeated decoding. Default detail complete preserves existing inline delivery. Inspect retained local HAR 1.2, native mitmproxy, Fiddler SAZ or aioquic 1.5.0 JSON qlog 0.3 events without contacting recorded URLs. Returns original ordinals, pointers/byte ranges/archive member names, preserved producer fields, precise numeric representations and exact exposed binary bytes inline. Excludes known transport credentials and explicitly marked values. Decodes every record before optional ordinal selection; malformed or oversized captures return no partial success. Duplicate JSON members are invalid; prototype-named members such as __proto__ are preserved as ordinary own JSON members without prototype mutation. Qlog reports trace-scoped STREAM interval unions and endpoint loss declarations; it does not recover bodies, prove network loss or correlate PCAP. Other qlog layouts are unsupported. Uses pinned upstream parsers, owned temporary files and bounded offline processes. SAZ preserves HTTP fields, XML metadata and encoded body/message bytes without replay or HAR conversion; encrypted archives are unsupported. Native mitmproxy requires caller-supplied mitmdump 12.2.3 on Linux. Browser transaction IDs, runtime attribution and original bytes of HAR Unicode text remain unknown.

**Input schema (verbatim, JSON Schema 2020-12):**

<details><summary>inputSchema for inspect_web_network_capture</summary>

```json
{
  "$defs": {
    "__schema0": {
      "description": "Absolute local HAR, mitmproxy, Fiddler SAZ or aioquic qlog capture path.",
      "minLength": 1,
      "pattern": "^[^\\x00]*$",
      "type": "string"
    },
    "__schema1": {
      "enum": [
        "har",
        "mitmproxy",
        "saz",
        "qlog"
      ],
      "type": "string"
    },
    "__schema2": {
      "$ref": "#/$defs/__schema3",
      "description": "Zero-based producer record ordinals, in caller-selected order. Omit to inspect every record."
    },
    "__schema3": {
      "items": {
        "$ref": "#/$defs/__schema4"
      },
      "minItems": 1,
      "type": "array"
    },
    "__schema4": {
      "maximum": 9007199254740991,
      "minimum": 0,
      "type": "integer"
    },
    "__schema5": {
      "$ref": "#/$defs/__schema6",
      "default": [],
      "description": "Literal text excluded from capture payloads, byte/numeric projections, producer coordinates, artifact paths/digests and diagnostic text. Declaration strings are never persisted in Evidence parameters. Canonical contract keys, enums and provider identities remain intact."
    },
    "__schema6": {
      "items": {
        "minLength": 1,
        "type": "string"
      },
      "type": "array"
    },
    "__schema7": {
      "$ref": "#/$defs/__schema8",
      "default": "complete",
      "description": "complete returns the complete analysis Evidence inline. summary retains that complete Evidence in this session and returns its inspect_analysis_view summary; inspect pages, items or facets through normalized_result.parent_evidence_id."
    },
    "__schema8": {
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
      "capture_path": "/captures/origin.qlog",
      "format": "qlog",
      "record_ordinals": [
        0,
        2
      ]
    },
    {
      "capture_path": "/captures/session.har",
      "format": "har",
      "record_ordinals": [
        0,
        2
      ]
    }
  ],
  "properties": {
    "capture_path": {
      "$ref": "#/$defs/__schema0",
      "description": "Absolute local HAR, mitmproxy, Fiddler SAZ or aioquic qlog capture path."
    },
    "detail": {
      "$ref": "#/$defs/__schema7",
      "description": "complete returns the complete analysis Evidence inline. summary retains that complete Evidence in this session and returns its inspect_analysis_view summary; inspect pages, items or facets through normalized_result.parent_evidence_id."
    },
    "format": {
      "$ref": "#/$defs/__schema1",
      "description": "Declared input artifact format."
    },
    "record_ordinals": {
      "$ref": "#/$defs/__schema2",
      "description": "Zero-based producer record ordinals, in caller-selected order. Omit to inspect every record."
    },
    "sensitive_values": {
      "$ref": "#/$defs/__schema5",
      "description": "Literal text excluded from capture payloads, byte/numeric projections, producer coordinates, artifact paths/digests and diagnostic text. Declaration strings are never persisted in Evidence parameters. Canonical contract keys, enums and provider identities remain intact."
    }
  },
  "required": [
    "capture_path",
    "format"
  ],
  "type": "object"
}
```

</details>

**Output schema:** see [`tool-specs/inspect_web_network_capture.json`](../tool-specs/inspect_web_network_capture.json) (`outputSchema`).

---

## inspect_web_page

<a id="inspectwebpage"></a>

**Title:** Inspect Web Page  
**Kind:** `browser-provider` · **Requires session:** false · **analysisOperation:** null  
**Providers:** rea-cdp-browser  
**Effects set (true flags):** accessesNetwork, mutatesSession  
**MCP annotations:** `{"destructiveHint":false,"idempotentHint":true,"openWorldHint":true,"readOnlyHint":false}`

**Description (verbatim, as advertised to the agent):**

> Passively inspect one selected page target through CDP without evaluating JavaScript, navigating, clicking, closing, or mutating the page. If no origin filter is supplied, capture is scoped to the target's current origin. Returns DOM structure, accessibility, scripts, resources, attach-window network and console metadata, workers, and redacted storage inventory as Evidence.

**Input schema (verbatim, JSON Schema 2020-12):**

<details><summary>inputSchema for inspect_web_page</summary>

```json
{
  "$defs": {
    "__schema0": {
      "additionalProperties": false,
      "properties": {
        "allowed_origins": {
          "$ref": "#/$defs/__schema2"
        },
        "cdp_endpoint": {
          "$ref": "#/$defs/__schema1",
          "description": "Literal loopback CDP endpoint: http://127.0.0.1:PORT, or ws://127.0.0.1:PORT/devtools/browser/ID."
        },
        "include_accessibility_text": {
          "$ref": "#/$defs/__schema5",
          "description": "Whether to include accessibility text in the result."
        },
        "include_console_text": {
          "$ref": "#/$defs/__schema6",
          "description": "Whether to include console text in the result."
        },
        "include_json_body_shapes": {
          "$ref": "#/$defs/__schema7",
          "description": "Whether to include json body shapes in the result."
        },
        "include_script_sources": {
          "$ref": "#/$defs/__schema11",
          "description": "Whether to include script sources in the result."
        },
        "include_storage_fingerprints": {
          "$ref": "#/$defs/__schema10",
          "description": "Whether to include storage fingerprints in the result."
        },
        "include_storage_keys": {
          "$ref": "#/$defs/__schema9",
          "description": "Whether to include storage keys in the result."
        },
        "include_websocket_shapes": {
          "$ref": "#/$defs/__schema8",
          "description": "Whether to include websocket shapes in the result."
        },
        "observation_ms": {
          "$ref": "#/$defs/__schema4"
        },
        "target_id": {
          "$ref": "#/$defs/__schema3",
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
      "description": "Literal loopback CDP endpoint: http://127.0.0.1:PORT, or ws://127.0.0.1:PORT/devtools/browser/ID.",
      "minLength": 1,
      "type": "string"
    },
    "__schema10": {
      "default": false,
      "type": "boolean"
    },
    "__schema11": {
      "const": false,
      "default": false,
      "type": "boolean"
    },
    "__schema12": {
      "additionalProperties": false,
      "properties": {
        "allowed_origins": {
          "$ref": "#/$defs/__schema2"
        },
        "cdp_endpoint": {
          "$ref": "#/$defs/__schema1",
          "description": "Literal loopback CDP endpoint: http://127.0.0.1:PORT, or ws://127.0.0.1:PORT/devtools/browser/ID."
        },
        "include_accessibility_text": {
          "$ref": "#/$defs/__schema5",
          "description": "Whether to include accessibility text in the result."
        },
        "include_console_text": {
          "$ref": "#/$defs/__schema6",
          "description": "Whether to include console text in the result."
        },
        "include_json_body_shapes": {
          "$ref": "#/$defs/__schema7",
          "description": "Whether to include json body shapes in the result."
        },
        "include_script_sources": {
          "$ref": "#/$defs/__schema13",
          "description": "Whether to include script sources in the result."
        },
        "include_storage_fingerprints": {
          "$ref": "#/$defs/__schema10",
          "description": "Whether to include storage fingerprints in the result."
        },
        "include_storage_keys": {
          "$ref": "#/$defs/__schema9",
          "description": "Whether to include storage keys in the result."
        },
        "include_websocket_shapes": {
          "$ref": "#/$defs/__schema8",
          "description": "Whether to include websocket shapes in the result."
        },
        "observation_ms": {
          "$ref": "#/$defs/__schema4"
        },
        "target_id": {
          "$ref": "#/$defs/__schema3",
          "description": "Exact CDP target identifier selected from the endpoint's target listing."
        }
      },
      "required": [
        "cdp_endpoint",
        "target_id",
        "include_script_sources"
      ],
      "type": "object"
    },
    "__schema13": {
      "const": true,
      "type": "boolean"
    },
    "__schema2": {
      "items": {
        "minLength": 1,
        "type": "string"
      },
      "type": "array"
    },
    "__schema3": {
      "minLength": 1,
      "type": "string"
    },
    "__schema4": {
      "default": 500,
      "maximum": 9007199254740991,
      "minimum": 0,
      "type": "integer"
    },
    "__schema5": {
      "default": false,
      "type": "boolean"
    },
    "__schema6": {
      "default": false,
      "type": "boolean"
    },
    "__schema7": {
      "default": false,
      "type": "boolean"
    },
    "__schema8": {
      "default": false,
      "type": "boolean"
    },
    "__schema9": {
      "default": false,
      "type": "boolean"
    }
  },
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "additionalProperties": false,
  "description": "Provide a complete input group: cdp_endpoint + target_id + [allowed_origins] + [observation_ms] + [include_accessibility_text] + [include_console_text] + [include_json_body_shapes] + [include_websocket_shapes] + [include_storage_keys] + [include_storage_fingerprints] + [include_script_sources]; cdp_endpoint + target_id + include_script_sources + [allowed_origins] + [observation_ms] + [include_accessibility_text] + [include_console_text] + [include_json_body_shapes] + [include_websocket_shapes] + [include_storage_keys] + [include_storage_fingerprints].",
  "examples": [
    {
      "cdp_endpoint": "http://127.0.0.1:9222",
      "target_id": "TARGET_ID_FROM_LIST_BROWSER_TARGETS"
    }
  ],
  "minProperties": 2,
  "properties": {
    "allowed_origins": {
      "$ref": "#/$defs/__schema2"
    },
    "cdp_endpoint": {
      "$ref": "#/$defs/__schema1",
      "description": "Literal loopback CDP endpoint: http://127.0.0.1:PORT, or ws://127.0.0.1:PORT/devtools/browser/ID."
    },
    "include_accessibility_text": {
      "$ref": "#/$defs/__schema5",
      "description": "Whether to include accessibility text in the result."
    },
    "include_console_text": {
      "$ref": "#/$defs/__schema6",
      "description": "Whether to include console text in the result."
    },
    "include_json_body_shapes": {
      "$ref": "#/$defs/__schema7",
      "description": "Whether to include json body shapes in the result."
    },
    "include_script_sources": {
      "anyOf": [
        {
          "$ref": "#/$defs/__schema11"
        },
        {
          "$ref": "#/$defs/__schema13"
        }
      ],
      "description": "Whether to include script sources in the result."
    },
    "include_storage_fingerprints": {
      "$ref": "#/$defs/__schema10",
      "description": "Whether to include storage fingerprints in the result."
    },
    "include_storage_keys": {
      "$ref": "#/$defs/__schema9",
      "description": "Whether to include storage keys in the result."
    },
    "include_websocket_shapes": {
      "$ref": "#/$defs/__schema8",
      "description": "Whether to include websocket shapes in the result."
    },
    "observation_ms": {
      "$ref": "#/$defs/__schema4"
    },
    "target_id": {
      "$ref": "#/$defs/__schema3",
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

**Output schema:** see [`tool-specs/inspect_web_page.json`](../tool-specs/inspect_web_page.json) (`outputSchema`).

---

## list_browser_targets

<a id="listbrowsertargets"></a>

**Title:** List Browser Targets  
**Kind:** `browser-provider` · **Requires session:** false · **analysisOperation:** null  
**Providers:** rea-cdp-browser  
**Effects set (true flags):** accessesNetwork, mutatesSession  
**MCP annotations:** `{"destructiveHint":false,"idempotentHint":true,"openWorldHint":true,"readOnlyHint":false}`

**Description (verbatim, as advertised to the agent):**

> List page targets exposed by the selected loopback Chrome DevTools Protocol endpoint. Optionally filter by exact origin. URLs preserve query values and fragments; only URL userinfo credentials are removed.

**Input schema (verbatim, JSON Schema 2020-12):**

<details><summary>inputSchema for list_browser_targets</summary>

```json
{
  "$defs": {
    "__schema0": {
      "description": "Literal loopback CDP endpoint: http://127.0.0.1:PORT, or ws://127.0.0.1:PORT/devtools/browser/ID.",
      "minLength": 1,
      "type": "string"
    },
    "__schema1": {
      "items": {
        "minLength": 1,
        "type": "string"
      },
      "type": "array"
    }
  },
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "additionalProperties": false,
  "examples": [
    {
      "cdp_endpoint": "http://127.0.0.1:9222"
    }
  ],
  "properties": {
    "allowed_origins": {
      "$ref": "#/$defs/__schema1"
    },
    "cdp_endpoint": {
      "$ref": "#/$defs/__schema0",
      "description": "Literal loopback CDP endpoint: http://127.0.0.1:PORT, or ws://127.0.0.1:PORT/devtools/browser/ID."
    }
  },
  "required": [
    "cdp_endpoint"
  ],
  "type": "object"
}
```

</details>

**Output schema:** see [`tool-specs/list_browser_targets.json`](../tool-specs/list_browser_targets.json) (`outputSchema`).

---

## observe_web_execution

<a id="observewebexecution"></a>

**Title:** Observe Web Execution  
**Kind:** `browser-provider` · **Requires session:** false · **analysisOperation:** null  
**Providers:** rea-cdp-browser  
**Effects set (true flags):** accessesNetwork, NOT idempotent, mayDiscardData, mutatesSession, mutatesTarget  
**MCP annotations:** `{"destructiveHint":true,"idempotentHint":false,"openWorldHint":true,"readOnlyHint":false}`

**Description (verbatim, as advertised to the agent):**

> Instrument one selected CDP page for a finite, externally driven precise coverage window. Resets execution counters and prevents optimized execution until stopped. Returns complete nested UTF-16 ranges/counts, independently hashed script text and request initiator associations by session script ID. Does not navigate, click, evaluate selected code or close the externally owned page. Navigation ends document-scoped collection; workers and UI causality remain outside this claim. Emits an actual armed progress notification before external actions.

**Input schema (verbatim, JSON Schema 2020-12):**

<details><summary>inputSchema for observe_web_execution</summary>

```json
{
  "$defs": {
    "__schema0": {
      "minLength": 1,
      "type": "string"
    },
    "__schema1": {
      "items": {
        "minLength": 1,
        "type": "string"
      },
      "type": "array"
    },
    "__schema2": {
      "minLength": 1,
      "type": "string"
    },
    "__schema3": {
      "default": 10000,
      "maximum": 2147483647,
      "minimum": 1,
      "type": "integer"
    }
  },
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "additionalProperties": false,
  "examples": [
    {
      "cdp_endpoint": "http://127.0.0.1:9222",
      "observation_ms": 10000,
      "target_id": "TARGET_ID_FROM_LIST_BROWSER_TARGETS"
    }
  ],
  "properties": {
    "allowed_origins": {
      "$ref": "#/$defs/__schema1"
    },
    "cdp_endpoint": {
      "$ref": "#/$defs/__schema0",
      "description": "Literal loopback Chrome DevTools Protocol endpoint."
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

**Output schema:** see [`tool-specs/observe_web_execution.json`](../tool-specs/observe_web_execution.json) (`outputSchema`).

---

## observe_web_session

<a id="observewebsession"></a>

**Title:** Observe Web Session  
**Kind:** `browser-provider` · **Requires session:** false · **analysisOperation:** null  
**Providers:** rea-cdp-browser  
**Effects set (true flags):** accessesNetwork, mutatesSession  
**MCP annotations:** `{"destructiveHint":false,"idempotentHint":true,"openWorldHint":true,"readOnlyHint":false}`

**Description (verbatim, as advertised to the agent):**

> Arm a CDP observation window of the requested duration while the user operates the page. By default it follows the selected target's current origin; an explicit origin list controls which origins may be retained. Records navigation, redirect, lifecycle, and failure events.

**Input schema (verbatim, JSON Schema 2020-12):**

<details><summary>inputSchema for observe_web_session</summary>

```json
{
  "$defs": {
    "__schema0": {
      "description": "Literal loopback CDP endpoint: http://127.0.0.1:PORT, or ws://127.0.0.1:PORT/devtools/browser/ID.",
      "minLength": 1,
      "type": "string"
    },
    "__schema1": {
      "items": {
        "minLength": 1,
        "type": "string"
      },
      "type": "array"
    },
    "__schema2": {
      "minLength": 1,
      "type": "string"
    },
    "__schema3": {
      "default": 10000,
      "maximum": 9007199254740991,
      "minimum": 1,
      "type": "integer"
    }
  },
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "additionalProperties": false,
  "examples": [
    {
      "cdp_endpoint": "http://127.0.0.1:9222",
      "observation_ms": 10000,
      "target_id": "TARGET_ID_FROM_LIST_BROWSER_TARGETS"
    }
  ],
  "properties": {
    "allowed_origins": {
      "$ref": "#/$defs/__schema1"
    },
    "cdp_endpoint": {
      "$ref": "#/$defs/__schema0",
      "description": "Literal loopback CDP endpoint: http://127.0.0.1:PORT, or ws://127.0.0.1:PORT/devtools/browser/ID."
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

**Output schema:** see [`tool-specs/observe_web_session.json`](../tool-specs/observe_web_session.json) (`outputSchema`).

---

