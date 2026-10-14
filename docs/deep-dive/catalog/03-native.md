# Tool family: Native providers & utilities

Generated mechanically from `.cache/mcp-tool-catalog.json` (produced by `scripts/generate-mcp-tool-catalog.mjs`, which registers every tool through the MCP SDK and exports the advertised JSON Schema 2020-12 input/output schemas) and `docs/public/product-catalog.json` (family `native`, surface `native-provider`, 23 tools). Input schemas below are **verbatim**. Output schemas are verbatim in `tool-specs/<tool>.json` (field `outputSchema`) because several exceed 100 KB; the complete per-tool spec (description, effects, annotations, inputSchema, outputSchema) is in that file.

| Tool | Kind | Session? | Providers advertising it | CLI command |
|---|---|---|---|---|
| [`capture_native_ui_scenario`](#capturenativeuiscenario) | native-provider | no | native-macos | `rea capture-native-ui-scenario` |
| [`close_gdb_session`](#closegdbsession) | native-provider | no | gnu.gdb | — |
| [`close_rizin_debug_session`](#closerizindebugsession) | native-provider | no | rizin.debugger | — |
| [`cutter_command`](#cuttercommand) | native-provider | no | cutter.python-plugin | `rea cutter-command` |
| [`demangle_swift`](#demangleswift) | native-provider | no | native-macos | `rea demangle-swift` |
| [`execute_rizin_command`](#executerizincommand) | native-provider | no | rizin | `rea execute-rizin-command` |
| [`gdb_console`](#gdbconsole) | native-provider | no | gnu.gdb | — |
| [`gdb_session_status`](#gdbsessionstatus) | native-provider | no | gnu.gdb | — |
| [`inspect_binary_layout`](#inspectbinarylayout) | native-provider | no | pwntools-elf | `rea inspect-binary-layout` |
| [`inspect_macho`](#inspectmacho) | native-provider | no | native-macos | `rea inspect-macho` |
| [`inspect_pe_resources`](#inspectperesources) | native-provider | no | rea-pe-resources | `rea inspect-pe-resources` |
| [`inspect_plist`](#inspectplist) | native-provider | no | native-macos | `rea inspect-plist` |
| [`inspect_recorded_crash`](#inspectrecordedcrash) | native-provider | no | pwntools-elf | `rea inspect-recorded-crash` |
| [`inspect_signature`](#inspectsignature) | native-provider | no | native-macos | `rea inspect-signature` |
| [`inspect_with_objdump`](#inspectwithobjdump) | native-provider | no | gnu.objdump | `rea inspect-with-objdump` |
| [`list_architectures`](#listarchitectures) | native-provider | no | native-macos | `rea list-architectures` |
| [`list_cutter_sessions`](#listcuttersessions) | native-provider | no | cutter.python-plugin | `rea list-cutter-sessions` |
| [`observe_native_calls`](#observenativecalls) | native-provider | no | native-macos | `rea observe-native-calls` |
| [`observe_native_ui`](#observenativeui) | native-provider | no | native-macos | `rea observe-native-ui` |
| [`rizin_debug_command`](#rizindebugcommand) | native-provider | no | rizin.debugger | — |
| [`rizin_debug_session_status`](#rizindebugsessionstatus) | native-provider | no | rizin.debugger | — |
| [`start_gdb_session`](#startgdbsession) | native-provider | no | gnu.gdb | — |
| [`start_rizin_debug_session`](#startrizindebugsession) | native-provider | no | rizin.debugger | — |

## capture_native_ui_scenario

<a id="capturenativeuiscenario"></a>

**Title:** Capture Native Ui Scenario  
**Kind:** `native-provider` · **Requires session:** false · **analysisOperation:** capture_native_ui_scenario  
**Providers:** native-macos  
**Effects set (true flags):** accessesNetwork, changesUiState, executesForeignCode, NOT idempotent, launchesProcess, mayDiscardData, mutatesSession, mutatesTarget, writesFilesystem  
**MCP annotations:** `{"destructiveHint":true,"idempotentHint":false,"openWorldHint":true,"readOnlyHint":false}`

**Description (verbatim, as advertised to the agent):**

> Run selected-element press, increment/decrement scroll, AXValue text entry and bounded wait steps in one exact native app window. Returns ordered before/after captures and action/capture failures. Actions can change app data, network activity and persistent state; application state is left as-is and restoration is not attempted.

**Input schema (verbatim, JSON Schema 2020-12):**

<details><summary>inputSchema for capture_native_ui_scenario</summary>

```json
{
  "$defs": {
    "__schema0": {
      "exclusiveMinimum": 0,
      "maximum": 9007199254740991,
      "type": "integer"
    },
    "__schema1": {
      "exclusiveMinimum": 0,
      "maximum": 9007199254740991,
      "type": "integer"
    },
    "__schema10": {
      "maximum": 9007199254740991,
      "minimum": 0,
      "type": "integer"
    },
    "__schema2": {
      "default": true,
      "type": "boolean"
    },
    "__schema3": {
      "default": true,
      "type": "boolean"
    },
    "__schema4": {
      "$ref": "#/$defs/__schema5",
      "default": 500,
      "description": "Maximum accessibility nodes per capture; increase for large windows."
    },
    "__schema5": {
      "exclusiveMinimum": 0,
      "maximum": 9007199254740991,
      "type": "integer"
    },
    "__schema6": {
      "items": {
        "$ref": "#/$defs/__schema7"
      },
      "minItems": 1,
      "type": "array"
    },
    "__schema7": {
      "oneOf": [
        {
          "additionalProperties": false,
          "properties": {
            "kind": {
              "const": "click",
              "type": "string"
            },
            "path": {
              "description": "Local filesystem path used by this operation.",
              "items": {
                "$ref": "#/$defs/__schema8"
              },
              "maxItems": 32,
              "type": "array"
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
            "direction": {
              "description": "Direction in which to traverse or compare relationships.",
              "enum": [
                "increment",
                "decrement"
              ],
              "type": "string"
            },
            "kind": {
              "const": "scroll",
              "type": "string"
            },
            "path": {
              "description": "Local filesystem path used by this operation.",
              "items": {
                "$ref": "#/$defs/__schema9"
              },
              "maxItems": 32,
              "type": "array"
            }
          },
          "required": [
            "kind",
            "path",
            "direction"
          ],
          "type": "object"
        },
        {
          "additionalProperties": false,
          "properties": {
            "kind": {
              "const": "key-entry",
              "type": "string"
            },
            "path": {
              "description": "Local filesystem path used by this operation.",
              "items": {
                "$ref": "#/$defs/__schema10"
              },
              "maxItems": 32,
              "type": "array"
            },
            "text": {
              "type": "string"
            }
          },
          "required": [
            "kind",
            "path",
            "text"
          ],
          "type": "object"
        },
        {
          "additionalProperties": false,
          "properties": {
            "kind": {
              "const": "wait",
              "type": "string"
            },
            "milliseconds": {
              "description": "Wait duration in milliseconds, within the 180-second operation deadline.",
              "maximum": 180000,
              "minimum": 0,
              "type": "integer"
            }
          },
          "required": [
            "kind",
            "milliseconds"
          ],
          "type": "object"
        }
      ]
    },
    "__schema8": {
      "maximum": 9007199254740991,
      "minimum": 0,
      "type": "integer"
    },
    "__schema9": {
      "maximum": 9007199254740991,
      "minimum": 0,
      "type": "integer"
    }
  },
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "additionalProperties": false,
  "examples": [
    {
      "pid": 123,
      "steps": [
        {
          "kind": "wait",
          "milliseconds": 100
        }
      ],
      "window_id": 456
    }
  ],
  "properties": {
    "accessibility": {
      "$ref": "#/$defs/__schema3"
    },
    "max_nodes": {
      "$ref": "#/$defs/__schema4",
      "description": "Maximum accessibility nodes per capture; increase for large windows."
    },
    "pid": {
      "$ref": "#/$defs/__schema0"
    },
    "screenshot": {
      "$ref": "#/$defs/__schema2"
    },
    "steps": {
      "$ref": "#/$defs/__schema6"
    },
    "window_id": {
      "$ref": "#/$defs/__schema1"
    }
  },
  "required": [
    "pid",
    "window_id",
    "steps"
  ],
  "type": "object"
}
```

</details>

**Output schema:** see [`tool-specs/capture_native_ui_scenario.json`](../tool-specs/capture_native_ui_scenario.json) (`outputSchema`).

---

## close_gdb_session

<a id="closegdbsession"></a>

**Title:** Close Gdb Session  
**Kind:** `native-provider` · **Requires session:** false · **analysisOperation:** close_gdb_session  
**Providers:** gnu.gdb  
**Effects set (true flags):** executesForeignCode, NOT idempotent, launchesProcess, mutatesSession, mutatesTarget  
**MCP annotations:** `{"destructiveHint":true,"idempotentHint":false,"openWorldHint":true,"readOnlyHint":false}`

**Description (verbatim, as advertised to the agent):**

> Close the owned GDB process after verifying the inferior state. When one live thread group has a verified durable output TTY, REA automatically detaches it, which may resume target execution; otherwise close reports that a disposition is required. REA never kills attached or remote targets as part of debugger cleanup. In a shared MCP server, this admitted close retires any active binary-analysis session; after target effects have settled, call open_binary before further analysis. Close an active Ghidra session explicitly first.

**Input schema (verbatim, JSON Schema 2020-12):**

<details><summary>inputSchema for close_gdb_session</summary>

```json
{
  "$defs": {
    "__schema0": {
      "format": "uuid",
      "pattern": "^([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-8][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}|00000000-0000-0000-0000-000000000000|ffffffff-ffff-ffff-ffff-ffffffffffff)$",
      "type": "string"
    }
  },
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "additionalProperties": false,
  "examples": [
    {
      "session_id": "00000000-0000-4000-8000-000000000001"
    }
  ],
  "properties": {
    "session_id": {
      "$ref": "#/$defs/__schema0"
    }
  },
  "required": [
    "session_id"
  ],
  "type": "object"
}
```

</details>

**Output schema:** see [`tool-specs/close_gdb_session.json`](../tool-specs/close_gdb_session.json) (`outputSchema`).

---

## close_rizin_debug_session

<a id="closerizindebugsession"></a>

**Title:** Close Rizin Debug Session  
**Kind:** `native-provider` · **Requires session:** false · **analysisOperation:** close_rizin_debug_session  
**Providers:** rizin.debugger  
**Effects set (true flags):** executesForeignCode, launchesProcess, mutatesSession, mutatesTarget  
**MCP annotations:** `{"destructiveHint":true,"idempotentHint":true,"openWorldHint":true,"readOnlyHint":false}`

**Description (verbatim, as advertised to the agent):**

> Close the REA-owned Rizin debugger only after verifying no inferior remains or detaching one with a verified caller-selected TTY output sink. A detached target may continue running and write to that TTY; target state is otherwise reported as unknown. REA never signals an inferior based on PID or path. In a shared MCP server, this admitted close retires any active binary-analysis session; after target effects have settled, call open_binary before further analysis. Close an active Ghidra session explicitly first.

**Input schema (verbatim, JSON Schema 2020-12):**

<details><summary>inputSchema for close_rizin_debug_session</summary>

```json
{
  "$defs": {
    "__schema0": {
      "format": "uuid",
      "pattern": "^([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-8][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}|00000000-0000-0000-0000-000000000000|ffffffff-ffff-ffff-ffff-ffffffffffff)$",
      "type": "string"
    }
  },
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "additionalProperties": false,
  "examples": [
    {
      "session_id": "00000000-0000-4000-8000-000000000001"
    }
  ],
  "properties": {
    "session_id": {
      "$ref": "#/$defs/__schema0"
    }
  },
  "required": [
    "session_id"
  ],
  "type": "object"
}
```

</details>

**Output schema:** see [`tool-specs/close_rizin_debug_session.json`](../tool-specs/close_rizin_debug_session.json) (`outputSchema`).

---

## cutter_command

<a id="cuttercommand"></a>

**Title:** Cutter Command  
**Kind:** `native-provider` · **Requires session:** false · **analysisOperation:** cutter_command  
**Providers:** cutter.python-plugin  
**Effects set (true flags):** accessesNetwork, changesUiState, executesForeignCode, NOT idempotent, launchesProcess, mutatesSession, mutatesTarget, writesFilesystem  
**MCP annotations:** `{"destructiveHint":true,"idempotentHint":false,"openWorldHint":true,"readOnlyHint":false}`

**Description (verbatim, as advertised to the agent):**

> Run one arbitrary Rizin command in a selected live Cutter session. Commands may edit and persist analysis state or execute plugin-provided effects; completion uncertainty is returned as Evidence and must not be retried automatically. In a shared MCP server, this admitted command closes any active binary-analysis session; after its effects have settled, call open_binary before further analysis. Close an active Ghidra session explicitly first.

**Input schema (verbatim, JSON Schema 2020-12):**

<details><summary>inputSchema for cutter_command</summary>

```json
{
  "$defs": {
    "__schema0": {
      "format": "uuid",
      "pattern": "^([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-8][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}|00000000-0000-0000-0000-000000000000|ffffffff-ffff-ffff-ffff-ffffffffffff)$",
      "type": "string"
    },
    "__schema1": {
      "maximum": 9007199254740991,
      "minimum": 0,
      "type": "integer"
    },
    "__schema2": {
      "minLength": 1,
      "type": "string"
    },
    "__schema3": {
      "default": false,
      "type": "boolean"
    }
  },
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "additionalProperties": false,
  "examples": [
    {
      "command": "ij",
      "expected_generation": 0,
      "json": true,
      "session_id": "00000000-0000-4000-8000-000000000001"
    }
  ],
  "properties": {
    "command": {
      "$ref": "#/$defs/__schema2"
    },
    "expected_generation": {
      "$ref": "#/$defs/__schema1",
      "description": "Expected generation used to reject stale or mismatched input."
    },
    "json": {
      "$ref": "#/$defs/__schema3"
    },
    "session_id": {
      "$ref": "#/$defs/__schema0"
    }
  },
  "required": [
    "session_id",
    "expected_generation",
    "command"
  ],
  "type": "object"
}
```

</details>

**Output schema:** see [`tool-specs/cutter_command.json`](../tool-specs/cutter_command.json) (`outputSchema`).

---

## demangle_swift

<a id="demangleswift"></a>

**Title:** Demangle Swift  
**Kind:** `native-provider` · **Requires session:** false · **analysisOperation:** demangle_swift  
**Providers:** native-macos  
**Effects set (true flags):** launchesProcess, mutatesSession  
**MCP annotations:** `{"destructiveHint":false,"idempotentHint":true,"openWorldHint":true,"readOnlyHint":false}`

**Description (verbatim, as advertised to the agent):**

> Demangle an ordered list of single-line Swift symbols without requiring Hopper. Each input returns demangled, unchanged, or invalid status.

**Input schema (verbatim, JSON Schema 2020-12):**

<details><summary>inputSchema for demangle_swift</summary>

```json
{
  "$defs": {
    "__schema0": {
      "items": {
        "allOf": [
          {
            "pattern": "^[^\\n]*$"
          },
          {
            "pattern": "^[^\\x00]*$"
          }
        ],
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
      "symbols": [
        "$s4Test3fooyyF"
      ]
    }
  ],
  "properties": {
    "symbols": {
      "$ref": "#/$defs/__schema0",
      "description": "Ordered Swift symbols to demangle."
    }
  },
  "required": [
    "symbols"
  ],
  "type": "object"
}
```

</details>

**Output schema:** see [`tool-specs/demangle_swift.json`](../tool-specs/demangle_swift.json) (`outputSchema`).

---

## execute_rizin_command

<a id="executerizincommand"></a>

**Title:** Execute Rizin Command  
**Kind:** `native-provider` · **Requires session:** false · **analysisOperation:** execute_rizin_command  
**Providers:** rizin  
**Effects set (true flags):** accessesNetwork, executesForeignCode, NOT idempotent, launchesProcess, mayDiscardData, mutatesSession, mutatesTarget, writesFilesystem  
**MCP annotations:** `{"destructiveHint":true,"idempotentHint":false,"openWorldHint":true,"readOnlyHint":false}`

**Description (verbatim, as advertised to the agent):**

> Execute one caller-selected Rizin command against a local artifact using the Rizin CLI profile that suppresses user settings and scripts while retaining plugins. Preserves decoded stdout and stderr inline with SHA-256 Evidence, up to a shared 16 MiB combined limit; invalid UTF-8 bytes are represented by replacement characters and flagged in Evidence limitations. output_truncated reports output beyond that limit and completion_status is unknown if buffer enforcement terminated the process. Rizin commands and retained plugins can execute foreign code, mutate files, access the network, and read files outside the selected artifact; identities and contents of those external inputs are not bound to Evidence. Command effects depend on the Rizin command and loaded plugins; JSON is command-specific and raw output remains authoritative. In a shared MCP server, this admitted command closes any active binary-analysis session; after its effects have settled, call open_binary before further analysis. Close an active Ghidra session explicitly first.

**Input schema (verbatim, JSON Schema 2020-12):**

<details><summary>inputSchema for execute_rizin_command</summary>

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
      "command": "iI",
      "path": "/tmp/program"
    }
  ],
  "properties": {
    "command": {
      "$ref": "#/$defs/__schema1"
    },
    "path": {
      "$ref": "#/$defs/__schema0",
      "description": "Local filesystem path used by this operation."
    }
  },
  "required": [
    "path",
    "command"
  ],
  "type": "object"
}
```

</details>

**Output schema:** see [`tool-specs/execute_rizin_command.json`](../tool-specs/execute_rizin_command.json) (`outputSchema`).

---

## gdb_console

<a id="gdbconsole"></a>

**Title:** Gdb Console  
**Kind:** `native-provider` · **Requires session:** false · **analysisOperation:** gdb_console  
**Providers:** gnu.gdb  
**Effects set (true flags):** accessesNetwork, executesForeignCode, NOT idempotent, launchesProcess, mutatesSession, mutatesTarget, writesFilesystem  
**MCP annotations:** `{"destructiveHint":true,"idempotentHint":false,"openWorldHint":true,"readOnlyHint":false}`

**Description (verbatim, as advertised to the agent):**

> Run one unrestricted GDB CLI command through MI interpreter-exec console and return raw MI, console, target, and log records inline with Evidence. A command timeout preserves collected records with completion_status unknown and stops the owned debugger session. Commands can execute shell, alter target state, access files, and use network. Closing the debugger never implies target termination. In a shared MCP server, this admitted command closes any active binary-analysis session; after its effects have settled, call open_binary before further analysis. Close an active Ghidra session explicitly first.

**Input schema (verbatim, JSON Schema 2020-12):**

<details><summary>inputSchema for gdb_console</summary>

```json
{
  "$defs": {
    "__schema0": {
      "format": "uuid",
      "pattern": "^([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-8][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}|00000000-0000-0000-0000-000000000000|ffffffff-ffff-ffff-ffff-ffffffffffff)$",
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
      "command": "info functions",
      "session_id": "00000000-0000-4000-8000-000000000001"
    }
  ],
  "properties": {
    "command": {
      "$ref": "#/$defs/__schema1"
    },
    "session_id": {
      "$ref": "#/$defs/__schema0"
    }
  },
  "required": [
    "session_id",
    "command"
  ],
  "type": "object"
}
```

</details>

**Output schema:** see [`tool-specs/gdb_console.json`](../tool-specs/gdb_console.json) (`outputSchema`).

---

## gdb_session_status

<a id="gdbsessionstatus"></a>

**Title:** Gdb Session Status  
**Kind:** `native-provider` · **Requires session:** false · **analysisOperation:** gdb_session_status  
**Providers:** gnu.gdb  
**Effects set (true flags):** none (pure read)  
**MCP annotations:** `{"destructiveHint":false,"idempotentHint":true,"openWorldHint":false,"readOnlyHint":true}`

**Description (verbatim, as advertised to the agent):**

> Return the observed lifecycle state and bounded recent MI records and process diagnostics for one persistent REA GDB session; truncation and invalid-UTF-8 fields report discarded or lossy data.

**Input schema (verbatim, JSON Schema 2020-12):**

<details><summary>inputSchema for gdb_session_status</summary>

```json
{
  "$defs": {
    "__schema0": {
      "format": "uuid",
      "pattern": "^([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-8][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}|00000000-0000-0000-0000-000000000000|ffffffff-ffff-ffff-ffff-ffffffffffff)$",
      "type": "string"
    }
  },
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "additionalProperties": false,
  "examples": [
    {
      "session_id": "00000000-0000-4000-8000-000000000001"
    }
  ],
  "properties": {
    "session_id": {
      "$ref": "#/$defs/__schema0"
    }
  },
  "required": [
    "session_id"
  ],
  "type": "object"
}
```

</details>

**Output schema:** see [`tool-specs/gdb_session_status.json`](../tool-specs/gdb_session_status.json) (`outputSchema`).

---

## inspect_binary_layout

<a id="inspectbinarylayout"></a>

**Title:** Inspect Binary Layout  
**Kind:** `native-provider` · **Requires session:** false · **analysisOperation:** inspect_binary_layout  
**Providers:** pwntools-elf  
**Effects set (true flags):** launchesProcess, mutatesSession, writesFilesystem  
**MCP annotations:** `{"destructiveHint":false,"idempotentHint":true,"openWorldHint":true,"readOnlyHint":false}`

**Description (verbatim, as advertised to the agent):**

> Inspect an explicit local binary without launching it as a host process. Returns file-backed section/segment ranges, linked addresses, original symbol/REL/RELA table identities, complete encoded RELR tables and upstream-derived offsets with unknown per-word locations/addends, raw name bytes, dependency/interpreter names and static mitigation inferences inline with artifact SHA-256 Evidence. Initial profile: ELF64 x86-64 little-endian EXEC/DYN/REL on Linux x64 via caller-supplied Python with unchanged pwntools 4.15.0, pyelftools 0.33 and Unicorn 2.1.2. Runtime addresses/library paths, overall relocation inventory completeness and complete derived GOT/PLT coverage remain unknown. Zero executable entry values mean absence; relocatable entries are not applicable. Upstream can emulate PLT instructions with Unicorn for derived static maps. Uses bounded complete output and owned temporary files/processes; malformed, unsupported or oversized objects return no partial success. Select detail summary to retain the complete layout Evidence in this session and receive only its summary view, then inspect sections, symbols, mitigations or linkage with inspect_analysis_view.

**Input schema (verbatim, JSON Schema 2020-12):**

<details><summary>inputSchema for inspect_binary_layout</summary>

```json
{
  "$defs": {
    "__schema0": {
      "description": "Absolute filesystem path to the selected binary",
      "minLength": 1,
      "pattern": "^[^\\x00]*$",
      "type": "string"
    },
    "__schema1": {
      "$ref": "#/$defs/__schema2",
      "default": "complete",
      "description": "complete returns the complete analysis Evidence inline. summary retains that complete Evidence in this session and returns its inspect_analysis_view summary; inspect pages, items or facets through normalized_result.parent_evidence_id."
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
      "path": "/artifacts/application.elf"
    },
    {
      "detail": "summary",
      "path": "/artifacts/application.elf"
    }
  ],
  "properties": {
    "detail": {
      "$ref": "#/$defs/__schema1",
      "description": "complete returns the complete analysis Evidence inline. summary retains that complete Evidence in this session and returns its inspect_analysis_view summary; inspect pages, items or facets through normalized_result.parent_evidence_id."
    },
    "path": {
      "$ref": "#/$defs/__schema0",
      "description": "Absolute filesystem path to the selected binary"
    }
  },
  "required": [
    "path"
  ],
  "type": "object"
}
```

</details>

**Output schema:** see [`tool-specs/inspect_binary_layout.json`](../tool-specs/inspect_binary_layout.json) (`outputSchema`).

---

## inspect_macho

<a id="inspectmacho"></a>

**Title:** Inspect Macho  
**Kind:** `native-provider` · **Requires session:** false · **analysisOperation:** inspect_macho  
**Providers:** native-macos  
**Effects set (true flags):** launchesProcess, mutatesSession  
**MCP annotations:** `{"destructiveHint":false,"idempotentHint":true,"openWorldHint":true,"readOnlyHint":false}`

**Description (verbatim, as advertised to the agent):**

> Inspect Mach-O slices, load commands, imports, exports, dependencies, build metadata, segments, sections, permissions, and exact command provenance without launching Hopper. Large frameworks return megabytes of symbols; detail summary retains the complete Evidence and returns slice identity with per-collection counts, then page rows with inspect_analysis_view kind macho.

**Input schema (verbatim, JSON Schema 2020-12):**

<details><summary>inputSchema for inspect_macho</summary>

```json
{
  "$defs": {
    "__schema0": {
      "$ref": "#/$defs/__schema1",
      "description": "Omitted or complete returns the complete inspection Evidence. summary retains that complete Evidence in this session and returns its inspect_analysis_view summary; use normalized_result.parent_evidence_id for macho pages."
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
    {}
  ],
  "properties": {
    "detail": {
      "$ref": "#/$defs/__schema0",
      "description": "Omitted or complete returns the complete inspection Evidence. summary retains that complete Evidence in this session and returns its inspect_analysis_view summary; use normalized_result.parent_evidence_id for macho pages."
    }
  },
  "type": "object"
}
```

</details>

**Output schema:** see [`tool-specs/inspect_macho.json`](../tool-specs/inspect_macho.json) (`outputSchema`).

---

## inspect_pe_resources

<a id="inspectperesources"></a>

**Title:** Inspect Pe Resources  
**Kind:** `native-provider` · **Requires session:** false · **analysisOperation:** inspect_pe_resources  
**Providers:** rea-pe-resources  
**Effects set (true flags):** mutatesSession  
**MCP annotations:** `{"destructiveHint":false,"idempotentHint":true,"openWorldHint":false,"readOnlyHint":false}`

**Description (verbatim, as advertised to the agent):**

> Inspect one explicit local PE32/PE32+ image's complete bounded type/name/language resource tree without executing it or opening a disassembler. Returns numeric IDs versus original UTF-16 names, directory/data-entry file locations, payload RVA/file ranges, complete SHA-256 hashes and static RT_GROUP_ICON image-resource candidates. Language fallback, image decoding and actual shell/window loading remain unobserved. Reads a stable regular file; malformed or ambiguous mappings, non-identical overlapping ranges and exhausted budgets return no partial success. Portable on supported Node hosts; no Windows SDK or engine installation required.

**Input schema (verbatim, JSON Schema 2020-12):**

<details><summary>inputSchema for inspect_pe_resources</summary>

```json
{
  "$defs": {
    "__schema0": {
      "description": "Absolute filesystem path to a PE image",
      "minLength": 1,
      "pattern": "^[^\\x00]*$",
      "type": "string"
    },
    "__schema1": {
      "$ref": "#/$defs/__schema2",
      "default": 67108864,
      "description": "Maximum stable artifact bytes to read (default 64 MiB)"
    },
    "__schema2": {
      "maximum": 536870912,
      "minimum": 64,
      "type": "integer"
    },
    "__schema3": {
      "$ref": "#/$defs/__schema4",
      "default": 16384,
      "description": "Maximum resource directory entries to examine; exceeding the budget fails without partial success"
    },
    "__schema4": {
      "maximum": 65536,
      "minimum": 1,
      "type": "integer"
    }
  },
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "additionalProperties": false,
  "examples": [
    {
      "path": "/artifacts/application.exe"
    }
  ],
  "properties": {
    "max_entries": {
      "$ref": "#/$defs/__schema3",
      "description": "Maximum resource directory entries to examine; exceeding the budget fails without partial success"
    },
    "max_file_bytes": {
      "$ref": "#/$defs/__schema1",
      "description": "Maximum stable artifact bytes to read (default 64 MiB)"
    },
    "path": {
      "$ref": "#/$defs/__schema0",
      "description": "Absolute filesystem path to a PE image"
    }
  },
  "required": [
    "path"
  ],
  "type": "object"
}
```

</details>

**Output schema:** see [`tool-specs/inspect_pe_resources.json`](../tool-specs/inspect_pe_resources.json) (`outputSchema`).

---

## inspect_plist

<a id="inspectplist"></a>

**Title:** Inspect Plist  
**Kind:** `native-provider` · **Requires session:** false · **analysisOperation:** inspect_plist  
**Providers:** native-macos  
**Effects set (true flags):** launchesProcess, mutatesSession  
**MCP annotations:** `{"destructiveHint":false,"idempotentHint":true,"openWorldHint":true,"readOnlyHint":false}`

**Description (verbatim, as advertised to the agent):**

> Parse Info.plist from the active artifact by default, or pass any local plist path. Returns normalized JSON rather than plutil text.

**Input schema (verbatim, JSON Schema 2020-12):**

<details><summary>inputSchema for inspect_plist</summary>

```json
{
  "$defs": {
    "__schema0": {
      "minLength": 1,
      "pattern": "^[^\\x00]*$",
      "type": "string"
    }
  },
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "additionalProperties": false,
  "examples": [
    {
      "path": "/Applications/Example.app/Contents/Info.plist"
    }
  ],
  "properties": {
    "path": {
      "$ref": "#/$defs/__schema0",
      "description": "Local filesystem path used by this operation."
    }
  },
  "type": "object"
}
```

</details>

**Output schema:** see [`tool-specs/inspect_plist.json`](../tool-specs/inspect_plist.json) (`outputSchema`).

---

## inspect_recorded_crash

<a id="inspectrecordedcrash"></a>

**Title:** Inspect Recorded Crash  
**Kind:** `native-provider` · **Requires session:** false · **analysisOperation:** inspect_recorded_crash  
**Providers:** pwntools-elf  
**Effects set (true flags):** launchesProcess, mutatesSession, writesFilesystem  
**MCP annotations:** `{"destructiveHint":false,"idempotentHint":true,"openWorldHint":true,"readOnlyHint":false}`

**Description (verbatim, as advertised to the agent):**

> Inspect a supplied Linux ELF64 amd64 or AArch64 little-endian core without launching its target or attaching to any live PID. Returns all recorded segments, raw note owners/descriptors and source ranges, every Linux CORE PRSTATUS thread/register and SIGINFO fields inline with SHA-256 Evidence. Historical PID is recorded metadata; current process/file identity, note coverage and signal-thread associations stay unknown. Optionally add derived core-only GDB/pwndbg mapping candidates through explicit BYO configuration; zero map flags mean unknown permissions. Uses the same stable snapshot for both stages, bounded complete output and owned cleanup. Linux x64 host profile: unchanged pwntools 4.15.0/pyelftools 0.33/Unicorn 2.1.2; optional unchanged pwndbg 2026.09.15. No implicit executable/library pairing, GDB command language, host configuration changes or dependency installation.

**Input schema (verbatim, JSON Schema 2020-12):**

<details><summary>inputSchema for inspect_recorded_crash</summary>

```json
{
  "$defs": {
    "__schema0": {
      "description": "Absolute filesystem path to a supplied Linux ELF core",
      "minLength": 1,
      "pattern": "^[^\\x00]*$",
      "type": "string"
    },
    "__schema1": {
      "$ref": "#/$defs/__schema2",
      "default": false,
      "description": "Add core-only mapping candidates through caller-supplied GDB/pwndbg"
    },
    "__schema2": {
      "type": "boolean"
    }
  },
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "additionalProperties": false,
  "examples": [
    {
      "path": "/artifacts/crash.core"
    },
    {
      "include_debugger_context": true,
      "path": "/artifacts/crash.core"
    }
  ],
  "properties": {
    "include_debugger_context": {
      "$ref": "#/$defs/__schema1",
      "description": "Add core-only mapping candidates through caller-supplied GDB/pwndbg"
    },
    "path": {
      "$ref": "#/$defs/__schema0",
      "description": "Absolute filesystem path to a supplied Linux ELF core"
    }
  },
  "required": [
    "path"
  ],
  "type": "object"
}
```

</details>

**Output schema:** see [`tool-specs/inspect_recorded_crash.json`](../tool-specs/inspect_recorded_crash.json) (`outputSchema`).

---

## inspect_signature

<a id="inspectsignature"></a>

**Title:** Inspect Signature  
**Kind:** `native-provider` · **Requires session:** false · **analysisOperation:** inspect_signature  
**Providers:** native-macos  
**Effects set (true flags):** launchesProcess, mutatesSession  
**MCP annotations:** `{"destructiveHint":false,"idempotentHint":true,"openWorldHint":true,"readOnlyHint":false}`

**Description (verbatim, as advertised to the agent):**

> Inspect the active Mach-O executable's code-signing identity, hashes, authorities, requirements, entitlements, hardened-runtime state, and exact command provenance.

**Input schema (verbatim, JSON Schema 2020-12):**

<details><summary>inputSchema for inspect_signature</summary>

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

**Output schema:** see [`tool-specs/inspect_signature.json`](../tool-specs/inspect_signature.json) (`outputSchema`).

---

## inspect_with_objdump

<a id="inspectwithobjdump"></a>

**Title:** Inspect With Objdump  
**Kind:** `native-provider` · **Requires session:** false · **analysisOperation:** inspect_with_objdump  
**Providers:** gnu.objdump  
**Effects set (true flags):** launchesProcess, mutatesSession  
**MCP annotations:** `{"destructiveHint":false,"idempotentHint":true,"openWorldHint":true,"readOnlyHint":false}`

**Description (verbatim, as advertised to the agent):**

> Run caller-selected GNU objdump inspection against a local artifact, or request operation=architectures without a path to list BFD targets advertised by the installed binary. Preserves decoded stdout and stderr inline with SHA-256 Evidence for artifact inspections, up to a shared 16 MiB combined limit; invalid UTF-8 bytes are represented by replacement characters and flagged in Evidence limitations. output_truncated reports output beyond that limit and completion_status is unknown if buffer enforcement terminated the process. The raw output is authoritative and REA does not claim a stable normalized format. DWARF does not follow local debug links by default. Set follow_debug_links to true to follow them; identities of external debug files are not bound to Evidence. REA clears DEBUGINFOD_URLS for objdump so DWARF processing does not make debuginfod network requests. Architecture output is subjectless and does not establish support for any artifact.

**Input schema (verbatim, JSON Schema 2020-12):**

<details><summary>inputSchema for inspect_with_objdump</summary>

```json
{
  "$defs": {
    "__schema0": {
      "additionalProperties": false,
      "properties": {
        "follow_debug_links": {
          "default": false,
          "type": "boolean"
        },
        "operation": {
          "enum": [
            "file_headers",
            "section_headers",
            "symbols",
            "relocations",
            "dwarf",
            "disassemble",
            "disassemble_all"
          ],
          "type": "string"
        },
        "path": {
          "description": "Local filesystem path used by this operation.",
          "minLength": 1,
          "type": "string"
        }
      },
      "required": [
        "path",
        "operation"
      ],
      "type": "object"
    },
    "__schema1": {
      "additionalProperties": false,
      "properties": {
        "operation": {
          "const": "architectures",
          "type": "string"
        }
      },
      "required": [
        "operation"
      ],
      "type": "object"
    }
  },
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "additionalProperties": false,
  "description": "Provide a complete input group: path + operation + [follow_debug_links]; operation.",
  "examples": [
    {
      "operation": "disassemble",
      "path": "/tmp/program"
    },
    {
      "operation": "architectures"
    }
  ],
  "minProperties": 1,
  "properties": {
    "follow_debug_links": {
      "default": false,
      "type": "boolean"
    },
    "operation": {
      "anyOf": [
        {
          "enum": [
            "file_headers",
            "section_headers",
            "symbols",
            "relocations",
            "dwarf",
            "disassemble",
            "disassemble_all"
          ],
          "type": "string"
        },
        {
          "const": "architectures",
          "type": "string"
        }
      ]
    },
    "path": {
      "description": "Local filesystem path used by this operation.",
      "minLength": 1,
      "type": "string"
    }
  },
  "required": [
    "operation"
  ],
  "type": "object"
}
```

</details>

**Output schema:** see [`tool-specs/inspect_with_objdump.json`](../tool-specs/inspect_with_objdump.json) (`outputSchema`).

---

## list_architectures

<a id="listarchitectures"></a>

**Title:** List Architectures  
**Kind:** `native-provider` · **Requires session:** false · **analysisOperation:** list_architectures  
**Providers:** native-macos  
**Effects set (true flags):** launchesProcess, mutatesSession  
**MCP annotations:** `{"destructiveHint":false,"idempotentHint":true,"openWorldHint":true,"readOnlyHint":false}`

**Description (verbatim, as advertised to the agent):**

> List thin or universal Mach-O slices with offsets, sizes, alignment, explicit coverage, and native-tool provenance.

**Input schema (verbatim, JSON Schema 2020-12):**

<details><summary>inputSchema for list_architectures</summary>

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

**Output schema:** see [`tool-specs/list_architectures.json`](../tool-specs/list_architectures.json) (`outputSchema`).

---

## list_cutter_sessions

<a id="listcuttersessions"></a>

**Title:** List Cutter Sessions  
**Kind:** `native-provider` · **Requires session:** false · **analysisOperation:** list_cutter_sessions  
**Providers:** cutter.python-plugin  
**Effects set (true flags):** accessesNetwork  
**MCP annotations:** `{"destructiveHint":false,"idempotentHint":true,"openWorldHint":true,"readOnlyHint":false}`

**Description (verbatim, as advertised to the agent):**

> List live REA bridge sessions hosted by upstream Cutter instances, including observed document identity and bridge-directory security status. Discovery admits at most 256 descriptor candidates (16 MiB at the descriptor byte limit), reads and probes at most eight concurrently, and reports bridge_directory_capacity_exceeded rather than claiming no sessions when that budget is exceeded.

**Input schema (verbatim, JSON Schema 2020-12):**

<details><summary>inputSchema for list_cutter_sessions</summary>

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

**Output schema:** see [`tool-specs/list_cutter_sessions.json`](../tool-specs/list_cutter_sessions.json) (`outputSchema`).

---

## observe_native_calls

<a id="observenativecalls"></a>

**Title:** Observe Native Calls  
**Kind:** `native-provider` · **Requires session:** false · **analysisOperation:** observe_native_calls  
**Providers:** native-macos  
**Effects set (true flags):** accessesNetwork, changesUiState, executesForeignCode, NOT idempotent, launchesProcess, mutatesSession, writesFilesystem  
**MCP annotations:** `{"destructiveHint":true,"idempotentHint":false,"openWorldHint":true,"readOnlyHint":false}`

**Description (verbatim, as advertised to the agent):**

> Launch the active Mach-O as an owned process under LLDB and record each entry into caller-selected functions or Objective-C methods: thread, module, symbol, load and file address, raw argument registers, selector, receiver class and optional caller frames. Every hit auto-continues. No expression is evaluated and no other process is attached. The process is killed when max_events or duration_ms is reached; exit status, captured stdout/stderr, unresolved breakpoints and limitations are returned inline. The process runs with the current user's permissions and may change files, show UI or use the network. A hardened-runtime target needs the get-task-allow entitlement.

**Input schema (verbatim, JSON Schema 2020-12):**

<details><summary>inputSchema for observe_native_calls</summary>

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
      "oneOf": [
        {
          "additionalProperties": false,
          "properties": {
            "kind": {
              "const": "function",
              "type": "string"
            },
            "module": {
              "$ref": "#/$defs/__schema3",
              "description": "Image file name that defines the symbol, such as `libsystem_kernel.dylib`; omit to match every image."
            },
            "name": {
              "$ref": "#/$defs/__schema2",
              "description": "Exact symbol name, such as `open`, a C++ or mangled Swift symbol, or `-[NSString length]`.",
              "minLength": 1,
              "pattern": "^[^\\x00]*$",
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
            "class_name": {
              "$ref": "#/$defs/__schema4",
              "description": "Implementing class; omit to match every class."
            },
            "kind": {
              "const": "objc-method",
              "type": "string"
            },
            "method_type": {
              "default": "any",
              "enum": [
                "instance",
                "class",
                "any"
              ],
              "type": "string"
            },
            "selector": {
              "$ref": "#/$defs/__schema4",
              "allOf": [
                {
                  "pattern": "^[^\\x00]*$"
                },
                {
                  "pattern": "^[^\\s\\x5b\\x5d]+$"
                }
              ],
              "description": "Selector such as `dataTaskWithRequest:completionHandler:`."
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
    "__schema10": {
      "maximum": 600000,
      "minimum": 100,
      "type": "integer"
    },
    "__schema11": {
      "$ref": "#/$defs/__schema12",
      "default": 1000,
      "description": "Stop observing and kill the process after this many recorded entries."
    },
    "__schema12": {
      "maximum": 100000,
      "minimum": 1,
      "type": "integer"
    },
    "__schema13": {
      "$ref": "#/$defs/__schema14",
      "default": 4,
      "description": "Integer argument registers to record per entry (arm64 has 8, x86_64 has 6)."
    },
    "__schema14": {
      "maximum": 8,
      "minimum": 0,
      "type": "integer"
    },
    "__schema15": {
      "$ref": "#/$defs/__schema16",
      "default": 0,
      "description": "Caller frames to record per entry."
    },
    "__schema16": {
      "maximum": 64,
      "minimum": 0,
      "type": "integer"
    },
    "__schema2": {
      "pattern": "^[^\\x00]*$",
      "type": "string"
    },
    "__schema3": {
      "$ref": "#/$defs/__schema2",
      "minLength": 1
    },
    "__schema4": {
      "$ref": "#/$defs/__schema2",
      "allOf": [
        {
          "pattern": "^[^\\x00]*$"
        },
        {
          "pattern": "^[^\\s\\x5b\\x5d]+$"
        }
      ],
      "minLength": 1,
      "type": "string"
    },
    "__schema5": {
      "default": [],
      "items": {
        "$ref": "#/$defs/__schema2"
      },
      "type": "array"
    },
    "__schema6": {
      "$ref": "#/$defs/__schema7",
      "default": {},
      "description": "Overrides on top of the environment REA runs with."
    },
    "__schema7": {
      "additionalProperties": {
        "pattern": "^[^\\x00]*$",
        "type": "string"
      },
      "propertyNames": {
        "minLength": 1,
        "pattern": "^[^=\\x00]+$",
        "type": "string"
      },
      "type": "object"
    },
    "__schema8": {
      "minLength": 1,
      "pattern": "^[^\\x00]*$",
      "type": "string"
    },
    "__schema9": {
      "$ref": "#/$defs/__schema10",
      "default": 10000,
      "description": "Observation window; the process is killed if it is still running."
    }
  },
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "additionalProperties": false,
  "examples": [
    {
      "arguments": [
        "--help"
      ],
      "backtrace_frames": 4,
      "breakpoints": [
        {
          "class_name": "NSURLSession",
          "kind": "objc-method",
          "selector": "dataTaskWithRequest:completionHandler:"
        },
        {
          "kind": "function",
          "module": "libsystem_kernel.dylib",
          "name": "open"
        }
      ],
      "duration_ms": 5000
    }
  ],
  "properties": {
    "argument_registers": {
      "$ref": "#/$defs/__schema13",
      "description": "Integer argument registers to record per entry (arm64 has 8, x86_64 has 6)."
    },
    "arguments": {
      "$ref": "#/$defs/__schema5"
    },
    "backtrace_frames": {
      "$ref": "#/$defs/__schema15",
      "description": "Caller frames to record per entry."
    },
    "breakpoints": {
      "$ref": "#/$defs/__schema0"
    },
    "duration_ms": {
      "$ref": "#/$defs/__schema9",
      "description": "Observation window; the process is killed if it is still running."
    },
    "environment": {
      "$ref": "#/$defs/__schema6",
      "description": "Overrides on top of the environment REA runs with."
    },
    "max_events": {
      "$ref": "#/$defs/__schema11",
      "description": "Stop observing and kill the process after this many recorded entries."
    },
    "working_directory": {
      "$ref": "#/$defs/__schema8"
    }
  },
  "required": [
    "breakpoints"
  ],
  "type": "object"
}
```

</details>

**Output schema:** see [`tool-specs/observe_native_calls.json`](../tool-specs/observe_native_calls.json) (`outputSchema`).

---

## observe_native_ui

<a id="observenativeui"></a>

**Title:** Observe Native Ui  
**Kind:** `native-provider` · **Requires session:** false · **analysisOperation:** observe_native_ui  
**Providers:** native-macos  
**Effects set (true flags):** launchesProcess, mutatesSession, writesFilesystem  
**MCP annotations:** `{"destructiveHint":false,"idempotentHint":true,"openWorldHint":true,"readOnlyHint":false}`

**Description (verbatim, as advertised to the agent):**

> Observe an already-running native app by PID and window ID, bound to the active Mach-O target. Captures a bounded accessibility tree and selected-window screenshot; OS permission denial fails without broad capture or target launch.

**Input schema (verbatim, JSON Schema 2020-12):**

<details><summary>inputSchema for observe_native_ui</summary>

```json
{
  "$defs": {
    "__schema0": {
      "exclusiveMinimum": 0,
      "maximum": 9007199254740991,
      "type": "integer"
    },
    "__schema1": {
      "exclusiveMinimum": 0,
      "maximum": 9007199254740991,
      "type": "integer"
    },
    "__schema2": {
      "default": true,
      "type": "boolean"
    },
    "__schema3": {
      "default": true,
      "type": "boolean"
    },
    "__schema4": {
      "$ref": "#/$defs/__schema5",
      "default": 500,
      "description": "Maximum accessibility nodes per capture; increase for large windows."
    },
    "__schema5": {
      "exclusiveMinimum": 0,
      "maximum": 9007199254740991,
      "type": "integer"
    }
  },
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "additionalProperties": false,
  "examples": [
    {
      "pid": 123,
      "window_id": 456
    }
  ],
  "properties": {
    "accessibility": {
      "$ref": "#/$defs/__schema3"
    },
    "max_nodes": {
      "$ref": "#/$defs/__schema4",
      "description": "Maximum accessibility nodes per capture; increase for large windows."
    },
    "pid": {
      "$ref": "#/$defs/__schema0"
    },
    "screenshot": {
      "$ref": "#/$defs/__schema2"
    },
    "window_id": {
      "$ref": "#/$defs/__schema1"
    }
  },
  "required": [
    "pid",
    "window_id"
  ],
  "type": "object"
}
```

</details>

**Output schema:** see [`tool-specs/observe_native_ui.json`](../tool-specs/observe_native_ui.json) (`outputSchema`).

---

## rizin_debug_command

<a id="rizindebugcommand"></a>

**Title:** Rizin Debug Command  
**Kind:** `native-provider` · **Requires session:** false · **analysisOperation:** rizin_debug_command  
**Providers:** rizin.debugger  
**Effects set (true flags):** accessesNetwork, changesUiState, executesForeignCode, NOT idempotent, launchesProcess, mayDiscardData, mutatesSession, mutatesTarget, writesFilesystem  
**MCP annotations:** `{"destructiveHint":true,"idempotentHint":false,"openWorldHint":true,"readOnlyHint":false}`

**Description (verbatim, as advertised to the agent):**

> Execute one unrestricted command in a persistent Rizin debugger session. Returns raw output inline with Evidence, including backend output interleaved before the completion marker. If the command exceeds the output or frame limit, `output_truncated` is true and `completion_status` is `unknown`; retained partial output is returned and the owned debugger session is stopped. Unsolicited frames already queued before the command make the session unavailable because correlation is ambiguous. Commands can access local files, shell, network, plugins, and target state; effects depend on the active backend and target. In a shared MCP server, this admitted command closes any active binary-analysis session; after its effects have settled, call open_binary before further analysis. Close an active Ghidra session explicitly first.

**Input schema (verbatim, JSON Schema 2020-12):**

<details><summary>inputSchema for rizin_debug_command</summary>

```json
{
  "$defs": {
    "__schema0": {
      "format": "uuid",
      "pattern": "^([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-8][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}|00000000-0000-0000-0000-000000000000|ffffffff-ffff-ffff-ffff-ffffffffffff)$",
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
      "command": "dr",
      "session_id": "00000000-0000-4000-8000-000000000001"
    }
  ],
  "properties": {
    "command": {
      "$ref": "#/$defs/__schema1"
    },
    "session_id": {
      "$ref": "#/$defs/__schema0"
    }
  },
  "required": [
    "session_id",
    "command"
  ],
  "type": "object"
}
```

</details>

**Output schema:** see [`tool-specs/rizin_debug_command.json`](../tool-specs/rizin_debug_command.json) (`outputSchema`).

---

## rizin_debug_session_status

<a id="rizindebugsessionstatus"></a>

**Title:** Rizin Debug Session Status  
**Kind:** `native-provider` · **Requires session:** false · **analysisOperation:** rizin_debug_session_status  
**Providers:** rizin.debugger  
**Effects set (true flags):** mutatesSession  
**MCP annotations:** `{"destructiveHint":false,"idempotentHint":true,"openWorldHint":false,"readOnlyHint":false}`

**Description (verbatim, as advertised to the agent):**

> Return observed lifecycle state and bounded recent NUL-framed output and process diagnostics for one Rizin debugger session; truncation fields report discarded data, and output_invalid_utf8 reports whether invalid UTF-8 has been observed in session frame bytes; recent output may contain replacement characters.

**Input schema (verbatim, JSON Schema 2020-12):**

<details><summary>inputSchema for rizin_debug_session_status</summary>

```json
{
  "$defs": {
    "__schema0": {
      "format": "uuid",
      "pattern": "^([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-8][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}|00000000-0000-0000-0000-000000000000|ffffffff-ffff-ffff-ffff-ffffffffffff)$",
      "type": "string"
    }
  },
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "additionalProperties": false,
  "examples": [
    {
      "session_id": "00000000-0000-4000-8000-000000000001"
    }
  ],
  "properties": {
    "session_id": {
      "$ref": "#/$defs/__schema0"
    }
  },
  "required": [
    "session_id"
  ],
  "type": "object"
}
```

</details>

**Output schema:** see [`tool-specs/rizin_debug_session_status.json`](../tool-specs/rizin_debug_session_status.json) (`outputSchema`).

---

## start_gdb_session

<a id="startgdbsession"></a>

**Title:** Start Gdb Session  
**Kind:** `native-provider` · **Requires session:** false · **analysisOperation:** start_gdb_session  
**Providers:** gnu.gdb  
**Effects set (true flags):** NOT idempotent, launchesProcess, mutatesSession  
**MCP annotations:** `{"destructiveHint":false,"idempotentHint":false,"openWorldHint":true,"readOnlyHint":false}`

**Description (verbatim, as advertised to the agent):**

> Start a BYO GDB process in MI3 mode when available, suppress startup files, and disable auto-loading. Persistent GDB sessions are available only on Linux, where REA can verify live inferior output descriptors through /proc before detaching; macOS descriptor verification is not implemented, and Windows Job Object cleanup can terminate debugger inferiors. Optionally set inferior_tty to a caller-selected terminal for future inferior runs; REA verifies the setting through GDB/MI before the session becomes ready. The selected terminal must remain available after GDB exits. A live inferior can be detached during close only while this durable output sink remains verified. The session persists in this REA MCP server process and receives an explicit session ID.

**Input schema (verbatim, JSON Schema 2020-12):**

<details><summary>inputSchema for start_gdb_session</summary>

```json
{
  "$defs": {
    "__schema0": {
      "$ref": "#/$defs/__schema1",
      "description": "Caller-selected terminal path for future inferior runs. GDB must report the exact configured path before the session is ready."
    },
    "__schema1": {
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
    "inferior_tty": {
      "$ref": "#/$defs/__schema0",
      "description": "Caller-selected terminal path for future inferior runs. GDB must report the exact configured path before the session is ready."
    }
  },
  "type": "object"
}
```

</details>

**Output schema:** see [`tool-specs/start_gdb_session.json`](../tool-specs/start_gdb_session.json) (`outputSchema`).

---

## start_rizin_debug_session

<a id="startrizindebugsession"></a>

**Title:** Start Rizin Debug Session  
**Kind:** `native-provider` · **Requires session:** false · **analysisOperation:** start_rizin_debug_session  
**Providers:** rizin.debugger  
**Effects set (true flags):** executesForeignCode, NOT idempotent, launchesProcess, mutatesSession, mutatesTarget  
**MCP annotations:** `{"destructiveHint":true,"idempotentHint":false,"openWorldHint":true,"readOnlyHint":false}`

**Description (verbatim, as advertised to the agent):**

> Start a persistent Rizin debugger session using `-N` to suppress user settings and scripts while retaining plugins, `-0` for NUL framing, and `-d` with an optional caller-selected IO debugger backend. Requires a caller-selected Linux TTY for inferior stdout and stderr; the target may write directly to that terminal while running and after detach. REA verifies both destinations and `dbg.exitkills=false` before detaching. Backend and target capabilities depend on the installed build. The session lives in this REA MCP process. Persistent sessions require Linux `/proc` descriptor readback. In a shared MCP server, starting this session retires any active binary-analysis session; after target effects have settled, call open_binary before further analysis. Close an active Ghidra session explicitly first.

**Input schema (verbatim, JSON Schema 2020-12):**

<details><summary>inputSchema for start_rizin_debug_session</summary>

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
      "minLength": 1,
      "type": "string"
    }
  },
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "additionalProperties": false,
  "examples": [
    {
      "inferior_tty": "/dev/pts/7",
      "path": "/tmp/program"
    }
  ],
  "properties": {
    "backend": {
      "$ref": "#/$defs/__schema2"
    },
    "inferior_tty": {
      "$ref": "#/$defs/__schema1"
    },
    "path": {
      "$ref": "#/$defs/__schema0",
      "description": "Local filesystem path used by this operation."
    }
  },
  "required": [
    "path",
    "inferior_tty"
  ],
  "type": "object"
}
```

</details>

**Output schema:** see [`tool-specs/start_rizin_debug_session.json`](../tool-specs/start_rizin_debug_session.json) (`outputSchema`).

---

