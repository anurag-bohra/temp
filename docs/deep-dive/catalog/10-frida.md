# Tool family: Frida instrumentation

Generated mechanically from `.cache/mcp-tool-catalog.json` (produced by `scripts/generate-mcp-tool-catalog.mjs`, which registers every tool through the MCP SDK and exports the advertised JSON Schema 2020-12 input/output schemas) and `docs/public/product-catalog.json` (family `frida`, surface `instrumentation-provider`, 9 tools). Input schemas below are **verbatim**. Output schemas are verbatim in `tool-specs/<tool>.json` (field `outputSchema`) because several exceed 100 KB; the complete per-tool spec (description, effects, annotations, inputSchema, outputSchema) is in that file.

| Tool | Kind | Session? | Providers advertising it | CLI command |
|---|---|---|---|---|
| [`close_frida_session`](#closefridasession) | native-provider | no | frida | — |
| [`frida_session_status`](#fridasessionstatus) | native-provider | no | frida | — |
| [`instrument_with_frida`](#instrumentwithfrida) | native-provider | no | frida | `rea instrument-with-frida` |
| [`list_frida_devices`](#listfridadevices) | native-provider | no | frida | `rea list-frida-devices` |
| [`list_frida_processes`](#listfridaprocesses) | native-provider | no | frida | `rea list-frida-processes` |
| [`load_frida_script`](#loadfridascript) | native-provider | no | frida | — |
| [`resume_frida_session`](#resumefridasession) | native-provider | no | frida | — |
| [`start_frida_session`](#startfridasession) | native-provider | no | frida | — |
| [`unload_frida_script`](#unloadfridascript) | native-provider | no | frida | — |

## close_frida_session

<a id="closefridasession"></a>

**Title:** Close Frida Session  
**Kind:** `native-provider` · **Requires session:** false · **analysisOperation:** close_frida_session  
**Providers:** frida  
**Effects set (true flags):** accessesNetwork, NOT idempotent, launchesProcess, mutatesSession, mutatesTarget  
**MCP annotations:** `{"destructiveHint":false,"idempotentHint":false,"openWorldHint":true,"readOnlyHint":false}`

**Description (verbatim, as advertised to the agent):**

> Unload session scripts and detach REA's Frida session. If a spawned process is still paused, resume it before detaching so it is not left suspended. REA never kills the target; its final state is reported as unknown.

**Input schema (verbatim, JSON Schema 2020-12):**

<details><summary>inputSchema for close_frida_session</summary>

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

**Output schema:** see [`tool-specs/close_frida_session.json`](../tool-specs/close_frida_session.json) (`outputSchema`).

---

## frida_session_status

<a id="fridasessionstatus"></a>

**Title:** Frida Session Status  
**Kind:** `native-provider` · **Requires session:** false · **analysisOperation:** frida_session_status  
**Providers:** frida  
**Effects set (true flags):** none (pure read)  
**MCP annotations:** `{"destructiveHint":false,"idempotentHint":true,"openWorldHint":false,"readOnlyHint":true}`

**Description (verbatim, as advertised to the agent):**

> Return observed Frida session state and queued script messages. Message history is bounded by the provider capture budget and reports truncation.

**Input schema (verbatim, JSON Schema 2020-12):**

<details><summary>inputSchema for frida_session_status</summary>

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

**Output schema:** see [`tool-specs/frida_session_status.json`](../tool-specs/frida_session_status.json) (`outputSchema`).

---

## instrument_with_frida

<a id="instrumentwithfrida"></a>

**Title:** Instrument With Frida  
**Kind:** `native-provider` · **Requires session:** false · **analysisOperation:** instrument_with_frida  
**Providers:** frida  
**Effects set (true flags):** accessesNetwork, executesForeignCode, NOT idempotent, launchesProcess, mutatesSession, mutatesTarget  
**MCP annotations:** `{"destructiveHint":true,"idempotentHint":false,"openWorldHint":true,"readOnlyHint":false}`

**Description (verbatim, as advertised to the agent):**

> Run one caller-authored Frida script against an explicitly selected process and detach when the observation window ends. The CLI and MCP share this ephemeral workflow; use MCP session operations for persistent sessions. Remote authentication is used only for this call and excluded from Evidence.

**Input schema (verbatim, JSON Schema 2020-12):**

<details><summary>inputSchema for instrument_with_frida</summary>

```json
{
  "$defs": {
    "__schema0": {
      "enum": [
        "attach",
        "spawn"
      ],
      "type": "string"
    },
    "__schema1": {
      "minLength": 1,
      "type": "string"
    },
    "__schema2": {
      "additionalProperties": false,
      "properties": {
        "address": {
          "maxLength": 2048,
          "minLength": 1,
          "type": "string"
        },
        "certificate": {
          "minLength": 1,
          "type": "string"
        },
        "keepalive_interval": {
          "description": "Remote keepalive interval in seconds",
          "exclusiveMinimum": 0,
          "maximum": 9007199254740991,
          "type": "integer"
        },
        "origin": {
          "minLength": 1,
          "type": "string"
        },
        "token": {
          "minLength": 1,
          "type": "string"
        }
      },
      "required": [
        "address"
      ],
      "type": "object"
    },
    "__schema3": {
      "exclusiveMinimum": 0,
      "maximum": 9007199254740991,
      "type": "integer"
    },
    "__schema4": {
      "minLength": 1,
      "type": "string"
    },
    "__schema5": {
      "items": {
        "type": "string"
      },
      "type": "array"
    },
    "__schema6": {
      "enum": [
        "inline",
        "file"
      ],
      "type": "string"
    },
    "__schema7": {
      "type": "string"
    },
    "__schema8": {
      "minLength": 1,
      "type": "string"
    },
    "__schema9": {
      "default": 1000,
      "maximum": 60000,
      "minimum": 0,
      "type": "integer"
    }
  },
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "additionalProperties": false,
  "examples": [
    {
      "device_id": "local",
      "duration_ms": 1000,
      "mode": "attach",
      "pid": 1234,
      "source": "send(Process.id);",
      "source_kind": "inline"
    }
  ],
  "properties": {
    "argv": {
      "$ref": "#/$defs/__schema5"
    },
    "device_id": {
      "$ref": "#/$defs/__schema1"
    },
    "duration_ms": {
      "$ref": "#/$defs/__schema9"
    },
    "mode": {
      "$ref": "#/$defs/__schema0",
      "description": "Operation mode that selects the requested behavior."
    },
    "path": {
      "$ref": "#/$defs/__schema8",
      "description": "Local filesystem path used by this operation."
    },
    "pid": {
      "$ref": "#/$defs/__schema3"
    },
    "program": {
      "$ref": "#/$defs/__schema4"
    },
    "remote": {
      "$ref": "#/$defs/__schema2"
    },
    "source": {
      "$ref": "#/$defs/__schema7"
    },
    "source_kind": {
      "$ref": "#/$defs/__schema6"
    }
  },
  "required": [
    "mode",
    "source_kind"
  ],
  "type": "object"
}
```

</details>

**Output schema:** see [`tool-specs/instrument_with_frida.json`](../tool-specs/instrument_with_frida.json) (`outputSchema`).

---

## list_frida_devices

<a id="listfridadevices"></a>

**Title:** List Frida Devices  
**Kind:** `native-provider` · **Requires session:** false · **analysisOperation:** list_frida_devices  
**Providers:** frida  
**Effects set (true flags):** accessesNetwork, launchesProcess  
**MCP annotations:** `{"destructiveHint":false,"idempotentHint":true,"openWorldHint":true,"readOnlyHint":false}`

**Description (verbatim, as advertised to the agent):**

> List Frida devices currently available to this host, optionally connecting to the caller-selected remote Frida endpoint. Remote authentication options are used for this call only and are never returned or recorded.

**Input schema (verbatim, JSON Schema 2020-12):**

<details><summary>inputSchema for list_frida_devices</summary>

```json
{
  "$defs": {
    "__schema0": {
      "additionalProperties": false,
      "properties": {
        "address": {
          "maxLength": 2048,
          "minLength": 1,
          "type": "string"
        },
        "certificate": {
          "minLength": 1,
          "type": "string"
        },
        "keepalive_interval": {
          "description": "Remote keepalive interval in seconds",
          "exclusiveMinimum": 0,
          "maximum": 9007199254740991,
          "type": "integer"
        },
        "origin": {
          "minLength": 1,
          "type": "string"
        },
        "token": {
          "minLength": 1,
          "type": "string"
        }
      },
      "required": [
        "address"
      ],
      "type": "object"
    }
  },
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "additionalProperties": false,
  "examples": [
    {}
  ],
  "properties": {
    "remote": {
      "$ref": "#/$defs/__schema0"
    }
  },
  "type": "object"
}
```

</details>

**Output schema:** see [`tool-specs/list_frida_devices.json`](../tool-specs/list_frida_devices.json) (`outputSchema`).

---

## list_frida_processes

<a id="listfridaprocesses"></a>

**Title:** List Frida Processes  
**Kind:** `native-provider` · **Requires session:** false · **analysisOperation:** list_frida_processes  
**Providers:** frida  
**Effects set (true flags):** accessesNetwork, launchesProcess  
**MCP annotations:** `{"destructiveHint":false,"idempotentHint":true,"openWorldHint":true,"readOnlyHint":false}`

**Description (verbatim, as advertised to the agent):**

> List processes observed on a selected Frida device or caller-supplied remote endpoint. A remote connection is closed after discovery; authentication values are never returned or recorded.

**Input schema (verbatim, JSON Schema 2020-12):**

<details><summary>inputSchema for list_frida_processes</summary>

```json
{
  "$defs": {
    "__schema0": {
      "minLength": 1,
      "type": "string"
    },
    "__schema1": {
      "additionalProperties": false,
      "properties": {
        "address": {
          "maxLength": 2048,
          "minLength": 1,
          "type": "string"
        },
        "certificate": {
          "minLength": 1,
          "type": "string"
        },
        "keepalive_interval": {
          "description": "Remote keepalive interval in seconds",
          "exclusiveMinimum": 0,
          "maximum": 9007199254740991,
          "type": "integer"
        },
        "origin": {
          "minLength": 1,
          "type": "string"
        },
        "token": {
          "minLength": 1,
          "type": "string"
        }
      },
      "required": [
        "address"
      ],
      "type": "object"
    }
  },
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "additionalProperties": false,
  "examples": [
    {
      "device_id": "local"
    }
  ],
  "properties": {
    "device_id": {
      "$ref": "#/$defs/__schema0"
    },
    "remote": {
      "$ref": "#/$defs/__schema1"
    }
  },
  "type": "object"
}
```

</details>

**Output schema:** see [`tool-specs/list_frida_processes.json`](../tool-specs/list_frida_processes.json) (`outputSchema`).

---

## load_frida_script

<a id="loadfridascript"></a>

**Title:** Load Frida Script  
**Kind:** `native-provider` · **Requires session:** false · **analysisOperation:** load_frida_script  
**Providers:** frida  
**Effects set (true flags):** accessesNetwork, executesForeignCode, NOT idempotent, launchesProcess, mutatesSession, mutatesTarget  
**MCP annotations:** `{"destructiveHint":true,"idempotentHint":false,"openWorldHint":true,"readOnlyHint":false}`

**Description (verbatim, as advertised to the agent):**

> Load caller-supplied JavaScript into a Frida session. Scripts can read or change target memory and behavior and can access the target process's capabilities. Messages and script errors are returned inline as Evidence; source content is not persisted.

**Input schema (verbatim, JSON Schema 2020-12):**

<details><summary>inputSchema for load_frida_script</summary>

```json
{
  "$defs": {
    "__schema0": {
      "format": "uuid",
      "pattern": "^([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-8][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}|00000000-0000-0000-0000-000000000000|ffffffff-ffff-ffff-ffff-ffffffffffff)$",
      "type": "string"
    },
    "__schema1": {
      "enum": [
        "inline",
        "file"
      ],
      "type": "string"
    },
    "__schema2": {
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
      "session_id": "00000000-0000-4000-8000-000000000001",
      "source": "send(Process.id);",
      "source_kind": "inline"
    }
  ],
  "properties": {
    "path": {
      "$ref": "#/$defs/__schema3",
      "description": "Local filesystem path used by this operation."
    },
    "session_id": {
      "$ref": "#/$defs/__schema0"
    },
    "source": {
      "$ref": "#/$defs/__schema2"
    },
    "source_kind": {
      "$ref": "#/$defs/__schema1"
    }
  },
  "required": [
    "session_id",
    "source_kind"
  ],
  "type": "object"
}
```

</details>

**Output schema:** see [`tool-specs/load_frida_script.json`](../tool-specs/load_frida_script.json) (`outputSchema`).

---

## resume_frida_session

<a id="resumefridasession"></a>

**Title:** Resume Frida Session  
**Kind:** `native-provider` · **Requires session:** false · **analysisOperation:** resume_frida_session  
**Providers:** frida  
**Effects set (true flags):** accessesNetwork, executesForeignCode, NOT idempotent, launchesProcess, mutatesSession, mutatesTarget  
**MCP annotations:** `{"destructiveHint":true,"idempotentHint":false,"openWorldHint":true,"readOnlyHint":false}`

**Description (verbatim, as advertised to the agent):**

> Resume the process created by a paused Frida spawn session. Attached processes are already running and cannot be resumed through this operation.

**Input schema (verbatim, JSON Schema 2020-12):**

<details><summary>inputSchema for resume_frida_session</summary>

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

**Output schema:** see [`tool-specs/resume_frida_session.json`](../tool-specs/resume_frida_session.json) (`outputSchema`).

---

## start_frida_session

<a id="startfridasession"></a>

**Title:** Start Frida Session  
**Kind:** `native-provider` · **Requires session:** false · **analysisOperation:** start_frida_session  
**Providers:** frida  
**Effects set (true flags):** accessesNetwork, NOT idempotent, launchesProcess, mutatesSession, mutatesTarget  
**MCP annotations:** `{"destructiveHint":false,"idempotentHint":false,"openWorldHint":true,"readOnlyHint":false}`

**Description (verbatim, as advertised to the agent):**

> Attach Frida to one selected process or spawn one selected target. Spawned targets remain paused until resume_frida_session, allowing scripts to load before execution. Closing a session detaches instrumentation; it does not kill the target.

**Input schema (verbatim, JSON Schema 2020-12):**

<details><summary>inputSchema for start_frida_session</summary>

```json
{
  "$defs": {
    "__schema0": {
      "enum": [
        "attach",
        "spawn"
      ],
      "type": "string"
    },
    "__schema1": {
      "minLength": 1,
      "type": "string"
    },
    "__schema2": {
      "additionalProperties": false,
      "properties": {
        "address": {
          "maxLength": 2048,
          "minLength": 1,
          "type": "string"
        },
        "certificate": {
          "minLength": 1,
          "type": "string"
        },
        "keepalive_interval": {
          "description": "Remote keepalive interval in seconds",
          "exclusiveMinimum": 0,
          "maximum": 9007199254740991,
          "type": "integer"
        },
        "origin": {
          "minLength": 1,
          "type": "string"
        },
        "token": {
          "minLength": 1,
          "type": "string"
        }
      },
      "required": [
        "address"
      ],
      "type": "object"
    },
    "__schema3": {
      "exclusiveMinimum": 0,
      "maximum": 9007199254740991,
      "type": "integer"
    },
    "__schema4": {
      "minLength": 1,
      "type": "string"
    },
    "__schema5": {
      "items": {
        "type": "string"
      },
      "type": "array"
    }
  },
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "additionalProperties": false,
  "examples": [
    {
      "device_id": "local",
      "mode": "attach",
      "pid": 1234
    }
  ],
  "properties": {
    "argv": {
      "$ref": "#/$defs/__schema5"
    },
    "device_id": {
      "$ref": "#/$defs/__schema1"
    },
    "mode": {
      "$ref": "#/$defs/__schema0",
      "description": "Operation mode that selects the requested behavior."
    },
    "pid": {
      "$ref": "#/$defs/__schema3"
    },
    "program": {
      "$ref": "#/$defs/__schema4"
    },
    "remote": {
      "$ref": "#/$defs/__schema2"
    }
  },
  "required": [
    "mode"
  ],
  "type": "object"
}
```

</details>

**Output schema:** see [`tool-specs/start_frida_session.json`](../tool-specs/start_frida_session.json) (`outputSchema`).

---

## unload_frida_script

<a id="unloadfridascript"></a>

**Title:** Unload Frida Script  
**Kind:** `native-provider` · **Requires session:** false · **analysisOperation:** unload_frida_script  
**Providers:** frida  
**Effects set (true flags):** accessesNetwork, NOT idempotent, launchesProcess, mutatesSession, mutatesTarget  
**MCP annotations:** `{"destructiveHint":false,"idempotentHint":false,"openWorldHint":true,"readOnlyHint":false}`

**Description (verbatim, as advertised to the agent):**

> Unload one caller-selected Frida script from a live session. This removes that script's instrumentation from the target.

**Input schema (verbatim, JSON Schema 2020-12):**

<details><summary>inputSchema for unload_frida_script</summary>

```json
{
  "$defs": {
    "__schema0": {
      "format": "uuid",
      "pattern": "^([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-8][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}|00000000-0000-0000-0000-000000000000|ffffffff-ffff-ffff-ffff-ffffffffffff)$",
      "type": "string"
    },
    "__schema1": {
      "format": "uuid",
      "pattern": "^([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-8][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}|00000000-0000-0000-0000-000000000000|ffffffff-ffff-ffff-ffff-ffffffffffff)$",
      "type": "string"
    }
  },
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "additionalProperties": false,
  "examples": [
    {
      "script_id": "00000000-0000-4000-8000-000000000002",
      "session_id": "00000000-0000-4000-8000-000000000001"
    }
  ],
  "properties": {
    "script_id": {
      "$ref": "#/$defs/__schema1"
    },
    "session_id": {
      "$ref": "#/$defs/__schema0"
    }
  },
  "required": [
    "session_id",
    "script_id"
  ],
  "type": "object"
}
```

</details>

**Output schema:** see [`tool-specs/unload_frida_script.json`](../tool-specs/unload_frida_script.json) (`outputSchema`).

---

