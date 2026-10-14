# Tool family: ADB device analysis & mutation

Generated mechanically from `.cache/mcp-tool-catalog.json` (produced by `scripts/generate-mcp-tool-catalog.mjs`, which registers every tool through the MCP SDK and exports the advertised JSON Schema 2020-12 input/output schemas) and `docs/public/product-catalog.json` (family `adb`, surface `adb-provider`, 24 tools). Input schemas below are **verbatim**. Output schemas are verbatim in `tool-specs/<tool>.json` (field `outputSchema`) because several exceed 100 KB; the complete per-tool spec (description, effects, annotations, inputSchema, outputSchema) is in that file.

| Tool | Kind | Session? | Providers advertising it | CLI command |
|---|---|---|---|---|
| [`capture_adb_screen`](#captureadbscreen) | adb-provider | no | adb | `rea capture-adb-screen` |
| [`collect_adb_bugreport`](#collectadbbugreport) | adb-provider | no | adb | `rea collect-adb-bugreport` |
| [`inspect_adb_client`](#inspectadbclient) | adb-provider | no | adb | `rea inspect-adb-client` |
| [`inspect_adb_device`](#inspectadbdevice) | adb-provider | no | adb | `rea inspect-adb-device` |
| [`inspect_adb_display`](#inspectadbdisplay) | adb-provider | no | adb | `rea inspect-adb-display` |
| [`inspect_adb_package`](#inspectadbpackage) | adb-provider | no | adb | `rea inspect-adb-package` |
| [`inspect_adb_window`](#inspectadbwindow) | adb-provider | no | adb | `rea inspect-adb-window` |
| [`install_adb_package`](#installadbpackage) | adb-provider | no | adb | `rea install-adb-package` |
| [`list_adb_devices`](#listadbdevices) | adb-provider | no | adb | `rea list-adb-devices` |
| [`list_adb_directory`](#listadbdirectory) | adb-provider | no | adb | `rea list-adb-directory` |
| [`list_adb_features`](#listadbfeatures) | adb-provider | no | adb | `rea list-adb-features` |
| [`list_adb_packages`](#listadbpackages) | adb-provider | no | adb | `rea list-adb-packages` |
| [`list_adb_processes`](#listadbprocesses) | adb-provider | no | adb | `rea list-adb-processes` |
| [`list_adb_services`](#listadbservices) | adb-provider | no | adb | `rea list-adb-services` |
| [`pull_adb_file`](#pulladbfile) | adb-provider | no | adb | `rea pull-adb-file` |
| [`pull_adb_package`](#pulladbpackage) | adb-provider | no | adb | `rea pull-adb-package` |
| [`push_adb_file`](#pushadbfile) | adb-provider | no | adb | `rea push-adb-file` |
| [`read_adb_logcat`](#readadblogcat) | adb-provider | no | adb | `rea read-adb-logcat` |
| [`read_adb_setting`](#readadbsetting) | adb-provider | no | adb | `rea read-adb-setting` |
| [`resolve_adb_packages`](#resolveadbpackages) | adb-provider | no | adb | `rea resolve-adb-packages` |
| [`start_adb_activity`](#startadbactivity) | adb-provider | no | adb | `rea start-adb-activity` |
| [`start_adb_app`](#startadbapp) | adb-provider | no | adb | `rea start-adb-app` |
| [`stop_adb_app`](#stopadbapp) | adb-provider | no | adb | `rea stop-adb-app` |
| [`uninstall_adb_package`](#uninstalladbpackage) | adb-provider | no | adb | `rea uninstall-adb-package` |

## capture_adb_screen

<a id="captureadbscreen"></a>

**Title:** Capture Adb Screen  
**Kind:** `adb-provider` · **Requires session:** false · **analysisOperation:** null  
**Providers:** adb  
**Effects set (true flags):** accessesNetwork, NOT idempotent, launchesProcess, mutatesSession, writesFilesystem  
**MCP annotations:** `{"destructiveHint":false,"idempotentHint":false,"openWorldHint":true,"readOnlyHint":false}`

**Description (verbatim, as advertised to the agent):**

> Capture one frame of the device screen as a PNG (`screencap -p` through exec-out, no device-side file) into a caller-selected output directory, digesting it and reporting its dimensions. No recording or interaction.

**Input schema (verbatim, JSON Schema 2020-12):**

<details><summary>inputSchema for capture_adb_screen</summary>

```json
{
  "$defs": {
    "__schema0": {
      "description": "Device serial exactly as `adb devices` reports it",
      "maxLength": 256,
      "minLength": 1,
      "pattern": "^[^\\x00\\s\"']+$",
      "type": "string"
    },
    "__schema1": {
      "description": "Local directory for the captured PNG; must not already contain it",
      "minLength": 1,
      "pattern": "^[^\\x00]*$",
      "type": "string"
    }
  },
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "additionalProperties": false,
  "examples": [
    {
      "output_directory": "/tmp/rea-captures",
      "serial": "emulator-5554"
    }
  ],
  "properties": {
    "output_directory": {
      "$ref": "#/$defs/__schema1",
      "description": "Local directory for the captured PNG; must not already contain it"
    },
    "serial": {
      "$ref": "#/$defs/__schema0",
      "description": "Device serial exactly as `adb devices` reports it"
    }
  },
  "required": [
    "serial",
    "output_directory"
  ],
  "type": "object"
}
```

</details>

**Output schema:** see [`tool-specs/capture_adb_screen.json`](../tool-specs/capture_adb_screen.json) (`outputSchema`).

---

## collect_adb_bugreport

<a id="collectadbbugreport"></a>

**Title:** Collect Adb Bugreport  
**Kind:** `adb-provider` · **Requires session:** false · **analysisOperation:** null  
**Providers:** adb  
**Effects set (true flags):** accessesNetwork, NOT idempotent, launchesProcess, mutatesSession, writesFilesystem  
**MCP annotations:** `{"destructiveHint":false,"idempotentHint":false,"openWorldHint":true,"readOnlyHint":false}`

**Description (verbatim, as advertised to the agent):**

> Collect one device-generated bugreport archive (`adb bugreport`) into a caller-selected output directory, digesting the zip. The archive contains the device's own dumpstate, dumpsys, and logcat report; collection can take minutes. Read-only with respect to configuration.

**Input schema (verbatim, JSON Schema 2020-12):**

<details><summary>inputSchema for collect_adb_bugreport</summary>

```json
{
  "$defs": {
    "__schema0": {
      "description": "Device serial exactly as `adb devices` reports it",
      "maxLength": 256,
      "minLength": 1,
      "pattern": "^[^\\x00\\s\"']+$",
      "type": "string"
    },
    "__schema1": {
      "description": "Local directory for the bugreport archive; REA writes exactly one new zip into it",
      "minLength": 1,
      "pattern": "^[^\\x00]*$",
      "type": "string"
    }
  },
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "additionalProperties": false,
  "examples": [
    {
      "output_directory": "/tmp/rea-bugreports",
      "serial": "emulator-5554"
    }
  ],
  "properties": {
    "output_directory": {
      "$ref": "#/$defs/__schema1",
      "description": "Local directory for the bugreport archive; REA writes exactly one new zip into it"
    },
    "serial": {
      "$ref": "#/$defs/__schema0",
      "description": "Device serial exactly as `adb devices` reports it"
    }
  },
  "required": [
    "serial",
    "output_directory"
  ],
  "type": "object"
}
```

</details>

**Output schema:** see [`tool-specs/collect_adb_bugreport.json`](../tool-specs/collect_adb_bugreport.json) (`outputSchema`).

---

## inspect_adb_client

<a id="inspectadbclient"></a>

**Title:** Inspect Adb Client  
**Kind:** `adb-provider` · **Requires session:** false · **analysisOperation:** null  
**Providers:** adb  
**Effects set (true flags):** launchesProcess, mutatesSession  
**MCP annotations:** `{"destructiveHint":false,"idempotentHint":true,"openWorldHint":true,"readOnlyHint":false}`

**Description (verbatim, as advertised to the agent):**

> Inspect the caller-selected adb client: resolved binary, version, and install path. Never contacts devices and never starts the adb server. REA never installs platform tools; select a binary with REA_ADB_PATH (absolute) or adb on PATH.

**Input schema (verbatim, JSON Schema 2020-12):**

<details><summary>inputSchema for inspect_adb_client</summary>

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

**Output schema:** see [`tool-specs/inspect_adb_client.json`](../tool-specs/inspect_adb_client.json) (`outputSchema`).

---

## inspect_adb_device

<a id="inspectadbdevice"></a>

**Title:** Inspect Adb Device  
**Kind:** `adb-provider` · **Requires session:** false · **analysisOperation:** null  
**Providers:** adb  
**Effects set (true flags):** accessesNetwork, launchesProcess, mutatesSession  
**MCP annotations:** `{"destructiveHint":false,"idempotentHint":true,"openWorldHint":true,"readOnlyHint":false}`

**Description (verbatim, as advertised to the agent):**

> Inspect one device's build identity through a fixed `getprop` whitelist: Android and SDK versions, security patch, fingerprint, product identity, CPU ABIs, and debuggable flag, plus the observed emulator indicator ro.kernel.qemu. Read-only with respect to the device.

**Input schema (verbatim, JSON Schema 2020-12):**

<details><summary>inputSchema for inspect_adb_device</summary>

```json
{
  "$defs": {
    "__schema0": {
      "description": "Device serial exactly as `adb devices` reports it",
      "maxLength": 256,
      "minLength": 1,
      "pattern": "^[^\\x00\\s\"']+$",
      "type": "string"
    }
  },
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "additionalProperties": false,
  "examples": [
    {
      "serial": "emulator-5554"
    }
  ],
  "properties": {
    "serial": {
      "$ref": "#/$defs/__schema0",
      "description": "Device serial exactly as `adb devices` reports it"
    }
  },
  "required": [
    "serial"
  ],
  "type": "object"
}
```

</details>

**Output schema:** see [`tool-specs/inspect_adb_device.json`](../tool-specs/inspect_adb_device.json) (`outputSchema`).

---

## inspect_adb_display

<a id="inspectadbdisplay"></a>

**Title:** Inspect Adb Display  
**Kind:** `adb-provider` · **Requires session:** false · **analysisOperation:** null  
**Providers:** adb  
**Effects set (true flags):** accessesNetwork, launchesProcess, mutatesSession  
**MCP annotations:** `{"destructiveHint":false,"idempotentHint":true,"openWorldHint":true,"readOnlyHint":false}`

**Description (verbatim, as advertised to the agent):**

> Report the display's physical and any overridden size (`wm size`) and density (`wm density`) as the device declares them. Read-only; setting values is not exposed.

**Input schema (verbatim, JSON Schema 2020-12):**

<details><summary>inputSchema for inspect_adb_display</summary>

```json
{
  "$defs": {
    "__schema0": {
      "description": "Device serial exactly as `adb devices` reports it",
      "maxLength": 256,
      "minLength": 1,
      "pattern": "^[^\\x00\\s\"']+$",
      "type": "string"
    }
  },
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "additionalProperties": false,
  "examples": [
    {
      "serial": "emulator-5554"
    }
  ],
  "properties": {
    "serial": {
      "$ref": "#/$defs/__schema0",
      "description": "Device serial exactly as `adb devices` reports it"
    }
  },
  "required": [
    "serial"
  ],
  "type": "object"
}
```

</details>

**Output schema:** see [`tool-specs/inspect_adb_display.json`](../tool-specs/inspect_adb_display.json) (`outputSchema`).

---

## inspect_adb_package

<a id="inspectadbpackage"></a>

**Title:** Inspect Adb Package  
**Kind:** `adb-provider` · **Requires session:** false · **analysisOperation:** null  
**Providers:** adb  
**Effects set (true flags):** accessesNetwork, launchesProcess, mutatesSession  
**MCP annotations:** `{"destructiveHint":false,"idempotentHint":true,"openWorldHint":true,"readOnlyHint":false}`

**Description (verbatim, as advertised to the agent):**

> Inspect one installed package through `dumpsys package`: version name/code, install and update times, installer, user id, flags, and the requested-permission count. A fixed projection of version-dependent output; unknown sections are ignored rather than guessed. Read-only.

**Input schema (verbatim, JSON Schema 2020-12):**

<details><summary>inputSchema for inspect_adb_package</summary>

```json
{
  "$defs": {
    "__schema0": {
      "description": "Device serial exactly as `adb devices` reports it",
      "maxLength": 256,
      "minLength": 1,
      "pattern": "^[^\\x00\\s\"']+$",
      "type": "string"
    },
    "__schema1": {
      "description": "Installed package to inspect",
      "maxLength": 256,
      "minLength": 1,
      "pattern": "^[A-Za-z][A-Za-z0-9_]*(\\.[A-Za-z][A-Za-z0-9_]*)*$",
      "type": "string"
    }
  },
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "additionalProperties": false,
  "examples": [
    {
      "package": "com.example.app",
      "serial": "emulator-5554"
    }
  ],
  "properties": {
    "package": {
      "$ref": "#/$defs/__schema1",
      "description": "Installed package to inspect"
    },
    "serial": {
      "$ref": "#/$defs/__schema0",
      "description": "Device serial exactly as `adb devices` reports it"
    }
  },
  "required": [
    "serial",
    "package"
  ],
  "type": "object"
}
```

</details>

**Output schema:** see [`tool-specs/inspect_adb_package.json`](../tool-specs/inspect_adb_package.json) (`outputSchema`).

---

## inspect_adb_window

<a id="inspectadbwindow"></a>

**Title:** Inspect Adb Window  
**Kind:** `adb-provider` · **Requires session:** false · **analysisOperation:** null  
**Providers:** adb  
**Effects set (true flags):** accessesNetwork, launchesProcess, mutatesSession  
**MCP annotations:** `{"destructiveHint":false,"idempotentHint":true,"openWorldHint":true,"readOnlyHint":false}`

**Description (verbatim, as advertised to the agent):**

> Report the window manager's current focus declarations (mCurrentFocus and mFocusedApp from `dumpsys window windows`, or from `dumpsys window displays` when the windows section declares neither, as on Android 16) — what is on screen at read time without any interaction. Read-only.

**Input schema (verbatim, JSON Schema 2020-12):**

<details><summary>inputSchema for inspect_adb_window</summary>

```json
{
  "$defs": {
    "__schema0": {
      "description": "Device serial exactly as `adb devices` reports it",
      "maxLength": 256,
      "minLength": 1,
      "pattern": "^[^\\x00\\s\"']+$",
      "type": "string"
    }
  },
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "additionalProperties": false,
  "examples": [
    {
      "serial": "emulator-5554"
    }
  ],
  "properties": {
    "serial": {
      "$ref": "#/$defs/__schema0",
      "description": "Device serial exactly as `adb devices` reports it"
    }
  },
  "required": [
    "serial"
  ],
  "type": "object"
}
```

</details>

**Output schema:** see [`tool-specs/inspect_adb_window.json`](../tool-specs/inspect_adb_window.json) (`outputSchema`).

---

## install_adb_package

<a id="installadbpackage"></a>

**Title:** Install Adb Package  
**Kind:** `adb-provider` · **Requires session:** false · **analysisOperation:** null  
**Providers:** adb  
**Effects set (true flags):** accessesNetwork, NOT idempotent, launchesProcess, mutatesDevice, mutatesSession, mutatesTarget  
**MCP annotations:** `{"destructiveHint":true,"idempotentHint":false,"openWorldHint":true,"readOnlyHint":false}`

**Description (verbatim, as advertised to the agent):**

> Install one local APK on the device (`adb install [-r]`), recording the APK's host digest and byte size. A device-mutating tool: `replace_requested` records whether `-r` was selected; `replaced` is null because install success does not establish prior package state. The device's own Success/Failure verdict is preserved with its reason.

**Input schema (verbatim, JSON Schema 2020-12):**

<details><summary>inputSchema for install_adb_package</summary>

```json
{
  "$defs": {
    "__schema0": {
      "description": "Device serial exactly as `adb devices` reports it",
      "maxLength": 256,
      "minLength": 1,
      "pattern": "^[^\\x00\\s\"']+$",
      "type": "string"
    },
    "__schema1": {
      "description": "Existing local APK file to install",
      "minLength": 1,
      "pattern": "^[^\\x00]*$",
      "type": "string"
    },
    "__schema2": {
      "$ref": "#/$defs/__schema3",
      "default": false,
      "description": "Request replacement mode and keep existing app data if present (adb install -r); does not establish whether the app was already installed"
    },
    "__schema3": {
      "type": "boolean"
    }
  },
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "additionalProperties": false,
  "examples": [
    {
      "apk_path": "/tmp/app.apk",
      "serial": "emulator-5554"
    },
    {
      "apk_path": "/tmp/app.apk",
      "replace": true,
      "serial": "emulator-5554"
    }
  ],
  "properties": {
    "apk_path": {
      "$ref": "#/$defs/__schema1",
      "description": "Existing local APK file to install"
    },
    "replace": {
      "$ref": "#/$defs/__schema2",
      "description": "Request replacement mode and keep existing app data if present (adb install -r); does not establish whether the app was already installed"
    },
    "serial": {
      "$ref": "#/$defs/__schema0",
      "description": "Device serial exactly as `adb devices` reports it"
    }
  },
  "required": [
    "serial",
    "apk_path"
  ],
  "type": "object"
}
```

</details>

**Output schema:** see [`tool-specs/install_adb_package.json`](../tool-specs/install_adb_package.json) (`outputSchema`).

---

## list_adb_devices

<a id="listadbdevices"></a>

**Title:** List Adb Devices  
**Kind:** `adb-provider` · **Requires session:** false · **analysisOperation:** null  
**Providers:** adb  
**Effects set (true flags):** accessesNetwork, launchesProcess, mutatesSession  
**MCP annotations:** `{"destructiveHint":false,"idempotentHint":true,"openWorldHint":true,"readOnlyHint":false}`

**Description (verbatim, as advertised to the agent):**

> List attached devices exactly as `adb devices -l` reports them: serial, state, transport, model metadata, and an inferred emulator/physical kind with its evidence basis. Emulators and USB or network devices appear alike; REA neither starts nor manages them. May start the local adb server on first use.

**Input schema (verbatim, JSON Schema 2020-12):**

<details><summary>inputSchema for list_adb_devices</summary>

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

**Output schema:** see [`tool-specs/list_adb_devices.json`](../tool-specs/list_adb_devices.json) (`outputSchema`).

---

## list_adb_directory

<a id="listadbdirectory"></a>

**Title:** List Adb Directory  
**Kind:** `adb-provider` · **Requires session:** false · **analysisOperation:** null  
**Providers:** adb  
**Effects set (true flags):** accessesNetwork, launchesProcess, mutatesSession  
**MCP annotations:** `{"destructiveHint":false,"idempotentHint":true,"openWorldHint":true,"readOnlyHint":false}`

**Description (verbatim, as advertised to the agent):**

> List the immediate children of one absolute device directory, including hidden entries: names, kinds, permissions, owner, group, sizes, dates, and symlink targets. Names and targets preserve embedded newlines. Recognizes the standard errors for absent paths and denied reads. Read-only.

**Input schema (verbatim, JSON Schema 2020-12):**

<details><summary>inputSchema for list_adb_directory</summary>

```json
{
  "$defs": {
    "__schema0": {
      "description": "Device serial exactly as `adb devices` reports it",
      "maxLength": 256,
      "minLength": 1,
      "pattern": "^[^\\x00\\s\"']+$",
      "type": "string"
    },
    "__schema1": {
      "description": "Absolute device directory path to list, including hidden children",
      "minLength": 1,
      "pattern": "^\\/[^\\x00]*$",
      "type": "string"
    }
  },
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "additionalProperties": false,
  "examples": [
    {
      "device_path": "/data/data/com.example.app",
      "serial": "emulator-5554"
    }
  ],
  "properties": {
    "device_path": {
      "$ref": "#/$defs/__schema1",
      "description": "Absolute device directory path to list, including hidden children"
    },
    "serial": {
      "$ref": "#/$defs/__schema0",
      "description": "Device serial exactly as `adb devices` reports it"
    }
  },
  "required": [
    "serial",
    "device_path"
  ],
  "type": "object"
}
```

</details>

**Output schema:** see [`tool-specs/list_adb_directory.json`](../tool-specs/list_adb_directory.json) (`outputSchema`).

---

## list_adb_features

<a id="listadbfeatures"></a>

**Title:** List Adb Features  
**Kind:** `adb-provider` · **Requires session:** false · **analysisOperation:** null  
**Providers:** adb  
**Effects set (true flags):** accessesNetwork, launchesProcess, mutatesSession  
**MCP annotations:** `{"destructiveHint":false,"idempotentHint":true,"openWorldHint":true,"readOnlyHint":false}`

**Description (verbatim, as advertised to the agent):**

> List the device's declared hardware and software features (`pm list features`) for device fingerprinting. Read-only.

**Input schema (verbatim, JSON Schema 2020-12):**

<details><summary>inputSchema for list_adb_features</summary>

```json
{
  "$defs": {
    "__schema0": {
      "description": "Device serial exactly as `adb devices` reports it",
      "maxLength": 256,
      "minLength": 1,
      "pattern": "^[^\\x00\\s\"']+$",
      "type": "string"
    }
  },
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "additionalProperties": false,
  "examples": [
    {
      "serial": "emulator-5554"
    }
  ],
  "properties": {
    "serial": {
      "$ref": "#/$defs/__schema0",
      "description": "Device serial exactly as `adb devices` reports it"
    }
  },
  "required": [
    "serial"
  ],
  "type": "object"
}
```

</details>

**Output schema:** see [`tool-specs/list_adb_features.json`](../tool-specs/list_adb_features.json) (`outputSchema`).

---

## list_adb_packages

<a id="listadbpackages"></a>

**Title:** List Adb Packages  
**Kind:** `adb-provider` · **Requires session:** false · **analysisOperation:** null  
**Providers:** adb  
**Effects set (true flags):** accessesNetwork, launchesProcess, mutatesSession  
**MCP annotations:** `{"destructiveHint":false,"idempotentHint":true,"openWorldHint":true,"readOnlyHint":false}`

**Description (verbatim, as advertised to the agent):**

> List installed packages on one device with each base APK's device path, optionally scoped to third-party or system packages. Paths are device filesystem paths, not host-local. Read-only.

**Input schema (verbatim, JSON Schema 2020-12):**

<details><summary>inputSchema for list_adb_packages</summary>

```json
{
  "$defs": {
    "__schema0": {
      "description": "Device serial exactly as `adb devices` reports it",
      "maxLength": 256,
      "minLength": 1,
      "pattern": "^[^\\x00\\s\"']+$",
      "type": "string"
    },
    "__schema1": {
      "$ref": "#/$defs/__schema2",
      "default": "all",
      "description": "Package scope: all packages, third-party only (-3), or system only (-s)"
    },
    "__schema2": {
      "enum": [
        "all",
        "third_party",
        "system"
      ],
      "type": "string"
    }
  },
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "additionalProperties": false,
  "examples": [
    {
      "scope": "third_party",
      "serial": "emulator-5554"
    }
  ],
  "properties": {
    "scope": {
      "$ref": "#/$defs/__schema1",
      "description": "Package scope: all packages, third-party only (-3), or system only (-s)"
    },
    "serial": {
      "$ref": "#/$defs/__schema0",
      "description": "Device serial exactly as `adb devices` reports it"
    }
  },
  "required": [
    "serial"
  ],
  "type": "object"
}
```

</details>

**Output schema:** see [`tool-specs/list_adb_packages.json`](../tool-specs/list_adb_packages.json) (`outputSchema`).

---

## list_adb_processes

<a id="listadbprocesses"></a>

**Title:** List Adb Processes  
**Kind:** `adb-provider` · **Requires session:** false · **analysisOperation:** null  
**Providers:** adb  
**Effects set (true flags):** accessesNetwork, launchesProcess, mutatesSession  
**MCP annotations:** `{"destructiveHint":false,"idempotentHint":true,"openWorldHint":true,"readOnlyHint":false}`

**Description (verbatim, as advertised to the agent):**

> List running processes exactly as `ps -A` reports them: user, pid, ppid, rss, state, and name. Useful for pairing with instrumentation lanes. Read-only.

**Input schema (verbatim, JSON Schema 2020-12):**

<details><summary>inputSchema for list_adb_processes</summary>

```json
{
  "$defs": {
    "__schema0": {
      "description": "Device serial exactly as `adb devices` reports it",
      "maxLength": 256,
      "minLength": 1,
      "pattern": "^[^\\x00\\s\"']+$",
      "type": "string"
    }
  },
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "additionalProperties": false,
  "examples": [
    {
      "serial": "emulator-5554"
    }
  ],
  "properties": {
    "serial": {
      "$ref": "#/$defs/__schema0",
      "description": "Device serial exactly as `adb devices` reports it"
    }
  },
  "required": [
    "serial"
  ],
  "type": "object"
}
```

</details>

**Output schema:** see [`tool-specs/list_adb_processes.json`](../tool-specs/list_adb_processes.json) (`outputSchema`).

---

## list_adb_services

<a id="listadbservices"></a>

**Title:** List Adb Services  
**Kind:** `adb-provider` · **Requires session:** false · **analysisOperation:** null  
**Providers:** adb  
**Effects set (true flags):** accessesNetwork, launchesProcess, mutatesSession  
**MCP annotations:** `{"destructiveHint":false,"idempotentHint":true,"openWorldHint":true,"readOnlyHint":false}`

**Description (verbatim, as advertised to the agent):**

> List the device's binder services with their interfaces (`service list`). Read-only.

**Input schema (verbatim, JSON Schema 2020-12):**

<details><summary>inputSchema for list_adb_services</summary>

```json
{
  "$defs": {
    "__schema0": {
      "description": "Device serial exactly as `adb devices` reports it",
      "maxLength": 256,
      "minLength": 1,
      "pattern": "^[^\\x00\\s\"']+$",
      "type": "string"
    }
  },
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "additionalProperties": false,
  "examples": [
    {
      "serial": "emulator-5554"
    }
  ],
  "properties": {
    "serial": {
      "$ref": "#/$defs/__schema0",
      "description": "Device serial exactly as `adb devices` reports it"
    }
  },
  "required": [
    "serial"
  ],
  "type": "object"
}
```

</details>

**Output schema:** see [`tool-specs/list_adb_services.json`](../tool-specs/list_adb_services.json) (`outputSchema`).

---

## pull_adb_file

<a id="pulladbfile"></a>

**Title:** Pull Adb File  
**Kind:** `adb-provider` · **Requires session:** false · **analysisOperation:** null  
**Providers:** adb  
**Effects set (true flags):** accessesNetwork, NOT idempotent, launchesProcess, mutatesSession, writesFilesystem  
**MCP annotations:** `{"destructiveHint":false,"idempotentHint":false,"openWorldHint":true,"readOnlyHint":false}`

**Description (verbatim, as advertised to the agent):**

> Pull one absolute device path (a database, shared-preferences XML, or any readable file) into a caller-selected output directory, digesting it with SHA-256. The local copy must not already exist. Read-only with respect to the device.

**Input schema (verbatim, JSON Schema 2020-12):**

<details><summary>inputSchema for pull_adb_file</summary>

```json
{
  "$defs": {
    "__schema0": {
      "description": "Device serial exactly as `adb devices` reports it",
      "maxLength": 256,
      "minLength": 1,
      "pattern": "^[^\\x00\\s\"']+$",
      "type": "string"
    },
    "__schema1": {
      "description": "Absolute device filesystem path to pull",
      "minLength": 1,
      "pattern": "^\\/[^\\x00]*$",
      "type": "string"
    },
    "__schema2": {
      "description": "Local directory for the pulled file; must not already contain the file",
      "minLength": 1,
      "pattern": "^[^\\x00]*$",
      "type": "string"
    }
  },
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "additionalProperties": false,
  "examples": [
    {
      "device_path": "/data/data/com.example.app/databases/app.db",
      "output_directory": "/tmp/rea-pulls",
      "serial": "emulator-5554"
    }
  ],
  "properties": {
    "device_path": {
      "$ref": "#/$defs/__schema1",
      "description": "Absolute device filesystem path to pull"
    },
    "output_directory": {
      "$ref": "#/$defs/__schema2",
      "description": "Local directory for the pulled file; must not already contain the file"
    },
    "serial": {
      "$ref": "#/$defs/__schema0",
      "description": "Device serial exactly as `adb devices` reports it"
    }
  },
  "required": [
    "serial",
    "device_path",
    "output_directory"
  ],
  "type": "object"
}
```

</details>

**Output schema:** see [`tool-specs/pull_adb_file.json`](../tool-specs/pull_adb_file.json) (`outputSchema`).

---

## pull_adb_package

<a id="pulladbpackage"></a>

**Title:** Pull Adb Package  
**Kind:** `adb-provider` · **Requires session:** false · **analysisOperation:** null  
**Providers:** adb  
**Effects set (true flags):** accessesNetwork, NOT idempotent, launchesProcess, mutatesSession, writesFilesystem  
**MCP annotations:** `{"destructiveHint":false,"idempotentHint":false,"openWorldHint":true,"readOnlyHint":false}`

**Description (verbatim, as advertised to the agent):**

> Pull one installed package's complete APK set (base plus every split, as `pm path` reports) from the device into a caller-selected output directory, creating a package-named subdirectory that must not already exist. Every pulled file is digested with SHA-256; partial pulls keep successful artifacts and per-file failure reasons. The device keeps the originals.

**Input schema (verbatim, JSON Schema 2020-12):**

<details><summary>inputSchema for pull_adb_package</summary>

```json
{
  "$defs": {
    "__schema0": {
      "description": "Device serial exactly as `adb devices` reports it",
      "maxLength": 256,
      "minLength": 1,
      "pattern": "^[^\\x00\\s\"']+$",
      "type": "string"
    },
    "__schema1": {
      "description": "Installed package name whose APK set is pulled",
      "maxLength": 256,
      "minLength": 1,
      "pattern": "^[A-Za-z][A-Za-z0-9_]*(\\.[A-Za-z][A-Za-z0-9_]*)*$",
      "type": "string"
    },
    "__schema2": {
      "description": "Local directory for the pulled APK set; REA creates a package-named subdirectory inside it",
      "minLength": 1,
      "pattern": "^[^\\x00]*$",
      "type": "string"
    }
  },
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "additionalProperties": false,
  "examples": [
    {
      "output_directory": "/tmp/rea-pulls",
      "package": "com.example.app",
      "serial": "emulator-5554"
    }
  ],
  "properties": {
    "output_directory": {
      "$ref": "#/$defs/__schema2",
      "description": "Local directory for the pulled APK set; REA creates a package-named subdirectory inside it"
    },
    "package": {
      "$ref": "#/$defs/__schema1",
      "description": "Installed package name whose APK set is pulled"
    },
    "serial": {
      "$ref": "#/$defs/__schema0",
      "description": "Device serial exactly as `adb devices` reports it"
    }
  },
  "required": [
    "serial",
    "package",
    "output_directory"
  ],
  "type": "object"
}
```

</details>

**Output schema:** see [`tool-specs/pull_adb_package.json`](../tool-specs/pull_adb_package.json) (`outputSchema`).

---

## push_adb_file

<a id="pushadbfile"></a>

**Title:** Push Adb File  
**Kind:** `adb-provider` · **Requires session:** false · **analysisOperation:** null  
**Providers:** adb  
**Effects set (true flags):** accessesNetwork, NOT idempotent, launchesProcess, mutatesDevice, mutatesSession, mutatesTarget, writesFilesystem  
**MCP annotations:** `{"destructiveHint":true,"idempotentHint":false,"openWorldHint":true,"readOnlyHint":false}`

**Description (verbatim, as advertised to the agent):**

> Push one local file to an absolute device path. A device-mutating tool: checks for an existing device file before transfer and refuses it unless overwrite is explicitly requested; this check is not an atomic create and another process can create the path before adb writes. When the device provides sha256sum, the transfer is verified by comparing it with the local digest.

**Input schema (verbatim, JSON Schema 2020-12):**

<details><summary>inputSchema for push_adb_file</summary>

```json
{
  "$defs": {
    "__schema0": {
      "description": "Device serial exactly as `adb devices` reports it",
      "maxLength": 256,
      "minLength": 1,
      "pattern": "^[^\\x00\\s\"']+$",
      "type": "string"
    },
    "__schema1": {
      "description": "Existing local regular file to push",
      "minLength": 1,
      "pattern": "^[^\\x00]*$",
      "type": "string"
    },
    "__schema2": {
      "description": "Absolute destination path on the device",
      "minLength": 1,
      "pattern": "^\\/[^\\x00]*$",
      "type": "string"
    },
    "__schema3": {
      "$ref": "#/$defs/__schema4",
      "default": false,
      "description": "Allow replacing an existing device file; refused by default"
    },
    "__schema4": {
      "type": "boolean"
    }
  },
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "additionalProperties": false,
  "examples": [
    {
      "device_path": "/data/local/tmp/frida-server",
      "local_path": "/tmp/frida-server",
      "serial": "emulator-5554"
    }
  ],
  "properties": {
    "device_path": {
      "$ref": "#/$defs/__schema2",
      "description": "Absolute destination path on the device"
    },
    "local_path": {
      "$ref": "#/$defs/__schema1",
      "description": "Existing local regular file to push"
    },
    "overwrite": {
      "$ref": "#/$defs/__schema3",
      "description": "Allow replacing an existing device file; refused by default"
    },
    "serial": {
      "$ref": "#/$defs/__schema0",
      "description": "Device serial exactly as `adb devices` reports it"
    }
  },
  "required": [
    "serial",
    "local_path",
    "device_path"
  ],
  "type": "object"
}
```

</details>

**Output schema:** see [`tool-specs/push_adb_file.json`](../tool-specs/push_adb_file.json) (`outputSchema`).

---

## read_adb_logcat

<a id="readadblogcat"></a>

**Title:** Read Adb Logcat  
**Kind:** `adb-provider` · **Requires session:** false · **analysisOperation:** null  
**Providers:** adb  
**Effects set (true flags):** accessesNetwork, launchesProcess, mutatesSession  
**MCP annotations:** `{"destructiveHint":false,"idempotentHint":true,"openWorldHint":true,"readOnlyHint":false}`

**Description (verbatim, as advertised to the agent):**

> Read a bounded dump of the device log (`logcat -d -t`) for one buffer, optionally restricted to a process id. No streaming, no clearing; the newest lines are kept when the count cap trims. Read-only.

**Input schema (verbatim, JSON Schema 2020-12):**

<details><summary>inputSchema for read_adb_logcat</summary>

```json
{
  "$defs": {
    "__schema0": {
      "description": "Device serial exactly as `adb devices` reports it",
      "maxLength": 256,
      "minLength": 1,
      "pattern": "^[^\\x00\\s\"']+$",
      "type": "string"
    },
    "__schema1": {
      "$ref": "#/$defs/__schema2",
      "default": 500,
      "description": "Number of most recent lines to read (logcat -d -t)"
    },
    "__schema2": {
      "maximum": 10000,
      "minimum": 1,
      "type": "integer"
    },
    "__schema3": {
      "$ref": "#/$defs/__schema4",
      "default": "main",
      "description": "Log buffer to read (logcat -b)"
    },
    "__schema4": {
      "enum": [
        "main",
        "system",
        "radio",
        "events",
        "crash"
      ],
      "type": "string"
    },
    "__schema5": {
      "$ref": "#/$defs/__schema6",
      "description": "Restrict to one process id (logcat --pid)"
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
      "buffer": "main",
      "count": 200,
      "serial": "emulator-5554"
    }
  ],
  "properties": {
    "buffer": {
      "$ref": "#/$defs/__schema3",
      "description": "Log buffer to read (logcat -b)"
    },
    "count": {
      "$ref": "#/$defs/__schema1",
      "description": "Number of most recent lines to read (logcat -d -t)"
    },
    "pid": {
      "$ref": "#/$defs/__schema5",
      "description": "Restrict to one process id (logcat --pid)"
    },
    "serial": {
      "$ref": "#/$defs/__schema0",
      "description": "Device serial exactly as `adb devices` reports it"
    }
  },
  "required": [
    "serial"
  ],
  "type": "object"
}
```

</details>

**Output schema:** see [`tool-specs/read_adb_logcat.json`](../tool-specs/read_adb_logcat.json) (`outputSchema`).

---

## read_adb_setting

<a id="readadbsetting"></a>

**Title:** Read Adb Setting  
**Kind:** `adb-provider` · **Requires session:** false · **analysisOperation:** null  
**Providers:** adb  
**Effects set (true flags):** accessesNetwork, launchesProcess, mutatesSession  
**MCP annotations:** `{"destructiveHint":false,"idempotentHint":true,"openWorldHint":true,"readOnlyHint":false}`

**Description (verbatim, as advertised to the agent):**

> Read one settings value (`settings get`) from the system, secure, or global namespace. Absent keys report the device's own null observation. Read-only; writing settings is not exposed.

**Input schema (verbatim, JSON Schema 2020-12):**

<details><summary>inputSchema for read_adb_setting</summary>

```json
{
  "$defs": {
    "__schema0": {
      "description": "Device serial exactly as `adb devices` reports it",
      "maxLength": 256,
      "minLength": 1,
      "pattern": "^[^\\x00\\s\"']+$",
      "type": "string"
    },
    "__schema1": {
      "description": "Settings namespace to read",
      "enum": [
        "system",
        "secure",
        "global"
      ],
      "type": "string"
    },
    "__schema2": {
      "description": "Setting key to read",
      "maxLength": 256,
      "minLength": 1,
      "pattern": "^[A-Za-z0-9._\\x2d]+$",
      "type": "string"
    }
  },
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "additionalProperties": false,
  "examples": [
    {
      "key": "adb_enabled",
      "namespace": "secure",
      "serial": "emulator-5554"
    }
  ],
  "properties": {
    "key": {
      "$ref": "#/$defs/__schema2",
      "description": "Setting key to read"
    },
    "namespace": {
      "$ref": "#/$defs/__schema1",
      "description": "Settings namespace to read"
    },
    "serial": {
      "$ref": "#/$defs/__schema0",
      "description": "Device serial exactly as `adb devices` reports it"
    }
  },
  "required": [
    "serial",
    "namespace",
    "key"
  ],
  "type": "object"
}
```

</details>

**Output schema:** see [`tool-specs/read_adb_setting.json`](../tool-specs/read_adb_setting.json) (`outputSchema`).

---

## resolve_adb_packages

<a id="resolveadbpackages"></a>

**Title:** Resolve Adb Packages  
**Kind:** `adb-provider` · **Requires session:** false · **analysisOperation:** null  
**Providers:** adb  
**Effects set (true flags):** accessesNetwork, launchesProcess, mutatesSession  
**MCP annotations:** `{"destructiveHint":false,"idempotentHint":true,"openWorldHint":true,"readOnlyHint":false}`

**Description (verbatim, as advertised to the agent):**

> Find installed packages by case-insensitive substring of the package name (e.g. `whatsapp` → `com.whatsapp`), returning each match's base APK device path. The first step of an easy get: resolve, then pull_adb_package the exact name. Read-only.

**Input schema (verbatim, JSON Schema 2020-12):**

<details><summary>inputSchema for resolve_adb_packages</summary>

```json
{
  "$defs": {
    "__schema0": {
      "description": "Device serial exactly as `adb devices` reports it",
      "maxLength": 256,
      "minLength": 1,
      "pattern": "^[^\\x00\\s\"']+$",
      "type": "string"
    },
    "__schema1": {
      "description": "Case-insensitive substring matched against installed package names (e.g. whatsapp)",
      "maxLength": 256,
      "minLength": 2,
      "type": "string"
    }
  },
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "additionalProperties": false,
  "examples": [
    {
      "query": "whatsapp",
      "serial": "emulator-5554"
    }
  ],
  "properties": {
    "query": {
      "$ref": "#/$defs/__schema1",
      "description": "Case-insensitive substring matched against installed package names (e.g. whatsapp)"
    },
    "serial": {
      "$ref": "#/$defs/__schema0",
      "description": "Device serial exactly as `adb devices` reports it"
    }
  },
  "required": [
    "serial",
    "query"
  ],
  "type": "object"
}
```

</details>

**Output schema:** see [`tool-specs/resolve_adb_packages.json`](../tool-specs/resolve_adb_packages.json) (`outputSchema`).

---

## start_adb_activity

<a id="startadbactivity"></a>

**Title:** Start Adb Activity  
**Kind:** `adb-provider` · **Requires session:** false · **analysisOperation:** null  
**Providers:** adb  
**Effects set (true flags):** accessesNetwork, NOT idempotent, launchesProcess, mutatesDevice, mutatesSession, mutatesTarget  
**MCP annotations:** `{"destructiveHint":true,"idempotentHint":false,"openWorldHint":true,"readOnlyHint":false}`

**Description (verbatim, as advertised to the agent):**

> Start an intent with `am start -W`: one action, optional data URI, optional explicit component, and up to 16 typed extras (string, boolean, int, long, float). A device-mutating tool; the full wait report determines success, with failed-attempt facts and raw output retained.

**Input schema (verbatim, JSON Schema 2020-12):**

<details><summary>inputSchema for start_adb_activity</summary>

```json
{
  "$defs": {
    "__schema0": {
      "description": "Device serial exactly as `adb devices` reports it",
      "maxLength": 256,
      "minLength": 1,
      "pattern": "^[^\\x00\\s\"']+$",
      "type": "string"
    },
    "__schema1": {
      "description": "Intent action to start",
      "maxLength": 256,
      "minLength": 1,
      "pattern": "^[A-Za-z][A-Za-z0-9._\\x2d]*$",
      "type": "string"
    },
    "__schema2": {
      "$ref": "#/$defs/__schema3",
      "description": "Intent data URI (-d)"
    },
    "__schema3": {
      "maxLength": 2048,
      "minLength": 1,
      "pattern": "^[^\\x00\\s]+$",
      "type": "string"
    },
    "__schema4": {
      "$ref": "#/$defs/__schema5",
      "description": "Explicit component to start (-n)"
    },
    "__schema5": {
      "maxLength": 512,
      "minLength": 1,
      "pattern": "^[A-Za-z0-9._\\x2d]+(\\/[A-Za-z0-9._\\x2d]*)?$",
      "type": "string"
    },
    "__schema6": {
      "$ref": "#/$defs/__schema7",
      "default": [],
      "description": "Typed intent extras (--es/--ez/--ei/--el/--ef)"
    },
    "__schema7": {
      "items": {
        "$ref": "#/$defs/__schema8"
      },
      "maxItems": 16,
      "type": "array"
    },
    "__schema8": {
      "additionalProperties": false,
      "properties": {
        "key": {
          "description": "Extra key",
          "maxLength": 256,
          "minLength": 1,
          "pattern": "^[A-Za-z0-9._\\x2d]+$",
          "type": "string"
        },
        "type": {
          "description": "Extra value type",
          "enum": [
            "string",
            "boolean",
            "int",
            "long",
            "float"
          ],
          "type": "string"
        },
        "value": {
          "description": "Extra value as text, parsed per type",
          "maxLength": 2048,
          "minLength": 1,
          "pattern": "^[^\\x00]*$",
          "type": "string"
        }
      },
      "required": [
        "key",
        "type",
        "value"
      ],
      "type": "object"
    }
  },
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "additionalProperties": false,
  "examples": [
    {
      "action": "android.intent.action.VIEW",
      "data_uri": "https://example.com/path",
      "serial": "emulator-5554"
    },
    {
      "action": "com.example.APP_ACTION",
      "extras": [
        {
          "key": "level",
          "type": "int",
          "value": "3"
        }
      ],
      "serial": "emulator-5554"
    }
  ],
  "properties": {
    "action": {
      "$ref": "#/$defs/__schema1",
      "description": "Intent action to start"
    },
    "component": {
      "$ref": "#/$defs/__schema4",
      "description": "Explicit component to start (-n)"
    },
    "data_uri": {
      "$ref": "#/$defs/__schema2",
      "description": "Intent data URI (-d)"
    },
    "extras": {
      "$ref": "#/$defs/__schema6",
      "description": "Typed intent extras (--es/--ez/--ei/--el/--ef)"
    },
    "serial": {
      "$ref": "#/$defs/__schema0",
      "description": "Device serial exactly as `adb devices` reports it"
    }
  },
  "required": [
    "serial",
    "action"
  ],
  "type": "object"
}
```

</details>

**Output schema:** see [`tool-specs/start_adb_activity.json`](../tool-specs/start_adb_activity.json) (`outputSchema`).

---

## start_adb_app

<a id="startadbapp"></a>

**Title:** Start Adb App  
**Kind:** `adb-provider` · **Requires session:** false · **analysisOperation:** null  
**Providers:** adb  
**Effects set (true flags):** accessesNetwork, NOT idempotent, launchesProcess, mutatesDevice, mutatesSession, mutatesTarget  
**MCP annotations:** `{"destructiveHint":true,"idempotentHint":false,"openWorldHint":true,"readOnlyHint":false}`

**Description (verbatim, as advertised to the agent):**

> Start one installed app's resolved launcher activity with `am start -W -n`. A device-mutating tool for dynamic analysis. The full wait report determines success; failures retain launch-attempt facts and raw output. Pair with `read_adb_logcat` (pid filter) and `list_adb_processes` to observe the app, and `stop_adb_app` to end the run.

**Input schema (verbatim, JSON Schema 2020-12):**

<details><summary>inputSchema for start_adb_app</summary>

```json
{
  "$defs": {
    "__schema0": {
      "description": "Device serial exactly as `adb devices` reports it",
      "maxLength": 256,
      "minLength": 1,
      "pattern": "^[^\\x00\\s\"']+$",
      "type": "string"
    },
    "__schema1": {
      "description": "Installed package whose launcher activity is started",
      "maxLength": 256,
      "minLength": 1,
      "pattern": "^[A-Za-z][A-Za-z0-9_]*(\\.[A-Za-z][A-Za-z0-9_]*)*$",
      "type": "string"
    }
  },
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "additionalProperties": false,
  "examples": [
    {
      "package": "com.example.app",
      "serial": "emulator-5554"
    }
  ],
  "properties": {
    "package": {
      "$ref": "#/$defs/__schema1",
      "description": "Installed package whose launcher activity is started"
    },
    "serial": {
      "$ref": "#/$defs/__schema0",
      "description": "Device serial exactly as `adb devices` reports it"
    }
  },
  "required": [
    "serial",
    "package"
  ],
  "type": "object"
}
```

</details>

**Output schema:** see [`tool-specs/start_adb_app.json`](../tool-specs/start_adb_app.json) (`outputSchema`).

---

## stop_adb_app

<a id="stopadbapp"></a>

**Title:** Stop Adb App  
**Kind:** `adb-provider` · **Requires session:** false · **analysisOperation:** null  
**Providers:** adb  
**Effects set (true flags):** accessesNetwork, NOT idempotent, launchesProcess, mutatesDevice, mutatesSession, mutatesTarget  
**MCP annotations:** `{"destructiveHint":true,"idempotentHint":false,"openWorldHint":true,"readOnlyHint":false}`

**Description (verbatim, as advertised to the agent):**

> Force-stop every process of one package (`am force-stop`), ending a dynamic-analysis run. A device-mutating tool; it succeeds whether or not the package had running processes.

**Input schema (verbatim, JSON Schema 2020-12):**

<details><summary>inputSchema for stop_adb_app</summary>

```json
{
  "$defs": {
    "__schema0": {
      "description": "Device serial exactly as `adb devices` reports it",
      "maxLength": 256,
      "minLength": 1,
      "pattern": "^[^\\x00\\s\"']+$",
      "type": "string"
    },
    "__schema1": {
      "description": "Package whose processes are force-stopped",
      "maxLength": 256,
      "minLength": 1,
      "pattern": "^[A-Za-z][A-Za-z0-9_]*(\\.[A-Za-z][A-Za-z0-9_]*)*$",
      "type": "string"
    }
  },
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "additionalProperties": false,
  "examples": [
    {
      "package": "com.example.app",
      "serial": "emulator-5554"
    }
  ],
  "properties": {
    "package": {
      "$ref": "#/$defs/__schema1",
      "description": "Package whose processes are force-stopped"
    },
    "serial": {
      "$ref": "#/$defs/__schema0",
      "description": "Device serial exactly as `adb devices` reports it"
    }
  },
  "required": [
    "serial",
    "package"
  ],
  "type": "object"
}
```

</details>

**Output schema:** see [`tool-specs/stop_adb_app.json`](../tool-specs/stop_adb_app.json) (`outputSchema`).

---

## uninstall_adb_package

<a id="uninstalladbpackage"></a>

**Title:** Uninstall Adb Package  
**Kind:** `adb-provider` · **Requires session:** false · **analysisOperation:** null  
**Providers:** adb  
**Effects set (true flags):** accessesNetwork, NOT idempotent, launchesProcess, mutatesDevice, mutatesSession, mutatesTarget  
**MCP annotations:** `{"destructiveHint":true,"idempotentHint":false,"openWorldHint":true,"readOnlyHint":false}`

**Description (verbatim, as advertised to the agent):**

> Uninstall one package from the device (`adb uninstall`), removing its data for user 0. A device-mutating tool; absent packages report the device's own refusal reason.

**Input schema (verbatim, JSON Schema 2020-12):**

<details><summary>inputSchema for uninstall_adb_package</summary>

```json
{
  "$defs": {
    "__schema0": {
      "description": "Device serial exactly as `adb devices` reports it",
      "maxLength": 256,
      "minLength": 1,
      "pattern": "^[^\\x00\\s\"']+$",
      "type": "string"
    },
    "__schema1": {
      "description": "Installed package to uninstall",
      "maxLength": 256,
      "minLength": 1,
      "pattern": "^[A-Za-z][A-Za-z0-9_]*(\\.[A-Za-z][A-Za-z0-9_]*)*$",
      "type": "string"
    }
  },
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "additionalProperties": false,
  "examples": [
    {
      "package": "com.example.app",
      "serial": "emulator-5554"
    }
  ],
  "properties": {
    "package": {
      "$ref": "#/$defs/__schema1",
      "description": "Installed package to uninstall"
    },
    "serial": {
      "$ref": "#/$defs/__schema0",
      "description": "Device serial exactly as `adb devices` reports it"
    }
  },
  "required": [
    "serial",
    "package"
  ],
  "type": "object"
}
```

</details>

**Output schema:** see [`tool-specs/uninstall_adb_package.json`](../tool-specs/uninstall_adb_package.json) (`outputSchema`).

---

