# Tool family: Apktool resources

Generated mechanically from `.cache/mcp-tool-catalog.json` (produced by `scripts/generate-mcp-tool-catalog.mjs`, which registers every tool through the MCP SDK and exports the advertised JSON Schema 2020-12 input/output schemas) and `docs/public/product-catalog.json` (family `apktool`, surface `apktool-provider`, 2 tools). Input schemas below are **verbatim**. Output schemas are verbatim in `tool-specs/<tool>.json` (field `outputSchema`) because several exceed 100 KB; the complete per-tool spec (description, effects, annotations, inputSchema, outputSchema) is in that file.

| Tool | Kind | Session? | Providers advertising it | CLI command |
|---|---|---|---|---|
| [`decode_android_resources`](#decodeandroidresources) | apktool-provider | no | apktool | `rea decode-android-resources` |
| [`inspect_apktool_client`](#inspectapktoolclient) | apktool-provider | no | apktool | `rea inspect-apktool-client` |

## decode_android_resources

<a id="decodeandroidresources"></a>

**Title:** Decode Android Resources  
**Kind:** `apktool-provider` · **Requires session:** false · **analysisOperation:** null  
**Providers:** apktool  
**Effects set (true flags):** launchesProcess, mutatesSession, writesFilesystem  
**MCP annotations:** `{"destructiveHint":false,"idempotentHint":true,"openWorldHint":true,"readOnlyHint":false}`

**Description (verbatim, as advertised to the agent):**

> Decode one local APK's resources with `apktool d --no-src` in a provider-owned workspace that is removed after projection: the readable AndroidManifest.xml, apktool.yml version and SDK facts, the app's string resources (default or one locale, bounded to 2000 entries), available string locales, and the decoded file count. The target APK is digest with SHA-256 before decoding; smali is skipped because Java-source recovery belongs to the JADX family.

**Input schema (verbatim, JSON Schema 2020-12):**

<details><summary>inputSchema for decode_android_resources</summary>

```json
{
  "$defs": {
    "__schema0": {
      "description": "Local APK file to decode",
      "minLength": 1,
      "pattern": "^[^\\x00]*$",
      "type": "string"
    },
    "__schema1": {
      "$ref": "#/$defs/__schema2",
      "default": true,
      "description": "Project res/values/strings.xml entries (bounded to 2000 entries)"
    },
    "__schema2": {
      "type": "boolean"
    },
    "__schema3": {
      "$ref": "#/$defs/__schema4",
      "description": "Project strings from res/values-<locale>/strings.xml instead of the default table"
    },
    "__schema4": {
      "maxLength": 16,
      "minLength": 2,
      "pattern": "^(?:[a-z]{2,3}(?:-(?:r?[A-Z]{2}|r?[0-9]{3}))?|b\\+[a-z]{2,3}(?:\\+[A-Za-z0-9]{2,8})*)$",
      "type": "string"
    }
  },
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "additionalProperties": false,
  "examples": [
    {
      "path": "/targets/Example.apk"
    },
    {
      "locale": "de",
      "path": "/targets/Example.apk"
    }
  ],
  "properties": {
    "include_strings": {
      "$ref": "#/$defs/__schema1",
      "description": "Project res/values/strings.xml entries (bounded to 2000 entries)"
    },
    "locale": {
      "$ref": "#/$defs/__schema3",
      "description": "Project strings from res/values-<locale>/strings.xml instead of the default table"
    },
    "path": {
      "$ref": "#/$defs/__schema0",
      "description": "Local APK file to decode"
    }
  },
  "required": [
    "path"
  ],
  "type": "object"
}
```

</details>

**Output schema:** see [`tool-specs/decode_android_resources.json`](../tool-specs/decode_android_resources.json) (`outputSchema`).

---

## inspect_apktool_client

<a id="inspectapktoolclient"></a>

**Title:** Inspect Apktool Client  
**Kind:** `apktool-provider` · **Requires session:** false · **analysisOperation:** null  
**Providers:** apktool  
**Effects set (true flags):** launchesProcess, mutatesSession  
**MCP annotations:** `{"destructiveHint":false,"idempotentHint":true,"openWorldHint":true,"readOnlyHint":false}`

**Description (verbatim, as advertised to the agent):**

> Inspect the caller-selected apktool launcher: resolved command, selection source, and version. Decodes nothing. REA never installs Apktool or Java; select a launcher with REA_APKTOOL_COMMAND (absolute) or apktool on PATH.

**Input schema (verbatim, JSON Schema 2020-12):**

<details><summary>inputSchema for inspect_apktool_client</summary>

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

**Output schema:** see [`tool-specs/inspect_apktool_client.json`](../tool-specs/inspect_apktool_client.json) (`outputSchema`).

---

