# Tool family: PCAP summaries

Generated mechanically from `.cache/mcp-tool-catalog.json` (produced by `scripts/generate-mcp-tool-catalog.mjs`, which registers every tool through the MCP SDK and exports the advertised JSON Schema 2020-12 input/output schemas) and `docs/public/product-catalog.json` (family `pcap`, surface `pcap-provider`, 2 tools). Input schemas below are **verbatim**. Output schemas are verbatim in `tool-specs/<tool>.json` (field `outputSchema`) because several exceed 100 KB; the complete per-tool spec (description, effects, annotations, inputSchema, outputSchema) is in that file.

| Tool | Kind | Session? | Providers advertising it | CLI command |
|---|---|---|---|---|
| [`inspect_pcap_capture`](#inspectpcapcapture) | pcap-provider | no | pcap | `rea inspect-pcap-capture` |
| [`inspect_pcap_client`](#inspectpcapclient) | pcap-provider | no | pcap | `rea inspect-pcap-client` |

## inspect_pcap_capture

<a id="inspectpcapcapture"></a>

**Title:** Inspect Pcap Capture  
**Kind:** `pcap-provider` · **Requires session:** false · **analysisOperation:** null  
**Providers:** pcap  
**Effects set (true flags):** launchesProcess, mutatesSession, writesFilesystem  
**MCP annotations:** `{"destructiveHint":false,"idempotentHint":true,"openWorldHint":true,"readOnlyHint":false}`

**Description (verbatim, as advertised to the agent):**

> Request detail summary for capture identity/counts, then page retained facts with inspect_analysis_view kind pcap. Default detail complete preserves inline delivery. Inspect one saved pcap or pcapng capture through an owned snapshot: metadata, exact packet count, SHA-256, IPv4/IPv6 address counts, DNS questions and address values from the same single-question response, TLS SNI, protocol distribution and HTTP URIs. All derived inventories are retained within declared resource budgets; unknown DNS attribution and excluded credentials remain explicit. Linux requires util-linux prlimit; Windows uses owned Job Objects. Requires caller-supplied capinfos and tshark; REA never captures traffic.

**Input schema (verbatim, JSON Schema 2020-12):**

<details><summary>inputSchema for inspect_pcap_capture</summary>

```json
{
  "$defs": {
    "__schema0": {
      "description": "Local pcap or pcapng capture file to inspect",
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
      "path": "/captures/session.pcap"
    }
  ],
  "properties": {
    "detail": {
      "$ref": "#/$defs/__schema1",
      "description": "complete returns the complete analysis Evidence inline. summary retains that complete Evidence in this session and returns its inspect_analysis_view summary; inspect pages, items or facets through normalized_result.parent_evidence_id."
    },
    "path": {
      "$ref": "#/$defs/__schema0",
      "description": "Local pcap or pcapng capture file to inspect"
    }
  },
  "required": [
    "path"
  ],
  "type": "object"
}
```

</details>

**Output schema:** see [`tool-specs/inspect_pcap_capture.json`](../tool-specs/inspect_pcap_capture.json) (`outputSchema`).

---

## inspect_pcap_client

<a id="inspectpcapclient"></a>

**Title:** Inspect Pcap Client  
**Kind:** `pcap-provider` · **Requires session:** false · **analysisOperation:** null  
**Providers:** pcap  
**Effects set (true flags):** launchesProcess, mutatesSession, writesFilesystem  
**MCP annotations:** `{"destructiveHint":false,"idempotentHint":true,"openWorldHint":true,"readOnlyHint":false}`

**Description (verbatim, as advertised to the agent):**

> Inspect the caller-selected tshark and capinfos binaries: selected commands, selection sources, and versions. Both tools must be usable. Reads no capture file. REA never installs the Wireshark suite; select binaries with REA_TSHARK_COMMAND and REA_CAPINFOS_COMMAND (absolute) or from PATH.

**Input schema (verbatim, JSON Schema 2020-12):**

<details><summary>inputSchema for inspect_pcap_client</summary>

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

**Output schema:** see [`tool-specs/inspect_pcap_client.json`](../tool-specs/inspect_pcap_client.json) (`outputSchema`).

---

