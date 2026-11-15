# har_mcp — HAR reader as an MCP server

`har_mcp` is a Model Context Protocol server (stdio transport) that exposes a
HAR (HTTP Archive) reader to agents: CodeBuddy Code, Claude Desktop, Cursor, or
anything else that speaks MCP.

The point is context economy. A 100MB capture never enters the model's context:
the agent surveys, filters, then reads one entry at a time. Every response is
size-capped, so a query answers in a couple of KB.

This project has **no CLI**. `cmd/har_mcp` is the MCP server; `internal/har` is
the implementation it calls.

## Register with a client

The server runs straight from GitHub — Go fetches and builds it on first launch,
so there is no install step and no local checkout.

```json
{
  "mcpServers": {
    "har_mcp": {
      "command": "go",
      "args": [
        "run",
        "github.com/baiji520/har_mcp/cmd/har_mcp@main"
      ]
    }
  }
}
```

`go run` compiles once and caches the result, so later launches are fast. To pin
a revision, replace `@main` with a tag or commit, e.g. `@v1.1.0`.

Requires Go 1.24+ on the machine running the client, and network access to the
Go module proxy on first launch. No configuration, no environment variables.

Every tool takes the capture's absolute path in a `file` argument, so one server
instance serves any number of HAR files.

## Tools

14 tools, one per analysis the library performs. Nothing the original CLI could
do is missing.

| Tool | What it answers |
|---|---|
| `har_summary` | What is in this capture? Size, entry count, status histogram, per-host table, slowest/largest requests. Start here. |
| `har_list` | Which entries match these filters? Compact table; the IDX column feeds every other tool. |
| `har_count` | How many match? A number, no rows. |
| `har_hosts` | Which backends does this page talk to? n / distinct paths / errors / MB per host. |
| `har_paths` | What is the API surface? Deduped endpoints with hits, methods, codes, average duration. |
| `har_show` | What is this one request? Method, URL, timing, headers, body previews. |
| `har_body` | What exactly is the payload? Pretty-printed JSON, or one field via `jq: ".data.token"`. |
| `har_headers` | Which headers were sent/received? Optional regex on the header name. |
| `har_form` | What is in this url-encoded POST body? Decoded key/value pairs. |
| `har_search` | Which request carries this string? Regex over request and/or response payloads. |
| `har_curl` | How do I replay this? curl command, auth headers stripped by default. |
| `har_extract` | Write a smaller capture, optionally redacted, to hand to someone else. |
| `har_raw` | Write one response body's decoded bytes (images, fonts) to a file. |
| `har_validate` | Is this actually a well-formed HAR? Envelope fields, pages, entry count. |

### Shared filters

`har_list`, `har_count`, `har_hosts`, `har_paths`, `har_search` and `har_extract`
accept the same filters:

`host` `path` `url` `mime` (regex, case-insensitive) · `method` ·
`status` (`200`, `2xx`, `>=400`, `!=301`) · `type` (`json|text|html|image|binary`) ·
`slow` (ms) · `big` (bytes) · `from` / `to` (entry index) · `limit` (0 = no cap)

`path` is a regex on the **URL path**; the capture file itself goes in `file`.

### Per-tool options

| Tool | Options |
|---|---|
| `har_list` | `format`: `table` (default) \| `json` \| `tsv` · `wide` |
| `har_paths` | `wide` |
| `har_show` | `idx` · `max` (chars per header/preview, default 800) · `full` |
| `har_body` | `idx` · `side`: `res` (default) \| `req` · `jq` · `lines` (default 200) · `raw` · `decode` |
| `har_headers` | `idx` · `side`: `req` (default) \| `res` · `name` (regex) |
| `har_form` | `idx` · `keys` (names only) · `key` (one field) |
| `har_curl` | `idx` · `includeAuth` |
| `har_search` | `pattern` · `side`: `both` (default) \| `req` \| `res` |
| `har_extract` | `out` · `redact` |
| `har_raw` | `idx` · `out` |

## Typical agent flow

```
har_summary  file=/tmp/cap.har
har_paths    file=/tmp/cap.har
har_list     file=/tmp/cap.har host=api.example.com status=2xx
har_show     file=/tmp/cap.har idx=42
har_body     file=/tmp/cap.har idx=42 jq=".data.token"
```

## Design notes

- **stdout carries protocol only.** The library writes into a buffer
  (`har.Invoke`), so a stray `Printf` can never corrupt the JSON-RPC stream. All
  diagnostics go to stderr.
- **Tool errors are results, not protocol errors.** A bad index, a missing file,
  an invalid regex or a non-integer `idx` returns `isError: true` with readable
  text the model can act on. Only malformed JSON-RPC gets a JSON-RPC error object.
- **One typed Options struct** (`har.Options`) is the only interface between the
  server and the library — no shell-style argument strings are built anywhere.
- **Large integers survive.** Bodies are decoded with `json.Number`, so an
  18-digit ID prints as `123456789012345678`, not `...45680`.
- **Redaction is strong, not a guarantee.** `har_extract` with `redact: true`
  scrubs secrets by key name, by value shape (hex/UUID/JWT), in URLs, fragments,
  form bodies, cookies, params and headers — but a secret inside an opaque blob
  under a meaningless key cannot be found by either method.
- **The index cache** (`$XDG_CACHE_HOME/har-go/*.idx`, keyed on path|size|mtime)
  makes the first call on a new capture pay the scan and later calls instant.
- **`har_extract` refuses to overwrite** an existing output path.
