// Command har_mcp serves the har reader as an MCP (Model Context Protocol)
// server over stdio.
//
// It exposes one tool per analysis the har library performs, so an agent can
// inspect a HAR file in small, targeted reads instead of pulling a 100MB capture
// into context:
//
//	har_summary  har_list     har_count   har_hosts   har_paths
//	har_show     har_body     har_headers har_form
//	har_search   har_curl     har_extract har_raw     har_validate
//
// Transport: newline-delimited JSON-RPC 2.0 on stdin/stdout, per the MCP stdio
// transport. Nothing but protocol messages may reach stdout — the har library
// writes into a buffer (see internal/har.Invoke), and all diagnostics go to
// stderr.
package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/baiji520/har_mcp/internal/har"
)

const (
	serverName      = "har_mcp"
	serverVersion   = har.Version
	protocolVersion = "2025-06-18"
	maxMessageBytes = 16 << 20
)

// ------------------------------------------------------------------ protocol

type rpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

// JSON-RPC error codes we emit.
const (
	codeParseError     = -32700
	codeInvalidRequest = -32600
	codeMethodNotFound = -32601
	codeInvalidParams  = -32602
	codeInternalError  = -32603
)

// isNotification reports whether a request carries no id, i.e. the client
// expects no response (MCP sends notifications/initialized this way).
func (r rpcRequest) isNotification() bool {
	if len(r.ID) == 0 {
		return true
	}
	return string(r.ID) == "null"
}

func main() {
	s := &server{out: bufio.NewWriter(os.Stdout)}
	if err := s.serve(os.Stdin); err != nil && !errors.Is(err, io.EOF) {
		fmt.Fprintf(os.Stderr, "har_mcp: %v\n", err)
		os.Exit(1)
	}
}

type server struct {
	out *bufio.Writer
}

func (s *server) serve(in io.Reader) error {
	sc := bufio.NewScanner(in)
	sc.Buffer(make([]byte, 0, 64<<10), maxMessageBytes)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		s.handleLine([]byte(line))
	}
	if err := sc.Err(); err != nil {
		return err
	}
	return io.EOF
}

func (s *server) handleLine(line []byte) {
	var req rpcRequest
	if err := json.Unmarshal(line, &req); err != nil {
		s.write(rpcResponse{
			JSONRPC: "2.0",
			ID:      json.RawMessage("null"),
			Error:   &rpcError{Code: codeParseError, Message: "parse error: " + err.Error()},
		})
		return
	}
	// A batch is not part of MCP; answer with an invalid-request error rather
	// than silently dropping it.
	if req.Method == "" && req.ID == nil {
		s.write(rpcResponse{
			JSONRPC: "2.0",
			ID:      json.RawMessage("null"),
			Error:   &rpcError{Code: codeInvalidRequest, Message: "invalid request"},
		})
		return
	}

	res, rerr := s.dispatch(req)
	if req.isNotification() {
		return
	}
	resp := rpcResponse{JSONRPC: "2.0", ID: req.ID, Result: res, Error: rerr}
	if rerr != nil {
		resp.Result = nil
	}
	s.write(resp)
}

func (s *server) dispatch(req rpcRequest) (any, *rpcError) {
	switch req.Method {
	case "initialize":
		return s.initialize(req.Params), nil
	case "ping":
		return map[string]any{}, nil
	case "tools/list":
		return map[string]any{"tools": toolDefs()}, nil
	case "tools/call":
		return s.callTool(req.Params)
	case "resources/list":
		return map[string]any{"resources": []any{}}, nil
	case "prompts/list":
		return map[string]any{"prompts": []any{}}, nil
	default:
		if strings.HasPrefix(req.Method, "notifications/") {
			// Notifications need no reply; acknowledge by returning nothing.
			return map[string]any{}, nil
		}
		return nil, &rpcError{Code: codeMethodNotFound, Message: "method not found: " + req.Method}
	}
}

func (s *server) initialize(params json.RawMessage) any {
	var p struct {
		ProtocolVersion string `json:"protocolVersion"`
	}
	_ = json.Unmarshal(params, &p)
	// Speak the client's revision when it is one we know, so a client pinned to
	// an older MCP revision does not have to upgrade.
	version := protocolVersion
	switch p.ProtocolVersion {
	case "2024-11-05", "2025-03-26", "2025-06-18":
		version = p.ProtocolVersion
	}
	return map[string]any{
		"protocolVersion": version,
		"capabilities": map[string]any{
			"tools": map[string]any{"listChanged": false},
		},
		"serverInfo": map[string]any{
			"name":    serverName,
			"version": serverVersion,
		},
		"instructions": "Read HAR (HTTP Archive) captures without dumping them into context. " +
			"Start with har_summary, narrow with har_list/har_paths, then read one entry with " +
			"har_show or har_body. Every tool takes the capture's absolute path as `file`; " +
			"`path` is a separate filter regex on the URL path.",
	}
}

func (s *server) write(resp rpcResponse) {
	b, err := json.Marshal(resp)
	if err != nil {
		fmt.Fprintf(os.Stderr, "har_mcp: marshal response: %v\n", err)
		return
	}
	s.out.Write(b)
	s.out.WriteByte('\n')
	s.out.Flush()
}

// ------------------------------------------------------------------ tools

type tool struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	InputSchema map[string]any `json:"inputSchema"`
}

type callResult struct {
	Content []contentBlock `json:"content"`
	IsError bool           `json:"isError,omitempty"`
}

type contentBlock struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

func textResult(text string) callResult {
	return callResult{Content: []contentBlock{{Type: "text", Text: text}}}
}

func errorResult(msg string) callResult {
	return callResult{Content: []contentBlock{{Type: "text", Text: msg}}, IsError: true}
}

func (s *server) callTool(params json.RawMessage) (any, *rpcError) {
	var p struct {
		Name      string         `json:"name"`
		Arguments map[string]any `json:"arguments"`
	}
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, &rpcError{Code: codeInvalidParams, Message: "invalid params: " + err.Error()}
	}
	if p.Arguments == nil {
		p.Arguments = map[string]any{}
	}
	c := toolCall{name: p.Name, args: p.Arguments}
	cmd, opts, err := c.options()
	if err != nil {
		// Argument problems are the caller's to fix, and the model reads the
		// text — report them as a tool result, not a protocol error.
		return errorResult(err.Error()), nil
	}
	file, err := c.file()
	if err != nil {
		return errorResult(err.Error()), nil
	}
	out, runErr := har.Invoke(file, cmd, opts)
	if runErr != nil {
		msg := runErr.Error()
		if out != "" {
			msg = strings.TrimRight(out, "\n") + "\n" + msg
		}
		return errorResult(msg), nil
	}
	if !utf8.ValidString(out) {
		return errorResult("output is binary (non-UTF-8); use har_raw with an `out` path to write the decoded bytes to a file"), nil
	}
	if out == "" {
		out = "(no output)"
	}
	return textResult(out), nil
}

// ------------------------------------------------------------------ schema helpers

// obj builds a JSON-schema object with the given properties and required list.
func obj(props map[string]any, required ...string) map[string]any {
	s := map[string]any{"type": "object", "properties": props}
	if len(required) > 0 {
		s["required"] = required
	}
	s["additionalProperties"] = false
	return s
}

func strProp(desc string) map[string]any {
	return map[string]any{"type": "string", "description": desc}
}

func enumProp(desc string, values ...string) map[string]any {
	return map[string]any{"type": "string", "description": desc, "enum": values}
}

func intProp(desc string) map[string]any {
	return map[string]any{"type": "integer", "description": desc, "minimum": 0}
}

func boolProp(desc string) map[string]any {
	return map[string]any{"type": "boolean", "description": desc}
}

// The capture path is `file`, not `path`: `path` is already a filter (regex on
// the URL path), and one name for two things silently filtered every row out.
const fileDesc = "Absolute path to the .har capture file."

// filterProps are the filters shared by every tool that selects entries. They
// map one-for-one onto har.Options fields, so the schema and the library cannot
// drift apart.
func filterProps() map[string]any {
	return map[string]any{
		"host":   strProp("Regex on hostname (case-insensitive)."),
		"path":   strProp("Regex on URL path (case-insensitive)."),
		"url":    strProp("Regex on the full URL (case-insensitive)."),
		"mime":   strProp("Regex on response MIME type (case-insensitive)."),
		"method": strProp("HTTP method, e.g. GET or POST."),
		"status": strProp("Status filter: 200 | 2xx | >=400 | <=400 | !=301."),
		"type":   enumProp("Coarse payload class.", "json", "text", "html", "image", "binary"),
		"slow":   intProp("Only entries slower than this many milliseconds."),
		"big":    intProp("Only responses larger than this many bytes."),
		"from":   intProp("Lowest entry index to include (inclusive)."),
		"to":     intProp("Highest entry index to include (inclusive)."),
		"limit":  intProp("Cap on returned rows (0 = no cap)."),
	}
}

func mergeProps(base map[string]any, extra map[string]any) map[string]any {
	out := make(map[string]any, len(base)+len(extra))
	for k, v := range base {
		out[k] = v
	}
	for k, v := range extra {
		out[k] = v
	}
	return out
}

func withFile(props map[string]any) map[string]any {
	return mergeProps(props, map[string]any{"file": strProp(fileDesc)})
}

func toolDefs() []tool {
	return []tool{
		{
			Name: "har_summary",
			Description: "One-screen overview of a HAR capture: file size, entry count, " +
				"status-code histogram, body stats, per-host table, slowest and largest requests. " +
				"Call this first when you do not yet know what a capture contains.",
			InputSchema: obj(withFile(map[string]any{}), "file"),
		},
		{
			Name: "har_list",
			Description: "Compact table of entries matching the filters. The first column (IDX) " +
				"is the entry number every other tool takes. Defaults to 200 rows; pass limit: 0 for all.",
			InputSchema: obj(withFile(mergeProps(filterProps(), map[string]any{
				"format": enumProp("Output format. `table` is compact and human-readable; `json` and `tsv` are machine-readable.", "table", "json", "tsv"),
				"wide":   boolProp("Use wider columns in table output."),
			})), "file"),
		},
		{
			Name: "har_count",
			Description: "Count how many entries match the filters, without listing them. " +
				"Cheaper than har_list when you only need a number.",
			InputSchema: obj(withFile(filterProps()), "file"),
		},
		{
			Name: "har_hosts",
			Description: "Per-host aggregation: request count, distinct paths, error count, total MB. " +
				"Use it to see which backends a page talks to.",
			InputSchema: obj(withFile(filterProps()), "file"),
		},
		{
			Name: "har_paths",
			Description: "Deduplicated endpoints with hit counts, methods, status codes and average " +
				"duration — the API surface of the capture. Usually the fastest way to find the " +
				"interesting request before reading it.",
			InputSchema: obj(withFile(mergeProps(filterProps(), map[string]any{
				"wide": boolProp("Use wider columns."),
			})), "file"),
		},
		{
			Name: "har_show",
			Description: "Context card for one entry: method, URL, timing, status, headers, and a " +
				"preview of request and response bodies. Start here to understand a request; use " +
				"har_body for the full payload.",
			InputSchema: obj(withFile(map[string]any{
				"idx":  intProp("Entry index from har_list."),
				"max":  intProp("Max characters to print per header value and body preview (default 800)."),
				"full": boolProp("Do not cap the preview."),
			}), "file", "idx"),
		},
		{
			Name: "har_body",
			Description: "Request or response payload of one entry. JSON is pretty-printed and capped " +
				"at 200 lines; base64 responses are decoded automatically. Use `jq` for a field path " +
				"like `.data.token` or `.items[0].id` to pull a single value instead of reading the body.",
			InputSchema: obj(withFile(map[string]any{
				"idx":    intProp("Entry index from har_list."),
				"side":   enumProp("Which body to read.", "res", "req"),
				"jq":     strProp("Field path to extract, e.g. `.data.token`, `.items[0].id`, `keys`."),
				"lines":  intProp("Max lines to print (default 200)."),
				"raw":    boolProp("Print the body verbatim, without JSON pretty-printing."),
				"decode": boolProp("Leave base64 content encoded instead of decoding it."),
			}), "file", "idx"),
		},
		{
			Name: "har_headers",
			Description: "Request or response headers of one entry, optionally filtered by a regex on " +
				"the header name.",
			InputSchema: obj(withFile(map[string]any{
				"idx":  intProp("Entry index from har_list."),
				"side": enumProp("Which header set to read.", "req", "res"),
				"name": strProp("Regex on header name, e.g. `^x-` or `cookie|auth`."),
			}), "file", "idx"),
		},
		{
			Name: "har_form",
			Description: "Decode an application/x-www-form-urlencoded request body into key/value " +
				"pairs. Use `keys` to list only the field names, or `key` to read one field.",
			InputSchema: obj(withFile(map[string]any{
				"idx":  intProp("Entry index from har_list."),
				"keys": boolProp("List field names only."),
				"key":  strProp("Print only this field's value."),
			}), "file", "idx"),
		},
		{
			Name: "har_search",
			Description: "Regex search inside request and/or response payloads, returning only the " +
				"matching lines with their entry index. Use it to locate which request carries a " +
				"token, ID or string without reading whole bodies.",
			InputSchema: obj(withFile(mergeProps(filterProps(), map[string]any{
				"pattern": strProp("Regex to search for (case-insensitive)."),
				"side":    enumProp("Search request bodies, response bodies, or both.", "both", "req", "res"),
			})), "file", "pattern"),
		},
		{
			Name: "har_curl",
			Description: "Generate a curl command that reproduces the request. Auth headers " +
				"(cookie, authorization) are stripped unless includeAuth is true.",
			InputSchema: obj(withFile(map[string]any{
				"idx":         intProp("Entry index from har_list."),
				"includeAuth": boolProp("Keep cookie/authorization headers (contains credentials)."),
			}), "file", "idx"),
		},
		{
			Name: "har_extract",
			Description: "Write a smaller HAR containing only the entries that match the filters. " +
				"Set redact to scrub tokens, cookies, passwords, coordinates and credential-shaped " +
				"values before the file leaves the machine. The output path must not already exist.",
			InputSchema: obj(withFile(mergeProps(filterProps(), map[string]any{
				"out":    strProp("Path for the new .har file. Must not exist yet."),
				"redact": boolProp("Sanitize secrets before writing."),
			})), "file", "out"),
		},
		{
			Name: "har_raw",
			Description: "Decode one entry's response body (base64 or plain) and write the raw bytes " +
				"to a file. Use this for images, fonts and other binary payloads that cannot be shown " +
				"as text.",
			InputSchema: obj(withFile(map[string]any{
				"idx": intProp("Entry index from har_list."),
				"out": strProp("Path to write the decoded bytes to."),
			}), "file", "idx", "out"),
		},
		{
			Name: "har_validate",
			Description: "Check that a file is a well-formed HAR: valid JSON, .log envelope fields, " +
				"page count and entry count. Use it when a capture misbehaves or when you need to " +
				"confirm which tool produced it.",
			InputSchema: obj(withFile(map[string]any{}), "file"),
		},
	}
}

// ------------------------------------------------------------------ arguments -> Options

// toolCall is one decoded tools/call: which tool, and the raw arguments map.
// Arguments are validated here so the command implementations can stay unaware
// of JSON types (json.Number vs float64) and of MCP naming.
type toolCall struct {
	name string
	args map[string]any
}

func (c toolCall) file() (string, error) {
	s, ok := c.args["file"].(string)
	if !ok || s == "" {
		return "", errors.New("missing required argument \"file\" (absolute path to the .har capture)")
	}
	return s, nil
}

func (c toolCall) str(key string) string {
	s, _ := c.args[key].(string)
	return s
}

func (c toolCall) bool(key string) bool {
	b, _ := c.args[key].(bool)
	return b
}

// int64Arg reads an integer argument. MCP clients send JSON numbers, which
// decode as float64 unless a decoder is told otherwise; both are accepted.
func (c toolCall) int64Arg(key string) (int64, bool, error) {
	v, ok := c.args[key]
	if !ok {
		return 0, false, nil
	}
	switch t := v.(type) {
	case float64:
		if t != math.Trunc(t) {
			return 0, false, fmt.Errorf("argument %q must be an integer, got %v", key, t)
		}
		return int64(t), true, nil
	case json.Number:
		n, err := t.Int64()
		if err != nil {
			return 0, false, fmt.Errorf("argument %q must be an integer, got %q", key, t.String())
		}
		return n, true, nil
	case string:
		n, err := strconv.ParseInt(t, 10, 64)
		if err != nil {
			return 0, false, fmt.Errorf("argument %q must be an integer, got %q", key, t)
		}
		return n, true, nil
	default:
		return 0, false, fmt.Errorf("argument %q must be an integer", key)
	}
}

func (c toolCall) requiredInt(key string) (int64, error) {
	n, ok, err := c.int64Arg(key)
	if err != nil {
		return 0, err
	}
	if !ok {
		return 0, fmt.Errorf("missing required argument %q (entry index from har_list)", key)
	}
	return n, nil
}

// options lowers a tools/call into the library's typed Options. One switch arm
// per tool keeps the mapping explicit: the server never invents behaviour the
// library does not have.
func (c toolCall) options() (cmd string, o har.Options, err error) {
	// Shared filters, present on every tool that selects entries.
	o.Host = c.str("host")
	o.Path = c.str("path")
	o.URL = c.str("url")
	o.Mime = c.str("mime")
	o.Method = c.str("method")
	o.Status = c.str("status")
	o.Type = c.str("type")
	if o.Slow, _, err = c.int64Arg("slow"); err != nil {
		return "", o, err
	}
	if o.Big, _, err = c.int64Arg("big"); err != nil {
		return "", o, err
	}
	if o.Limit, o.HasLimit, err = c.int64Arg("limit"); err != nil {
		return "", o, err
	}
	if o.From, o.HasFrom, err = c.int64Arg("from"); err != nil {
		return "", o, err
	}
	if o.To, o.HasTo, err = c.int64Arg("to"); err != nil {
		return "", o, err
	}

	switch c.name {
	case "har_summary":
		return har.CmdSummary, o, nil

	case "har_list":
		o.Format = c.str("format")
		o.Wide = c.bool("wide")
		return har.CmdList, o, nil

	case "har_count":
		return har.CmdCount, o, nil

	case "har_hosts":
		return har.CmdHosts, o, nil

	case "har_paths":
		o.Wide = c.bool("wide")
		return har.CmdPaths, o, nil

	case "har_show":
		if o.Idx, err = c.requiredInt("idx"); err != nil {
			return "", o, err
		}
		if o.Max, _, err = c.int64Arg("max"); err != nil {
			return "", o, err
		}
		o.Full = c.bool("full")
		return har.CmdShow, o, nil

	case "har_body":
		if o.Idx, err = c.requiredInt("idx"); err != nil {
			return "", o, err
		}
		o.Side = c.str("side")
		if o.Side != "" && o.Side != "req" && o.Side != "res" {
			return "", o, fmt.Errorf("argument \"side\" must be \"res\" or \"req\", got %q", o.Side)
		}
		o.JQ = c.str("jq")
		if n, _, lerr := c.int64Arg("lines"); lerr != nil {
			return "", o, lerr
		} else {
			o.Lines = int(n)
		}
		o.Raw = c.bool("raw")
		o.Decode = c.bool("decode")
		return har.CmdBody, o, nil

	case "har_headers":
		if o.Idx, err = c.requiredInt("idx"); err != nil {
			return "", o, err
		}
		o.Side = c.str("side")
		if o.Side != "req" && o.Side != "res" {
			o.Side = "req"
		}
		o.HeaderName = c.str("name")
		return har.CmdHeaders, o, nil

	case "har_form":
		if o.Idx, err = c.requiredInt("idx"); err != nil {
			return "", o, err
		}
		o.Keys = c.bool("keys")
		o.Key = c.str("key")
		return har.CmdForm, o, nil

	case "har_curl":
		if o.Idx, err = c.requiredInt("idx"); err != nil {
			return "", o, err
		}
		o.Auth = c.bool("includeAuth")
		return har.CmdCurl, o, nil

	case "har_search":
		o.Pattern = c.str("pattern")
		if o.Pattern == "" {
			return "", o, errors.New("missing required argument \"pattern\" (regex to search for)")
		}
		o.Side = c.str("side")
		if o.Side != "req" && o.Side != "res" {
			o.Side = "both"
		}
		return har.CmdSearch, o, nil

	case "har_extract":
		o.Out = c.str("out")
		if o.Out == "" {
			return "", o, errors.New("missing required argument \"out\" (path for the new .har file)")
		}
		o.Redact = c.bool("redact")
		return har.CmdSlice, o, nil

	case "har_raw":
		if o.Idx, err = c.requiredInt("idx"); err != nil {
			return "", o, err
		}
		o.Out = c.str("out")
		if o.Out == "" {
			return "", o, errors.New("missing required argument \"out\" (path to write the decoded bytes to)")
		}
		return har.CmdRaw, o, nil

	case "har_validate":
		return har.CmdValidate, o, nil
	}
	return "", o, fmt.Errorf("unknown tool %q", c.name)
}
