// Package har reads HAR (HTTP Archive) captures for LLM context economy.
//
// Core ideas:
//   - One streaming scan builds a per-entry index (TSV-like rows + byte offsets
//     into the raw file). Subsequent reads seek only what they need.
//   - Every output is size-capped: a query answers in ~1-4KB even on 100MB+ files.
//   - Options.Limit caps output rows (0 = no cap); Options.From/To select a range.
//
// Redaction (har_extract with redact) is JSON-aware: bodies are re-serialized
// through encoding/json with numbers kept as json.Number, so output stays valid
// JSON and 18-digit IDs are not rounded. It covers, by key name: JSON body keys,
// nested (stringified) JSON, form-urlencoded bodies, URL query + fragment,
// request queryString[], postData.params[], cookies[] (both sides), and headers.
// It also covers by value shape: opaque credentials (32+ hex, UUIDs, JWTs) and
// lat/lng coordinates, wherever they appear in URLs, headers, params or bodies.
//
// Known residual: a secret embedded inside an opaque blob that sits under a
// meaningless key (e.g. {"apiExpInfo":[{"str":"...phone..."}]}) cannot be found
// by name or by shape. Treat redaction as strong, not as a guarantee.
//
// The package has no CLI entry point: Invoke is the only way in, and
// cmd/har_mcp exposes each command as an MCP tool.
package har

import (
	"bufio"
	"bytes"
	"crypto/md5"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

const version = "1.1.0"

// cacheMagic identifies the index format. Bump it whenever the scan semantics or
// the row layout change: caches are keyed on path|size|mtime only, so an old
// .idx written by a different build would otherwise be trusted silently.
const cacheMagic = "HARIDX05"

// stdout is the command output sink. MCP runs point it at a buffer so a tool
// call returns text instead of writing to the server's stdio.
var stdout io.Writer = os.Stdout

// stderr receives warnings. Same reason as stdout: a stdio MCP server must keep
// its real stderr free for protocol diagnostics.
var stderr io.Writer = os.Stderr

func outf(format string, a ...any) { fmt.Fprintf(stdout, format, a...) }
func outln(a ...any)               { fmt.Fprintln(stdout, a...) }
func outs(a ...any)                { fmt.Fprint(stdout, a...) }

func warnf(format string, a ...any) { fmt.Fprintf(stderr, "har: "+format+"\n", a...) }

// errDie is the panic payload die() raises. Commands are written as straight-line
// code that aborts on bad input; Run recovers this type and returns it as an
// error, so the same code serves a CLI (prints and exits 1) and a library (MCP
// tool result) without threading error values through every helper.
type errDie struct{ msg string }

func (e errDie) Error() string { return e.msg }

func die(f string, a ...any) { panic(errDie{msg: fmt.Sprintf(f, a...)}) }

// ---------------------------------------------------------------- filtering

type filters struct {
	host, path_, url, mime, status, method, typ string
	slow, big                                   int64
	limit, from, to                             int64 // -1 = unset
	limitSet, fromSet, toSet                    bool
}

// entryRows returns only the slots that hold real entry objects.
func entryRows(rows []row) []row {
	out := make([]row, 0, len(rows))
	for _, r := range rows {
		if r.isEntry() {
			out = append(out, r)
		}
	}
	return out
}

// isEntry reports whether an entries[] slot actually holds a HAR entry object.
// Exporters occasionally emit null/scalar/array slots; they keep their array
// position (so IDX matches har_show) but must not appear in aggregations.
func (r row) isEntry() bool { return r.url != "" || r.method != "" }

func (f *filters) statusMatch(code int64) bool {
	s := f.status
	if s == "" {
		return true
	}
	num := func(str string) int64 { v, _ := strconv.ParseInt(str, 10, 64); return v }
	switch {
	case len(s) == 3 && s[1] == 'x' && s[2] == 'x':
		return strconv.FormatInt(code, 10)[:1] == s[:1]
	case strings.HasPrefix(s, ">="):
		return code >= num(s[2:])
	case strings.HasPrefix(s, "<="):
		return code <= num(s[2:])
	case strings.HasPrefix(s, "!="):
		return code != num(s[2:])
	case strings.HasPrefix(s, ">"):
		return code > num(s[1:])
	case strings.HasPrefix(s, "<"):
		return code < num(s[1:])
	case strings.HasPrefix(s, "="):
		return code == num(s[1:])
	default:
		return code == num(s)
	}
}

func typeMatch(mime, t string) bool {
	if t == "" {
		return true
	}
	m := strings.ToLower(mime)
	switch t {
	case "json":
		return strings.Contains(m, "json")
	case "text":
		return strings.HasPrefix(m, "text/") || strings.Contains(m, "json") ||
			strings.Contains(m, "xml") || strings.Contains(m, "javascript") || strings.Contains(m, "xhtml")
	case "html":
		return strings.Contains(m, "html")
	case "image":
		return strings.HasPrefix(m, "image/")
	case "binary":
		return !strings.HasPrefix(m, "text/") && !strings.Contains(m, "json") && !strings.HasPrefix(m, "image/")
	default:
		return strings.Contains(m, strings.ToLower(t))
	}
}

type row struct {
	idx            int64
	method, status string
	host, path     string
	mime           string
	respBytes      int64
	ms             int64
	reqBodyLen     int64
	encoding       string
	statusText     string
	textLen        int64
	url            string
	started        string // entry startedDateTime (for summary span without a second pass)
	startOffset    int64  // byte offset of this entry object in the raw file
	endOffset      int64  // byte offset just past this entry object
}

func (r row) match(f filters) bool {
	if f.fromSet && r.idx < f.from {
		return false
	}
	if f.toSet && r.idx > f.to {
		return false
	}
	if f.host != "" && !ciRE(f.host).MatchString(r.host) {
		return false
	}
	if f.path_ != "" && !ciRE(f.path_).MatchString(r.path) {
		return false
	}
	if f.url != "" && !ciRE(f.url).MatchString(r.url) {
		return false
	}
	if f.mime != "" && !ciRE(f.mime).MatchString(r.mime) {
		return false
	}
	c, _ := strconv.ParseInt(r.status, 10, 64)
	if !f.statusMatch(c) {
		return false
	}
	if !typeMatch(r.mime, f.typ) {
		return false
	}
	if f.method != "" && !strings.EqualFold(r.method, f.method) {
		return false
	}
	if f.slow > 0 && r.ms < f.slow {
		return false
	}
	if f.big > 0 && r.respBytes < f.big {
		return false
	}
	return true
}

// ciRE caches compiled case-insensitive regexes.
var reCache = map[string]*regexp.Regexp{}

func ciRE(pat string) *regexp.Regexp {
	if re, ok := reCache[pat]; ok {
		return re
	}
	re, err := regexp.Compile("(?i)" + pat)
	if err != nil {
		die("bad regex %q: %v", pat, err)
	}
	reCache[pat] = re
	return re
}

// ---------------------------------------------------------------- call options

// args is the internal shape every command implementation reads. It is built
// from Options by argsFor and never from command-line syntax: this binary has no
// CLI, so nothing here should depend on how a flag would have been spelled.
type args struct {
	f         filters
	rest      []string
	flags     map[string]string
	positions []string
}

// Options is the typed surface between the MCP server and the commands: one
// field per thing a tool can ask for. Fields are zero-valued when unset, which
// is why the three Has* flags exist — limit 0 means "no cap" and must be
// distinguishable from "not given".
type Options struct {
	// Filters (shared by list/count/hosts/paths/search/slice).
	Host, Path, URL, Mime, Method, Status, Type string
	Slow, Big                                   int64
	Limit, From, To                             int64
	HasLimit, HasFrom, HasTo                    bool

	// list / paths presentation.
	Format string // "", "table", "json", "tsv"
	Wide   bool

	// Entry selectors and per-entry readers.
	Idx    int64
	Max    int64
	Full   bool
	Side   string // "req" | "res"
	JQ     string
	Lines  int
	Raw    bool
	Decode bool

	// form
	Keys bool
	Key  string

	// headers
	HeaderName string

	// curl
	Auth bool

	// slice
	Out    string
	Redact bool

	// search
	Pattern string
}

// argsFor lowers Options into the internal args struct for one command,
// including the positional arguments that command expects.
func (o Options) argsFor(cmd string) args {
	a := args{flags: map[string]string{}}

	a.f.host = o.Host
	a.f.path_ = o.Path
	a.f.url = o.URL
	a.f.mime = o.Mime
	a.f.status = o.Status
	a.f.method = o.Method
	a.f.typ = o.Type
	a.f.slow = o.Slow
	a.f.big = o.Big

	if o.HasLimit {
		a.f.limit, a.f.limitSet = o.Limit, true
		a.flags["limit"] = strconv.FormatInt(o.Limit, 10)
	}
	if o.HasFrom {
		a.f.from, a.f.fromSet = o.From, true
		a.flags["from"] = strconv.FormatInt(o.From, 10)
	}
	if o.HasTo {
		a.f.to, a.f.toSet = o.To, true
		a.flags["to"] = strconv.FormatInt(o.To, 10)
	}

	// Validate eagerly, exactly as the CLI did: a bad pattern that only failed
	// once rows existed would otherwise silently match nothing.
	for _, pat := range []string{a.f.host, a.f.path_, a.f.url, a.f.mime} {
		if pat != "" {
			ciRE(pat)
		}
	}
	if a.f.status != "" && !validStatusExpr(a.f.status) {
		die("status wants 200 | 2xx | >=400 | <=400 | !=301 | 301, got %q", a.f.status)
	}

	switch o.Format {
	case "json":
		a.flags["json"] = "1"
	case "tsv":
		a.flags["tsv"] = "1"
	}
	if o.Wide {
		a.flags["wide"] = "1"
	}
	if o.Full {
		a.flags["full"] = "1"
	}
	if o.Max > 0 {
		a.flags["max"] = strconv.FormatInt(o.Max, 10)
	}
	if o.JQ != "" {
		a.flags["jq"] = o.JQ
	}
	if o.Lines > 0 {
		a.flags["lines"] = strconv.Itoa(o.Lines)
	}
	if o.Raw {
		a.flags["raw"] = "1"
	}
	if o.Decode {
		a.flags["decode"] = "1"
	}
	if o.Keys {
		a.flags["keys"] = "1"
	}
	if o.Key != "" {
		a.flags["key"] = o.Key
	}
	if o.Auth {
		a.flags["auth"] = "1"
	}
	if o.Redact {
		a.flags["redact"] = "1"
	}
	if o.Out != "" {
		a.flags["out"] = o.Out
	}

	idx := strconv.FormatInt(o.Idx, 10)
	side := o.Side
	if side != "req" && side != "res" {
		side = "res"
	}
	switch cmd {
	case "show":
		a.rest = []string{idx}
	case "body":
		// cmdBody reads the side from positions[0] and the index after it.
		a.positions = []string{side, idx}
		a.flags["where"] = side
	case "headers":
		a.rest = []string{side, idx}
		if o.HeaderName != "" {
			a.rest = append(a.rest, o.HeaderName)
		}
	case "form":
		a.rest = []string{idx}
	case "curl":
		a.rest = []string{idx}
	case "search":
		a.positions = []string{o.Pattern}
		switch o.Side {
		case "req":
			a.flags["where"] = "req"
		case "res":
			a.flags["where"] = "res"
		default:
			a.flags["where"] = "both"
		}
	case "raw":
		a.rest = []string{idx, o.Out}
	}
	return a
}

var statusExprRe = regexp.MustCompile(`^(?:\d{3}|[1-5]xx|(?:>=|<=|!=|>|<|=)\d{3})$`)

func validStatusExpr(s string) bool { return statusExprRe.MatchString(s) }

// ---------------------------------------------------------------- HAR scan

// isArrayFrame reports whether the top of the stack is an array context.
func isArrayFrame(stack []frameT) bool { return len(stack) > 0 && stack[len(stack)-1].isArray }

// skipRestOfValue consumes the remainder of a container whose opening delimiter
// has already been read (depth starts at 1). Used to step over array-valued
// entries[] elements without desyncing the decoder.
func skipRestOfValue(dec *json.Decoder) error {
	depth := 1
	for {
		tok, err := dec.Token()
		if err != nil {
			return err
		}
		switch t := tok.(type) {
		case json.Delim:
			switch t {
			case '{', '[':
				depth++
			case '}', ']':
				depth--
				if depth == 0 {
					return nil
				}
			}
		}
	}
}

type frameT struct {
	key     string
	isArray bool
}

// scanEntry extracts one entry's summary fields by walking a JSON object with
// json.Decoder tokens (no full unmarshal — avoids allocating giant body strings).
// Key/value state machine: inside an object a string is a key; inside an array
// it is a value. waitKey tracks which one the next string is expected to be.
// errNonObject marks an entries[] element that is not an object (null or a
// bare scalar). scanFile skips such elements with an empty span instead of
// desyncing — some exporters emit null entries.
var errNonObject = errors.New("entries element is not an object")

func isSkippableElemErr(err error) bool { return errors.Is(err, errNonObject) }

// scanEntry extracts one entry's summary fields by walking a JSON object with
// json.Decoder tokens (no full unmarshal — avoids allocating giant body strings).
// Key/value state machine: inside an object a string is a key; inside an array
// it is a value. waitKey tracks which one the next string is expected to be.
func scanEntry(dec *json.Decoder) (row, error) {
	tok, err := dec.Token()
	if err != nil {
		return row{}, err
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		// Scalar elements (null, 42, "x", true) are already fully consumed by the
		// token read above. An array element has only had its '[' consumed, so the
		// rest of that array still has to be stepped over — otherwise the decoder
		// desyncs and swallows the following entries.
		if d == '[' {
			if err := skipRestOfValue(dec); err != nil {
				return row{}, err
			}
		}
		return row{}, errNonObject
	}
	var r row
	r.encoding = ""
	// r.status stays empty until a real status is seen, so a string-typed
	// "status" can still be captured; it defaults to "0" when the entry has none.
	// the entry's own '{' was consumed above; it is depth 1
	depth := 1
	var stack []frameT
	waitKey := true // entry's own keys start immediately
	lastKey := ""
	inReq, inResp, inContent, inPost := false, false, false, false
	for {
		tok, err := dec.Token()
		if err != nil {
			return r, err
		}
		switch t := tok.(type) {
		case json.Delim:
			switch t {
			case '{':
				depth++
				if lastKey == "request" && depth == 2 {
					inReq = true
				}
				if lastKey == "response" && depth == 2 {
					inResp = true
				}
				if lastKey == "content" && depth == 3 {
					inContent = true
				}
				if lastKey == "postData" && depth == 3 {
					inPost = true
				}
				stack = append(stack, frameT{key: lastKey})
				waitKey = true
			case '}':
				depth--
				if len(stack) > 0 {
					popped := stack[len(stack)-1].key
					stack = stack[:len(stack)-1]
					if popped == "request" && depth == 1 {
						inReq = false
					}
					if popped == "response" && depth == 1 {
						inResp = false
					}
					if popped == "content" && depth == 2 {
						inContent = false
					}
					if popped == "postData" && depth == 2 {
						inPost = false
					}
				}
				if depth == 0 {
					if r.status == "" {
						r.status = "0" // entry carried no usable status
					}
					return r, io.EOF // closed the entry object itself
				}
				// parent may be an object (keys resume) or an array (next is a value)
				waitKey = !isArrayFrame(stack)
				if len(stack) > 0 {
					lastKey = stack[len(stack)-1].key
				}
			case '[':
				depth++
				stack = append(stack, frameT{key: lastKey, isArray: true})
				// array contents are values, not keys
				waitKey = false
			case ']':
				depth--
				if len(stack) > 0 {
					stack = stack[:len(stack)-1]
				}
				// the parent of an array may be an object: keys resume
				waitKey = !isArrayFrame(stack)
				if len(stack) > 0 {
					lastKey = stack[len(stack)-1].key
				}
			}
		case string:
			if waitKey {
				lastKey = t
				waitKey = false
			} else {
				if depth == 1 && lastKey == "startedDateTime" && r.started == "" {
					r.started = t
				}
				applyStr(&r, inReq, inResp, inContent, inPost, lastKey, t)
				waitKey = !isArrayFrame(stack) // after a value, keys resume in objects
			}
		case json.Number:
			if v, err := t.Float64(); err == nil {
				applyNum(&r, inReq, inResp, inContent, lastKey, v)
			}
			waitKey = !isArrayFrame(stack)
		case bool:
			waitKey = !isArrayFrame(stack)
		case nil:
			waitKey = !isArrayFrame(stack)
		}
	}
}

// applyStr captures the summary string fields at their known spots.
func applyStr(r *row, inReq, inResp, inContent, inPost bool, key, v string) {
	switch {
	case inReq && key == "url" && r.url == "":
		r.url = v
		i := strings.Index(v, "://")
		if i < 0 {
			return
		}
		rest := v[i+3:]
		host := rest
		if j := strings.IndexAny(rest, "/?#"); j >= 0 {
			host = rest[:j]
		}
		if at := strings.LastIndex(host, "@"); at >= 0 {
			host = host[at+1:]
		}
		r.host = host
		p := ""
		if j := strings.IndexAny(rest, "/?#"); j >= 0 {
			p = rest[j:]
			if q := strings.IndexAny(p, "?#"); q >= 0 {
				p = p[:q]
			}
		}
		r.path = p
	case inReq && key == "method" && r.method == "":
		r.method = v
	case inPost && key == "text":
		r.reqBodyLen = int64(len(v))
	case inResp && key == "statusText":
		r.statusText = v
	case inContent && key == "mimeType":
		r.mime = v
	case inContent && key == "encoding":
		r.encoding = v
	case inContent && key == "text":
		r.textLen = int64(len(v))
	// Some HAR emitters write numeric spec fields as strings ("200", "-1").
	// Accept those so the index is not silently empty.
	case inResp && key == "status" && r.status == "":
		if n, ok := numFromStr(v); ok {
			r.status = strconv.FormatInt(n, 10)
		}
	case inResp && key == "bodySize" && r.respBytes == 0:
		if n, ok := numFromStr(v); ok && n > 0 {
			r.respBytes = n
		}
	case inContent && key == "size" && r.respBytes == 0:
		if n, ok := numFromStr(v); ok {
			r.respBytes = n
		}
	case key == "time" && !inReq && !inContent && r.ms == 0:
		// entry-level time; response.time is also accepted as a fallback
		if n, ok := numFromStr(v); ok {
			r.ms = n
		}
	}
}

// numFromStr parses a number that may be encoded as a JSON string.
func numFromStr(s string) (int64, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, false
	}
	f, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return 0, false
	}
	return int64(math.Round(f)), true
}

// applyNum captures the summary number fields.
func applyNum(r *row, inReq, inResp, inContent bool, key string, v float64) {
	n := int64(math.Round(v))
	switch {
	case inResp && key == "status":
		r.status = strconv.FormatInt(n, 10)
	case inResp && key == "bodySize" && n > 0 && r.respBytes == 0:
		r.respBytes = n
	case inContent && key == "size":
		r.respBytes = n
	case !inReq && !inResp && !inContent && key == "time":
		r.ms = n
	}
}

// scanFile streams the whole .log.entries array once, filling rows and
// recording byte spans for random access later.
func scanFile(path string) ([]row, headMeta, error) {
	var meta headMeta
	fh, err := os.Open(path)
	if err != nil {
		return nil, meta, err
	}
	defer fh.Close()
	br := bufio.NewReaderSize(fh, 1<<20)
	dec := json.NewDecoder(br)
	dec.UseNumber()

	// navigate to .log.entries (capturing .log.version / .log.creator on the way)
	var rows []row
	if err := gotoEntries(dec, &meta); err != nil {
		return nil, meta, fmt.Errorf("no .log.entries found: %w", err)
	}

	// dec is positioned right after the '[' of .log.entries. For each entry:
	// record InputOffset (logical bytes consumed), scan the entry, record the
	// offset again — BEFORE any More() lookahead for the next entry, so the
	// span never includes the separating comma or whitespace.
	for {
		if !dec.More() {
			// consume ']'
			if _, err := dec.Token(); err != nil {
				return nil, meta, err
			}
			break
		}
		start := dec.InputOffset()
		var r row
		r.idx = int64(len(rows))
		r.status = "0"
		rr, err := scanEntry(dec)
		if err != nil && err != io.EOF {
			// Non-object elements (null/scalars/arrays — some exports emit them)
			// are kept as placeholder rows so IDX stays aligned with the array
			// position, and their real span is recorded so har_extract can
			// reproduce them byte-for-byte.
			if isSkippableElemErr(err) {
				rows = append(rows, row{
					idx:         int64(len(rows)),
					status:      "0",
					startOffset: start,
					endOffset:   dec.InputOffset(),
				})
				continue
			}
			return rows, meta, err
		}
		end := dec.InputOffset()
		if os.Getenv("HARDBG3") != "" {
			fmt.Fprintf(os.Stderr, "entry %d span=%d..%d\n", len(rows), start, end)
		}
		r = rr
		r.idx = int64(len(rows))
		r.startOffset, r.endOffset = start, end
		rows = append(rows, r)
	}
	return rows, meta, nil
}

// headMeta carries the small .log header fields captured during the walk.
type headMeta struct {
	version, creatorName, creatorVersion string
}

// gotoEntries walks tokens until it consumes the '[' of .log.entries.
// Each open delim carries the key that named it; .log.entries is the array
// whose parent object was named "log" and which itself is named "entries".
// Along the way it captures .log.version and .log.creator.{name,version}.
func gotoEntries(dec *json.Decoder, meta *headMeta) error {
	type lvl struct {
		isArray bool
		key     string // the key that named this level ("" for the root)
	}
	var stack []lvl
	wantKey := false // a string token next is a key (only inside objects)
	lastKey := ""    // most recent key seen at the current level
	inCreator := false
	for {
		tok, err := dec.Token()
		if err != nil {
			return err
		}
		switch t := tok.(type) {
		case json.Delim:
			switch t {
			case '{':
				if len(stack) == 2 && stack[1].key == "log" && lastKey == "creator" {
					inCreator = true
				}
				stack = append(stack, lvl{key: lastKey})
				wantKey, lastKey = true, ""
			case '[':
				if len(stack) == 2 && !stack[0].isArray && !stack[1].isArray &&
					stack[1].key == "log" && lastKey == "entries" {
					return nil
				}
				stack = append(stack, lvl{isArray: true, key: lastKey})
				wantKey, lastKey = false, ""
			case '}', ']':
				if t == '}' && inCreator && len(stack) == 3 {
					inCreator = false
				}
				if len(stack) == 0 {
					return fmt.Errorf("no .log.entries found")
				}
				stack = stack[:len(stack)-1]
				wantKey = len(stack) > 0 && !stack[len(stack)-1].isArray
				if len(stack) > 0 {
					lastKey = stack[len(stack)-1].key
				}
			}
		case string:
			if wantKey {
				lastKey = t
				wantKey = false
			} else {
				// a string VALUE: capture header fields, then re-arm key state
				if inCreator {
					switch lastKey {
					case "name":
						meta.creatorName = t
					case "version":
						meta.creatorVersion = t
					}
				} else if len(stack) == 2 && stack[1].key == "log" && lastKey == "version" {
					meta.version = t
				}
				wantKey = len(stack) > 0 && !stack[len(stack)-1].isArray
			}
		default:
			// number/bool/null value: the next string in an object is a key
			wantKey = len(stack) > 0 && !stack[len(stack)-1].isArray
		}
	}
}

// ---------------------------------------------------------------- cache

func cachePath(path string) string {
	st, err := os.Stat(path)
	if err != nil {
		die("cannot stat %s: %v", path, err)
	}
	// The key carries path|size|mtime *and* the cache format tag, so a build with
	// different scan semantics can never be served a stale index.
	sum := md5.Sum([]byte(fmt.Sprintf("%s|%d|%d|%s", path, st.Size(), st.ModTime().UnixNano(), cacheMagic)))
	return filepath.Join(cacheDir(), fmt.Sprintf("%x.idx", sum))
}

func cacheDir() string {
	base := os.Getenv("XDG_CACHE_HOME")
	if base == "" {
		home, _ := os.UserHomeDir()
		base = filepath.Join(home, ".cache")
	}
	d := filepath.Join(base, "har-go")
	os.MkdirAll(d, 0o755)
	return d
}

// idx format (little endian):
//
//	magic cacheMagic, u32 count, 3 head strings (version, creatorName, creatorVersion)
//	then per row:
//	10 x i64 fields (idx, status, respBytes, ms, reqBodyLen, textLen,
//	     startOffset, endOffset, + 2 reserved)
//	then per-row string block: url, host, path, method, mime, encoding, statusText, started
//	  each: u32 len + bytes (u32 — URLs can exceed 64KiB)
func putHeadStrings(buf *bytes.Buffer, meta headMeta) {
	for _, s := range []string{meta.version, meta.creatorName, meta.creatorVersion} {
		var slen [4]byte
		binary.LittleEndian.PutUint32(slen[:], uint32(len(s)))
		buf.Write(slen[:])
		buf.WriteString(s)
	}
}

func saveIndex(path string, rows []row, meta headMeta) string {
	dst := cachePath(path)
	tmp := dst + ".tmp"
	var buf bytes.Buffer
	buf.WriteString(cacheMagic)
	var u32 [4]byte
	binary.LittleEndian.PutUint32(u32[:], uint32(len(rows)))
	buf.Write(u32[:])
	putHeadStrings(&buf, meta)
	var u64 [8]byte
	put := func(n int64) {
		binary.LittleEndian.PutUint64(u64[:], uint64(n))
		buf.Write(u64[:])
	}
	var strbuf bytes.Buffer
	putstr := func(s string) {
		var slen [4]byte
		binary.LittleEndian.PutUint32(slen[:], uint32(len(s)))
		strbuf.Write(slen[:])
		strbuf.WriteString(s)
	}
	for _, r := range rows {
		put(r.idx)
		put(parseI64(r.status))
		put(r.respBytes)
		put(r.ms)
		put(r.reqBodyLen)
		put(r.textLen)
		put(r.startOffset)
		put(r.endOffset)
		put(0)
		put(0)
		putstr(r.url)
		putstr(r.host)
		putstr(r.path)
		putstr(r.method)
		putstr(r.mime)
		putstr(r.encoding)
		putstr(r.statusText)
		putstr(r.started)
	}
	buf.Write(strbuf.Bytes())
	if err := os.WriteFile(tmp, buf.Bytes(), 0o644); err != nil {
		return "" // cache write failure is non-fatal
	}
	os.Rename(tmp, dst)
	sweepCache(filepath.Dir(dst))
	return dst
}

// sweepCache drops index files nobody has touched for a fortnight so the cache
// dir cannot grow without bound. Best-effort: failures are ignored, and any
// evicted HAR is merely rescanned (a 29MB file takes ~170ms).
func sweepCache(dir string) {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	cutoff := time.Now().Add(-14 * 24 * time.Hour)
	for _, e := range ents {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".idx") {
			continue
		}
		info, err := e.Info()
		if err != nil || !info.ModTime().Before(cutoff) {
			continue
		}
		os.Remove(filepath.Join(dir, e.Name()))
	}
}

func parseI64(s string) int64 { v, _ := strconv.ParseInt(s, 10, 64); return v }

func loadIndex(path string) ([]row, headMeta, bool) {
	var meta headMeta
	data, err := os.ReadFile(cachePath(path))
	if err != nil || len(data) < 24 || string(data[:8]) != cacheMagic {
		return nil, meta, false
	}
	u32 := binary.LittleEndian.Uint32(data[8:12])
	n := int(u32)
	if n < 0 || int64(n)*80+24 > int64(len(data)) {
		return nil, meta, false
	}
	// getLS reads a u32-length-prefixed string from src starting at *cur,
	// advancing the cursor. Bounds failures yield "" without advancing.
	getLS := func(src []byte, cur *int) string {
		pos := *cur
		if pos < 0 || pos+4 > len(src) {
			return ""
		}
		l := int(binary.LittleEndian.Uint32(src[pos : pos+4]))
		pos += 4
		if l < 0 || pos+l > len(src) {
			return ""
		}
		s := string(src[pos : pos+l])
		*cur = pos + l
		return s
	}
	sp := 12
	meta.version = getLS(data, &sp)
	meta.creatorName = getLS(data, &sp)
	meta.creatorVersion = getLS(data, &sp)
	if sp > len(data) {
		return nil, meta, false
	}
	numblkStart := sp // sp is now past the 3 head strings' payloads
	numblkEnd := numblkStart + n*80
	if numblkEnd > len(data) {
		return nil, meta, false
	}
	strs := data[numblkEnd:]
	ssp := 0 // cursor *relative to strs*
	rows := make([]row, 0, n)
	for i := 0; i < n; i++ {
		off := numblkStart + i*80
		g := func(k int) int64 {
			return int64(binary.LittleEndian.Uint64(data[off+k*8 : off+k*8+8]))
		}
		r := row{
			idx:         g(0),
			status:      strconv.FormatInt(g(1), 10),
			respBytes:   g(2),
			ms:          g(3),
			reqBodyLen:  g(4),
			textLen:     g(5),
			startOffset: g(6),
			endOffset:   g(7),
			url:         getLS(strs, &ssp),
			host:        getLS(strs, &ssp),
			path:        getLS(strs, &ssp),
			method:      getLS(strs, &ssp),
			mime:        getLS(strs, &ssp),
			encoding:    getLS(strs, &ssp),
			statusText:  getLS(strs, &ssp),
			started:     getLS(strs, &ssp),
		}
		rows = append(rows, r)
	}
	return rows, meta, true
}

// loadRows returns the index + header meta, scanning if needed.
func loadRows(path string) ([]row, headMeta) {
	if rows, meta, ok := loadIndex(path); ok {
		return rows, meta
	}
	rows, meta, err := scanFile(path)
	if err != nil {
		die("scan %s: %v", path, err)
	}
	saveIndex(path, rows, meta)
	return rows, meta
}

func filtered(rows []row, f filters) []row {
	var out []row
	for _, r := range rows {
		if !r.match(f) {
			continue
		}
		out = append(out, r)
	}
	return out
}

// ---------------------------------------------------------------- entry bytes

// entryJSON reads one entry's raw JSON bytes using cached offsets.
// Falls back to a full rescan when offsets are unavailable (old cache).
func entryJSON(path string, r row) []byte {
	fh, err := os.Open(path)
	if err != nil {
		die("%v", err)
	}
	defer fh.Close()
	st, _ := os.Stat(path)
	fsize := st.Size()
	if r.startOffset >= 0 && r.endOffset > r.startOffset && r.endOffset <= fsize {
		buf := make([]byte, r.endOffset-r.startOffset)
		if _, err := fh.ReadAt(buf, r.startOffset); err == nil {
			return bytes.Trim(bytes.TrimSpace(buf), ",\t \n\r")
		}
	}
	// fallback: stream-scan again
	rows, _, err := scanFile(path)
	if err != nil {
		die("rescan: %v", err)
	}
	if int(r.idx) >= len(rows) {
		die("entry %d out of range", r.idx)
	}
	rr := rows[r.idx]
	if rr.endOffset <= rr.startOffset {
		// A non-object elements[] slot with no recorded bytes (old cache).
		return []byte("null")
	}
	if rr.endOffset > fsize || rr.startOffset < 0 {
		die("entry %d span corrupt in cache — delete the .idx and retry", r.idx)
	}
	buf := make([]byte, rr.endOffset-rr.startOffset)
	fh.ReadAt(buf, rr.startOffset)
	return bytes.Trim(bytes.TrimSpace(buf), ",\t \n\r")
}

// pick reads a nested string/number out of an entry's generic map.
func pick(m map[string]any, path ...string) any {
	var cur any = m
	for _, k := range path {
		mm, ok := cur.(map[string]any)
		if !ok {
			return nil
		}
		cur = mm[k]
	}
	return cur
}

func pickStr(m map[string]any, path ...string) string {
	v := pick(m, path...)
	if v == nil {
		return ""
	}
	switch t := v.(type) {
	case string:
		return t
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64)
	default:
		return fmt.Sprint(t)
	}
}

func pickNum(m map[string]any, path ...string) float64 {
	v := pick(m, path...)
	n, _ := v.(float64)
	return n
}

// loadEntry unmarshals one entry into a generic map.
func loadEntry(path string, r row) map[string]any {
	var m map[string]any
	if err := json.Unmarshal(entryJSON(path, r), &m); err != nil {
		die("parse entry %d: %v", r.idx, err)
	}
	if m == nil {
		die("entry %d is not a HAR entry object (entries[] holds a null/scalar slot there)", r.idx)
	}
	return m
}

// ---------------------------------------------------------------- formatting

func hsz(n int64) string {
	switch {
	case n >= 1<<20:
		return fmt.Sprintf("%.1fM", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.1fK", float64(n)/(1<<10))
	default:
		return fmt.Sprintf("%db", n)
	}
}

// trunc shortens s to at most w runes (rune-aware: byte slicing would split
// CJK text mid-character). w <= 0 means "no limit".
func trunc(s string, w int) string {
	if w <= 0 || utf8.RuneCountInString(s) <= w {
		return s
	}
	r := []rune(s)
	return string(r[:w-1]) + "…"
}

// ---------------------------------------------------------------- commands

func cmdSummary(a args, path string, rows []row, meta headMeta) {
	st, _ := os.Stat(path)
	outf("file    %s\n", path)
	outf("size    %s (%d bytes)\n", hsz(st.Size()), st.Size())
	if meta.creatorName != "" {
		outf("creator %s %s\n", meta.creatorName, meta.creatorVersion)
	}
	if len(rows) > 0 {
		outf("span    %s  ..  %s\n", rows[0].started, rows[len(rows)-1].started)
	}
	outf("entries %d\n", len(rows))

	// status histogram
	hist := map[string]int64{}
	for _, r := range rows {
		hist[r.status]++
	}
	var codes []string
	for k := range hist {
		codes = append(codes, k)
	}
	sort.Strings(codes)
	parts := make([]string, 0, len(codes))
	for _, k := range codes {
		parts = append(parts, fmt.Sprintf("%s:%d", k, hist[k]))
	}
	outf("status  %s\n", strings.Join(parts, " "))

	b64, js, empty := 0, 0, 0
	for _, r := range rows {
		if r.encoding == "base64" {
			b64++
		}
		if strings.Contains(r.mime, "json") {
			js++
		}
		if r.textLen == 0 {
			empty++
		}
	}
	outf("bodies  base64=%d  json=%d  empty=%d\n", b64, js, empty)

	// per-host aggregation
	type hs struct {
		n, paths int64
		bad      int64
		bytes    int64
		maxms    int64
	}
	agg := map[string]*hs{}
	pathSet := map[string]map[string]bool{}
	for _, r := range rows {
		if !r.isEntry() {
			continue
		}
		h := agg[r.host]
		if h == nil {
			h = &hs{}
			agg[r.host] = h
			pathSet[r.host] = map[string]bool{}
		}
		h.n++
		h.bytes += r.respBytes
		if r.ms > h.maxms {
			h.maxms = r.ms
		}
		if c := parseI64(r.status); c >= 400 || c == 0 {
			h.bad++
		}
		pathSet[r.host][r.path] = true
	}
	hasMS := false
	for _, r := range rows {
		if r.ms > 0 {
			hasMS = true
		}
	}
	if hasMS {
		outln("\n-- hosts: n  uniqPaths  errs  MB  slowest_ms  host --")
	} else {
		outln("\n-- hosts: n  uniqPaths  errs  MB  host --")
	}
	type hrow struct {
		name       string
		n, np, bad int64
		mb         float64
		mx         int64
	}
	var hrs []hrow
	for name, h := range agg {
		hrs = append(hrs, hrow{name, h.n, int64(len(pathSet[name])), h.bad, float64(h.bytes) / (1 << 20), h.maxms})
	}
	sort.Slice(hrs, func(i, j int) bool {
		if hrs[i].n != hrs[j].n {
			return hrs[i].n > hrs[j].n
		}
		return hrs[i].name < hrs[j].name
	})
	for i, h := range hrs {
		if i >= 25 {
			break
		}
		if hasMS {
			outf("  %5d %8d %5d %6.1fM %9d  %s\n", h.n, h.np, h.bad, h.mb, h.mx, h.name)
		} else {
			outf("  %5d %8d %5d %6.1fM  %s\n", h.n, h.np, h.bad, h.mb, h.name)
		}
	}

	// largest 5 (skip slowest if no timings)
	if hasMS {
		srt := entryRows(rows)
		sort.Slice(srt, func(i, j int) bool {
			if srt[i].ms != srt[j].ms {
				return srt[i].ms > srt[j].ms
			}
			return srt[i].idx < srt[j].idx
		})
		outln("\n-- slowest --")
		for i := 0; i < len(srt) && i < 5; i++ {
			r := srt[i]
			outf("  #%-5d %6d ms  %-4s %-4s %s%s\n", r.idx, r.ms, r.method, r.status, r.host, trunc(r.path, 60))
		}
	}
	srt := entryRows(rows)
	sort.Slice(srt, func(i, j int) bool {
		if srt[i].respBytes != srt[j].respBytes {
			return srt[i].respBytes > srt[j].respBytes
		}
		return srt[i].idx < srt[j].idx
	})
	outln("\n-- largest --")
	for i := 0; i < len(srt) && i < 5; i++ {
		r := srt[i]
		outf("  #%-5d %8s  %-4s %-4s %s%s\n", r.idx, hsz(r.respBytes), r.method, r.status, r.host, trunc(r.path, 55))
	}
	outln("\nnext: har_paths | har_list with a host filter | har_search | har_show")
}

func cmdList(a args, path string, rows []row) {
	// every format is row-capped: default 200, limit changes it, limit 0 = no cap
	limit := int64(200)
	if _, ok := a.flags["limit"]; ok {
		limit = a.f.limit // validated non-negative in parseArgs
	}
	all := filtered(rows, a.f)
	sel := all
	if limit > 0 && int64(len(sel)) > limit {
		sel = sel[:limit]
	}
	switch {
	case a.flags["tsv"] == "1":
		for _, r := range sel {
			outf("%d\t%s\t%s\t%s\t%s\t%s\t%d\t%d\t%d\t%s\t%s\t%d\t%s\n",
				r.idx, r.method, r.status, r.host, r.path, r.mime, r.respBytes, r.ms,
				r.reqBodyLen, r.encoding, r.statusText, r.textLen, r.url)
		}
		if len(sel) < len(all) {
			outf("# capped %d/%d matches (pass limit: 0 for all)\n", len(sel), len(all))
		}
	case a.flags["json"] == "1":
		type jrow struct {
			Idx        int64  `json:"idx"`
			Method     string `json:"method"`
			Status     int64  `json:"status"`
			Host       string `json:"host"`
			Path       string `json:"path"`
			Mime       string `json:"mime"`
			Bytes      int64  `json:"bytes"`
			Ms         int64  `json:"ms"`
			ReqBytes   int64  `json:"reqBytes"`
			Encoding   string `json:"encoding"`
			StatusText string `json:"statusText"`
			TextLen    int64  `json:"textLen"`
			URL        string `json:"url"`
		}
		out := make([]jrow, 0, len(sel))
		for _, r := range sel {
			out = append(out, jrow{r.idx, r.method, parseI64(r.status), r.host, r.path,
				r.mime, r.respBytes, r.ms, r.reqBodyLen, r.encoding, r.statusText, r.textLen, r.url})
		}
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		enc.Encode(out)
	default:
		w := 74
		if a.flags["wide"] == "1" {
			w = 200
		}
		outf("%-5s %-5s %-4s %-7s %-28s %s\n", "IDX", "MTH", "CODE", "SIZE", "HOST", "PATH")
		for _, r := range sel {
			if !r.isEntry() {
				outf("%-5d %-5s %-4s %-7s %-28s %s\n", r.idx, "-", "-", "-", "", "(not an entry object)")
				continue
			}
			outf("%-5d %-5s %-4s %-7s %-28s %s\n", r.idx, trunc(r.method, 5), r.status, hsz(r.respBytes), trunc(r.host, 28), trunc(r.path, w))
		}
		if len(sel) < len(all) {
			outf("# %d shown of %d/%d entries match (pass limit: 0 for all)\n", len(sel), len(all), len(rows))
		} else {
			outf("# %d/%d entries match\n", len(all), len(rows))
		}
	}
}

func cmdCount(a args, path string, rows []row) {
	sel := filtered(rows, a.f)
	outln(len(sel))
}

func cmdHosts(a args, path string, rows []row) {
	sel := filtered(rows, a.f)
	type hs struct {
		n, bad, bytes int64
		paths         map[string]bool
	}
	agg := map[string]*hs{}
	for _, r := range sel {
		if !r.isEntry() {
			continue
		}
		h := agg[r.host]
		if h == nil {
			h = &hs{paths: map[string]bool{}}
			agg[r.host] = h
		}
		h.n++
		h.bytes += r.respBytes
		if c := parseI64(r.status); c >= 400 || c == 0 {
			h.bad++
		}
		h.paths[r.path] = true
	}
	type hr struct {
		name       string
		n, np, bad int64
		mb         float64
	}
	var out []hr
	for name, h := range agg {
		out = append(out, hr{name, h.n, int64(len(h.paths)), h.bad, float64(h.bytes) / (1 << 20)})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].n != out[j].n {
			return out[i].n > out[j].n
		}
		return out[i].name < out[j].name
	})
	lim := int64(100)
	if v, ok := a.flags["limit"]; ok {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil {
			if n <= 0 {
				n = math.MaxInt32 // 0 = no cap
			}
			lim = n
		}
	}
	for i, h := range out {
		if int64(i) >= lim {
			break
		}
		outf("%-5d %-8d %-5d %-9s %s\n", h.n, h.np, h.bad, fmt.Sprintf("%.2fM", h.mb), h.name)
	}
}

func cmdPaths(a args, path string, rows []row) {
	sel := filtered(rows, a.f)
	type ps struct {
		n, bad, bytes, ms int64
		meth              map[string]bool
		codes             map[string]bool
	}
	agg := map[string]*ps{}
	for _, r := range sel {
		if !r.isEntry() {
			continue
		}
		k := r.host + r.path
		h := agg[k]
		if h == nil {
			h = &ps{meth: map[string]bool{}, codes: map[string]bool{}}
			agg[k] = h
		}
		h.n++
		h.bytes += r.respBytes
		h.ms += r.ms
		h.meth[r.method] = true
		h.codes[r.status] = true
		if c := parseI64(r.status); c >= 400 || c == 0 {
			h.bad++
		}
	}
	type pr struct {
		k           string
		n, bad      int64
		kb          float64
		avg         int64
		meth, codes string
	}
	var out []pr
	for k, h := range agg {
		ms := []string{}
		for m := range h.meth {
			ms = append(ms, m)
		}
		sort.Strings(ms)
		cs := []string{}
		for c := range h.codes {
			cs = append(cs, c)
		}
		sort.Strings(cs)
		avg := int64(0)
		if h.n > 0 {
			avg = h.ms / h.n
		}
		out = append(out, pr{k, h.n, h.bad, float64(h.bytes) / 1024, avg, strings.Join(ms, "/"), strings.Join(cs, ",")})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].n != out[j].n {
			return out[i].n > out[j].n
		}
		return out[i].k < out[j].k
	})
	lim := int64(40)
	if v, ok := a.flags["limit"]; ok {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil {
			if n <= 0 {
				n = math.MaxInt32 // 0 = no cap
			}
			lim = n
		}
	}
	w := 74
	if a.flags["wide"] == "1" {
		w = 130
	}
	hasMS := false
	for _, r := range rows {
		if r.ms > 0 {
			hasMS = true
		}
	}
	if hasMS {
		outf("%-5s %-8s %-7s %-4s %-6s %-11s %s\n", "HITS", "KB", "AVG", "ERR", "MTH", "CODES", "ENDPOINT")
	} else {
		outf("%-5s %-8s %-4s %-6s %-11s %s\n", "HITS", "KB", "ERR", "MTH", "CODES", "ENDPOINT")
	}
	for i, h := range out {
		if int64(i) >= lim {
			break
		}
		if hasMS {
			outf("%-5d %-8.1f %-7s %-4d %-6s %-11s %s\n", h.n, h.kb, fmt.Sprintf("%dms", h.avg), h.bad, h.meth, h.codes, trunc(h.k, w))
		} else {
			outf("%-5d %-8.1f %-4d %-6s %-11s %s\n", h.n, h.kb, h.bad, h.meth, h.codes, trunc(h.k, w))
		}
	}
}

func checkIdx(rows []row, idx int64) {
	if idx < 0 || int64(len(rows)) <= idx {
		die("index %d out of range (0..%d) — see har_list", idx, len(rows)-1)
	}
}

func cmdShow(a args, path string, rows []row) {
	if len(a.rest) == 0 {
		die("show needs an entry index (idx)")
	}
	idx, err := strconv.ParseInt(a.rest[0], 10, 64)
	if err != nil {
		die("entry index must be a number, got %q", a.rest[0])
	}
	checkIdx(rows, idx)
	r := rows[idx]
	m := loadEntry(path, r)
	max := int64(800)
	if a.flags["full"] == "1" {
		max = math.MaxInt64 / 4
	}
	if v, ok := a.flags["max"]; ok {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil || n <= 0 {
			die("--max wants a positive number of chars, got %q", v)
		}
		max = n
	}
	req, _ := pick(m, "request").(map[string]any)
	resp, _ := pick(m, "response").(map[string]any)
	outf("### #%d  %s %s\n", r.idx, pickStr(req, "method"), pickStr(req, "url"))
	outf("time: %s  dur=%dms  status=%s %s  mime=%s  respBytes=%d  reqBodyLen=%d  encoding=%s\n",
		pickStr(m, "startedDateTime"), int64(math.Round(pickNum(m, "time"))), r.status,
		pickStr(resp, "statusText"), pickStr(resp, "content", "mimeType"),
		int64(math.Round(pickNum(resp, "content", "size"))),
		lenStr(pick(req, "postData", "text")),
		pickStr(resp, "content", "encoding"))

	dumpHeaders(req, max)
	if pb := lenStr(pick(req, "postData", "text")); pb > 0 {
		outf("-- request body: %d chars  (har_body idx=%d side=req to inspect) --\n", pb, r.idx)
		outln(trunc(pickStr(req, "postData", "text"), int(max)))
	}
	dumpHeaders(resp, max)
	ct, _ := pick(resp, "content").(map[string]any)
	if rb := lenStr(pick(ct, "text")); rb > 0 {
		enc := pickStr(ct, "encoding")
		outf("-- response body: %d chars, encoding=%s  (har_body idx=%d side=res to inspect) --\n", rb, enc, r.idx)
		if enc == "base64" {
			outf("# binary — decode with: har_raw idx=%d out=<path>\n", r.idx)
		} else {
			outln(trunc(pickStr(ct, "text"), int(max)))
		}
	}
}

func lenStr(v any) int64 {
	if s, ok := v.(string); ok {
		return int64(len(s))
	}
	return 0
}

func dumpHeaders(node any, max int64) {
	hdrs, ok := node.(map[string]any)["headers"].([]any)
	if !ok {
		return
	}
	label := "request"
	if mm, ok := node.(map[string]any); ok {
		if u := pickStr(mm, "url"); u != "" {
			label = "request"
		}
		if _, isResp := mm["status"]; isResp {
			label = "response"
		}
	}
	outf("-- %s headers --\n", label)
	for _, h := range hdrs {
		hm, ok := h.(map[string]any)
		if !ok {
			continue
		}
		outf("%s: %s\n", pickStr(hm, "name"), trunc(pickStr(hm, "value"), int(max)))
	}
}

func cmdBody(a args, path string, rows []row) {
	// body takes the side (req|res) and the entry index from argsFor
	where := a.flags["where"]
	var rest []string
	if len(a.positions) > 0 && (a.positions[0] == "req" || a.positions[0] == "res") {
		where = a.positions[0]
		rest = a.positions[1:]
	} else {
		rest = a.positions
	}
	if where == "" || where == "both" {
		where = "res"
	}
	if len(rest) == 0 {
		die("body needs an entry index (idx)")
	}
	idx, err := strconv.ParseInt(rest[0], 10, 64)
	if err != nil {
		die("index must be a number, got %q", rest[0])
	}
	checkIdx(rows, idx)
	r := rows[idx]
	m := loadEntry(path, r)
	var body string
	if where == "req" {
		body = pickStr(m, "request", "postData", "text")
	} else {
		body = pickStr(m, "response", "content", "text")
		if a.flags["decode"] != "1" && pickStr(m, "response", "content", "encoding") == "base64" {
			raw, err := base64.StdEncoding.DecodeString(body)
			if err != nil {
				die("base64 decode: %v", err)
			}
			if a.flags["raw"] == "1" {
				stdout.Write(raw)
			} else {
				previewBody(raw, a)
			}
			return
		}
	}
	if a.flags["raw"] == "1" {
		outs(body)
		return
	}
	if jf := a.flags["jq"]; jf != "" {
		applyMiniJQ(body, jf)
		return
	}
	previewBody([]byte(body), a)
}

func previewBody(b []byte, a args) {
	// pretty-print JSON, else truncate text lines
	// json.Number keeps 18-digit IDs intact: decoding into `any` would turn them
	// into float64 and print ...45680 where the wire had ...45678.
	if v, ok := decodeJSONStrict(string(b)); ok {
		if _, isStr := v.(string); !isStr {
			p, err := json.MarshalIndent(v, "", "  ")
			if err != nil {
				p = b
			}
			lines := bytes.Split(p, []byte("\n"))
			lim := 200
			if v, ok := a.flags["lines"]; ok {
				lim, _ = strconv.Atoi(v)
			}
			for i, l := range lines {
				if i >= lim {
					outf("… (truncated at %d lines — pass lines: N, or use jq for one field)\n", lim)
					break
				}
				stdout.Write(l)
				outln()
			}
			return
		}
	}
	lines := bytes.Split(b, []byte("\n"))
	lim := 200
	if v, ok := a.flags["lines"]; ok {
		lim, _ = strconv.Atoi(v)
	}
	for i, l := range lines {
		if i >= lim {
			outf("… (truncated at %d lines)\n", lim)
			break
		}
		outln(trunc(string(l), 400))
	}
}

// applyMiniJQ supports the small subset agents actually use:
//
//	.a.b.c          field path -> prints value (pretty if object/array)
//	.a | keys       top-level keys of subobject
//	keys            keys of root
//
// splitPath turns "a.b[0].c[2][\"d\"]" into segments: key a, key b, idx 0, key c, idx 2, key d.
type pathSeg struct {
	val   string
	index bool
}

func splitPath(p string) []pathSeg {
	var segs []pathSeg
	p = strings.TrimPrefix(p, ".")
	i := 0
	cur := strings.Builder{}
	flush := func() {
		if cur.Len() > 0 {
			segs = append(segs, pathSeg{val: cur.String()})
			cur.Reset()
		}
	}
	for i < len(p) {
		switch c := p[i]; c {
		case '.':
			flush()
			i++
		case '[':
			flush()
			j := strings.IndexByte(p[i:], ']')
			if j < 0 {
				die("jq: unclosed [ in path %q", p)
			}
			inner := p[i+1 : i+j]
			inner = strings.Trim(inner, "'\"")
			segs = append(segs, pathSeg{val: inner, index: !strings.ContainsAny(p[i+1:i+j], "\"'")})
			i += j + 1
		default:
			cur.WriteByte(c)
			i++
		}
	}
	flush()
	return segs
}

// Anything else: error explaining the subset.
func applyMiniJQ(body, expr string) {
	// json.Number, not float64: extracting .user.id must not round an 18-digit ID.
	v, ok := decodeJSONStrict(body)
	if !ok {
		// not JSON: print raw (maybe user wants text)
		outs(body)
		return
	}
	cur := v
	expr = strings.TrimSpace(expr)
	expr = strings.TrimPrefix(expr, ".")
	pipeParts := strings.Split(expr, "|")
	for pi, part := range pipeParts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if part == "keys" {
			mm, ok := cur.(map[string]any)
			if !ok {
				die("jq keys: current node is not an object")
			}
			ks := make([]string, 0, len(mm))
			for k := range mm {
				ks = append(ks, k)
			}
			sort.Strings(ks)
			if pi == len(pipeParts)-1 {
				out, _ := json.MarshalIndent(ks, "", "  ")
				outln(string(out))
			} else {
				die("keys must be the last jq segment")
			}
			return
		}
		// field path: .a.b, .a[0].b, [0], .a["b"]
		for _, seg := range splitPath(part) {
			switch {
			case seg.index:
				n, err := strconv.Atoi(seg.val)
				if err != nil {
					die("jq: bad index [%s]", seg.val)
				}
				arr, ok := cur.([]any)
				if !ok {
					die("jq: %s is not an array", seg.val)
				}
				if n < 0 {
					n += len(arr) // jq-style negative index
				}
				if n < 0 || n >= len(arr) {
					die("jq: index %d out of range (array has %d)", n, len(arr))
				}
				cur = arr[n]
			default:
				mm, ok := cur.(map[string]any)
				if !ok {
					die("jq: %q is not an object (pass raw: true for the whole body)", seg.val)
				}
				cur = mm[seg.val]
			}
		}
	}
	out, err := json.MarshalIndent(cur, "", "  ")
	if err != nil {
		die("jq: %v", err)
	}
	outln(string(out))
}

func cmdHeaders(a args, path string, rows []row) {
	// har headers req|res IDX [regex] — a.rest already excludes the file argument
	where := "req"
	rest := a.rest
	if len(rest) > 0 && (rest[0] == "req" || rest[0] == "res" ||
		rest[0] == "request" || rest[0] == "response") {
		switch rest[0] {
		case "res", "response":
			where = "res"
		}
		rest = rest[1:]
	} else {
		rest = a.rest
	}
	if len(rest) == 0 {
		die("headers needs an entry index (idx)")
	}
	idx, err := strconv.ParseInt(rest[0], 10, 64)
	if err != nil {
		die("index must be a number")
	}
	checkIdx(rows, idx)
	m := loadEntry(path, rows[idx])
	node := pick(m, "request")
	if where == "res" {
		node = pick(m, "response")
	}
	nm, _ := node.(map[string]any)
	hdrs, _ := nm["headers"].([]any)
	var pat *regexp.Regexp
	if len(rest) > 1 {
		pat = ciRE(rest[1])
	}
	for _, h := range hdrs {
		hm, ok := h.(map[string]any)
		if !ok {
			continue
		}
		name, val := pickStr(hm, "name"), pickStr(hm, "value")
		if pat != nil && !pat.MatchString(name) {
			continue
		}
		outf("%s: %s\n", name, val)
	}
}

func cmdForm(a args, path string, rows []row) {
	if len(a.rest) == 0 {
		die("form needs an entry index (idx)")
	}
	idx, err := strconv.ParseInt(a.rest[0], 10, 64)
	if err != nil {
		die("index must be a number")
	}
	checkIdx(rows, idx)
	m := loadEntry(path, rows[idx])
	body := pickStr(m, "request", "postData", "text")
	mt := pickStr(m, "request", "postData", "mimeType")
	outf("# entry #%d  postData.mimeType=%s\n", idx, mt)
	only, keysMode := a.flags["key"], a.flags["keys"] == "1"
	n := 0
	for _, pair := range strings.Split(body, "&") {
		if pair == "" {
			continue
		}
		k, v := pair, ""
		if i := strings.Index(pair, "="); i >= 0 {
			k, v = pair[:i], pair[i+1:]
		}
		k = urlDecode(k)
		v = urlDecode(v)
		if only != "" && !strings.EqualFold(k, only) {
			continue
		}
		if keysMode {
			outln(k)
			continue
		}
		outf("%-28s = %s\n", k, trunc(v, 160))
		n++
		if n >= 60 {
			outf("# (60 pairs shown) per-key: har_form idx=%d key=NAME\n", idx)
			break
		}
	}
}

func urlDecode(s string) string {
	r := strings.NewReplacer("+", " ")
	s = r.Replace(s)
	var out []byte
	for i := 0; i < len(s); i++ {
		if s[i] == '%' && i+2 < len(s) {
			if v, err := strconv.ParseUint(s[i+1:i+3], 16, 8); err == nil {
				out = append(out, byte(v))
				i += 2
				continue
			}
		}
		out = append(out, s[i])
	}
	return string(out)
}

var dropHeaders = map[string]bool{
	"host": true, "content-length": true, "connection": true,
	"accept-encoding": true, "proxy-connection": true, "content-type": false,
}

func cmdCurl(a args, path string, rows []row) {
	if len(a.rest) == 0 {
		die("curl needs an entry index (idx)")
	}
	idx, err := strconv.ParseInt(a.rest[0], 10, 64)
	if err != nil {
		die("index must be a number")
	}
	checkIdx(rows, idx)
	m := loadEntry(path, rows[idx])
	req, _ := pick(m, "request").(map[string]any)
	if req == nil {
		die("entry has no request")
	}
	keepAuth := a.flags["auth"] == "1"
	sq := func(s string) string { return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'" }
	meth := pickStr(req, "method")
	url := pickStr(req, "url")
	outf("curl -sS -i -X %s %s", meth, sq(url))
	hdrs, _ := req["headers"].([]any)
	for _, h := range hdrs {
		hm, ok := h.(map[string]any)
		if !ok {
			continue
		}
		name, val := pickStr(hm, "name"), pickStr(hm, "value")
		lower := strings.ToLower(name)
		switch {
		case dropHeaders[lower] && lower != "content-type":
			continue
		case !keepAuth && (lower == "cookie" || lower == "authorization" || lower == "proxy-authorization"):
			continue
		}
		outf(" \\\n  -H %s", sq(name+": "+val))
	}
	if pb := lenStr(pick(req, "postData", "text")); pb > 0 {
		body := pickStr(req, "postData", "text")
		full := body
		if len(body) > 200 {
			body = body[:200]
		}
		outf(" \\\n  --data-binary %s", sq(body))
		if len(full) > 200 {
			outf("   # body truncated to 200 of %d chars; full body: har_body idx=%d side=req raw=true", len(full), idx)
		}
	}
	outln()
}

func cmdSearch(a args, path string, rows []row) {
	// argsFor puts the pattern in positions[0]; the CLI used to pick it out of
	// a mixed positional list, which no longer exists.
	pat := ""
	if len(a.positions) > 0 {
		pat = a.positions[0]
	}
	if pat == "" {
		die("search needs a pattern (regex)")
	}
	re := ciRE(pat)
	where := a.flags["where"]
	if where == "" {
		where = "both"
	}
	sel := filtered(rows, a.f)
	lim := int64(40)
	if v, ok := a.flags["limit"]; ok {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil {
			if n <= 0 {
				n = math.MaxInt32 // 0 = no cap
			}
			lim = n
		}
	}
	fh, err := os.Open(path)
	if err != nil {
		die("%v", err)
	}
	defer fh.Close()
	n := int64(0)
	for _, r := range sel {
		if n >= lim {
			outf("… capped at %d matches (raise limit to see more)\n", lim)
			return
		}
		buf := entryJSON(path, r)
		var m map[string]any
		if json.Unmarshal(buf, &m) != nil {
			continue
		}
		type pair struct {
			src, txt string
		}
		var pairs []pair
		if where == "req" || where == "both" {
			pairs = append(pairs, pair{"req", pickStr(m, "request", "postData", "text")})
		}
		if where == "res" || where == "both" {
			pairs = append(pairs, pair{"res", pickStr(m, "response", "content", "text")})
		}
		for _, pr := range pairs {
			if pr.txt == "" {
				continue
			}
			for li, line := range strings.Split(pr.txt, "\n") {
				if re.MatchString(line) {
					n++
					if n > lim {
						outf("… capped at %d matches (raise limit to see more)\n", lim)
						return
					}
					outf("#%d %s L%d [%s] %s\n", r.idx, pr.src, li+1, r.status, trunc(line, 200))
				}
			}
		}
	}
}

func cmdRaw(a args, path string, rows []row) {
	// raw takes the entry index and an output path from argsFor
	rest := a.rest
	// "-" and stdout are fine, but writing onto the source file would destroy it
	if len(rest) > 1 && rest[1] != "-" {
		if abs, err := filepath.Abs(rest[1]); err == nil && abs == path {
			die("refusing to write output onto the source HAR (%s) — pick another outfile", path)
		}
	}
	if len(rest) == 0 {
		die("raw needs an entry index (idx)")
	}
	idx, err := strconv.ParseInt(rest[0], 10, 64)
	if err != nil {
		die("index must be a number")
	}
	checkIdx(rows, idx)
	m := loadEntry(path, rows[idx])
	body := pickStr(m, "response", "content", "text")
	out := stdout
	outName := "-"
	if len(rest) > 1 {
		f, err := os.Create(rest[1])
		if err != nil {
			die("%v", err)
		}
		defer f.Close()
		out = f
		outName = rest[1]
	}
	if pickStr(m, "response", "content", "encoding") == "base64" {
		raw, derr := base64.StdEncoding.DecodeString(body)
		if derr != nil {
			die("base64 decode: %v", derr)
		}
		out.Write(raw)
	} else {
		io.WriteString(out, body)
	}
	if outName != "-" {
		st, _ := os.Stat(outName)
		kind := ""
		if b, err := exec.Command("file", "-b", outName).Output(); err == nil {
			kind = strings.TrimSpace(string(b))
		}
		outf("%s  %s  (%s)\n", outName, trunc(kind, 60), hsz(st.Size()))
	}
}

var redactKeys = regexp.MustCompile(`(?i)^(tok(en)?|access[-_]?token|refresh[-_]?token|id[-_]?token|authorization|cookie|sign(ature)?|password|passwd|secret|api[-_]?key|apikey|utoken|u2at|u2st|session[-_]?id|open[-_]?id|union[-_]?id|device[-_]?id|imei|idfa|oaid|mtgsig|csecuuid|uuid|lat(itude)?|lng|longitude|poiid|cityid|order[-_]?id|trade[-_]?no|phone|mobile|tel|email)$`)

var redactURLKeys = regexp.MustCompile(`(?i)(token|sign|uuid|utoken|session_?id|userid|imei|idfa|open_?id|union_?id|\blat\b|\blng\b|latitude|longitude|location|poiid|cityid|msid|accesstoken|utm_)`)

func redactWalk(v any) any {
	switch t := v.(type) {
	case map[string]any:
		for k, vv := range t {
			if redactKeys.MatchString(k) {
				t[k] = "<redacted>"
			} else {
				t[k] = redactWalk(vv)
			}
		}
		return t
	case []any:
		for i := range t {
			t[i] = redactWalk(t[i])
		}
		return t
	case string:
		// APIs commonly nest a JSON document inside a string field; walk it too.
		if inner := tryRedactJSON(t); inner != nil {
			return *inner
		}
		// Likewise a nested form-urlencoded payload.
		if strings.Contains(t, "=") {
			if fb := redactFormBody(t); fb != t {
				return fb
			}
		}
		// Opaque credentials under keys that name nothing (session UUIDs,
		// device ids) are only recognizable by shape.
		if looksLikeCredential(t) {
			return "<redacted>"
		}
		return t
	default:
		return v
	}
}

// tryRedactJSON returns a re-serialized, redacted copy of s when s is itself a
// JSON object/array (stringified JSON), else nil.
func tryRedactJSON(s string) *string {
	t := strings.TrimSpace(s)
	if len(t) < 2 || (t[0] != '{' && t[0] != '[') {
		return nil
	}
	v, ok := decodeJSONStrict(t)
	if !ok {
		return nil
	}
	if _, isStr := v.(string); isStr {
		return nil
	}
	out, err := marshalNoEscape(redactWalk(v))
	if err != nil {
		return nil
	}
	return &out
}

// decodeJSONStrict decodes one complete JSON document, keeping numbers as
// json.Number so 18-digit IDs survive (float64 would round them) and rejecting
// trailing garbage that would otherwise yield a truncated re-encode.
func decodeJSONStrict(s string) (any, bool) {
	dec := json.NewDecoder(strings.NewReader(s))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, false
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, false
	}
	return v, true
}

// marshalNoEscape renders JSON without HTML escaping (<) so redacted
// bodies stay byte-comparable to the original apart from the redactions.
func marshalNoEscape(v any) (string, error) {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return "", err
	}
	return strings.TrimRight(b.String(), "\n"), nil
}

// redactFormBody sanitizes an application/x-www-form-urlencoded body, keying off
// redactURLKeys. Returns s unchanged unless it looks like form pairs.
func redactFormBody(s string) string {
	if s == "" || !strings.Contains(s, "=") {
		return s
	}
	fields := strings.Split(s, "&")
	out := make([]string, len(fields))
	changed, pairs := false, 0
	for i, kv := range fields {
		eq := strings.IndexByte(kv, '=')
		if eq < 0 {
			out[i] = kv
			continue
		}
		pairs++
		if sensitiveKey(kv[:eq]) || looksLikeCredential(kv[eq+1:]) {
			out[i] = kv[:eq] + "=<redacted>"
			changed = true
		} else {
			out[i] = kv
		}
	}
	if pairs == 0 || !changed {
		return s
	}
	return strings.Join(out, "&")
}

func redactBody(s string) string {
	if s == "" {
		return s
	}
	if v, ok := decodeJSONStrict(s); ok {
		if _, isStr := v.(string); !isStr {
			if out, err := marshalNoEscape(redactWalk(v)); err == nil {
				return out
			}
			return s
		}
	}
	// not a JSON document — try form-urlencoded before giving up
	return redactFormBody(s)
}

// redactPairs redacts sensitive keys in a query/fragment string while
// preserving the original separators ('&' vs ';') and segment order.
func redactPairs(q string) string {
	var b strings.Builder
	for i := 0; i < len(q); {
		j := i
		for j < len(q) && q[j] != '&' && q[j] != ';' {
			j++
		}
		seg := q[i:j]
		if eq := strings.IndexByte(seg, '='); eq > 0 && (sensitiveKey(seg[:eq]) || looksLikeCredential(seg[eq+1:])) {
			b.WriteString(seg[:eq])
			b.WriteString("=<redacted>")
		} else {
			b.WriteString(seg)
		}
		if j < len(q) {
			b.WriteByte(q[j])
			j++
		}
		i = j
	}
	return b.String()
}

var (
	// lat,lng pairs (e.g. /latlng/22.759952,-1.2345) — often in the URL *path*,
	// where no key name is available to key off.
	coordPair = regexp.MustCompile(`-?\d{1,3}\.\d{3,},\s*-?\d{1,3}\.\d{3,}`)
	// a single decimal coordinate straight after a lat/lng-ish marker segment
	coordAfterMarker = regexp.MustCompile(`(?i)((?:latlng|lat[-_,]?lng|geo|position|loc)[/=])-?\d{1,3}\.\d{3,}`)
)

func redactURL(u string) string {
	if u == "" {
		return u
	}
	u = coordPair.ReplaceAllString(u, "<redacted>")
	u = coordAfterMarker.ReplaceAllString(u, "${1}<redacted>")
	// The fragment can carry credentials too (OAuth implicit flow puts the
	// access token after '#'); redact it with the same key rules.
	frag := ""
	if fi := strings.IndexByte(u, '#'); fi >= 0 {
		frag = "#" + redactPairs(u[fi+1:])
		u = u[:fi]
	}
	qi := strings.IndexByte(u, '?')
	if qi >= 0 {
		u = u[:qi] + "?" + redactPairs(u[qi+1:])
	}
	return u + frag
}

var redactHdrs = regexp.MustCompile(`(?i)author|cookie|token|secret|api.?key|sign|password|session|jwt|bearer|ticket|mtgsig|utoken|u2at|u2st|userid|yoda|lsid|oauth|nonce|deviceid|uuid|umt|dlt|traceid|logid|cryptkey|csec|\blat\b|\blng\b|latitude|longitude|^t$`)

// sensitiveKey reports whether a parameter name (query key, form field, or
// postData.params entry) names something that must not reach an output file.
func sensitiveKey(k string) bool {
	return redactKeys.MatchString(k) || redactURLKeys.MatchString(k)
}

// looksLikeCredential catches opaque credentials carried in fields whose *name*
// gives nothing away (CN apps stuff device ids into arbitrary headers):
// long hex digests, UUIDs, and three-part JWTs.
var looksLikeCredentialRe = regexp.MustCompile(`(?i)^(?:uuid:)?(?:[0-9a-f]{32,}|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{8,})$`)

func looksLikeCredential(v string) bool {
	return len(v) >= 32 && looksLikeCredentialRe.MatchString(strings.TrimSpace(v))
}

// redactCookieArr blanks every cookie value: a cookie jar is a credential
// store, so the name is not what decides sensitivity here.
func redactCookieArr(v any) {
	arr, ok := v.([]any)
	if !ok {
		return
	}
	for _, c := range arr {
		if cm, ok := c.(map[string]any); ok {
			if _, has := cm["value"]; has {
				cm["value"] = "<redacted>"
			}
		}
	}
}

// redactParams blanks value in name/value pair arrays (postData.params[],
// request.queryString[]). Spec-legal and emitted by Chrome, but easy to miss.
func redactParams(v any) {
	arr, ok := v.([]any)
	if !ok {
		return
	}
	for _, p := range arr {
		pm, ok := p.(map[string]any)
		if !ok {
			continue
		}
		if sensitiveKey(pickStr(pm, "name")) {
			pm["value"] = "<redacted>"
		}
	}
}

func redactEntry(m map[string]any) {
	if req, ok := m["request"].(map[string]any); ok {
		if pd, ok := req["postData"].(map[string]any); ok {
			if s, ok := pd["text"].(string); ok {
				pd["text"] = redactBody(s)
			}
			redactParams(pd["params"])
		}
		if u, ok := req["url"].(string); ok {
			req["url"] = redactURL(u)
		}
		redactHeaders(req["headers"])
		redactCookieArr(req["cookies"])
		redactParams(req["queryString"])
	}
	if resp, ok := m["response"].(map[string]any); ok {
		if c, ok := resp["content"].(map[string]any); ok {
			if s, ok := c["text"].(string); ok {
				c["text"] = redactBody(s)
			}
		}
		redactHeaders(resp["headers"])
		redactCookieArr(resp["cookies"])
	}
}

func redactHeaders(v any) {
	hs, ok := v.([]any)
	if !ok {
		return
	}
	for _, h := range hs {
		if hm, ok := h.(map[string]any); ok {
			if redactHdrs.MatchString(pickStr(hm, "name")) || looksLikeCredential(pickStr(hm, "value")) {
				hm["value"] = "<redacted>"
			}
		}
	}
}

// headVals carries raw JSON for the slice header, read without unmarshalling
// the whole file (only the bytes before .log.entries are touched).
type headVals struct {
	version string
	creator json.RawMessage
	pages   json.RawMessage
}

// readHead streams the file up to .log.entries, capturing .log.version and the
// raw JSON of .log.creator / .log.pages (both live before entries in every
// sane writer's output; anything after entries is simply not captured).
func readHead(path string) headVals {
	var hv headVals
	f, err := os.Open(path)
	if err != nil {
		return hv
	}
	defer f.Close()
	br := bufio.NewReaderSize(f, 1<<16)
	dec := json.NewDecoder(br)
	dec.UseNumber()
	type lvl struct {
		isObj bool
		key   string
	}
	var stack []lvl
	wantKey := false
	lastKey := ""
	for {
		tok, err := dec.Token()
		if err != nil {
			return hv
		}
		switch t := tok.(type) {
		case json.Delim:
			// wantKey==false means we just read a key and the next token is its
			// VALUE — if that value is an object/array we can capture it raw.
			if !wantKey && len(stack) == 2 && stack[1].key == "log" {
				if (t == '{' && lastKey == "creator") || (t == '[' && lastKey == "pages") {
					var raw json.RawMessage
					if rerr := dec.Decode(&raw); rerr != nil {
						return hv
					}
					if lastKey == "creator" {
						hv.creator = raw
					} else {
						hv.pages = raw
					}
					wantKey = true // value consumed; next token is a key of .log
					continue
				}
			}
			isObj := t == '{'
			stack = append(stack, lvl{isObj, lastKey})
			wantKey, lastKey = isObj, ""
		case string:
			if wantKey {
				lastKey = t
				wantKey = false
				if len(stack) == 2 && stack[1].key == "log" && t == "entries" {
					return hv // reached entries; header captured as far as it goes
				}
				continue
			}
			if len(stack) == 2 && stack[1].key == "log" && lastKey == "version" {
				hv.version = t
			}
			wantKey = len(stack) > 0 && stack[len(stack)-1].isObj
		default:
			wantKey = len(stack) > 0 && stack[len(stack)-1].isObj
		}
	}
}

func cmdSlice(a args, path string, rows []row, meta headMeta) {
	outPath := a.flags["out"]
	if outPath == "" {
		die("extract needs an output path (out)")
	}
	if !filepath.IsAbs(outPath) {
		wd, _ := os.Getwd()
		outPath = filepath.Join(wd, outPath)
	}
	if _, err := os.Stat(outPath); err == nil {
		die("%s already exists — refusing to overwrite (rm it first if you meant that)", outPath)
	}
	sel := filtered(rows, a.f)
	all := len(sel)
	// slice has no default cap (an export should be complete), but limit
	// must still work here like it does everywhere else.
	if _, ok := a.flags["limit"]; ok && a.f.limit > 0 && int64(len(sel)) > a.f.limit {
		sel = sel[:a.f.limit]
	}
	redact := a.flags["redact"] == "1"
	if abs, err := filepath.Abs(outPath); err == nil && abs == path {
		die("refusing to slice onto the source HAR (%s) — pick another --out", path)
	}

	// Rebuild the file: header fields streamed from the file head (never a full
	// unmarshal), entries emitted one at a time from cached byte offsets.
	hv := readHead(path)

	// Write to a sibling temp file and rename on success, so a failure part-way
	// through never leaves a half-written .har behind.
	tmp, err := os.CreateTemp(filepath.Dir(outPath), ".har-slice-*")
	if err != nil {
		die("%v", err)
	}
	tmpName := tmp.Name()
	fail := func(format string, xs ...any) {
		tmp.Close()
		os.Remove(tmpName)
		die(format, xs...)
	}
	w := bufio.NewWriterSize(tmp, 1<<20)
	var werr error
	wr := func(b []byte) {
		if werr == nil {
			_, werr = w.Write(b)
		}
	}
	ws := func(s string) { wr([]byte(s)) }

	ws(`{"log":{"version":`)
	vb, _ := json.Marshal(hv.version)
	wr(vb)
	ws(`,"creator":`)
	if len(hv.creator) > 0 {
		wr(hv.creator)
	} else {
		cb, _ := json.Marshal(map[string]string{"name": meta.creatorName, "version": meta.creatorVersion})
		wr(cb)
	}
	if len(hv.pages) > 0 && string(hv.pages) != "null" {
		ws(`,"pages":`)
		wr(hv.pages)
	}
	ws(`,"entries":[`)

	first := true
	for _, r := range sel {
		buf := entryJSON(path, r)
		if redact {
			// Numbers are kept as json.Number end-to-end: float64 would round
			// 18-digit IDs and HTML-escaping would rewrite the whole document.
			if m, ok := decodeJSONStrict(string(buf)); ok {
				if mm, isMap := m.(map[string]any); isMap {
					redactEntry(mm)
					if out, merr := marshalNoEscape(mm); merr == nil {
						buf = []byte(out)
					}
				}
			}
		}
		if !first {
			wr([]byte{','})
		}
		first = false
		wr(buf)
	}
	ws("]}}")
	if werr != nil {
		fail("write %s: %v", outPath, werr)
	}
	if err := w.Flush(); err != nil {
		fail("write %s: %v", outPath, err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		die("write %s: %v", outPath, err)
	}
	if err := os.Rename(tmpName, outPath); err != nil {
		os.Remove(tmpName)
		die("write %s: %v", outPath, err)
	}

	st, _ := os.Stat(outPath)
	outf("%s\n  entries: %d  size: %s  redact: %v\n", outPath, len(sel), hsz(st.Size()), redact)
	if len(sel) < all {
		outf("  capped: %d of %d matches (pass limit: 0 for all)\n", len(sel), all)
	}
}

func cmdValidate(a args, path string, rows []row) {
	st, _ := os.Stat(path)
	outf("valid JSON  (%s)\n", hsz(st.Size()))
	data, _ := os.ReadFile(path)
	var head struct {
		Log struct {
			Version string `json:"version"`
			Creator struct {
				Name    string `json:"name"`
				Version string `json:"version"`
			} `json:"creator"`
			Pages []any `json:"pages"`
		} `json:"log"`
	}
	if err := json.Unmarshal(data, &head); err != nil {
		outf("INVALID JSON: %v\n", err)
		die("invalid JSON: %v", err)
	}
	outf("  creator: %s %s\n", head.Log.Creator.Name, head.Log.Creator.Version)
	outf("  version: %s\n", head.Log.Version)
	if head.Log.Pages == nil {
		outf("  pages:   absent (no pageRef)\n")
	} else {
		outf("  pages:   %d\n", len(head.Log.Pages))
	}
	if rows != nil {
		outf("  entries: %d\n", len(rows))
	} else if scanned, _, err := scanFile(path); err == nil {
		outf("  entries: %d\n", len(scanned))
	} else {
		outf("  entries: UNREADABLE — .log.entries missing or not an array (%v)\n", err)
		die("unreadable entries: %v", err)
	}
	if head.Log.Version == "" && head.Log.Creator.Name == "" {
		outf("  warning: no .log envelope fields — not a HAR file?\n")
	}
}

// ---------------------------------------------------------------- entry point

// Version is the har library version.
const Version = version

// Commands is the set of analyses this package can perform. The MCP server
// exposes one tool per name; there is no other entry point.
const (
	CmdSummary  = "summary"
	CmdList     = "list"
	CmdCount    = "count"
	CmdHosts    = "hosts"
	CmdPaths    = "paths"
	CmdShow     = "show"
	CmdBody     = "body"
	CmdHeaders  = "headers"
	CmdForm     = "form"
	CmdCurl     = "curl"
	CmdSearch   = "search"
	CmdRaw      = "raw"
	CmdSlice    = "slice"
	CmdValidate = "validate"
)

// handlers maps a command name to its implementation. Every handler takes the
// same shape so dispatch stays a single call.
var handlers = map[string]func(a args, path string, rows []row, meta headMeta){
	CmdSummary:  func(a args, p string, r []row, m headMeta) { cmdSummary(a, p, r, m) },
	CmdList:     func(a args, p string, r []row, _ headMeta) { cmdList(a, p, r) },
	CmdCount:    func(a args, p string, r []row, _ headMeta) { cmdCount(a, p, r) },
	CmdHosts:    func(a args, p string, r []row, _ headMeta) { cmdHosts(a, p, r) },
	CmdPaths:    func(a args, p string, r []row, _ headMeta) { cmdPaths(a, p, r) },
	CmdShow:     func(a args, p string, r []row, _ headMeta) { cmdShow(a, p, r) },
	CmdBody:     func(a args, p string, r []row, _ headMeta) { cmdBody(a, p, r) },
	CmdHeaders:  func(a args, p string, r []row, _ headMeta) { cmdHeaders(a, p, r) },
	CmdForm:     func(a args, p string, r []row, _ headMeta) { cmdForm(a, p, r) },
	CmdCurl:     func(a args, p string, r []row, _ headMeta) { cmdCurl(a, p, r) },
	CmdSearch:   func(a args, p string, r []row, _ headMeta) { cmdSearch(a, p, r) },
	CmdRaw:      func(a args, p string, r []row, _ headMeta) { cmdRaw(a, p, r) },
	CmdSlice:    func(a args, p string, r []row, m headMeta) { cmdSlice(a, p, r, m) },
	CmdValidate: func(a args, p string, r []row, _ headMeta) { cmdValidate(a, p, r) },
}

// Invoke runs one command against a HAR file and returns everything it printed.
// It never writes to os.Stdout and never exits, so it can be served from a
// long-lived process. Errors are ordinary error values, not exit codes.
func Invoke(harPath, cmd string, o Options) (output string, err error) {
	var buf bytes.Buffer
	stdout, stderr = &buf, &buf
	defer func() {
		stdout, stderr = os.Stdout, os.Stderr
		if r := recover(); r != nil {
			if d, ok := r.(errDie); ok {
				err = errors.New(d.msg)
				return
			}
			panic(r)
		}
	}()
	err = runCommand(harPath, cmd, o)
	output = buf.String()
	return output, err
}

func runCommand(harPath, cmd string, o Options) error {
	handler, ok := handlers[cmd]
	if !ok {
		return fmt.Errorf("unknown command %q", cmd)
	}
	path := harPath
	if path == "" {
		return errors.New("no HAR file given")
	}
	if st, err := os.Stat(path); err != nil || !st.Mode().IsRegular() {
		return fmt.Errorf("%s is not a readable file", path)
	}
	if !filepath.IsAbs(path) {
		wd, _ := os.Getwd()
		path = filepath.Join(wd, path)
	}
	var rows []row
	var meta headMeta
	// validate inspects the envelope itself; the index scan would reject the
	// very files it is meant to report on.
	if cmd != CmdValidate {
		rows, meta = loadRows(path)
	}
	handler(o.argsFor(cmd), path, rows, meta)
	return nil
}
