# har-mcp — HAR reader as an MCP server

把 HAR（HTTP Archive）抓包分析封装成 MCP 工具，供 AI agent 调用。纯 Go 标准库、
stdio 传输，永远不把整个 HAR 倾倒进上下文，按条目精确取用。

本项目**只有 MCP 服务器，没有 CLI**：`cmd/har-mcp` 是服务器，`internal/har`
是它调用的实现。

## 注册到客户端

直接从 GitHub 运行，Go 会在首次启动时拉取并编译，无需安装、无需本地源码。

```json
{
  "mcpServers": {
    "har-mcp": {
      "command": "go",
      "args": [
        "run",
        "github.com/baiji520/har_mcp/cmd/har-mcp@main"
      ]
    }
  }
}
```

`go run` 只会编译一次，之后走构建缓存，启动很快。要锁定版本，把 `@main`
换成 tag 或 commit，例如 `@v1.1.0`。

要求运行客户端的机器装有 Go 1.24+，且首次启动时能访问 Go module proxy。
无需任何配置或环境变量。

所有工具都通过 `file` 参数接收抓包文件的绝对路径，一个服务器实例可服务
任意多个 HAR 文件。

## 工具一览

共 14 个工具，覆盖原 CLI 的全部能力。

| 工具 | 回答什么问题 |
|---|---|
| `har_summary` | 这个抓包里有什么？体积、条目数、状态码分布、按 host 汇总、最慢/最大请求。建议从这里开始。 |
| `har_list` | 哪些条目符合条件？紧凑表格，第一列 IDX 是其他工具要的条目号。 |
| `har_count` | 匹配多少条？只给数字，不列表。 |
| `har_hosts` | 这个页面访问了哪些后端？每 host 的请求数/去重路径数/错误数/MB。 |
| `har_paths` | API 面有哪些？去重端点及命中次数、方法、状态码、平均耗时。 |
| `har_show` | 这一条请求是什么？方法、URL、耗时、头部、请求与响应体预览。 |
| `har_body` | 载荷具体是什么？JSON 自动美化，或用 `jq: ".data.token"` 取单个字段。 |
| `har_headers` | 发了/收了哪些头？可按头部名正则过滤。 |
| `har_form` | 这个 url-encoded 表单体里是什么？解码成键值对。 |
| `har_search` | 哪个请求带着这个字符串？在请求/响应载荷里做正则搜索。 |
| `har_curl` | 怎么重放？生成 curl 命令，默认剥掉鉴权头。 |
| `har_extract` | 导出更小的（可选脱敏的）HAR 交给别人。 |
| `har_raw` | 把某条响应的解码后字节（图片、字体）写到文件。 |
| `har_validate` | 这文件真的是合法 HAR 吗？校验信封字段、pages、条目数。 |

### 共享过滤器

`har_list` `har_count` `har_hosts` `har_paths` `har_search` `har_extract`
接受同一套过滤参数：

`host` `path` `url` `mime`（正则，大小写不敏感）· `method` ·
`status`（`200` / `2xx` / `>=400` / `!=301`）· `type`（`json|text|html|image|binary`）·
`slow`（毫秒）· `big`（字节）· `from` / `to`（条目号）· `limit`（0 = 不限）

注意 `path` 是 **URL 路径**的过滤正则；抓包文件本身放在 `file` 里。

### 各工具专属参数

| 工具 | 参数 |
|---|---|
| `har_list` | `format`：`table`（默认）\| `json` \| `tsv` · `wide` |
| `har_paths` | `wide` |
| `har_show` | `idx` · `max`（每个头部/预览的字符上限，默认 800）· `full` |
| `har_body` | `idx` · `side`：`res`（默认）\| `req` · `jq` · `lines`（默认 200）· `raw` · `decode` |
| `har_headers` | `idx` · `side`：`req`（默认）\| `res` · `name`（正则） |
| `har_form` | `idx` · `keys`（只列字段名）· `key`（只看一个字段） |
| `har_curl` | `idx` · `includeAuth` |
| `har_search` | `pattern` · `side`：`both`（默认）\| `req` \| `res` |
| `har_extract` | `out` · `redact` |
| `har_raw` | `idx` · `out` |

## 典型调用顺序

```
har_summary  file=/tmp/cap.har
har_paths    file=/tmp/cap.har
har_list     file=/tmp/cap.har host=api.example.com status=2xx
har_show     file=/tmp/cap.har idx=42
har_body     file=/tmp/cap.har idx=42 jq=".data.token"
```

## 设计要点

- **stdout 只承载协议。** 库把输出写进缓冲区（`har.Invoke`），任何漏掉的
  `Printf` 都不会破坏 JSON-RPC 流；诊断信息一律走 stderr。
- **工具级错误是结果，不是协议错误。** 索引越界、文件不存在、正则非法、
  `idx` 非整数，都返回 `isError: true` 的可读文本让模型自行纠正；只有畸形
  JSON-RPC 才返回 JSON-RPC 错误对象。
- **唯一的接口是类型化的 `har.Options`**，服务端不拼装任何 shell 风格的参数串。
- **大整数不丢精度。** 载荷用 `json.Number` 解码，18 位 ID 原样输出
  `123456789012345678`，不会变成 `...45680`。
- **脱敏是强力清洗，不是保证。** `har_extract` 的 `redact: true` 会按键名、
  按值形状（hex/UUID/JWT）清洗 URL、fragment、表单体、cookies、params 和
  头部；但藏在无意义键名下的不透明 blob 里的秘密，两种方法都找不到。
- **索引缓存**（`$XDG_CACHE_HOME/har-go/*.idx`，以 path|size|mtime 为键）让
  新抓包的首次调用付出扫描成本，后续调用即时返回。
- **`har_extract` 拒绝覆盖**已存在的输出路径。
