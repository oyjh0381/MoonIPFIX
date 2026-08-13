# Native CLI / 原生命令行

`moonipfix inspect [--session KEY] [--deny-warnings] [FILE|-]` incrementally decodes a file or standard input and writes schema-v1 JSONL only to stdout. `moonipfix validate` uses the same stream path but emits only sequence, Diagnostic, and statistics evidence. Human-readable Diagnostics go to stderr. One input defaults to Session Key `cli:default`; callers should provide a stable `--session` when correlating exported state.

`moonipfix inspect [--session KEY] [--deny-warnings] [文件|-]` 以增量方式读取文件或标准输入，并且只向标准输出写入 v1 JSONL。`moonipfix validate` 复用同一流式解码路径，但只输出序列、诊断和统计证据。便于人工阅读的诊断仅写入标准错误。单输入的默认 Session Key 为 `cli:default`；需要关联导出状态时应显式传入稳定的 `--session`。

Exit codes / 退出码：`0` success，`2` usage，`3` warning rejected by `--deny-warnings`，`4` malformed or truncated input，`5` resource limit，`6` file/stdin/stdout I/O error (including broken pipes). MoonIPFIX is an offline decoder and does not open sockets or act as an online Collecting Process.

`moonipfix templates` emits every Template definition and lifecycle event, followed by deterministic `template_state` records for the final active state. Options Templates mark Scope Fields separately. `moonipfix stats` emits Sequence audits while reading and one final `stream_statistics` record with Message, Set, Template, record, field, unknown-field, Diagnostic, and Sequence Gap totals. Both commands use the same `StreamDecoder` as `inspect`; they do not maintain a database or introduce a second parsing path.
