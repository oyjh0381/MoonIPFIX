# Keep protocol Modules portable and the CLI Native

The `decoder`, `registry`, and `jsonl` Modules will avoid filesystem, terminal, socket, host-time, and environment capabilities and will be tested on Native, Wasm GC, and JavaScript. Only the `moonipfix` CLI adapts Native files, stdin, stdout, stderr, and process exit codes, preserving a reusable protocol library without making the CLI abstraction leak into callers.
