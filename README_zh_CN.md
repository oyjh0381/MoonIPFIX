# MoonIPFIX

MoonIPFIX 是采用 Apache-2.0 许可证的原创 MoonBit IPFIX 遥测解码库与原生 CLI。项目实现 RFC 7011 的 Template、Options Template、Data Set、动态模板生命周期和序列连续性审计，支持固定/可变长度、Reduced-Size、Enterprise IE、未知字段无损保留以及版本化 JSONL。

MoonIPFIX 处理 exporter 已聚合的 IPFIX Message，不读取 PCAP、不从网络分组推导流，因此与 MoonCap 等抓包解码项目不同。v0.1 不实现在线监听、存储、NetFlow v9、Exporter 编码和 RFC 6313 结构化列表。

## 运行

```sh
moon run examples/library_decode
python tools/make_example_stream.py
moon run cmd/moonipfix --target native -- inspect .scratch/example.ipfix
moon run cmd/moonipfix --target native -- validate .scratch/example.ipfix
moon run cmd/moonipfix --target native -- templates .scratch/example.ipfix
moon run cmd/moonipfix --target native -- stats .scratch/example.ipfix
```

输入文件可写 `-` 表示 stdin；`--session KEY` 显式定义模板命名空间；`--deny-warnings` 将警告转换为退出码 3。完整接口、退出码、JSONL、资源上限和安全边界见 [CLI 文档](docs/cli.md)、[JSONL 契约](docs/jsonl-schema.md)与 [协议范围](docs/protocol-scope.md)。

## 验证

运行 `moon check --target all --deny-warn`、三个目标的 `moon test --deny-warn`、`python tools/test_cli.py`。`python tools/benchmark_100k.py` 提供可复现的十万记录基准，不把绝对耗时作为 CI 门槛。

实现依据公开 RFC 7011、RFC 7012 和固定版本 IANA 注册表，未移植或复制现有 IPFIX 库。详见 [生态查重](docs/ecosystem-review.md)、[测试来源](docs/test-provenance.md)和 [第三方声明](THIRD_PARTY_NOTICES.md)。
