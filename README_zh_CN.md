# MoonIPFIX

MoonIPFIX 是一个采用 Apache-2.0 许可证的原创 MoonBit 库，用于解码和审计由模板驱动的 IP Flow Information Export（IPFIX）流遥测数据。项目面向需要消费 exporter 产生的 IPFIX Message、但不希望绑定在线网络 Collector、抓包解析器、数据库或可视化系统的开发者。

项目当前处于设计基线阶段。仓库先固定协议范围、领域语言、公开模块接口缝、安全模型、测试策略与实现路线，再开始协议实现。

## v0.1 计划范围

- 解码 RFC 7011 Message Header、Template Set、Options Template Set、Data Set 与 Data Record。
- 依据调用方提供的 Session Key、Observation Domain ID 和 Template ID 隔离 Template 状态。
- 支持定长与变长字段、Reduced-Size Encoding、Template Withdrawal 和 Enterprise Information Element。
- 使用可复现的 IANA 注册表快照解释标准 Information Element，并无损保留未知字段。
- 基于同一解析实现提供完整消息解码与任意分块的增量解码。
- 返回强类型字段值，以及包含精确输入偏移的结构化 Diagnostic。
- 对缓冲字节、会话、Template、字段、记录和 Diagnostic 强制执行可配置上限。
- 提供 Native `moonipfix` CLI，包括 `inspect`、`validate`、`templates` 和 `stats`，机器输出采用带版本的 JSONL。

## 公开模块接口缝

- `decoder`：完整消息/增量解码、Template 生命周期、强类型记录、配置与 Diagnostic。
- `registry`：固定版本 IANA Information Element 元数据与调用方提供的 Enterprise 元数据。
- `jsonl`：稳定、带版本的机器输出契约。
- `cmd/moonipfix`：Native 文件/stdin 与终端适配层。

安全字节读取、Template 存储机制与恢复细节均保持为实现内部知识。测试和调用方通过相同的公开接口验证行为。

## 基线验证

```sh
moon fmt --check
moon check --target all --deny-warn
moon test --target wasm-gc --deny-warn
moon test --target js --deny-warn
moon test --target native --deny-warn
moon run cmd/moonipfix --target native -- version
```

## 标准与边界

MoonIPFIX v0.1 依据 [RFC 7011](https://www.rfc-editor.org/info/rfc7011/)、[RFC 7012](https://www.rfc-editor.org/info/rfc7012/) 和 [IANA IPFIX Information Elements 注册表](https://www.iana.org/assignments/ipfix/ipfix.xhtml) 实现。详细内容见[协议范围](docs/protocol-scope.md)、[架构](docs/architecture.md)、[测试策略](docs/testing.md)、[安全模型](docs/security.md)和[生态查重](docs/ecosystem-review.md)。

首版明确不实现在线 Collector、Exporter 编码、NetFlow v9、RFC 6313 结构化数据、数据库和可视化。

MoonIPFIX 不是抓包解析器。MoonCap 等项目处理 PCAP/PCAPNG 与原始网络分组；MoonIPFIX 处理 exporter 已产生的 IPFIX Message，并通过动态 Template 解释 Data Record，两者的输入、状态模型与用途不同。

## 许可证

源码采用 [Apache License 2.0](LICENSE)。规范、注册表数据、生成物、依赖与测试素材来源记录在 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)。
