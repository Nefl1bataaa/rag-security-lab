# 入库策略模式

策略在索引构建前运行，扫描 `.txt` 和 `.md` 文档中的合成 Canary、忽略指令、系统覆盖、强制输出及伪调试指令等特征。

## 模式对比

| 模式 | 扫描 | 记录事件 | 移动文档 | 是否进入索引 | 用途 |
|---|---|---|---|---|---|
| `off` | 是 | 基线记录 | 否 | 是 | 漏洞复现 |
| `audit` | 是 | Level 7 告警 | 否 | 是 | 观察期与误报评估 |
| `enforce` | 是 | Level 10 告警 | 是 | 否 | 阻断与隔离 |

实验室默认使用 `audit`，避免首次运行时移动示例投毒文档。部署为防护控制时应显式使用 `enforce`。

## 命令

```bash
python -m rag_lab ingest --policy off
python -m rag_lab ingest --policy audit
python -m rag_lab ingest --policy enforce
```

可指定独立路径进行无副作用测试：

```bash
python -m rag_lab ingest \
  --policy enforce \
  --corpus /tmp/rag-corpus \
  --quarantine /tmp/rag-quarantine \
  --index /tmp/rag-index.json \
  --log /tmp/rag-audit.jsonl
```

## 事件语义

`off` 与 `audit` 使用 `rag_ingestion_policy`：

```json
{"event_type":"rag_ingestion_policy","policy_mode":"audit","suspicious_document":true,"action":"alert","disposition":"observed"}
```

`enforce` 使用 `rag_integrity`：

```json
{"event_type":"rag_integrity","policy_mode":"enforce","suspicious_document":true,"action":"quarantined","disposition":"blocked"}
```

日志保留文档 ID、SHA-256 和命中特征，但不把完整文档内容发送到 Wazuh。

## 回归验证

1. `off`：索引应包含 1 个投毒块。
2. `audit`：索引仍包含投毒块，SOC 应出现规则 `100305`。
3. `enforce`：投毒块数量应变为 0，SOC 应出现规则 `100360`。
4. 使用相同攻击问题复测，模型不应再输出 Canary。

## 已知局限

- 正则扫描可能被同义改写、Unicode 混淆或跨段拆分绕过。
- Canary 命中适合实验验证，不等同于通用敏感数据检测。
- 生产环境还需要来源签名、上传者身份、审批流程、语义分类器和输出 DLP。
