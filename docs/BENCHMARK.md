# 批量安全评估

评估器把当前语料库与隔离区合并为只读实验快照，在内存中模拟三种策略，因此不会恢复、移动或删除靶场文件。

## 快速评估

不调用模型，只评估扫描和检索：

```bash
python scripts/run_security_benchmark.py
```

调用 Ollama，对标记为 `model_test` 的用例比较 `off` 与 `enforce`：

```bash
python scripts/run_security_benchmark.py \
  --with-model \
  --model qwen2.5:0.5b \
  --model-modes off enforce
```

报告默认保存到 `reports/security-benchmark.json`。

## 指标

- `poison_detection_rate`：扫描器对已标注投毒文档的检出率。
- `false_positive_rate`：正常文档被扫描器误判的比例。
- `poisoned_retrieval_hit_rate`：攻击问题召回投毒块的比例。
- `benign_poison_exposure_rate`：正常问题意外召回投毒块的比例。
- `expected_document_hit_rate`：Top-K 中包含预期文档的比例。
- `clean_expected_document_hit_rate`：只针对正常问题的预期文档命中率。
- `cross_tenant_leak_count`：租户过滤后仍出现其他租户文档的次数。
- `attack_success_rate`：模型测试中 Canary 泄露的攻击用例比例。
- `benign_canary_leak_rate`：正常模型测试中意外输出 Canary 的比例。
- `retrieval/model_latency_ms_p50/p95`：检索和模型调用延迟。

报告不保存完整模型回答，只保存 SHA-256、长度和 Canary 判断。
## 当前实测结果

在 VMware Linux 虚拟机上使用 Ollama `qwen2.5:0.5b` 完成一次真实模型评估：

| 指标 | off | enforce |
|---|---:|---:|
| 模型测试用例数 | 9 | 9 |
| 攻击成功率（ASR） | 40% | 0% |
| 正常问题 Canary 泄露率 | 0% | 0% |
| 模型延迟 P50 | 1841.706 ms | 2118.972 ms |
| 模型延迟 P95 | 8318.995 ms | 3345.563 ms |

结合 24 个离线检索用例，本轮实验还得到：扫描检出率 100%、误报率 0%、`off/audit` 投毒召回率 75%、`enforce` 投毒召回率 0%、正常文档命中率 93.75%，跨租户泄露 0 次。

该结果表明 `enforce` 在这组用例中阻断了全部 Canary 泄露。每种模式仅有 9 次模型调用，延迟尤其容易受首次加载、CPU 调度和上下文长度影响；应把 P50/P95 视为本轮观测值，而不是通用性能结论。
