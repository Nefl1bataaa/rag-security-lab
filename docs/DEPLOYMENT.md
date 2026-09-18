# VMware + Ollama + Wazuh 部署指南

## 拓扑

| 节点 | 地址 | 组件 | 内存 |
|---|---|---|---:|
| SOC-server | `<SOC_SERVER_IP>` | Wazuh Manager、Indexer、Dashboard | 8 GB |
| Linux-server | `<RAG_SERVER_IP>` | RAG Lab、Ollama、Wazuh Agent | 4 GB + Swap |
| Windows Host | `<HOST_VMNET_IP>` | VMware；可选下载代理 | 16 GB 主机 |

上表使用脱敏占位符。部署时请替换为自己的 VMware 隔离网段地址。

模型测试期间可暂停 `/opt/websec-lab` 的 Docker 容器，避免宿主机内存压力。

## Linux-server

```bash
cd /opt/rag-security-lab
bash scripts/bootstrap_ubuntu.sh
source .venv/bin/activate
python -m unittest discover -s tests -v
```

Bootstrap 使用 `--policy off` 建立可复现漏洞基线。日常观察可执行：

```bash
python -m rag_lab ingest --policy audit
```

安装 Ollama 后拉取轻量模型：

```bash
ollama pull qwen2.5:0.5b
ollama list
```

确认服务：

```bash
systemctl is-active ollama
systemctl is-active wazuh-agent
ss -lntp | grep 11434
```

Ollama 应只监听 `127.0.0.1:11434`。

## Agent 日志采集

把 `wazuh/agent/ossec.conf.fragment.xml` 中的 `<localfile>` 合并进 Agent 现有的唯一 `<ossec_config>` 元素。不要覆盖原 WebSec Lab 配置。

```bash
sudo /var/ossec/bin/wazuh-logcollector -t
sudo systemctl restart wazuh-agent
systemctl is-active wazuh-agent
```

## SOC-server 规则

复制以下三个文件到 `/var/ossec/etc/rules/`：

- `wazuh/rules/rag_security_rules.xml`
- `wazuh/rules/rag_policy_rules.xml`
- `wazuh/rules/rag_quarantine_rules.xml`

然后执行：

```bash
sudo chown --reference=/var/ossec/etc/rules/local_rules.xml /var/ossec/etc/rules/rag_security_rules.xml /var/ossec/etc/rules/rag_policy_rules.xml /var/ossec/etc/rules/rag_quarantine_rules.xml
sudo chmod --reference=/var/ossec/etc/rules/local_rules.xml /var/ossec/etc/rules/rag_security_rules.xml /var/ossec/etc/rules/rag_policy_rules.xml /var/ossec/etc/rules/rag_quarantine_rules.xml
sudo /var/ossec/bin/wazuh-analysisd -t
sudo systemctl restart wazuh-manager
systemctl is-active wazuh-manager
```

## 规则测试

在 SOC-server 运行：

```bash
sudo /var/ossec/bin/wazuh-logtest
```

逐行输入 `wazuh/samples/events.jsonl`。预期结果：

| 事件 | 规则 |
|---|---:|
| audit 模式发现可疑文档 | `100305` |
| 投毒文档进入上下文 | `100310` |
| 跨租户检索 | `100320` |
| Canary 泄露 | `100330` |
| 文档自动隔离 | `100360` |

## 三模式实验

```bash
cd /opt/rag-security-lab
source .venv/bin/activate
python -m rag_lab ingest --policy off
python -m rag_lab ingest --policy audit
python -m rag_lab ingest --policy enforce
```

`enforce` 预期：

```text
quarantined_document_count: 1
poisoned_chunk_count: 0
```

## SOC 查询

```bash
sudo grep -a '"id":"100305"' /var/ossec/logs/alerts/alerts.json | tail -n 1
sudo grep -a '"id":"100310"' /var/ossec/logs/alerts/alerts.json | tail -n 1
sudo grep -a '"id":"100330"' /var/ossec/logs/alerts/alerts.json | tail -n 1
sudo grep -a '"id":"100360"' /var/ossec/logs/alerts/alerts.json | tail -n 1
```

Dashboard 查询：

```text
rule.groups: rag_security_lab
```
