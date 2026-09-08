# vpn-traffic-classify

基于 PCAP 流量特征的 VPN 协议识别实验代码。

当前实现位于 `vpnflow/`，包含特征提取、TCP 流重组、TLS ClientHello 解析、标准 VPN 协议规则，以及 Trojan / Shadowsocks 训练、评估和统一生产推理工具。

原始 PCAP 样本、训练输出、可执行文件和环境缓存不纳入版本控制。

## 统一最终预测器

统一预测器以单个离线 PCAP 为输入。Go 程序负责流重组、规则识别和特征生成，Python 决策层加载带清单及哈希校验的 XGBoost 模型，生成逐流 JSONL 和整包汇总 JSON。

构建 Go 提取器：

```bash
cd vpnflow
go build -o out/vpnflow ./cmd/vpnflow
```

安装推理依赖并运行（默认 `shadow` 模式）：

```bash
python -m pip install -r requirements-inference.txt
python scripts/unified_predictor.py \
  --pcap sample.pcap \
  --vpnflow-bin out/vpnflow \
  --model-dir models \
  --mode shadow \
  --flow-output out/sample.flows.jsonl \
  --summary-output out/sample.summary.json
```

模型均不可用时，标准协议规则仍会产生结果；其他流输出 `unknown`。`shadow` 模式只记录 ML 候选，不改变最终标签。`enforce` 模式也只允许清单中状态为 `promoted` 的模型参与最终判定。

从当前特征集训练、按来源隔离验证并导出模型：

```bash
python -m pip install -r requirements-training.txt
python scripts/export_xgb_models.py \
  --csv out/trojan_all_samples_features.csv \
  --model-dir models \
  --target-precision 0.99
```

导出器会保存 XGBoost 原生 JSON、`manifest.json`、特征顺序、适用性门控、数据哈希、逐来源指标和重载一致性结果。只有来源隔离验证精确率严格高于 99% 且其他安全条件均通过时，模型才标记为 `promoted`。

未标注 PCAP 也可直接提取特征：

```bash
out/vpnflow --pcap sample.pcap --inference \
  --output out/features.csv \
  --protocol-output out/protocols.jsonl
```

运行测试：

```bash
go test ./...
python -m unittest discover -s scripts/tests -v
```
