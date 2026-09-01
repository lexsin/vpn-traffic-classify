# vpn-traffic-classify

基于 PCAP 流量特征的 VPN 协议识别实验代码。

当前实现位于 `vpnflow/`，包含特征提取、TCP 流重组、TLS ClientHello 解析，以及 Trojan / Shadowsocks 训练与评估工具。

原始 PCAP 样本、训练输出、可执行文件和环境缓存不纳入版本控制。
