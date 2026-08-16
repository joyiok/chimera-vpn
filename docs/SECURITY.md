# 威胁模型与安全边界

## 设计目标

- 针对“能被动 DPI、能主动探测、按协议指纹封锁”的国家级审查者。
- 攻击者可以观测全部流量、伪造探测包，但目标是不误伤大量合法流量。
- 本仓库是研究原型，**不要直接用于高风险生产环境**。

## 当前提供的性质

- 每个 (seed, generation) 生成独立协议形态，无固定 magic bytes。
- 握手与数据全程 AEAD；无明文协商字段。
- 非法握手包静默丢弃，服务端新建会话限速。
- 会话密钥具备前向保密（临时 X25519 + transcript）。
- 服务端一个 UDP socket 多客户端复用，按地址隔离。

## 已知缺口

1. **流量分析**：包长已按 128/512/1024/1452 阶梯整形；发送 IAT 为截断指数分布
   （默认 ≤20ms）。均匀间隔本身会被分类器当特征（Wang et al., CCS 2015
   *Seeing through Network-Protocol Obfuscation*；obfs4 IAT mode）。
   长连接方向模式仍在，不是 Marionette/完整流量变形。
2. **主动探测**：client-first 非法首包回 decoy 物种（UPGen §2.1 对 active
   scanning 的有限防护；obfs4 要先证明共享秘密才说话）。server-first knock
   仍发真实首帧。generation 窗口对 client-first 可并行。
3. **重放**：序列号防了即时重放；会话密钥来自临时 ECDH，跨重启录制数据面无效。
   没有跨重启的握手账本（依赖 pending 限速）。
4. **丢包恢复**：ACK/SKIP 推进窗口（跳过语义，不重传）；上层协议自带可靠性。
5. **密码学**：AES-GCM 与 ChaCha20-Poly1305 均已接入；基因组默认只抽 AES 三档。
6. **平台**：Windows 路由接管已实现待真机验收；移动端已接 protect/排除路由，未真机审计；
   配置含 PSK 明文落盘（建议 `chmod 0600`；Windows 用 0600，后续可 DPAPI）。
7. **DoS**：pending 上限 1024、单地址 1s 限速、每会话令牌桶、`max_sessions` 默认 256。
   单个客户端断开不再拖垮 chimerad。

本仓库仍是研究型抗审查协议栈。运维面（守护进程、限速、抖动、generation 窗口、
systemd 硬化）已按自建 VPN 生产要求收紧；**不要把它当成在国家级对手下的完整隐蔽方案**。

## 测试覆盖

- 流编解码 roundtrip、篡改拒绝、流式分帧。
- packet 模式乱序/重复包。
- UDP 握手 6 种模式、3 客户端并发 mux。
- 地址池分配/释放。
- 全部竞态检测：`go test -race ./...`。

## 参考文献（实现时对照）

- Wails, Jansen, Johnson, Sherr. *Censorship Evasion with Unidentified Protocol Generation*. USENIX Security 2025. 本仓库的协议生成路线。
- Wang, Dyer, et al. *Seeing through Network-Protocol Obfuscation*. CCS 2015. 均匀包长/IAT 可被决策树打掉。
- Dyer et al. *Marionette*. USENIX Security 2015；obfs4 IAT mode：非均匀间隔。
- Fifield. *Turbo Tunnel*. FOCI 2020. 可靠性层与混淆层分离（本仓库 ACK/SKIP 是跳过而非重传）。

先在仓库提 Issue，附带：
- 平台/Go 版本
- 复现命令
- `go test -race ./...` 输出
- 如涉及协议：`cmd/gencompiler -json` 的 genome 规格
