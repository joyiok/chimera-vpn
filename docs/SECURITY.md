# 威胁模型与安全边界

## 设计目标

- 针对“能被动 DPI、能主动探测、按协议指纹封锁”的国家级审查者。
- 攻击者可以观测全部流量、伪造探测包，但目标是不误伤大量合法流量。
- 本仓库是研究原型，**不要把它当成在国家级对手下已经验证的隐蔽方案**。

## 当前提供的性质

- 每个 (seed, generation) 生成独立协议形态，无固定 magic bytes。
- 握手与数据全程 AEAD；无明文协商字段。
- UDP 握手数据报带物种级随机可打印封面，使 gfw.report 推断的 GFW
  全加密检测器（Wu et al., USENIX Security 2023）Ex2/Ex4 命中。
- 非法握手包静默丢弃；server-first 需要 PSK-MAC knock 才回答真实首帧。
- 已认证握手首包/knock 进入进程内重放表（Alice et al., IMC 2020）。
- 服务端新建会话限速；会话密钥具备前向保密（临时 X25519 + transcript）。
- 服务端一个 UDP socket 多客户端复用，按地址隔离。

## 已知缺口

1. **流量分析**：包长已按 128/512/1024/1452 阶梯整形；发送 IAT 为截断指数分布
   （默认 ≤20ms）。均匀间隔本身会被分类器当特征（Wang et al., CCS 2015
   *Seeing through Network-Protocol Obfuscation*；obfs4 IAT mode）。
   长连接方向模式仍在，不是 Marionette/完整流量变形。
2. **主动探测**：client-first 非法首包回 decoy 物种（UPGen §2.1 对 active
   scanning 的有限防护；obfs4 要先证明共享秘密才说话）。server-first 现已要求
   认证 knock，随机探针不再拿到真实首帧。decoy 本身仍暴露“这里有一个会说话的 UDP 服务”。
3. **重放**：序列号防了即时重放；会话密钥来自临时 ECDH，跨重启录制数据面无效。
   握手首包哈希表默认落盘（`/var/lib/chimera/handshake.replay`，TTL 约 1 小时）；
   写失败时退回内存。`replay_path: ""` 关闭持久化。
4. **丢包恢复**：ACK/SKIP 推进窗口（跳过语义，不重传）；上层协议自带可靠性。
5. **密码学**：AES-GCM 与 ChaCha20-Poly1305 均已接入；基因组默认只抽 AES 三档。
6. **平台**：Windows / Linux 路由接管已实现待真机验收；移动端已接 protect/排除路由，未真机审计；
   配置含 PSK 明文落盘（建议 `chmod 0600`；Windows 用 0600，后续可 DPAPI）。
   `bash scripts/selftest.sh` 覆盖本机 userspace 数据面，不替代真机路由验收。
7. **DoS**：pending 上限 1024、单地址 1s 限速、每会话令牌桶、`max_sessions` 默认 256。
   单个客户端断开不再拖垮 chimerad。
8. **UDP vs 论文中的 TCP**：Wu 2023 / IMC 2020 的测量对象是 TCP 首个 payload。
   CHIMERA 跑在 UDP 上；封面与重放表是同一套启发式的回归测试，**不是**“已经骗过 GFW”的证明。
9. **封面残余指纹**：CoverLen 每物种固定（24–32），内容每次随机。审查者仍可按
   “可打印前缀 + 高熵 AEAD”训练单服务器分类器（UPGen 的残差风险：一次只倒一台）。

运维面（守护进程、限速、抖动、generation 窗口、systemd 硬化、FEP 封面、knock、重放表）
已按自建 VPN 收紧。两端必须同时升级：旧客户端不发封面/认证 knock，无法与本版本握手。

## 测试覆盖

- 流编解码 roundtrip、篡改拒绝、流式分帧。
- packet 模式乱序/重复包。
- UDP 握手 6 种模式、3 客户端并发 mux。
- 推断 FEP 检测器（Algorithm 1）对握手首包的豁免；首包/knock 重放不建第二会话。
- 地址池分配/释放。
- 本机 userspace 自测：`scripts/selftest.sh`（握手 + 分配 + 回显）。
- 全部竞态检测：`go test -race ./...`。

## 参考文献（实现时对照）

- Wails, Jansen, Johnson, Sherr. *Censorship Evasion with Unidentified Protocol Generation*. USENIX Security 2025. 本仓库的协议生成路线。
- Wu, Sippe, Sivakumar, et al. *How the Great Firewall of China Detects and Blocks Fully Encrypted Traffic*. USENIX Security 2023. https://gfw.report/publications/usenixsecurity23/en/
- Alice, Bock, et al. *How China Detects and Blocks Shadowsocks*. IMC 2020. https://gfw.report/publications/imc20/en/
- Wang, Dyer, et al. *Seeing through Network-Protocol Obfuscation*. CCS 2015. 均匀包长/IAT 可被决策树打掉。
- Dyer et al. *Marionette*. USENIX Security 2015；obfs4 IAT mode：非均匀间隔。
- Fifield. *Turbo Tunnel*. FOCI 2020. 可靠性层与混淆层分离（本仓库 ACK/SKIP 是跳过而非重传）。

先在仓库提 Issue，附带：
- 平台/Go 版本
- 复现命令
- `go test -race ./...` 输出
- 如涉及协议：`cmd/gencompiler -json` 的 genome 规格
