# 线上协议说明

## 1. 协议基因组（Genome）

`internal/genome.Generate(seed []byte, generation uint64)` 用 HMAC-DRBG 从
`(seed, generation)` 确定性生成：

- 握手模式：`c_s` / `c_s_c` / `c_s_c_s` / `c_c_s` / `s_c` / `s_c_s`
- 每个消息的明文字段池：`version` / `type` / `nonce` / `reserved`
- 每个消息的加密字段池：`key_material` / `certificate` / `extra` / `pad_length`
- 长度字段：宽度 `u8/u16/u24/u32`、大小端、语义 `ciphertext|record`、位置、是否单独分段
- padding 策略：`none` / `uniform[min,max]` / `burst`
- 密码套件：`aes-128-gcm` / `aes-192-gcm` / `aes-256-gcm`（协议级同一种）

JSON 规格示例由 `cmd/gencompiler -json` 导出；`ProtocolFingerprint` 是设计指纹。

## 2. 帧格式

线上帧 = 明文区 + 密文区：

```text
+---------------------------+--------------------------------------+
| 按基因组排列的明文字段     |  AEAD 密文（含 16 字节 GCM tag）      |
+---------------------------+--------------------------------------+
```

- 明文区包含 length 字段；**length 是 AEAD 的 AAD**，所以必须在加密前确定。
- 长度语义：
  - `ciphertext`：值为密文字节数（解析时先读完所有明文字段再校验）
  - `record`：值为整帧字节数
- `LengthAlone=true` 时发送端分三段：`[长度之前的字段][长度字段][长度之后的字段+密文]`。
  流式 `ReadFrame` 对此透明。
- 密文内部顺序：加密字段（按基因组顺序）→ payload → padding。
  `pad_length` 字段在密文内自描述 padding 长度；无 padding 时无此字段。

## 3. 握手与密钥

1. PSK 经 HKDF-SHA256 派生 bootstrap 方向密钥 `C2S` / `S2C`。
2. 双方在握手消息的 `key_material` 字段交换 X25519 临时公钥（raw32 或 X9.63 编码）。
3. 握手 transcript = 每个原始帧字节按顺序写入 SHA-256。
4. 会话密钥 = HKDF(shared_secret, salt=PSK, info=方向+transcript hex)，长度与所选 AES 密钥匹配。
5. 应用数据使用 `PacketSession` 或 `Session`。

## 4. Nonce 规则（重要）

- AEAD nonce 12 字节 = `uint32(message index) BE || uint64(sequence) BE`。
- 同一 bootstrap 方向密钥会被多个握手消息复用，因此 message index 必须参与 nonce。
- 流模式严格递增；解码失败不推进序号。
- 包模式发送端独立递增 `packetSend`；接收端在 `[base, base+8192)` 窗口内逐个尝试 nonce，
  命中后置 seen 位，**连续 seen 才推进 base**（允许 IP 包乱序）。
- 丢包恢复（见下节）：ACK 推进连续位置，SKIP 越过永久缺口，base 不会再永久停滞。

## 5. 控制包、地址分配与丢包恢复

- 应用载荷首字节 `0x01` = `ControlAssignIP`；其余字节为分配的 IPv4 字符串。
- IP 包首字节必为 `0x4x`（IPv4）或 `0x6x`（IPv6），不会与 `0x01`-`0x03` 冲突。
- 服务端 `Accept` 握手完成后立即发送控制包，然后才进入正常数据转发。
- 客户端 `PacketTunnel.WaitControl` 自行读 socket（因为平台此时还没启动泵），
  期间遇到的数据包进入 256 深度的 `data` 队列，`ReceivePacket` 优先取该队列。
- `core/assign.go` 的地址池：`client_cidr` 内 host offset 2 起分配，offset 1 保留给网关，
  广播地址排除；释放后复用。

### 丢包恢复（ACK / SKIP）

包模式重排窗口只允许"连续 seen 才推进 base"，永久丢帧会卡死窗口。恢复机制
（载荷在 AEAD 密文内，审查者不可见；两端对称实现）：

- `0x02 = ControlAck`，载荷 9 字节 = `0x02 || uint64(contiguous_base) BE`。
  接收端每解码 32 个数据帧（`ackEvery`）发送一次，报告自己的连续接收位置。
- `0x03 = ControlSkip`，载荷 9 字节 = `0x03 || uint64(target_base) BE`。
  发送端发现未确认跨度 `sent - peerBase >= 6144`（`skipSpan` = 窗口的 3/4）时，
  请求对端把 base 直接跳到当前发送位置。
- 接收端 `AdvanceBaseTo(target)`：清空 seen 位图、base 前移；低于/等于当前 base
  是幂等 no-op，超出窗口被拒绝（防伪造的越权跳变）。
- SKIP 语义：只牺牲"迟到帧"（跳变之后到达的旧帧不再可认证）；缺口之上的乱序帧
  本来就已即时投递，不受影响。这是权衡而非重传：VPN 载荷是 IP 包，上层协议
  自带可靠性。
- 会话状态（encode/decode/窗口推进）由 `sessMu` 串行化：用户 goroutine 发送的
  同时接收循环在解码。

## 6. 抗探测行为（当前实现）

- 所有非法/错 nonce/错步骤的握手数据报：**静默丢弃，不响应**。
- server-first 模式需要客户端先发一个 32 字节随机 knock；服务器只把来源地址记下。
- 新会话创建防护：首包 ≥16 字节、同源地址 1s 限速、全局 pending ≤1024。
- 尚未实现：主动探测诱饵、端口跳跃、时序/包长整形。

## 7. 密码学边界

- 只实现 AES-GCM（Go 标准库）；ChaCha20-Poly1305 在枚举中未接入。
- 握手前字段用 PSK bootstrap 加密；临时 ECDH 提供前向保密。
- 没有握手重放窗口（序列号存在，但历史 nonce 未持久化检查）。
- `EstimatedEntropyBits` 只是生成器自记账，不是安全证明。
