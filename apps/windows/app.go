package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"chimera/internal/invite"
)

// DefaultServerAddr 是 SelectServerDefault 返回的默认服务器地址。
// 生产环境应替换为真实入口；这里使用本机/内网占位地址。
const DefaultServerAddr = "127.0.0.1:4789"

// appConfig 是持久化到可执行文件旁的 JSON 配置。
// 字段名与前端 Config() 返回的 map key 保持一致（camelCase）。
type appConfig struct {
	SeedHex    string `json:"seedHex"`
	Generation uint64 `json:"generation"`
	PSKHex     string `json:"pskHex"`
	ServerAddr string `json:"serverAddr"`
	// Transport is the underlay: "udp" (default) or "tcp" for networks
	// that throttle UDP.
	Transport     string        `json:"transport"`
	SplitTunnel   bool          `json:"splitTunnel"`
	PortHopCount  int           `json:"portHopCount"`
	PortHopSpread int           `json:"portHopSpread"`
	TunIP         string        `json:"tunIP"` // fallback when the server has no client_cidr
	Servers       []savedServer `json:"servers,omitempty"`
}

type savedServer struct {
	Name string `json:"name"`
	Addr string `json:"addr"`
}

// ChimeraApp 是 Wails 绑定的后端结构体。
// 它保存连接配置，并通过 core_bridge 中的 build-tag 桥接真实传输层。
type ChimeraApp struct {
	ctx context.Context

	mu      sync.Mutex
	cfg     appConfig
	status  string // disconnected / connecting / connected / error
	lastErr string
	quit    bool

	wdOnce sync.Once
}

// 失联判定阈值：keepalive 默认 25s 一个周期，3.5 个周期无任何入站帧视为
// 链路死亡（NAT 超时 / 网络切换 / 服务器重启），触发自动重连。
const linkLostAfter = 90 * time.Second

// NewChimeraApp 创建后端应用实例。
func NewChimeraApp() *ChimeraApp {
	return &ChimeraApp{
		status: "disconnected",
	}
}

// startup 在 Wails 前端加载完成后调用。
// 如果磁盘上已有配置文件，则载入内存，便于前端初始化表单。
func (a *ChimeraApp) startup(ctx context.Context) {
	a.ctx = ctx
	if err := a.loadConfig(); err != nil {
		log.Printf("[ChimeraApp] 读取已保存配置失败: %v", err)
	}
	startTray(a)
}

// Start 校验参数、保存配置到可执行文件旁，并启动协议传输层。
// 任何参数非法或启动失败都会返回 error，并把状态置为 error。
func (a *ChimeraApp) Start(seedHex string, generation uint64, pskHex string, serverAddr string) error {
	a.mu.Lock()
	split := a.cfg.SplitTunnel
	a.mu.Unlock()
	return a.start(seedHex, generation, pskHex, serverAddr, "", split, a.cfg.PortHopCount, a.cfg.PortHopSpread)
}

// StartWithTransport 是 Start 的扩展，允许选择 udp 或 tcp 底层传输。
// 旧前端继续调用 Start 时会沿用上次保存的 transport（默认 udp）。
func (a *ChimeraApp) StartWithTransport(seedHex string, generation uint64, pskHex string, serverAddr string, transport string) error {
	a.mu.Lock()
	hops := a.cfg.PortHopCount
	spread := a.cfg.PortHopSpread
	a.mu.Unlock()
	return a.start(seedHex, generation, pskHex, serverAddr, transport, true, hops, spread)
}

// StartAdvanced 是完整参数入口：transport + splitTunnel。
func (a *ChimeraApp) StartAdvanced(seedHex string, generation uint64, pskHex string, serverAddr string, transport string, splitTunnel bool) error {
	a.mu.Lock()
	hops := a.cfg.PortHopCount
	spread := a.cfg.PortHopSpread
	a.mu.Unlock()
	return a.start(seedHex, generation, pskHex, serverAddr, transport, splitTunnel, hops, spread)
}

// StartWithOptions 是完整参数入口：传输 + 分流 + 端口跳跃。
func (a *ChimeraApp) StartWithOptions(seedHex string, generation uint64, pskHex string, serverAddr string, transport string, splitTunnel bool, portHopCount int, portHopSpread int) error {
	return a.start(seedHex, generation, pskHex, serverAddr, transport, splitTunnel, portHopCount, portHopSpread)
}

func (a *ChimeraApp) start(seedHex string, generation uint64, pskHex string, serverAddr string, transport string, splitTunnel bool, portHopCount int, portHopSpread int) error {
	seedHex = strings.TrimSpace(seedHex)
	pskHex = strings.TrimSpace(pskHex)
	serverAddr = strings.TrimSpace(serverAddr)
	transport = strings.ToLower(strings.TrimSpace(transport))
	if transport == "" {
		a.mu.Lock()
		transport = a.cfg.Transport
		a.mu.Unlock()
	}
	if transport == "" {
		transport = "udp"
	}
	if transport != "udp" && transport != "tcp" && transport != "websocket" && transport != "wss" {
		err := fmt.Errorf("transport 必须是 udp 或 tcp")
		a.setError(err)
		return err
	}
	if portHopCount < 0 || portHopCount > 16 {
		err := fmt.Errorf("portHopCount 必须在 0-16 之间")
		a.setError(err)
		return err
	}
	if portHopCount > 1 && portHopSpread <= 0 {
		err := fmt.Errorf("portHopCount > 1 时必须设置 portHopSpread")
		a.setError(err)
		return err
	}

	if err := validateHexField("seedHex", seedHex); err != nil {
		a.setError(err)
		return err
	}
	if err := validateHexField("pskHex", pskHex); err != nil {
		a.setError(err)
		return err
	}
	if serverAddr == "" {
		err := fmt.Errorf("serverAddr 不能为空")
		a.setError(err)
		return err
	}

	cfg := appConfig{
		SeedHex:       seedHex,
		Generation:    generation,
		PSKHex:        pskHex,
		ServerAddr:    serverAddr,
		Transport:     transport,
		SplitTunnel:   splitTunnel,
		PortHopCount:  portHopCount,
		PortHopSpread: portHopSpread,
		TunIP:         "10.99.0.2",
	}

	a.mu.Lock()
	a.cfg = cfg
	a.status = "connecting"
	a.lastErr = ""
	a.mu.Unlock()

	// 配置必须先落盘，再启动传输层。
	if err := a.saveConfig(); err != nil {
		a.setError(err)
		return err
	}

	// 若已有旧连接，先优雅停止。
	stopPacketBridge()
	if err := stopTransport(); err != nil {
		log.Printf("[ChimeraApp] 停止旧传输层失败: %v", err)
	}

	if err := startTransport(cfg); err != nil {
		a.setError(err)
		return err
	}

	// 优先使用服务器自动分配的地址；服务器未开启 client_cidr 时回退到 tunIP。
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	ip, err := getAssignedIP(ctx)
	cancel()
	if err != nil {
		log.Printf("[ChimeraApp] 服务器未分配地址（%v），使用回退地址 %s", err, cfg.TunIP)
		ip = cfg.TunIP
	}
	if err := startPacketBridge(ip, cfg.SplitTunnel); err != nil {
		_ = stopTransport()
		a.setError(err)
		return err
	}

	a.mu.Lock()
	a.status = "connected"
	a.lastErr = ""
	a.mu.Unlock()
	a.rememberServer(cfg.ServerAddr, cfg.ServerAddr)
	if err := a.saveConfig(); err != nil {
		log.Printf("[ChimeraApp] 保存入口列表失败: %v", err)
	}
	a.startWatchdog()
	return nil
}

// startWatchdog 启动失联自动重连监督循环（幂等，随进程退出终止）。
// 健康链路上 keepalive 每 25s 刷新入站活跃；超过 linkLostAfter 无任何
// 入站帧说明五元组已死，重走完整 Start 流程（新握手、新 TUN 配置、
// 路由接管重建；服务器轮换过 generation 时探测窗口自动跟上）。
func (a *ChimeraApp) startWatchdog() {
	a.wdOnce.Do(func() {
		go func() {
			ticker := time.NewTicker(5 * time.Second)
			defer ticker.Stop()
			for range ticker.C {
				a.mu.Lock()
				status := a.status
				cfg := a.cfg
				a.mu.Unlock()
				if status != "connected" {
					continue
				}
				idle := linkIdleFor()
				if idle < linkLostAfter {
					continue
				}
				log.Printf("[watchdog] 链路静默 %v，自动重连 server=%s", idle, cfg.ServerAddr)
				a.mu.Lock()
				a.status = "connecting"
				a.mu.Unlock()
				if err := a.Start(cfg.SeedHex, cfg.Generation, cfg.PSKHex, cfg.ServerAddr); err != nil {
					log.Printf("[watchdog] 重连失败: %v", err)
				}
			}
		}()
	})
}

// Stop 停止传输层，但不会退出应用进程（GUI 保持运行）。
func (a *ChimeraApp) Stop() error {
	stopPacketBridge()
	if err := stopTransport(); err != nil {
		a.setError(err)
		return err
	}

	a.mu.Lock()
	a.status = "disconnected"
	a.lastErr = ""
	a.mu.Unlock()
	return nil
}

// Status 返回当前连接状态。
// 状态值为 disconnected / connecting / connected / error；
// 处于 error 时，返回 "error: <最后一次错误>"，便于前端直接展示。
func (a *ChimeraApp) Status() string {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.status == "error" {
		if a.lastErr != "" {
			return "error: " + a.lastErr
		}
		return "error"
	}
	return a.status
}

// Config 返回当前保存的配置（内存中的最新值）。
// key 为 seedHex / generation / pskHex / serverAddr，与 Start 参数名一致。
func (a *ChimeraApp) Config() (map[string]any, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	return map[string]any{
		"seedHex":       a.cfg.SeedHex,
		"generation":    a.cfg.Generation,
		"pskHex":        a.cfg.PSKHex,
		"serverAddr":    a.cfg.ServerAddr,
		"transport":     a.cfg.Transport,
		"splitTunnel":   a.cfg.SplitTunnel,
		"portHopCount":  a.cfg.PortHopCount,
		"portHopSpread": a.cfg.PortHopSpread,
		"tunIP":         a.cfg.TunIP,
		"servers":       a.cfg.Servers,
	}, nil
}

// Servers returns saved VPN entry points (host:port), not protocol secrets.
func (a *ChimeraApp) Servers() []savedServer {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]savedServer, len(a.cfg.Servers))
	copy(out, a.cfg.Servers)
	return out
}

// RememberServer upserts an entry by address and writes chimera-config.json.
func (a *ChimeraApp) RememberServer(name, addr string) error {
	a.mu.Lock()
	a.cfg.Servers = upsertServer(a.cfg.Servers, name, addr)
	a.mu.Unlock()
	return a.saveConfig()
}

// ForgetServer removes a saved entry by address.
func (a *ChimeraApp) ForgetServer(addr string) error {
	addr = strings.TrimSpace(addr)
	a.mu.Lock()
	filtered := a.cfg.Servers[:0]
	for _, s := range a.cfg.Servers {
		if !strings.EqualFold(s.Addr, addr) {
			filtered = append(filtered, s)
		}
	}
	a.cfg.Servers = filtered
	a.mu.Unlock()
	return a.saveConfig()
}

// Traffic is cumulative TUN IP bytes since the current session started.
func (a *ChimeraApp) Traffic() map[string]any {
	sent, recv := trafficBytes()
	return map[string]any{
		"sent": sent,
		"recv": recv,
	}
}

// HideToTray hides the window; the process stays in the notification area.
func (a *ChimeraApp) HideToTray() {
	if a.ctx != nil {
		runtimeWindowHide(a.ctx)
	}
}

// QuitApp tears down the tunnel and exits (tray “退出”).
func (a *ChimeraApp) QuitApp() {
	a.mu.Lock()
	a.quit = true
	a.mu.Unlock()
	_ = a.Stop()
	stopTray()
	if a.ctx != nil {
		runtimeQuit(a.ctx)
	}
}

func (a *ChimeraApp) beforeClose(ctx context.Context) (prevent bool) {
	a.mu.Lock()
	quitting := a.quit
	a.mu.Unlock()
	if quitting {
		stopTray()
		return false
	}
	runtimeWindowHide(ctx)
	return true
}

func (a *ChimeraApp) rememberServer(name, addr string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.cfg.Servers = upsertServer(a.cfg.Servers, name, addr)
}

func upsertServer(list []savedServer, name, addr string) []savedServer {
	addr = strings.TrimSpace(addr)
	name = strings.TrimSpace(name)
	if addr == "" {
		return list
	}
	if name == "" {
		name = addr
	}
	for i, s := range list {
		if strings.EqualFold(s.Addr, addr) {
			if name != "" && name != addr {
				list[i].Name = name
			}
			return list
		}
	}
	return append(list, savedServer{Name: name, Addr: addr})
}

// SelectServerDefault 返回默认服务器地址常量。
func (a *ChimeraApp) SelectServerDefault() string {
	return DefaultServerAddr
}

// ParseInvite fills the form from a chimera:// URL or pasted client.json.
// Never log the raw text; it contains the PSK.
func (a *ChimeraApp) ParseInvite(text string) (map[string]any, error) {
	p, err := invite.Parse(text)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"serverAddr": p.Addr,
		"seedHex":    p.SeedHex,
		"pskHex":     p.PSKHex,
		"generation": p.Generation,
		"name":       p.Name,
	}, nil
}

// CopyInvite encodes the current fields as a chimera://v1/ URL and copies it
// to the clipboard when the Wails context is ready.
func (a *ChimeraApp) CopyInvite(name, addr, seedHex, pskHex string, generation uint64) (string, error) {
	link, err := invite.Format(invite.Profile{
		Addr:       addr,
		SeedHex:    seedHex,
		PSKHex:     pskHex,
		Generation: generation,
		Name:       name,
	})
	if err != nil {
		return "", err
	}
	if err := runtimeClipboardSet(a.ctx, link); err != nil {
		log.Printf("[ChimeraApp] clipboard: %v", err)
	}
	return link, nil
}

// setError 将状态置为 error 并记录最后一次错误。
func (a *ChimeraApp) setError(err error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.status = "error"
	a.lastErr = err.Error()
}

// configFilePath 返回可执行文件旁的 chimera-config.json 路径。
func (a *ChimeraApp) configFilePath() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("获取可执行文件路径失败: %w", err)
	}
	return filepath.Join(filepath.Dir(exe), "chimera-config.json"), nil
}

// saveConfig 把当前配置写入可执行文件旁的 JSON 文件。
func (a *ChimeraApp) saveConfig() error {
	path, err := a.configFilePath()
	if err != nil {
		return err
	}

	a.mu.Lock()
	data, err := json.MarshalIndent(a.cfg, "", "  ")
	a.mu.Unlock()
	if err != nil {
		return fmt.Errorf("序列化配置失败: %w", err)
	}

	// 0600：配置中包含 PSK，尽量限制可读权限（Windows 上按文件系统语义处理）。
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("写入配置 %s 失败: %w", path, err)
	}
	log.Printf("[ChimeraApp] 配置已写入 %s", path)
	return nil
}

// loadConfig 从可执行文件旁读取配置；文件不存在时静默返回。
func (a *ChimeraApp) loadConfig() error {
	path, err := a.configFilePath()
	if err != nil {
		return err
	}

	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("读取配置 %s 失败: %w", path, err)
	}

	var cfg appConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return fmt.Errorf("解析配置 %s 失败: %w", path, err)
	}
	// 兼容旧配置文件：没有 transport/splitTunnel 字段时启用推荐默认值。
	var probe map[string]any
	if err := json.Unmarshal(data, &probe); err == nil {
		if _, ok := probe["transport"]; !ok || cfg.Transport == "" {
			cfg.Transport = "udp"
		}
		if _, ok := probe["splitTunnel"]; !ok {
			cfg.SplitTunnel = true
		}
		if _, ok := probe["portHopCount"]; !ok {
			cfg.PortHopCount = 1
		}
	}

	a.mu.Lock()
	a.cfg = cfg
	a.mu.Unlock()
	return nil
}

// validateHexField 校验字段是否为非空、合法的十六进制字符串。
func validateHexField(name, value string) error {
	if value == "" {
		return fmt.Errorf("%s 不能为空", name)
	}
	if _, err := hex.DecodeString(value); err != nil {
		return fmt.Errorf("%s 必须是合法的十六进制字符串: %w", name, err)
	}
	return nil
}
