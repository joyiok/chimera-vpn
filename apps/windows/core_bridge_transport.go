//go:build with_transport

// with_transport 构建：真正调用 monorepo 核心传输层 chimera/core。
// 仅当 /home/joy/chimera 根模块已提供 core 包时才能编译通过。
package main

import (
	"context"
	"fmt"
	"log"
	"time"

	core "chimera/core"
	geoip "chimera/geoip"

	bridge "chimera/windows-client/internal/bridge"
)

// transportClient 持有真实核心客户端；stopTransport 会关闭它。
var transportClient *core.Client

// packetBridge 是 Windows Wintun 数据面；stopPacketBridge 会关闭它。
var packetBridge *bridge.Bridge

// routeTakeover 管理 0/1 + 128/1 默认路由接管与服务器 /32 例外。
var routeTakeover = bridge.NewRouteTakeover()

// startTransport 使用计划中的 core API 创建并启动客户端。
// GenerationWindow=2：服务器轮换 generation 后握手超时自动探测 gen+1/gen+2。
// transport / portHop 参数必须真正传入核心——UI 上选了 tcp/wss 或开启
// 跳跃时，底层拨号必须随之改变，否则用户以为在 TCP 实际还在 UDP。
func startTransport(cfg appConfig) error {
	hopCount, hopSpread := cfg.PortHopCount, cfg.PortHopSpread
	if hopCount > 1 && hopSpread <= 0 {
		hopSpread = 2048
	}
	client, err := core.NewClient(core.Config{
		SeedHex:          cfg.SeedHex,
		Generation:       cfg.Generation,
		GenerationWindow: 2,
		JitterMax:        20 * time.Millisecond,
		PSKHex:           cfg.PSKHex,
		ServerAddr:       cfg.ServerAddr,
		Transport:        cfg.Transport,
		PortHopCount:     hopCount,
		PortHopSpread:    hopSpread,
	})
	if err != nil {
		return fmt.Errorf("core.NewClient: %w", err)
	}

	if err := client.Start(); err != nil {
		_ = client.Close()
		return fmt.Errorf("client.Start: %w", err)
	}

	transportClient = client
	log.Printf("[coreBridge] 真实传输层已启动：server=%s transport=%s generation=%d hop=%d/%d",
		cfg.ServerAddr, cfg.Transport, client.Generation(), hopCount, hopSpread)
	return nil
}

// linkIdleFor 返回当前会话的入站静默时长；未连接时为 0。
// app 层 watchdog 据此判定失联（健康链路 keepalive 下不会超过一个间隔）。
func linkIdleFor() time.Duration {
	if transportClient == nil {
		return 0
	}
	return transportClient.IdleFor()
}

func trafficBytes() (sent, recv uint64) {
	if transportClient == nil {
		return 0, 0
	}
	return transportClient.Bytes()
}

// stopTransport 关闭真实核心客户端。
func stopTransport() error {
	if transportClient == nil {
		return nil
	}

	err := transportClient.Close()
	transportClient = nil
	if err != nil {
		return fmt.Errorf("client.Close: %w", err)
	}
	return nil
}

// getAssignedIP 等待服务器下发自动分配的 TUN 地址。
func getAssignedIP(ctx context.Context) (string, error) {
	if transportClient == nil {
		return "", fmt.Errorf("transport not started")
	}
	return transportClient.AssignedIP(ctx)
}

// startPacketBridge 创建 Wintun 虚拟网卡、启动双向包泵，并接管默认路由。
// 路由接管失败按非致命处理：隧道仍可用（用户手工路由），只记日志。
func startPacketBridge(ip string, cfg appConfig) error {
	if transportClient == nil {
		return fmt.Errorf("transport not started")
	}
	stopPacketBridge()
	b, err := bridge.Start(ip, 1400, sendPacket, receivePacket)
	if err != nil {
		return fmt.Errorf("bridge.Start: %w", err)
	}
	packetBridge = b
	log.Printf("[coreBridge] Wintun packet bridge started with %s/24", ip)

	// Geo split: 大陆直连。优先用户提供的 mmdb（数据始终最新），
	// 未配置时用内置 chnroute 快照。
	var geoPrefixes []string
	if cfg.GeoipDb != "" {
		r, err := geoip.Open(cfg.GeoipDb)
		if err != nil {
			log.Printf("[coreBridge] geoip db %s 不可用（%v），改用内置 chnroute", cfg.GeoipDb, err)
		} else {
			prefixes, perr := r.CountryPrefixes([]string{"CN"})
			r.Close()
			if perr != nil {
				log.Printf("[coreBridge] geoip db 遍历失败（%v），改用内置 chnroute", perr)
			} else {
				for _, p := range prefixes {
					if p.IP.To4() != nil {
						geoPrefixes = append(geoPrefixes, p.String())
					}
				}
				log.Printf("[coreBridge] geoip db %s: %d 条大陆路由", cfg.GeoipDb, len(geoPrefixes))
			}
		}
	}

	serverAddr := transportClient.Config().ServerAddr
	if err := routeTakeover.Install(b.Name(), ip, serverAddr, cfg.SplitTunnel, geoPrefixes); err != nil {
		log.Printf("[coreBridge] 默认路由接管失败（隧道仍可用，可手工添加路由）: %v", err)
	} else {
		log.Printf("[coreBridge] 默认路由已接管: 0.0.0.0/1 + 128.0.0.0/1 -> %s，服务器例外 %s（split=%v）", b.Name(), serverAddr, cfg.SplitTunnel)
	}
	return nil
}

// stopPacketBridge 释放路由并停止 Wintun 数据面。
func stopPacketBridge() {
	if packetBridge != nil {
		if err := routeTakeover.Release(); err != nil {
			log.Printf("[coreBridge] 释放接管路由失败（重启后自动消失）: %v", err)
		}
		_ = packetBridge.Close()
		packetBridge = nil
	}
}

// sendPacket 发送一个 IP 包给核心传输层。
func sendPacket(ipPacket []byte) error {
	if transportClient == nil {
		return fmt.Errorf("transport not started")
	}
	return transportClient.SendPacket(ipPacket)
}

// receivePacket 从核心传输层接收一个 IP 包。
func receivePacket() ([]byte, error) {
	if transportClient == nil {
		return nil, fmt.Errorf("transport not started")
	}
	return transportClient.ReceivePacket()
}
