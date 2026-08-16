//go:build with_transport

// with_transport 构建：真正调用 monorepo 核心传输层 chimera/core。
// 仅当 /home/joy/chimera 根模块已提供 core 包时才能编译通过。
package main

import (
	"context"
	"fmt"
	"log"

	core "chimera/core"

	bridge "chimera/windows-client/internal/bridge"
)

// transportClient 持有真实核心客户端；stopTransport 会关闭它。
var transportClient *core.Client

// packetBridge 是 Windows Wintun 数据面；stopPacketBridge 会关闭它。
var packetBridge *bridge.Bridge

// startTransport 使用计划中的 core API 创建并启动客户端。
func startTransport(cfg appConfig) error {
	client, err := core.NewClient(core.Config{
		SeedHex:    cfg.SeedHex,
		Generation: cfg.Generation,
		PSKHex:     cfg.PSKHex,
		ServerAddr: cfg.ServerAddr,
	})
	if err != nil {
		return fmt.Errorf("core.NewClient: %w", err)
	}

	if err := client.Start(); err != nil {
		_ = client.Close()
		return fmt.Errorf("client.Start: %w", err)
	}

	transportClient = client
	log.Printf("[coreBridge] 真实传输层已启动：server=%s generation=%d", cfg.ServerAddr, cfg.Generation)
	return nil
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

// startPacketBridge 创建 Wintun 虚拟网卡并启动双向包泵。
func startPacketBridge(ip string) error {
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
	return nil
}

// stopPacketBridge 停止 Wintun 数据面。
func stopPacketBridge() {
	if packetBridge != nil {
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
