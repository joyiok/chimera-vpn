//go:build with_transport

// with_transport 构建：真正调用 monorepo 核心传输层 chimera/core。
// 仅当 /home/joy/chimera 根模块已提供 core 包时才能编译通过。
package main

import (
	"fmt"
	"log"

	core "chimera/core"
)

// transportClient 持有真实核心客户端；stopTransport 会关闭它。
var transportClient *core.Client

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
