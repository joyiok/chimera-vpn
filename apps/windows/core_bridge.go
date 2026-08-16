//go:build !with_transport

// 默认构建：传输层 stub。
// 在 monorepo 的 chimera/core 合并之前，GUI 仍可完整编译、启动，
// 但 Start 会返回明确错误，提示需要 with_transport 标签重新构建。
package main

import (
	"context"
	"errors"
	"log"
)

// startTransport 是桩实现：不启动任何真实协议。
func startTransport(cfg appConfig) error {
	log.Printf("[coreBridge] 传输层 stub：server=%s generation=%d，未启动真实协议", cfg.ServerAddr, cfg.Generation)
	return errors.New("transport not compiled: rebuild with -tags with_transport")
}

// stopTransport 桩实现：无真实资源需要释放。
func stopTransport() error {
	return nil
}

// sendPacket 桩实现：真实传输层未编译。
func sendPacket(ipPacket []byte) error {
	return errors.New("transport not compiled: rebuild with -tags with_transport")
}

// receivePacket 桩实现：真实传输层未编译。
func receivePacket() ([]byte, error) {
	return nil, errors.New("transport not compiled: rebuild with -tags with_transport")
}

func getAssignedIP(ctx context.Context) (string, error) {
	return "", errors.New("transport not compiled: rebuild with -tags with_transport")
}

func startPacketBridge(ip string) error {
	return errors.New("transport not compiled: rebuild with -tags with_transport")
}

func stopPacketBridge() {}
