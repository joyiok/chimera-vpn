package main

import (
	"fmt"
	"os/exec"
	"strings"
)

func configureTUN(name, address string, mtu int) error {
	if out, err := exec.Command("ip", "addr", "add", address, "dev", name).CombinedOutput(); err != nil {
		if !ipAddrAlreadyPresent(out) {
			return fmt.Errorf("ip addr add: %v: %s", err, out)
		}
	}
	if out, err := exec.Command("ip", "link", "set", "dev", name, "mtu", fmt.Sprint(mtu), "up").CombinedOutput(); err != nil {
		return fmt.Errorf("ip link set: %v: %s", err, out)
	}
	return nil
}

func ipAddrAlreadyPresent(out []byte) bool {
	s := strings.ToLower(string(out))
	return strings.Contains(s, "file exists")
}
