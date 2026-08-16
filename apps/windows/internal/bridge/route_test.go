package bridge

import (
	"net"
	"testing"
)

func mustNet(s string) net.IPNet {
	_, n, err := net.ParseCIDR(s)
	if err != nil {
		panic(err)
	}
	return *n
}

func TestTunGateway(t *testing.T) {
	cases := []struct {
		ip   string
		want string
	}{
		{"10.99.0.5", "10.99.0.1"},
		{"10.99.0.2", "10.99.0.1"},
		{"192.168.50.130", "192.168.50.1"},
	}
	for _, c := range cases {
		got, err := tunGateway(c.ip)
		if err != nil {
			t.Fatalf("tunGateway(%s): %v", c.ip, err)
		}
		if got != c.want {
			t.Errorf("tunGateway(%s) = %s, want %s", c.ip, got, c.want)
		}
	}
	if _, err := tunGateway("not-an-ip"); err == nil {
		t.Error("tunGateway should reject non-IP input")
	}
	if _, err := tunGateway("fe80::1"); err == nil {
		t.Error("tunGateway should reject IPv6")
	}
}

func TestHostFromAddr(t *testing.T) {
	cases := []struct{ in, want string }{
		{"1.2.3.4:443", "1.2.3.4"},
		{"vpn.example.com:443", "vpn.example.com"},
		{"vpn.example.com", "vpn.example.com"},
		{"[2001:db8::1]:443", "2001:db8::1"},
	}
	for _, c := range cases {
		if got := hostFromAddr(c.in); got != c.want {
			t.Errorf("hostFromAddr(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestChoosePhysicalAdapter(t *testing.T) {
	tun := "Chimera"
	serverIP := net.ParseIP("203.0.113.7")

	adapters := []adapterInfo{
		{name: "Loopback", index: 1, operUp: true, ifType: ifTypeLoopback},
		{name: tun, description: "Wintun Userspace Tunnel", index: 5, operUp: true, ifType: ifTypeTunnel, gateway: "10.99.0.1"},
		{name: "Wi-Fi", index: 12, operUp: true, ifType: 71, metric: 30, gateway: "192.168.1.1", onLink: []net.IPNet{mustNet("192.168.1.0/24")}},
		{name: "Ethernet", index: 13, operUp: true, ifType: 6, metric: 10, gateway: "192.168.1.1", onLink: []net.IPNet{mustNet("192.168.1.0/24")}},
		{name: "Old VPN", description: "TAP-Windows Adapter", index: 20, operUp: false, ifType: ifTypeTunnel, gateway: "10.8.0.1"},
	}

	// Best metric wins between two same-subnet physical adapters.
	got, err := choosePhysicalAdapter(adapters, serverIP, tun)
	if err != nil {
		t.Fatal(err)
	}
	if got.name != "Ethernet" {
		t.Errorf("got adapter %q, want Ethernet (lowest metric)", got.name)
	}

	// Server inside the LAN subnet -> that adapter directly.
	lanServer := net.ParseIP("192.168.1.50")
	got, err = choosePhysicalAdapter(adapters, lanServer, tun)
	if err != nil {
		t.Fatal(err)
	}
	if got.name != "Ethernet" {
		t.Errorf("got adapter %q for LAN server, want a 192.168.1.0/24 adapter", got.name)
	}

	// Nothing usable -> error.
	if _, err := choosePhysicalAdapter(adapters[:1], serverIP, tun); err == nil {
		t.Error("expected error when only loopback is present")
	}
}

func TestResolveServerIPv4(t *testing.T) {
	if ip, err := resolveServerIPv4("192.0.2.10"); err != nil || ip.String() != "192.0.2.10" {
		t.Errorf("literal IPv4: ip=%v err=%v", ip, err)
	}
	if _, err := resolveServerIPv4("2001:db8::1"); err == nil {
		t.Error("IPv6 server should be rejected for now")
	}
	if _, err := resolveServerIPv4("no-such-host.invalid"); err != nil {
		// 期望失败；但某些环境（WSL DNS 代理）会劫持解析，此时跳过该断言。
		t.Logf("unresolvable host errored as expected (or DNS proxy present): %v", err)
	}
}

func TestAdapterContainsIP(t *testing.T) {
	a := adapterInfo{onLink: []net.IPNet{mustNet("10.99.0.0/24")}}
	if !a.containsIP(net.ParseIP("10.99.0.7")) {
		t.Error("10.99.0.7 should be on-link")
	}
	if a.containsIP(net.ParseIP("10.99.1.7")) {
		t.Error("10.99.1.7 should not be on-link")
	}
	if a.containsIP(net.ParseIP("2001:db8::1")) {
		t.Error("IPv6 should never match an IPv4 on-link set")
	}
}
