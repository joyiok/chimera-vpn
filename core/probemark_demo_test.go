package core

// 临时演示：本地握手并把上线字节录下来，直观展示 probe_mark 的效果。
// 运行: go test ./core/ -run TestMarkDemo -v （演示后删除此文件）

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"chimera/internal/compiler"
	"chimera/internal/genome"
	"chimera/internal/tunnel"
)

type markRecordConn struct {
	net.PacketConn
	captured [][]byte
}

func (r *markRecordConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	r.captured = append(r.captured, append([]byte(nil), p...))
	return r.PacketConn.WriteTo(p, addr)
}

func TestMarkDemo(t *testing.T) {
	seed := make([]byte, 32)
	psk := make([]byte, 32)
	for i := 0; i < 32; i++ {
		seed[i] = byte(i)
		psk[i] = byte(0xAA + i)
	}
	g, err := genome.GenerateWithCipher(seed, 0, "")
	if err != nil {
		t.Fatal(err)
	}
	cp, err := compiler.Compile(g, psk)
	if err != nil {
		t.Fatal(err)
	}

	for _, marked := range []bool{false, true} {
		mark := ""
		if marked {
			mark = "MEASURE-7"
			if err := compiler.SetProbeMark(mark); err != nil {
				t.Fatal(err)
			}
		} else {
			_ = compiler.SetProbeMark("")
		}

		serverConn, _ := net.ListenPacket("udp", "127.0.0.1:0")
		clientConn, _ := net.ListenPacket("udp", "127.0.0.1:0")
		rec := &markRecordConn{PacketConn: clientConn}

		ctx, cancel := context.WithCancel(context.Background())
		mux := tunnel.NewServerMux(serverConn, cp, psk).WithKeepalive(-1)
		go mux.Run(ctx)

		hh, err := compiler.NewHandshake(cp, genome.DirClient, psk)
		if err != nil {
			t.Fatal(err)
		}
		frame, _, err := hh.EncodeStep()
		if err != nil {
			t.Fatal(err)
		}
		wire := hh.WrapDatagram(frame)
		if _, err := rec.WriteTo(wire, serverConn.LocalAddr()); err != nil {
			t.Fatal(err)
		}

		t.Logf("\n=== %s ===\n", map[bool]string{false: "默认（无标记）", true: "开启 probe_mark = MEASURE-7"}[marked])
		for i, dg := range rec.captured {
			p := dg
			if len(p) > 44 {
				p = p[:44]
			}
			out := make([]byte, len(p))
			for j, c := range p {
				if c >= 0x20 && c <= 0x7e {
					out[j] = c
				} else {
					out[j] = '.'
				}
			}
			hit := ""
			if len(mark) > 0 && containsStr(dg, mark) {
				hit = "   <== 含标记"
			}
			t.Logf("  上行数据报 #%d (%3d B): %q%s\n", i, len(dg), string(out), hit)
		}
		if marked {
			t.Logf("  → 观察者 grep %q 即可锁定这个部署\n", mark)
		} else {
			fmt.Println("  → 全随机封面，无规律可抓")
		}

		time.Sleep(50 * time.Millisecond)
		cancel()
		serverConn.Close()
		clientConn.Close()
		_ = tunnel.DefaultJitterMax
	}
}

func containsStr(b []byte, s string) bool {
	return len(s) > 0 && len(b) >= len(s) && indexOf(b, s) >= 0
}

func indexOf(b []byte, s string) int {
	for i := 0; i+len(s) <= len(b); i++ {
		match := true
		for j := 0; j < len(s); j++ {
			if b[i+j] != s[j] {
				match = false
				break
			}
		}
		if match {
			return i
		}
	}
	return -1
}

// TestProbeMarkRoundTrip: both ends configured with the same mark must
// still establish a session and move data — detectability never breaks
// functionality.
func TestProbeMarkRoundTrip(t *testing.T) {
	seed := make([]byte, 32)
	psk := make([]byte, 32)
	for i := 0; i < 32; i++ {
		seed[i] = byte(0x30 + i)
		psk[i] = byte(0x60 + i)
	}

	srvCfg := testConfig("127.0.0.1:0", "udp")
	srvCfg.ProbeMark = "MEASURE-7"
	srv, err := NewServer(srvCfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	defer srv.Close()

	cliCfg := testConfig(srv.LocalAddr().String(), "udp")
	cliCfg.ProbeMark = "MEASURE-7"
	cli, err := NewClient(cliCfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := cli.Start(); err != nil {
		t.Fatalf("marked client handshake failed: %v", err)
	}
	defer cli.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := srv.Accept(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	if err := conn.SendPacket([]byte("marked-echo")); err != nil {
		t.Fatal(err)
	}
	got, err := cli.ReceivePacket()
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "marked-echo" {
		t.Fatalf("got %q", got)
	}
}
