// Command gencompiler is the reference CLI for the CHIMERA protocol genome
// compiler: seed in, executable protocol species out.
package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"

	"chimera/internal/compiler"
	"chimera/internal/genome"
)

func main() {
	var (
		seedHex  = flag.String("seed", "", "genome seed, 64 hex chars (32 bytes); random when empty")
		gen      = flag.Uint64("gen", 0, "protocol generation / mutation number")
		jsonOut  = flag.String("json", "", "write the full protocol genome as JSON to this file")
		skipDemo = flag.Bool("no-demo", false, "skip the in-memory handshake demo")
	)
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: gencompiler -seed <64 hex chars> [-gen N] [-json out.json] [-no-demo]\n")
		flag.PrintDefaults()
	}
	flag.Parse()

	seed, generatedSeed, err := loadSeed(*seedHex)
	if err != nil {
		fatal(err)
	}
	psk := sha256.Sum256(append(append([]byte(nil), seed...), []byte("|psk")...))

	g, err := genome.Generate(seed, *gen)
	if err != nil {
		fatal(err)
	}

	printSummary(g, seed, generatedSeed)

	if *jsonOut != "" {
		b, err := json.MarshalIndent(g, "", "  ")
		if err != nil {
			fatal(err)
		}
		if err := os.WriteFile(*jsonOut, append(b, '\n'), 0o644); err != nil {
			fatal(err)
		}
		fmt.Printf("\nfull genome written to %s\n", *jsonOut)
	}

	if !*skipDemo {
		if err := runDemo(g, psk[:]); err != nil {
			fatal(fmt.Errorf("demo failed: %w", err))
		}
	}
}

func loadSeed(hexSeed string) ([]byte, bool, error) {
	if strings.TrimSpace(hexSeed) == "" {
		seed := make([]byte, 32)
		if _, err := rand.Read(seed); err != nil {
			return nil, false, err
		}
		return seed, true, nil
	}
	clean := strings.ReplaceAll(strings.TrimSpace(hexSeed), "0x", "")
	b, err := hex.DecodeString(clean)
	if err != nil {
		return nil, false, fmt.Errorf("seed must be hex: %w", err)
	}
	if len(b) != 32 {
		return nil, false, fmt.Errorf("seed must be 32 bytes (64 hex chars), got %d", len(b))
	}
	return b, false, nil
}

func printSummary(g *genome.ProtocolGenome, seed []byte, generated bool) {
	seedHex := hex.EncodeToString(seed)
	if generated {
		fmt.Printf("seed  : %s  (newly generated; save it!)\n", seedHex)
	} else {
		fmt.Printf("seed  : %s\n", seedHex)
	}
	fmt.Printf("generation          : %d\n", g.Generation)
	fmt.Printf("protocol fingerprint: %s\n", g.ProtocolFingerprint)
	fmt.Printf("est. design entropy : %.1f bits\n", g.EstimatedEntropyBits)
	fmt.Printf("handshake pattern   : %s\n", g.HandshakePattern)
	fmt.Println()

	for _, m := range g.Handshake {
		printMessage(m)
	}
	fmt.Println("app record (both directions):")
	printMessage(g.AppRecord)
}

func printMessage(m genome.MessageSpec) {
	var plain []string
	for _, f := range m.PlainFields {
		if f.Kind == genome.FieldLength {
			plain = append(plain, fmt.Sprintf("%s(%s,%s,%s,alone=%v)", f.Kind, f.Encoding, f.Endian, f.Subject, m.LengthAlone))
			continue
		}
		if f.ValueHex != "" {
			plain = append(plain, fmt.Sprintf("%s[%s]", f.Kind, f.ValueHex))
		} else {
			plain = append(plain, fmt.Sprintf("%s(%s)", f.Kind, f.Encoding))
		}
	}
	var enc []string
	for _, f := range m.EncryptedFields {
		enc = append(enc, fmt.Sprintf("%s(%s)", f.Kind, f.Encoding))
	}
	fmt.Printf("  %-10s %-6s plain=%-55s enc=%s payload=%v pad=%s[%d,%d] cipher=%s\n",
		m.Name, m.Direction, strings.Join(plain, " "), strings.Join(enc, " "), m.HasPayload,
		m.Padding.Mode, m.Padding.Min, m.Padding.Max, m.Cipher)
}

func runDemo(g *genome.ProtocolGenome, psk []byte) error {
	cp, err := compiler.Compile(g, psk)
	if err != nil {
		return err
	}

	client, err := compiler.NewHandshake(cp, genome.DirClient, psk)
	if err != nil {
		return err
	}
	server, err := compiler.NewHandshake(cp, genome.DirServer, psk)
	if err != nil {
		return err
	}
	client.SetEarlyData([]byte("0-RTT demo early bytes"))
	server.SetEarlyData([]byte("server early bytes"))

	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()

	clientDone := make(chan error, 1)
	serverDone := make(chan error, 1)
	go func() { clientDone <- client.Run(left) }()
	go func() { serverDone <- server.Run(right) }()
	if err := <-clientDone; err != nil {
		return fmt.Errorf("client handshake: %w", err)
	}
	if err := <-serverDone; err != nil {
		return fmt.Errorf("server handshake: %w", err)
	}

	cs, err := client.Finish()
	if err != nil {
		return err
	}
	ss, err := server.Finish()
	if err != nil {
		return err
	}

	fmt.Println("\n-- handshake demo --")
	fmt.Printf("handshake OK over generated pattern %q\n", g.HandshakePattern)

	const p1 = "hello chimera, this is an app record"
	const p2 = "payload from the other direction"

	// net.Pipe writes block until the peer reads, so pair each send with a
	// concurrent receive.
	type recvResult struct {
		msg *compiler.Message
		err error
	}
	c2sRecv := make(chan recvResult, 1)
	go func() {
		m, err := ss.Recv(right)
		c2sRecv <- recvResult{m, err}
	}()
	if err := cs.Send(left, []byte(p1)); err != nil {
		return err
	}
	r1 := <-c2sRecv
	if r1.err != nil {
		return r1.err
	}
	if string(r1.msg.Payload) != p1 {
		return fmt.Errorf("c2s payload mismatch: %q", r1.msg.Payload)
	}

	s2cRecv := make(chan recvResult, 1)
	go func() {
		m, err := cs.Recv(left)
		s2cRecv <- recvResult{m, err}
	}()
	if err := ss.Send(right, []byte(p2)); err != nil {
		return err
	}
	r2 := <-s2cRecv
	if r2.err != nil {
		return r2.err
	}
	if string(r2.msg.Payload) != p2 {
		return fmt.Errorf("s2c payload mismatch: %q", r2.msg.Payload)
	}
	fmt.Printf("app record c2s  : %q (round trip OK)\n", r1.msg.Payload)
	fmt.Printf("app record s2c  : %q (round trip OK)\n", r2.msg.Payload)
	fmt.Println("session keys derived from X25519 + PSK + handshake transcript")
	return nil
}

func fatal(err error) {
	fmt.Fprintf(os.Stderr, "gencompiler: %v\n", err)
	os.Exit(1)
}
