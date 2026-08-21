// Command chimera-eval scores a pcap against the gfw.report / Wu 2023
// fully-encrypted-traffic heuristics and prints payload-length plus
// inter-arrival stats. This is the inferred detector from the paper, not
// a measurement of the live GFW.
package main

import (
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math"
	"os"
	"sort"
	"strings"

	"chimera/internal/compiler"
)

func main() {
	pcapPath := flag.String("pcap", "", "classic pcap file from tcpdump -w (not pcapng)")
	port := flag.Int("port", 4789, "UDP port to keep; 0 = all UDP")
	jsonOut := flag.Bool("json", false, "print JSON instead of text")
	ladder := flag.Bool("ladder", false, "derive a shape-bucket ladder from the capture (packet-length quantiles) instead of scoring; feed the output to shape_buckets in server/client config")
	flag.Parse()
	if *pcapPath == "" {
		fmt.Fprintf(os.Stderr, "usage: chimera-eval -pcap capture.pcap [-port 4789] [-ladder]\n")
		os.Exit(2)
	}
	pkts, err := loadPackets(*pcapPath, *port)
	if err != nil {
		fmt.Fprintf(os.Stderr, "chimera-eval: %v\n", err)
		os.Exit(1)
	}
	if *ladder {
		buckets := deriveLadder(pkts)
		if len(buckets) == 0 {
			fmt.Fprintf(os.Stderr, "chimera-eval: no UDP packets matched -port %d\n", *port)
			os.Exit(1)
		}
		if *jsonOut {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			if err := enc.Encode(map[string]any{"packets": len(pkts), "buckets": buckets}); err != nil {
				fmt.Fprintf(os.Stderr, "chimera-eval: %v\n", err)
				os.Exit(1)
			}
			return
		}
		fmt.Printf("# shape ladder from %d packets (p10/p30/p50/p70/p90)\n", len(pkts))
		fmt.Printf("\"shape_buckets\": [%s]\n", joinInts(buckets))
		return
	}
	rep := evaluate(pkts)
	if *jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(rep); err != nil {
			fmt.Fprintf(os.Stderr, "chimera-eval: %v\n", err)
			os.Exit(1)
		}
		return
	}
	printReport(rep)
}

func loadPackets(path string, port int) ([]datum, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return readUDPPayloads(f, port)
}

// deriveLadder converts observed packet lengths into a send-side padding
// ladder: the p10/p30/p50/p70/p90 length quantiles, clamped to the valid
// bucket range and de-duplicated in ascending order. Shaping to these
// buckets makes the tunnel's length distribution track the capture's.
func deriveLadder(pkts []datum) []int {
	if len(pkts) == 0 {
		return nil
	}
	lens := make([]float64, 0, len(pkts))
	for _, d := range pkts {
		lens = append(lens, float64(len(d.payload)))
	}
	sort.Float64s(lens)
	q := func(p float64) int {
		v := int(math.Round(percentile(lens, p)))
		switch {
		case v < 64:
			v = 64
		case v > 1452:
			v = 1452
		}
		return v
	}
	var out []int
	for _, p := range []float64{0.10, 0.30, 0.50, 0.70, 0.90} {
		b := q(p)
		if len(out) == 0 || b > out[len(out)-1] {
			out = append(out, b)
		}
	}
	return out
}

func joinInts(xs []int) string {
	parts := make([]string, len(xs))
	for i, x := range xs {
		parts[i] = fmt.Sprint(x)
	}
	return strings.Join(parts, ", ")
}

type report struct {
	Packets       int            `json:"packets"`
	Flows         int            `json:"flows"`
	FirstExempt   int            `json:"first_exempt"`
	FirstBlocked  int            `json:"first_blocked"`
	ExemptRate    float64        `json:"exempt_rate"`
	Rules         map[string]int `json:"fep_rules"`
	LengthBuckets map[string]int `json:"length_buckets"`
	IATMsP50      float64        `json:"iat_ms_p50"`
	IATMsP90      float64        `json:"iat_ms_p90"`
	IATMsMean     float64        `json:"iat_ms_mean"`
	Note          string         `json:"note"`
}

type datum struct {
	tsUs    int64
	payload []byte
	flow    string
}

func evaluateFile(path string, port int) (report, error) {
	f, err := os.Open(path)
	if err != nil {
		return report{}, err
	}
	defer f.Close()
	pkts, err := readUDPPayloads(f, port)
	if err != nil {
		return report{}, err
	}
	return evaluate(pkts), nil
}

func evaluate(pkts []datum) report {
	rep := report{
		Packets:       len(pkts),
		Rules:         map[string]int{},
		LengthBuckets: map[string]int{},
		Note:          "Wu 2023 Algorithm 1 inferred by gfw.report, applied to UDP first payloads. Not a live-GFW verdict. Path RTT usually dwarfs the 20ms send jitter.",
	}
	if len(pkts) == 0 {
		return rep
	}

	first := map[string][]byte{}
	var iats []float64
	lastTs := map[string]int64{}
	for _, p := range pkts {
		rep.LengthBuckets[lengthBucket(len(p.payload))]++
		if _, ok := first[p.flow]; !ok {
			first[p.flow] = p.payload
		}
		if prev, ok := lastTs[p.flow]; ok {
			dt := float64(p.tsUs-prev) / 1000.0
			if dt >= 0 && dt < 60_000 {
				iats = append(iats, dt)
			}
		}
		lastTs[p.flow] = p.tsUs
	}
	rep.Flows = len(first)
	for _, payload := range first {
		exempt, rule := compiler.FEPExemption(payload)
		if exempt {
			rep.FirstExempt++
			if rule == "" {
				rule = "exempt"
			}
			rep.Rules[rule]++
		} else {
			rep.FirstBlocked++
			rep.Rules["blocked"]++
		}
	}
	if rep.Flows > 0 {
		rep.ExemptRate = float64(rep.FirstExempt) / float64(rep.Flows)
	}
	if len(iats) > 0 {
		sort.Float64s(iats)
		rep.IATMsP50 = percentile(iats, 0.50)
		rep.IATMsP90 = percentile(iats, 0.90)
		sum := 0.0
		for _, v := range iats {
			sum += v
		}
		rep.IATMsMean = sum / float64(len(iats))
	}
	return rep
}

func lengthBucket(n int) string {
	switch {
	case n <= 128:
		return "<=128"
	case n <= 512:
		return "<=512"
	case n <= 1024:
		return "<=1024"
	case n <= 1452:
		return "<=1452"
	case n <= 1500:
		return "<=1500"
	default:
		return ">1500"
	}
}

func percentile(sorted []float64, p float64) float64 {
	if len(sorted) == 0 {
		return 0
	}
	idx := int(math.Round(p * float64(len(sorted)-1)))
	if idx < 0 {
		idx = 0
	}
	if idx >= len(sorted) {
		idx = len(sorted) - 1
	}
	return sorted[idx]
}

func printReport(rep report) {
	fmt.Printf("packets=%d flows=%d\n", rep.Packets, rep.Flows)
	fmt.Printf("first-datagram FEP exempt=%d blocked=%d rate=%.3f\n", rep.FirstExempt, rep.FirstBlocked, rep.ExemptRate)
	fmt.Printf("rules %s\n", formatCounts(rep.Rules))
	fmt.Printf("payload lengths %s\n", formatCounts(rep.LengthBuckets))
	fmt.Printf("IAT ms p50=%.1f p90=%.1f mean=%.1f\n", rep.IATMsP50, rep.IATMsP90, rep.IATMsMean)
	fmt.Println(rep.Note)
}

func formatCounts(m map[string]int) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s:%d", k, m[k]))
	}
	return strings.Join(parts, " ")
}

func readUDPPayloads(r io.Reader, port int) ([]datum, error) {
	var hdr [24]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, fmt.Errorf("pcap header: %w", err)
	}
	magic := binary.LittleEndian.Uint32(hdr[0:4])
	swap := false
	ns := false
	switch magic {
	case 0xa1b2c3d4:
	case 0xa1b23c4d:
		ns = true
	case 0xd4c3b2a1:
		swap = true
	case 0x4d3cb2a1:
		swap = true
		ns = true
	case 0x0a0d0d0a:
		return nil, fmt.Errorf("pcapng is not supported; use tcpdump -w file.pcap")
	default:
		return nil, fmt.Errorf("not a classic pcap (magic %08x)", magic)
	}
	u32 := binary.LittleEndian.Uint32
	if swap {
		u32 = binary.BigEndian.Uint32
	}
	linkType := u32(hdr[20:24])
	var out []datum
	var rec [16]byte
	for {
		if _, err := io.ReadFull(r, rec[:]); err != nil {
			if err == io.EOF {
				return out, nil
			}
			return nil, err
		}
		tsSec := u32(rec[0:4])
		tsFrac := u32(rec[4:8])
		incl := u32(rec[8:12])
		if incl > 1<<20 {
			return nil, fmt.Errorf("implausible packet length %d", incl)
		}
		buf := make([]byte, incl)
		if _, err := io.ReadFull(r, buf); err != nil {
			return nil, err
		}
		tsUs := int64(tsSec)*1_000_000 + int64(tsFrac)
		if ns {
			tsUs = int64(tsSec)*1_000_000 + int64(tsFrac)/1000
		}
		payloads := udpPayloads(buf, linkType)
		for _, p := range payloads {
			if port != 0 && int(p.srcPort) != port && int(p.dstPort) != port {
				continue
			}
			if len(p.payload) == 0 {
				continue
			}
			out = append(out, datum{
				tsUs:    tsUs,
				payload: p.payload,
				flow:    flowKey(p.src, p.dst, p.srcPort, p.dstPort),
			})
		}
	}
}

type udpDatagram struct {
	src, dst         string
	srcPort, dstPort uint16
	payload          []byte
}

func udpPayloads(frame []byte, linkType uint32) []udpDatagram {
	be := binary.BigEndian.Uint16
	switch linkType {
	case 1: // Ethernet
		if len(frame) < 14 {
			return nil
		}
		eth := be(frame[12:14])
		off := 14
		if eth == 0x8100 && len(frame) >= 18 {
			eth = be(frame[16:18])
			off = 18
		}
		return ipUDP(frame[off:], eth)
	case 101: // raw IP
		if len(frame) == 0 {
			return nil
		}
		ver := frame[0] >> 4
		eth := uint16(0x0800)
		if ver == 6 {
			eth = 0x86dd
		}
		return ipUDP(frame, eth)
	case 113: // Linux SLL
		if len(frame) < 16 {
			return nil
		}
		return ipUDP(frame[16:], be(frame[14:16]))
	default:
		return nil
	}
}

func ipUDP(ip []byte, ethertype uint16) []udpDatagram {
	switch ethertype {
	case 0x0800:
		return ipv4UDP(ip)
	case 0x86dd:
		return ipv6UDP(ip)
	default:
		return nil
	}
}

func ipv4UDP(ip []byte) []udpDatagram {
	if len(ip) < 20 {
		return nil
	}
	ihl := int(ip[0]&0x0f) * 4
	if ihl < 20 || len(ip) < ihl {
		return nil
	}
	if ip[9] != 17 {
		return nil
	}
	return parseUDP(ip[12:16], ip[16:20], ip[ihl:])
}

func ipv6UDP(ip []byte) []udpDatagram {
	if len(ip) < 40 {
		return nil
	}
	if ip[6] != 17 {
		return nil
	}
	return parseUDP(ip[8:24], ip[24:40], ip[40:])
}

func parseUDP(src, dst, udp []byte) []udpDatagram {
	if len(udp) < 8 {
		return nil
	}
	return []udpDatagram{{
		src:     fmt.Sprintf("%x", src),
		dst:     fmt.Sprintf("%x", dst),
		srcPort: binary.BigEndian.Uint16(udp[0:2]),
		dstPort: binary.BigEndian.Uint16(udp[2:4]),
		payload: append([]byte(nil), udp[8:]...),
	}}
}

func flowKey(a, b string, pa, pb uint16) string {
	left := fmt.Sprintf("%s:%d", a, pa)
	right := fmt.Sprintf("%s:%d", b, pb)
	if left > right {
		left, right = right, left
	}
	return left + "-" + right
}
