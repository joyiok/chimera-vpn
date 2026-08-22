package geoip

import (
	"net"
	"os"
	"testing"
)

// TestVerifyRealDB runs against a real GeoLite2-Country database when
// GEOIP_TEST_DB points at one (download from P3TERX/GeoLite.mmdb releases
// or MaxMind). Skipped otherwise so CI stays hermetic.
func TestVerifyRealDB(t *testing.T) {
	path := os.Getenv("GEOIP_TEST_DB")
	if path == "" {
		t.Skip("GEOIP_TEST_DB not set")
	}
	r, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()

	prefixes, err := r.CountryPrefixes([]string{"CN"})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("CN prefixes: %d", len(prefixes))
	if len(prefixes) < 4000 {
		t.Fatalf("suspiciously few CN prefixes: %d", len(prefixes))
	}
	v4 := 0
	found := false
	for _, n := range prefixes {
		if n.IP.To4() == nil {
			continue // GeoLite2 includes CN IPv6; routing filters per family
		}
		v4++
		if n.Contains(net.ParseIP("1.0.1.1")) {
			found = true
		}
	}
	if v4 < 4000 {
		t.Fatalf("suspiciously few CN IPv4 prefixes: %d", v4)
	}
	if !found {
		t.Fatal("1.0.1.1 not covered by any CN prefix")
	}
}
