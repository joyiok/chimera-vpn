// Package geoip reads MaxMind-compatible .mmdb databases and extracts
// per-country route prefixes for geo split tunneling.
//
// Use with any GeoLite2-Country-compatible database (free GeoLite2, or the
// community Country.mmdb builds refreshed daily). Databases are read via
// memory mapping; iterating a full country table takes milliseconds.
package geoip

import (
	"fmt"
	"net"

	maxminddb "github.com/oschwald/maxminddb-golang"
)

type countryRecord struct {
	Country struct {
		ISOCode string `maxminddb:"iso_code"`
	} `maxminddb:"country"`
}

// Reader wraps an open mmdb database.
type Reader struct {
	r *maxminddb.Reader
}

// Open memory-maps an mmdb file. The caller must Close it.
func Open(path string) (*Reader, error) {
	r, err := maxminddb.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open geoip db %s: %w", path, err)
	}
	return &Reader{r: r}, nil
}

// Close releases the database.
func (r *Reader) Close() error { return r.r.Close() }

// CountryPrefixes walks every network in the database and returns those
// whose country ISO code is in codes (e.g. ["CN"]). This is the route
// list for geo split tunneling: always current because it comes straight
// from the database rather than a committed snapshot.
func (r *Reader) CountryPrefixes(codes []string) ([]*net.IPNet, error) {
	want := make(map[string]bool, len(codes))
	for _, c := range codes {
		want[c] = true
	}
	var out []*net.IPNet
	it := r.r.Networks(maxminddb.SkipAliasedNetworks)
	rec := countryRecord{}
	for it.Next() {
		network, nerr := it.Network(&rec)
		if nerr != nil {
			return out, nerr
		}
		if want[rec.Country.ISOCode] {
			out = append(out, network)
		}
	}
	return out, it.Err()
}

// Prefixes returns every network in the database as plain CIDR strings.
func (r *Reader) Prefixes() ([]string, error) {
	it := r.r.Networks(maxminddb.SkipAliasedNetworks)
	var out []string
	for it.Next() {
		network, nerr := it.Network(nil)
		if nerr != nil {
			return out, nerr
		}
		out = append(out, network.String())
	}
	return out, it.Err()
}
