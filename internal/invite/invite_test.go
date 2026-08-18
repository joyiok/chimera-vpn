package invite

import (
	"encoding/base64"
	"strings"
	"testing"
)

func sample() Profile {
	return Profile{
		Addr:       "198.51.100.10:4789",
		SeedHex:    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
		PSKHex:     "fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0efeeedecebeae9e8e7e6e5e4e3e2e1e0",
		Generation: 0,
		Name:       "vps",
	}
}

func TestRoundTrip(t *testing.T) {
	want := sample()
	url, err := Format(want)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(url, "chimera://v1/") {
		t.Fatalf("prefix: %s", url)
	}
	got, err := Parse(url)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("got %+v want %+v", got, want)
	}
}

func TestParseSurroundingText(t *testing.T) {
	url, err := Format(sample())
	if err != nil {
		t.Fatal(err)
	}
	got, err := Parse("入口：" + url + " 发你")
	if err != nil {
		t.Fatal(err)
	}
	if got.Addr != "198.51.100.10:4789" || got.Name != "vps" {
		t.Fatalf("%+v", got)
	}
}

func TestParseConnectQuery(t *testing.T) {
	p := sample()
	raw := "chimera://connect?addr=" + p.Addr + "&seed=" + p.SeedHex + "&psk=" + p.PSKHex + "&generation=2&name=hk"
	got, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if got.Generation != 2 || got.Name != "hk" || got.Addr != p.Addr {
		t.Fatalf("%+v", got)
	}
}

func TestParseClientJSON(t *testing.T) {
	p := sample()
	raw := `{
  "serverAddr": "` + p.Addr + `",
  "seedHex": "` + strings.ToUpper(p.SeedHex) + `",
  "generation": 0,
  "pskHex": "` + p.PSKHex + `"
}`
	got, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if got.SeedHex != p.SeedHex {
		t.Fatalf("hex not normalized: %s", got.SeedHex)
	}
	if got.Addr != p.Addr {
		t.Fatalf("%+v", got)
	}
}

func TestParseCompactJSONPayload(t *testing.T) {
	p := sample()
	raw := `{"v":1,"a":"` + p.Addr + `","s":"` + p.SeedHex + `","p":"` + p.PSKHex + `","g":0}`
	url := schemePrefix + base64.RawURLEncoding.EncodeToString([]byte(raw))
	got, err := Parse(url)
	if err != nil {
		t.Fatal(err)
	}
	if got.Addr != p.Addr || got.SeedHex != p.SeedHex || got.PSKHex != p.PSKHex {
		t.Fatalf("%+v", got)
	}
}

func TestRejectBadHex(t *testing.T) {
	_, err := Format(Profile{Addr: "x:1", SeedHex: "aa", PSKHex: sample().PSKHex})
	if err == nil {
		t.Fatal("expected short seed to fail")
	}
}
