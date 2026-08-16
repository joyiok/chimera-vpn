package core

import "testing"

func TestAddressPoolAllocateAndRelease(t *testing.T) {
	p, err := newAddressPool("10.99.0.0/24")
	if err != nil {
		t.Fatal(err)
	}
	first, err := p.Allocate()
	if err != nil {
		t.Fatal(err)
	}
	if first != "10.99.0.2" {
		t.Fatalf("first address = %s, want 10.99.0.2", first)
	}
	second, _ := p.Allocate()
	if second != "10.99.0.3" {
		t.Fatalf("second address = %s, want 10.99.0.3", second)
	}

	p.Release(first)
	next, err := p.Allocate()
	if err != nil {
		t.Fatal(err)
	}
	if next != first {
		t.Fatalf("released address not reused: got %s, want %s", next, first)
	}
}

func TestAddressPoolRejectsSmallPrefix(t *testing.T) {
	if _, err := newAddressPool("10.99.0.0/31"); err == nil {
		t.Fatal("expected /31 to be rejected")
	}
}
