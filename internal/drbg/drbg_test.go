package drbg

import (
	"bytes"
	"testing"
)

func TestDeterministic(t *testing.T) {
	a := New([]byte("seed"), "t")
	b := New([]byte("seed"), "t")
	if !bytes.Equal(a.Bytes(64), b.Bytes(64)) {
		t.Fatal("same seed produced different output")
	}
}

func TestDistinctLabelsAndSeeds(t *testing.T) {
	if bytes.Equal(New([]byte("s"), "a").Bytes(64), New([]byte("s"), "b").Bytes(64)) {
		t.Fatal("labels did not separate streams")
	}
	if bytes.Equal(New([]byte("a"), "l").Bytes(64), New([]byte("b"), "l").Bytes(64)) {
		t.Fatal("seeds did not separate streams")
	}
}

func TestIntnBoundsAndSpread(t *testing.T) {
	r := New([]byte("intn"), "t")
	for _, n := range []int{1, 2, 3, 7, 255, 256, 1000} {
		for i := 0; i < 5000; i++ {
			v := r.Intn(n)
			if v < 0 || v >= n {
				t.Fatalf("Intn(%d) out of range: %d", n, v)
			}
		}
	}
}

func TestPerm(t *testing.T) {
	r := New([]byte("perm"), "t")
	seen := map[int]bool{}
	for _, v := range r.Perm(20) {
		if seen[v] {
			t.Fatal("duplicate in permutation")
		}
		seen[v] = true
	}
}

func TestChildIndependence(t *testing.T) {
	root := New([]byte("root"), "t")
	c1 := root.Child("one")
	c2 := root.Child("two")
	if bytes.Equal(c1.Bytes(64), c2.Bytes(64)) {
		t.Fatal("child streams should differ")
	}
}
