package compiler

import (
	"bytes"
	"testing"
)

func TestKnockRoundTrip(t *testing.T) {
	psk := testPSK(1)
	knock, err := EncodeKnock(psk)
	if err != nil {
		t.Fatal(err)
	}
	if len(knock) != KnockInnerLen {
		t.Fatalf("len %d want %d", len(knock), KnockInnerLen)
	}
	if !VerifyKnock(psk, knock) {
		t.Fatal("fresh knock rejected")
	}
	if VerifyKnock(testPSK(2), knock) {
		t.Fatal("knock accepted under the wrong PSK")
	}
	tampered := append([]byte(nil), knock...)
	tampered[0] ^= 0x01
	if VerifyKnock(psk, tampered) {
		t.Fatal("tampered nonce accepted")
	}
	tampered = append([]byte(nil), knock...)
	tampered[len(tampered)-1] ^= 0x01
	if VerifyKnock(psk, tampered) {
		t.Fatal("tampered MAC accepted")
	}
	if VerifyKnock(psk, knock[:len(knock)-1]) {
		t.Fatal("truncated knock accepted")
	}
}

func TestKnockUniqueNonces(t *testing.T) {
	psk := testPSK(3)
	a, err := EncodeKnock(psk)
	if err != nil {
		t.Fatal(err)
	}
	b, err := EncodeKnock(psk)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(a, b) {
		t.Fatal("two knocks collided")
	}
}

func TestVerifyKnockAcceptsTrailingPad(t *testing.T) {
	psk := testPSK(4)
	knock, err := EncodeKnock(psk)
	if err != nil {
		t.Fatal(err)
	}
	padded := append(append([]byte(nil), knock...), []byte("printable-tail")...)
	if !VerifyKnock(psk, padded) {
		t.Fatal("knock with trailing pad rejected")
	}
	if string(KnockReplayKey(padded)) != string(knock) {
		t.Fatal("replay key must be the unpadded knock")
	}
}

func TestEncodeKnockEmptyPSK(t *testing.T) {
	if _, err := EncodeKnock(nil); err == nil {
		t.Fatal("empty PSK accepted")
	}
}
