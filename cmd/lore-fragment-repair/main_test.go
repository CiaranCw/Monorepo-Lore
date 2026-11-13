package main

import (
	"bytes"
	"testing"
)

func TestStorageWireRoundTrip(t *testing.T) {
	a := address{Hash: bytes.Repeat([]byte{0x11}, 32), Context: bytes.Repeat([]byte{0x22}, 16)}
	f := fragment{
		Address: a, Flags: payloadStoredMask | 8,
		PayloadSize: 3, ContentSize: 9, Payload: []byte("abc"),
	}
	gotAddress, err := decodeAddress(encodeAddress(a))
	if err != nil || gotAddress.String() != a.String() {
		t.Fatalf("address=%v err=%v", gotAddress, err)
	}
	wire := encodePutRequest(f)
	if len(wire) == 0 || f.Flags&^payloadStoredMask != 8 {
		t.Fatal("stored-state flag normalization failed")
	}
	getWire := appendMessage(nil, 1, encodeAddress(a))
	getWire = appendMessage(getWire, 2, encodeFragment(fragment{
		Flags: 8, PayloadSize: 3, ContentSize: 9,
	}))
	getWire = appendBytes(getWire, 3, []byte("abc"))
	getWire = appendMessage(getWire, 4, appendVarint(nil, 1, 0))
	got, err := decodeGetResponse(getWire)
	if err != nil || got.Address.String() != a.String() ||
		got.Flags != 8 || string(got.Payload) != "abc" {
		t.Fatalf("fragment=%+v err=%v", got, err)
	}
}

func TestQueryFoundInOtherContextNeedsRepair(t *testing.T) {
	packed := []byte{}
	packed = append(packed, 0, 1, 2, 3)
	wire := appendBytes(nil, 1, packed)
	states, err := decodeQueryResponse(wire)
	if err != nil || len(states) != 4 {
		t.Fatalf("states=%v err=%v", states, err)
	}
	missing := 0
	for _, state := range states {
		if state != 0 {
			missing++
		}
	}
	if missing != 3 {
		t.Fatalf("different-context fragment must be repaired: %v", states)
	}
}
