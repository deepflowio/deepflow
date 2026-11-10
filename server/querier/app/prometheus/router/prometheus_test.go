package router

import (
	"bytes"
	"strings"
	"testing"

	"github.com/golang/snappy"
)

func TestDecodeRemoteReadRequest(t *testing.T) {
	want := []byte("remote read request")
	compressed := snappy.Encode(nil, want)

	got, err := decodeRemoteReadRequest(bytes.NewReader(compressed))
	if err != nil {
		t.Fatalf("decodeRemoteReadRequest() error = %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("decodeRemoteReadRequest() = %q, want %q", got, want)
	}
}

func TestDecodeRemoteReadRequestTooLarge(t *testing.T) {
	// A 5-byte snappy header that declares a 256 MiB decoded length, which is
	// above decodeReadLimit (32 MiB). Decoding it would allocate 256 MiB, so it
	// must be rejected before snappy.Decode is called.
	bomb := []byte{0x80, 0x80, 0x80, 0x80, 0x01}

	_, err := decodeRemoteReadRequest(bytes.NewReader(bomb))
	if err == nil {
		t.Fatal("decodeRemoteReadRequest() expected an error for an oversized decoded length")
	}
	if !strings.Contains(err.Error(), "exceeds limit") {
		t.Fatalf("decodeRemoteReadRequest() error = %v, want it to mention the limit", err)
	}
}
