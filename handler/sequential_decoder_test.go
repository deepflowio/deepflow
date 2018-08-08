package handler

import (
	"os"
	"testing"

	"github.com/google/gopacket/pcapgo"
)

func BenchmarkDecoder(b *testing.B) {
	b.StopTimer()
	f, _ := os.Open("sequential_decoder_test.pcap")
	r, _ := pcapgo.NewReader(f)
	packet, _, err := r.ReadPacketData()
	if packet == nil || err != nil {
		f.Close()
		return
	}
	packet = packet[42:]

	b.StartTimer()
	decoder := NewSequentialDecoder(packet)
	decoder.DecodeHeader()
	for {
		meta := &MetaPktHdr{}
		if decoder.NextPacket(meta) {
			break
		}
	}
	f.Close()
}
