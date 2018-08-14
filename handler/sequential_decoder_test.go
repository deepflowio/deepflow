package handler

import (
	"os"
	"testing"

	"github.com/google/gopacket/pcapgo"
)

const (
	MIN_PPS = 5000000 // 5Mpps
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
	for i := 0; i < MIN_PPS; {
		decoder := NewSequentialDecoder(packet)
		decoder.DecodeHeader()
		for {
			meta := &MetaPacket{}
			if decoder.NextPacket(meta) {
				break
			}
			i++
		}
	}
	f.Close()
}
