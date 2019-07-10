package adapter

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"testing"

	"github.com/google/gopacket/pcapgo"
	. "gitlab.x.lan/yunshan/droplet-libs/datatype"
)

const (
	MIN_PPS = 5000000 // 5Mpps
)

func TestDecoder(t *testing.T) {
	var buffer bytes.Buffer
	f, _ := os.Open("icmp_decode_test.pcap")
	r, _ := pcapgo.NewReader(f)
	for {
		packet, _, err := r.ReadPacketData()
		if err != nil || packet == nil {
			break
		}

		decoder := NewSequentialDecoder(packet[42:])
		decoder.DecodeHeader()
		for {
			meta := &MetaPacket{}
			if decoder.NextPacket(meta) {
				break
			}
			if len(meta.RawHeader) > 0 {
				buffer.Write(meta.RawHeader)
			}
		}
	}
	f.Close()

	expectFile := "icmp_decode_test.result"
	content, _ := ioutil.ReadFile(expectFile)
	expected := string(content)
	actual := buffer.String()
	if expected != actual {
		ioutil.WriteFile("actual_icmp.txt", []byte(actual), 0644)
		t.Error(fmt.Sprintf("Inconsistent with %s, written to actual_icmp.txt", expectFile))
	}
}

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
