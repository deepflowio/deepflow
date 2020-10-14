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
	f, _ := os.Open("icmp_decode_test.pcap") // 目前使用的时IPv4传输的
	r, _ := pcapgo.NewReader(f)
	for {
		packet, _, err := r.ReadPacketData()
		if err != nil || packet == nil {
			break
		}

		decoder := NewSequentialDecoder(packet[42:]) // 因为pcap是IPv4 + UDP, 所以这里是 14 + 20 + 8 = 42
		if invalid, _, _ := decoder.DecodeHeader(); invalid {
			t.Error(fmt.Sprintf("DecodeHeader failed, invalid header."))
			continue
		}
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
	f, _ := os.Open("icmp_decode_test.pcap")
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
		if invalid, _, _ := decoder.DecodeHeader(); invalid {
			b.Error(fmt.Sprintf("DecodeHeader failed, invalid header."))
			continue
		}
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
