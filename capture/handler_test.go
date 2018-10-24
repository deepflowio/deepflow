package capture

import (
	"os"
	"strings"
	"testing"

	"github.com/google/gopacket/pcapgo"
	"gitlab.x.lan/yunshan/droplet-libs/datatype"
	"gitlab.x.lan/yunshan/droplet-libs/queue"
)

func loadPcap(file string) []RawPacket {
	var f *os.File
	cwd, _ := os.Getwd()
	if strings.Contains(cwd, "capture") {
		f, _ = os.Open(file)
	} else { // dlv
		f, _ = os.Open("capture/" + file)
	}
	defer f.Close()

	r, _ := pcapgo.NewReader(f)
	var packets []RawPacket
	for {
		packet, _, err := r.ReadPacketData()
		if err != nil || packet == nil {
			break
		}
		packets = append(packets, packet)
	}
	return packets
}

func BenchmarkHandler(b *testing.B) {
	packets := loadPcap("handler_test.pcap")
	mq := queue.NewOverwriteQueues("benchmark", 1, 100)
	handler := PacketHandler{queue: mq, remoteSegments: NewSegmentSet()}
	handler.Init("none")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		packet := packets[i%len(packets)]
		handler.Handle(0, packet, len(packet))
		if mq.Len(0) > 0 {
			datatype.ReleaseMetaPacket(mq.Get(0).(*datatype.MetaPacket))
		}
	}
}
