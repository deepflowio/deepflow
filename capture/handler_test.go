package capture

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/gopacket/pcapgo"
	"gitlab.x.lan/yunshan/droplet-libs/queue"
)

type StubMultiQueue int

func (q *StubMultiQueue) Len(_ queue.HashKey) int {
	return *(*int)(q)
}

func (q *StubMultiQueue) Put(_ queue.HashKey, items ...interface{}) error {
	*(*int)(q) += len(items)
	return nil
}

func (q *StubMultiQueue) Puts(_ []queue.HashKey, items []interface{}) error {
	*(*int)(q) += len(items)
	return nil
}

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

func TestTimeoutFlush(t *testing.T) {
	packets := loadPcap("handler_test.pcap")
	mq := StubMultiQueue(0)
	handler := PacketHandler{queue: &mq, remoteSegments: NewSegmentSet()}
	handler.Init(1, "none")
	timestamp := time.Duration(0)
	for _, packet := range packets[:3] {
		handler.Handle(timestamp, packet, len(packet))
		timestamp += 199 * time.Millisecond
	}
	if mq.Len(0) != 3 {
		t.Error("Not flushed")
	}
}

func BenchmarkHandler(b *testing.B) {
	packets := loadPcap("handler_test.pcap")
	mq := StubMultiQueue(0)
	handler := PacketHandler{queue: &mq, remoteSegments: NewSegmentSet()}
	handler.Init(1, "none")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		packet := packets[i%len(packets)]
		handler.Handle(0, packet, len(packet))
	}
}
