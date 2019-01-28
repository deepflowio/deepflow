package adapter

import (
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/google/gopacket/pcapgo"
	"gitlab.x.lan/yunshan/droplet-libs/queue"
	"gitlab.x.lan/yunshan/droplet-libs/stats"
	. "gitlab.x.lan/yunshan/droplet-libs/utils"
	q "gitlab.x.lan/yunshan/droplet/queue"
)

func generateTridentAdapter() *TridentAdapter {
	queues := q.NewManager().NewQueues("1-meta-packet-to-labeler", 1024, 4, 9)
	adapter := &TridentAdapter{
		listenBufferSize: 1024,
		cacheSize:        16,

		queues:    queues,
		itemKeys:  make([]queue.HashKey, 0, PACKET_MAX+1),
		itemBatch: make([]interface{}, PACKET_MAX),
		udpPool: sync.Pool{
			New: func() interface{} {
				return make([]byte, UDP_BUFFER_SIZE)
			},
		},

		instances: make(map[TridentKey]*tridentInstance),
		counter:   &PacketCounter{},
		stats:     &PacketCounter{},
	}
	adapter.itemKeys = append(adapter.itemKeys, queue.HashKey(0))
	stats.RegisterCountable("trident-adapter", adapter)
	return adapter
}

func TestTimestampAdjust(t *testing.T) {
	adapter := generateTridentAdapter()
	f, _ := os.Open("trident_timestamp_adjust.pcap")
	defer f.Close()
	r, _ := pcapgo.NewReader(f)
	packetCount := uint64(0)
	var firstPacketTime, totalAdjust time.Duration
	for {
		data, _, err := r.ReadPacketData()
		if err != nil || data == nil {
			break
		}
		data = data[42:]
		key := IpToUint32(net.ParseIP("172.20.1.153").To4())
		timeAdjust := adapter.getTimeAdjust(key)
		totalAdjust += timeAdjust
		decoder := NewSequentialDecoder(data, timeAdjust)
		if _, invalid := decoder.DecodeHeader(); invalid {
			t.Log("data is invalid")
			adapter.udpPool.Put(data)
			continue
		}
		packetCount++
		if packetCount == 1 {
			firstPacketTime = decoder.timestamp
		}
		adapter.findAndAdd(data, key, decoder.Seq(), decoder.timestamp)
	}
	expectMaxTime := uint64(abs(firstPacketTime-time.Duration(time.Now().UnixNano())) / time.Second)
	actualMaxTime := adapter.counter.MaxTime
	expectAverageTime := expectMaxTime / packetCount
	// 因未达到定期上报时间节点，counter中的AverageTime只做了求和，需手动平均
	actualAverageTime := adapter.counter.AverageTime / adapter.counter.RxPackets
	if expectAverageTime != actualAverageTime || expectMaxTime != actualMaxTime {
		t.Errorf("expectMaxTime:%d, actualMaxTime:%d", expectMaxTime, actualMaxTime)
		t.Errorf("expectAverageTime:%d, actualAverageTime:%d", expectAverageTime, actualAverageTime)
	}
}
