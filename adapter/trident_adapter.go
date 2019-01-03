package adapter

import (
	"bytes"
	"encoding/gob"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/op/go-logging"
	"github.com/spf13/cobra"
	"gitlab.x.lan/yunshan/droplet-libs/datatype"
	"gitlab.x.lan/yunshan/droplet-libs/queue"
	"gitlab.x.lan/yunshan/droplet-libs/stats"
	. "gitlab.x.lan/yunshan/droplet-libs/utils"

	"gitlab.x.lan/yunshan/droplet/dropletctl"
)

const (
	LISTEN_PORT     = 20033
	PACKET_MAX      = 256
	TRIDENT_TIMEOUT = 60 * time.Second
)

const (
	ADAPTER_CMD_SHOW = iota
)

var log = logging.MustGetLogger("trident_adapter")

type PacketCounter struct {
	RxPackets uint64 `statsd:"rx_packets"`
	RxDropped uint64 `statsd:"rx_dropped"` // 当前SEQ减去上次的SEQ
	RxErrors  uint64 `statsd:"rx_errors"`  // 当前SEQ小于上次的SEQ时+1，包乱序并且超出了CACHE_SIZE
	RxCached  uint64 `statsd:"rx_cached"`

	TxPackets uint64 `statsd:"tx_packets"`
	TxDropped uint64 `statsd:"tx_dropped"`
	TxErrors  uint64 `statsd:"tx_errors"`
}

type TridentKey = uint32

type tridentInstance struct {
	seq       uint32
	timestamp time.Duration

	cache      [][]byte
	cacheCount uint8
	cacheMap   uint64
}

type TridentAdapter struct {
	listenBufferSize int
	cacheSize        int
	timeAdjust       int64

	queues    queue.MultiQueueWriter
	itemKeys  []queue.HashKey
	itemBatch []interface{}
	udpPool   sync.Pool

	instances map[TridentKey]*tridentInstance
	counter   *PacketCounter
	stats     *PacketCounter

	running  bool
	listener *net.UDPConn
}

func NewTridentAdapter(queues queue.MultiQueueWriter, listenBufferSize, cacheSize int, timeAdjust int64) *TridentAdapter {
	adapter := &TridentAdapter{}
	adapter.counter = &PacketCounter{}
	adapter.stats = &PacketCounter{}
	adapter.listenBufferSize = listenBufferSize
	adapter.cacheSize = cacheSize
	adapter.timeAdjust = timeAdjust
	adapter.queues = queues
	adapter.itemKeys = make([]queue.HashKey, 0, PACKET_MAX+1)
	adapter.itemKeys = append(adapter.itemKeys, queue.HashKey(0))
	adapter.itemBatch = make([]interface{}, PACKET_MAX)
	adapter.instances = make(map[TridentKey]*tridentInstance)
	adapter.udpPool.New = func() interface{} { return make([]byte, UDP_BUFFER_SIZE) }
	listener, err := net.ListenUDP("udp4", &net.UDPAddr{Port: LISTEN_PORT})
	if err != nil {
		log.Error(err)
		return nil
	}
	adapter.listener = listener
	stats.RegisterCountable("trident_adapter", adapter)
	dropletctl.Register(dropletctl.DROPLETCTL_ADAPTER, adapter)
	return adapter
}

func (a *TridentAdapter) GetCounter() interface{} {
	counter := &PacketCounter{}
	counter, a.counter = a.counter, counter
	return counter
}

func (a *TridentAdapter) IsRunning() bool {
	return a.running
}

func (a *TridentAdapter) cacheClear(data []byte, key uint32, seq uint32) {
	startSeq := a.instances[key].seq
	instance := a.instances[key]
	if instance.cacheCount > 0 {
		for i := 0; i < a.cacheSize; i++ {
			if instance.cacheMap&(1<<uint64(i)) == uint64(1<<uint32(i)) {
				dataSeq := uint32(i) + startSeq + 1
				a.decode(a.instances[key].cache[i], key)
				drop := uint64(dataSeq - instance.seq - 1)
				a.counter.RxDropped += drop
				a.stats.RxDropped += drop
				instance.seq = dataSeq
				a.counter.RxPackets += 1
				a.stats.RxPackets += 1
			}
		}
		instance.cacheCount = 0
		instance.cacheMap = 0
	}

	if seq > 0 {
		drop := uint64(seq - instance.seq - 1)
		a.counter.RxPackets += 1
		a.stats.RxPackets += 1
		a.counter.RxDropped += drop
		a.stats.RxDropped += drop
		a.decode(data, key)
		instance.seq = seq
	}
}

func (a *TridentAdapter) cacheLookup(data []byte, key uint32, seq uint32, timestamp time.Duration) {
	instance := a.instances[key]
	instance.timestamp = timestamp
	// droplet重启或trident重启时，不考虑SEQ
	if (instance.cacheCount == 0 && seq-instance.seq == 1) || instance.seq == 0 || seq == 1 {
		instance.seq = seq
		a.decode(data, key)
		a.counter.RxPackets += 1
		a.stats.RxPackets += 1
	} else {
		if seq <= instance.seq {
			a.counter.RxErrors += 1
			a.stats.RxErrors += 1
			a.udpPool.Put(data)
			log.Warningf("trident(%v) recv seq %d is less than current %d, drop", IpFromUint32(key), seq, instance.seq)
			return
		}
		log.Debugf("trident(%v) cache add seq %d, current seq is %d", IpFromUint32(key), seq, instance.seq)
		offset := seq - instance.seq - 1
		// cache满或乱序超过CACHE_SIZE, 清空cache
		if int(offset) >= a.cacheSize || int(instance.cacheCount) == a.cacheSize {
			a.cacheClear(data, key, seq)
			return
		}
		instance.cache[offset] = data
		instance.cacheCount++
		instance.cacheMap |= 1 << offset
		a.counter.RxCached++
		a.stats.RxCached++
	}
}

func (a *TridentAdapter) findAndAdd(data []byte, key uint32, seq uint32, timestamp time.Duration) {
	if a.instances[key] == nil {
		instance := &tridentInstance{}
		instance.cache = make([][]byte, a.cacheSize)
		a.instances[key] = instance
	}
	a.cacheLookup(data, key, seq, timestamp)
}

func (a *TridentAdapter) decode(data []byte, ip uint32) {
	decoder := NewSequentialDecoder(data, a.timeAdjust)
	ifMacSuffix, _ := decoder.DecodeHeader()

	for {
		meta := datatype.AcquireMetaPacket()
		meta.InPort = uint32(datatype.PACKET_SOURCE_TOR) | ifMacSuffix
		meta.Exporter = ip
		if decoder.NextPacket(meta) {
			datatype.ReleaseMetaPacket(meta)
			break
		}

		a.counter.TxPackets++
		a.stats.TxPackets++
		a.itemKeys = append(a.itemKeys, queue.HashKey(meta.GenerateHash()))
		a.itemBatch = append(a.itemBatch, meta)
	}

	if len(a.itemBatch) > 0 {
		a.queues.Puts(a.itemKeys, a.itemBatch)
		a.itemKeys = a.itemKeys[:1]
		a.itemBatch = a.itemBatch[:0]
	}

	a.udpPool.Put(data)
}

func (a *TridentAdapter) flushInstance() {
	timestamp := time.Now().UnixNano()
	for key, instance := range a.instances {
		if timestamp > int64(instance.timestamp) && timestamp-int64(instance.timestamp) >= int64(TRIDENT_TIMEOUT) {
			instance.timestamp = time.Duration(timestamp)
			if instance.cacheMap != 0 {
				a.cacheClear(nil, key, 0)
			}
		}
	}
}

func (a *TridentAdapter) run() {
	log.Infof("Starting trident adapter Listenning <%s>", a.listener.LocalAddr())
	a.listener.SetReadDeadline(time.Now().Add(TRIDENT_TIMEOUT))
	a.listener.SetReadBuffer(a.listenBufferSize)
	for a.running {
		data := a.udpPool.Get().([]byte)
		_, remote, err := a.listener.ReadFromUDP(data)
		if err != nil {
			if err.(net.Error).Timeout() {
				a.listener.SetReadDeadline(time.Now().Add(TRIDENT_TIMEOUT))
				a.flushInstance()
				continue
			}
			log.Errorf("trident adapter listener.ReadFromUDP err: %s", err)
			return
		}

		decoder := NewSequentialDecoder(data, a.timeAdjust)
		if _, invalid := decoder.DecodeHeader(); invalid {
			a.udpPool.Put(data)
			continue
		}
		a.findAndAdd(data, IpToUint32(remote.IP.To4()), decoder.Seq(), decoder.timestamp)
	}
	a.listener.Close()
	log.Info("Stopped trident adapter")
}

func (a *TridentAdapter) Start() error {
	if !a.running {
		log.Info("Start trident adapter")
		a.running = true
		go a.run()
	}
	return nil
}

func (a *TridentAdapter) RecvCommand(conn *net.UDPConn, port int, operate uint16, arg *bytes.Buffer) {
	buff := bytes.Buffer{}
	switch operate {
	case ADAPTER_CMD_SHOW:
		encoder := gob.NewEncoder(&buff)
		if err := encoder.Encode(a.stats); err != nil {
			log.Error(err)
			return
		}
		dropletctl.SendToDropletCtl(conn, port, 0, &buff)
		break
	default:
		log.Warningf("Trident Adapter recv unknown command(%v).", operate)
	}
}

func CommmandGetCounter(count *PacketCounter) bool {
	_, result, err := dropletctl.SendToDroplet(dropletctl.DROPLETCTL_ADAPTER, ADAPTER_CMD_SHOW, nil)
	if err != nil {
		log.Warning(err)
		return false
	}
	decoder := gob.NewDecoder(result)
	if err = decoder.Decode(count); err != nil {
		log.Error(err)
		return false
	}
	return true
}

func RegisterCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "adapter",
		Short: "config droplet adapter module",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("please run with arguments 'show'.\n")
		},
	}
	show := &cobra.Command{
		Use:   "show",
		Short: "show module adapter infomation",
		Run: func(cmd *cobra.Command, args []string) {
			count := PacketCounter{}
			if CommmandGetCounter(&count) {
				fmt.Println("Trident-Adapter Module Running Status:")
				fmt.Printf("\tRX_PACKETS:           %v\n", count.RxPackets)
				fmt.Printf("\tRX_DROP:              %v\n", count.RxDropped)
				fmt.Printf("\tRX_ERROR:             %v\n", count.RxErrors)
				fmt.Printf("\tRX_CACHE:             %v\n", count.RxCached)
				fmt.Printf("\tTX_PACKETS:           %v\n", count.TxPackets)
				fmt.Printf("\tTX_DROP:              %v\n", count.TxDropped)
				fmt.Printf("\tTX_ERROR:             %v\n", count.TxErrors)
			}
		},
	}
	showPerf := &cobra.Command{
		Use:   "show-perf",
		Short: "show adapter performance information",
		Run: func(cmd *cobra.Command, args []string) {
			last := PacketCounter{}
			if !CommmandGetCounter(&last) {
				return
			}
			time.Sleep(1 * time.Second)
			now := PacketCounter{}
			if !CommmandGetCounter(&now) {
				return
			}
			fmt.Println("Trident-Adapter Module Performance:")
			fmt.Printf("\tRX_PACKETS/S:             %v\n", now.RxPackets-last.RxPackets)
			fmt.Printf("\tRX_DROPPED/S:             %v\n", now.RxDropped-last.RxDropped)
			fmt.Printf("\tRX_ERRORS/S:              %v\n", now.RxErrors-last.RxErrors)
			fmt.Printf("\tRX_CACHED/S:              %v\n", now.RxCached-last.RxCached)
			fmt.Printf("\tTX_PACKETS/S:             %v\n", now.TxPackets-last.TxPackets)
			fmt.Printf("\tTX_DROPPED/S:             %v\n", now.TxDropped-last.TxDropped)
			fmt.Printf("\tTX_ERRORS/S:              %v\n", now.TxErrors-last.TxErrors)
		},
	}
	cmd.AddCommand(show)
	cmd.AddCommand(showPerf)
	return cmd
}
