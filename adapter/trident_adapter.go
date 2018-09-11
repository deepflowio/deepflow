package adapter

import (
	"bytes"
	"encoding/gob"
	"fmt"
	"net"
	"runtime"
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
	LISTEN_PORT = 20033
	CACHE_SIZE  = 16
	QUEUE_MAX   = 16
	PACKET_MAX  = 200
)

const (
	ADAPTER_CMD_SHOW = iota
)

var log = logging.MustGetLogger("trident_adapter")

type PacketCounter struct {
	RxPackets uint64 `statsd:"rx_packets"`
	RxDrop    uint64 `statsd:"rx_drop"`  // 当前SEQ减去上次的SEQ
	RxError   uint64 `statsd:"rx_error"` // 当前SEQ小于上次的SEQ时+1，包乱序并且超出了CACHE_SIZE

	TxPackets uint64 `statsd:"tx_packets"`
	TxDrop    uint64 `statsd:"tx_drop"`
	TxError   uint64 `statsd:"tx_error"`
}

type TridentKey = uint32

type tridentInstance struct {
	seq uint32

	cache      [CACHE_SIZE][]byte
	cacheCount uint8
	cacheMap   uint16
}

type MetaPacketBlock = [1024]datatype.MetaPacket

type TridentAdapter struct {
	queues          []queue.QueueWriter
	queueCount      int
	hashBuffers     [QUEUE_MAX][PACKET_MAX]interface{}
	hashBufferCount [QUEUE_MAX]int
	metaPacketPool  sync.Pool
	udpPool         sync.Pool
	block           *MetaPacketBlock
	blockCursor     int

	instances map[TridentKey]*tridentInstance
	counter   *PacketCounter
	stats     *PacketCounter

	running  bool
	listener *net.UDPConn
}

func NewTridentAdapter(queues ...queue.QueueWriter) *TridentAdapter {
	adapter := &TridentAdapter{}
	adapter.counter = &PacketCounter{}
	adapter.stats = &PacketCounter{}
	adapter.queues = queues
	adapter.queueCount = len(queues)
	adapter.instances = make(map[TridentKey]*tridentInstance)
	adapter.udpPool.New = func() interface{} { return make([]byte, UDP_BUFFER_SIZE) }
	adapter.metaPacketPool.New = func() interface{} {
		block := new(MetaPacketBlock)
		runtime.SetFinalizer(block, func(b *MetaPacketBlock) { adapter.metaPacketPool.Put(b) })
		return block
	}
	adapter.block = adapter.metaPacketPool.Get().(*MetaPacketBlock)
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

func (a *TridentAdapter) alloc() *datatype.MetaPacket {
	metaPacket := &a.block[a.blockCursor]
	a.blockCursor++
	if a.blockCursor >= len(a.block) {
		a.block = a.metaPacketPool.Get().(*MetaPacketBlock)
		a.blockCursor = 0
	}
	return metaPacket
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
		for i := 0; i < CACHE_SIZE; i++ {
			if instance.cacheMap&(1<<uint32(i)) > 0 {
				dataSeq := uint32(i) + startSeq
				a.decode(a.instances[key].cache[i], key)
				drop := uint64(dataSeq - instance.seq - 1)
				a.counter.RxDrop += drop
				a.stats.RxDrop += drop
				instance.seq = dataSeq
				a.counter.RxPackets += 1
				a.stats.RxPackets += 1
			}
		}
	}
	drop := uint64(seq - instance.seq - 1)
	a.counter.RxPackets += 1
	a.stats.RxPackets += 1
	a.counter.RxDrop += drop
	a.stats.RxDrop += drop
	a.decode(data, key)
	instance.seq = seq
	instance.cacheCount = 0
	instance.cacheMap = 0
}

func (a *TridentAdapter) cacheLookup(data []byte, key uint32, seq uint32) {
	instance := a.instances[key]
	// droplet重启或trident重启时，不考虑SEQ
	if (instance.cacheCount == 0 && seq-instance.seq == 1) || instance.seq == 0 || seq == 1 {
		instance.seq = seq
		a.decode(data, key)
		a.counter.RxPackets += 1
		a.stats.RxPackets += 1
	} else {
		if seq <= instance.seq {
			a.counter.RxError += 1
			a.stats.RxError += 1
			a.udpPool.Put(data)
			log.Warningf("trident(%v) seq is less than current, drop", key)
			return
		}
		offset := seq - instance.seq - 1
		// cache满或乱序超过CACHE_SIZE, 清空cache
		if offset >= CACHE_SIZE || instance.cacheCount == CACHE_SIZE {
			a.cacheClear(data, key, seq)
			return
		}
		instance.cache[offset] = data
		instance.cacheCount++
		instance.cacheMap |= 1 << offset
	}
}

func (a *TridentAdapter) findAndAdd(data []byte, key uint32, seq uint32) {
	if a.instances[key] == nil {
		a.instances[key] = &tridentInstance{}
	}
	a.cacheLookup(data, key, seq)
}

func (a *TridentAdapter) decode(data []byte, ip uint32) {
	decoder := NewSequentialDecoder(data)
	ifMacSuffix, _ := decoder.DecodeHeader()

	for {
		meta := a.alloc()
		meta.InPort = uint32(datatype.PACKET_SOURCE_TOR) | ifMacSuffix
		meta.Exporter = ip
		if decoder.NextPacket(meta) {
			break
		}

		a.counter.TxPackets++
		a.stats.TxPackets++
		hash := meta.InPort + meta.IpSrc + meta.IpDst +
			uint32(meta.Protocol) + uint32(meta.PortSrc) + uint32(meta.PortDst)
		index := hash % uint32(a.queueCount)
		a.hashBuffers[index][a.hashBufferCount[index]] = meta
		a.hashBufferCount[index]++
	}

	for index := 0; index < a.queueCount; index++ {
		count := a.hashBufferCount[index]
		if count > 0 {
			a.queues[index].Put(a.hashBuffers[index][:count]...)
			a.hashBufferCount[index] = 0
		}
	}
	a.udpPool.Put(data)
}

func (a *TridentAdapter) run() {
	log.Infof("Starting trident adapter Listenning <%s>", a.listener.LocalAddr())
	for a.running {
		data := a.udpPool.Get().([]byte)
		_, remote, err := a.listener.ReadFromUDP(data)
		if err != nil {
			log.Warningf("trident adapter listener.ReadFromUDP err: %s", err)
		}

		decoder := NewSequentialDecoder(data)
		if _, invalid := decoder.DecodeHeader(); invalid {
			a.udpPool.Put(data)
			continue
		}
		a.findAndAdd(data, IpToUint32(remote.IP), decoder.Seq())
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
				fmt.Printf("\tRX_DROP:              %v\n", count.RxDrop)
				fmt.Printf("\tRX_ERROR:             %v\n", count.RxError)
				fmt.Printf("\tTX_PACKETS:           %v\n", count.TxPackets)
				fmt.Printf("\tTX_DROP:              %v\n", count.TxDrop)
				fmt.Printf("\tTX_ERROR:             %v\n", count.TxError)
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
			fmt.Printf("\tRX_DROP/S:                %v\n", now.RxDrop-last.RxDrop)
			fmt.Printf("\tRX_ERROR/S:               %v\n", now.RxError-last.RxError)
			fmt.Printf("\tTX_PACKETS/S:             %v\n", now.TxPackets-last.TxPackets)
			fmt.Printf("\tTX_DROP/S:                %v\n", now.TxDrop-last.TxDrop)
			fmt.Printf("\tTX_ERROR/S:               %v\n", now.TxError-last.TxError)
		},
	}
	cmd.AddCommand(show)
	cmd.AddCommand(showPerf)
	return cmd
}
