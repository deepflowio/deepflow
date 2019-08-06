package adapter

import (
	"net"
	"sync"
	"time"

	"github.com/op/go-logging"
	"gitlab.x.lan/yunshan/droplet-libs/datatype"
	"gitlab.x.lan/yunshan/droplet-libs/debug"
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
	ADAPTER_CMD_STATUS
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
	cacheCount uint16
	timeAdjust time.Duration
}

type TridentAdapter struct {
	command

	listenBufferSize int
	cacheSize        int

	queues    queue.MultiQueueWriter
	itemKeys  []queue.HashKey
	itemBatch []interface{}
	udpPool   sync.Pool

	instancesLock sync.Mutex // 仅用于droplet-ctl打印trident信息
	instances     map[TridentKey]*tridentInstance
	counter       *PacketCounter
	stats         *PacketCounter

	running  bool
	listener *net.UDPConn
}

func NewTridentAdapter(queues queue.MultiQueueWriter, listenBufferSize, cacheSize int) *TridentAdapter {
	adapter := &TridentAdapter{
		listenBufferSize: listenBufferSize,
		cacheSize:        cacheSize,

		queues:    queues,
		itemKeys:  make([]queue.HashKey, 0, PACKET_MAX+1),
		itemBatch: make([]interface{}, 0, PACKET_MAX),
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
	listener, err := net.ListenUDP("udp4", &net.UDPAddr{Port: LISTEN_PORT})
	if err != nil {
		log.Error(err)
		return nil
	}
	adapter.listener = listener
	adapter.command.init(adapter)
	stats.RegisterCountable("trident-adapter", adapter)
	debug.Register(dropletctl.DROPLETCTL_ADAPTER, adapter)
	return adapter
}

func (a *TridentAdapter) GetCounter() interface{} {
	counter := &PacketCounter{}
	counter, a.counter = a.counter, counter
	return counter
}

func (a *TridentAdapter) Closed() bool {
	return false // FIXME: never close?
}

func (a *TridentAdapter) cacheClear(instance *tridentInstance, key uint32) {
	if instance.cacheCount > 0 {
		startSeq := instance.seq
		for i := 0; i < a.cacheSize; i++ {
			if instance.cache[i] != nil {
				dataSeq := uint32(i) + startSeq + 1
				drop := uint64(dataSeq - instance.seq - 1)
				a.counter.RxDropped += drop
				a.stats.RxDropped += drop

				instance.seq = dataSeq
				instance.timestamp = a.decode(instance.cache[i], key)
				instance.cache[i] = nil
			}
		}
		instance.cacheCount = 0
	}
}

func (a *TridentAdapter) cacheLookup(data []byte, key uint32, seq uint32, timestamp time.Duration) {
	instance := a.instances[key]
	a.counter.RxPackets += 1
	a.stats.RxPackets += 1
	// droplet重启或trident重启时，不考虑SEQ
	if (instance.cacheCount == 0 && seq-instance.seq == 1) || instance.seq == 0 || seq == 1 {
		instance.seq = seq
		instance.timestamp = a.decode(data, key)
	} else {
		// seq-instance.seq > 0xf0000000条件是为了避免u32环回来，例如0-0xffffffff应该是正常的
		if seq <= instance.seq && seq-instance.seq > 0xf0000000 {
			a.counter.RxErrors += 1
			a.stats.RxErrors += 1

			if timestamp > instance.timestamp+time.Minute { // trident故障后10s自动重启，增加一些Buffer避免误判
				log.Infof("trident(%v) restart since timestamp %v > %v + 10s, reset sequence from %d to %d",
					IpFromUint32(key), timestamp, instance.timestamp, instance.seq, seq)
				a.cacheClear(instance, key)
				instance.seq = seq
				instance.timestamp = timestamp
			} else {
				log.Warningf("trident(%v) recv seq %d is less than current %d, drop", IpFromUint32(key), seq, instance.seq)
			}

			a.udpPool.Put(data)
			return
		}
		offset := seq - instance.seq - 1
		// cache满或乱序超过CACHE_SIZE, 清空cache
		if int(offset) >= a.cacheSize || int(instance.cacheCount) == a.cacheSize {
			a.cacheClear(instance, key)

			offset = seq - instance.seq - 1
			if offset == 0 {
				instance.seq = seq
				instance.timestamp = a.decode(data, key)
				return
			} else if int(offset) >= a.cacheSize {
				drop := uint64(int(offset) - a.cacheSize + 1)
				a.counter.RxDropped += drop
				a.stats.RxDropped += drop

				offset = uint32(a.cacheSize) - 1
				instance.seq = seq - uint32(a.cacheSize)
			}
		}
		instance.cache[offset] = data
		instance.cacheCount++
		instance.timestamp = timestamp
		a.counter.RxCached++
		a.stats.RxCached++
	}
}

func (a *TridentAdapter) findAndAdd(data []byte, key uint32, seq uint32, timestamp time.Duration) {
	if a.instances[key] == nil {
		instance := &tridentInstance{}
		instance.cache = make([][]byte, a.cacheSize)
		a.instancesLock.Lock()
		a.instances[key] = instance
		a.instancesLock.Unlock()
	}
	a.cacheLookup(data, key, seq, timestamp)
}

func (a *TridentAdapter) decode(data []byte, ip uint32) time.Duration {
	decoder := NewSequentialDecoder(data)
	inPort, _ := decoder.DecodeHeader()
	timestamp := decoder.timestamp

	for {
		meta := datatype.AcquireMetaPacket()
		meta.InPort = inPort
		meta.Exporter = ip
		if decoder.NextPacket(meta) {
			datatype.ReleaseMetaPacket(meta)
			break
		}

		a.counter.TxPackets++
		a.stats.TxPackets++
		a.itemKeys = append(a.itemKeys, queue.HashKey(meta.GenerateQueueHash()))
		a.itemBatch = append(a.itemBatch, meta)

		if len(a.itemBatch) >= cap(a.itemBatch) {
			a.queues.Puts(a.itemKeys, a.itemBatch)
			a.itemKeys = a.itemKeys[:1]
			a.itemBatch = a.itemBatch[:0]
		}
	}

	if len(a.itemBatch) > 0 {
		a.queues.Puts(a.itemKeys, a.itemBatch)
		a.itemKeys = a.itemKeys[:1]
		a.itemBatch = a.itemBatch[:0]
	}

	a.udpPool.Put(data)
	return timestamp
}

func (a *TridentAdapter) flushInstance() {
	timestamp := time.Now().UnixNano()
	for key, instance := range a.instances {
		if timestamp > int64(instance.timestamp) && timestamp-int64(instance.timestamp) >= int64(TRIDENT_TIMEOUT) {
			if instance.cacheCount > 0 {
				a.cacheClear(instance, key)
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
		key := IpToUint32(remote.IP.To4())
		decoder := NewSequentialDecoder(data)
		if _, invalid := decoder.DecodeHeader(); invalid {
			a.udpPool.Put(data)
			continue
		}
		a.findAndAdd(data, key, decoder.Seq(), decoder.timestamp)
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
