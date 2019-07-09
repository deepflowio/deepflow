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
	cacheCount uint8
	cacheMap   uint64
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

	instancesLock sync.Mutex
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

func (a *TridentAdapter) cacheClear(data []byte, key uint32, seq uint32) {
	startSeq := a.instances[key].seq
	instance := a.instances[key]
	if instance.cacheCount > 0 {
		for i := 0; i < a.cacheSize; i++ {
			if instance.cacheMap&(1<<uint64(i)) == uint64(1<<uint32(i)) {
				dataSeq := uint32(i) + startSeq + 1
				instance.timestamp = a.decode(a.instances[key].cache[i], key)
				drop := uint64(dataSeq - instance.seq - 1)
				a.counter.RxDropped += drop
				a.stats.RxDropped += drop
				instance.seq = dataSeq
			}
		}
		instance.cacheCount = 0
		instance.cacheMap = 0
	}

	if seq > 0 {
		drop := uint64(seq - instance.seq - 1)
		a.counter.RxDropped += drop
		a.stats.RxDropped += drop
		instance.timestamp = a.decode(data, key)
		instance.seq = seq
	}
}

func (a *TridentAdapter) cacheLookup(data []byte, key uint32, seq uint32) {
	a.instancesLock.Lock()
	instance := a.instances[key]
	a.instancesLock.Unlock()
	a.counter.RxPackets += 1
	a.stats.RxPackets += 1
	// droplet重启或trident重启时，不考虑SEQ
	if (instance.cacheCount == 0 && seq-instance.seq == 1) || instance.seq == 0 || seq == 1 {
		instance.seq = seq
		instance.timestamp = a.decode(data, key)
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
			a.instancesLock.Lock()
			a.cacheClear(data, key, seq)
			a.instancesLock.Unlock()
			return
		}
		instance.cache[offset] = data
		instance.cacheCount++
		instance.cacheMap |= 1 << offset
		a.counter.RxCached++
		a.stats.RxCached++
	}
}

func (a *TridentAdapter) findAndAdd(data []byte, key uint32, seq uint32) {
	a.instancesLock.Lock()
	if a.instances[key] == nil {
		instance := &tridentInstance{}
		instance.cache = make([][]byte, a.cacheSize)
		a.instances[key] = instance
	}
	a.instancesLock.Unlock()
	a.cacheLookup(data, key, seq)
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
		a.itemKeys = append(a.itemKeys, queue.HashKey(meta.GenerateHash()))
		a.itemBatch = append(a.itemBatch, meta)
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
	a.instancesLock.Lock()
	for key, instance := range a.instances {
		if timestamp > int64(instance.timestamp) && timestamp-int64(instance.timestamp) >= int64(TRIDENT_TIMEOUT) {
			if instance.cacheMap != 0 {
				a.cacheClear(nil, key, 0)
			}
		}
	}
	a.instancesLock.Unlock()
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
		a.findAndAdd(data, key, decoder.Seq())
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
