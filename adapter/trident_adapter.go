package adapter

import (
	"net"
	"os"
	"sync"
	"time"

	"github.com/op/go-logging"
	"gitlab.x.lan/yunshan/droplet-libs/debug"
	"gitlab.x.lan/yunshan/droplet-libs/pool"
	"gitlab.x.lan/yunshan/droplet-libs/queue"
	"gitlab.x.lan/yunshan/droplet-libs/stats"
	. "gitlab.x.lan/yunshan/droplet-libs/utils"

	"gitlab.x.lan/yunshan/droplet/dropletctl"
)

const (
	LISTEN_PORT      = 20033
	QUEUE_BATCH_SIZE = 4096
	TRIDENT_TIMEOUT  = 2 * time.Second

	BATCH_SIZE = 128
)

var log = logging.MustGetLogger("trident_adapter")

type TridentKey = uint32

type packetBuffer struct {
	buffer    []byte
	tridentIp uint32
	decoder   SequentialDecoder
	hash      uint8
}

type tridentInstance struct {
	seq       uint32
	timestamp time.Duration

	cache      []*packetBuffer
	cacheCount uint16
	timeAdjust time.Duration
}

type TridentAdapter struct {
	command
	statsCounter

	listenBufferSize int
	cacheSize        int

	instancesLock sync.Mutex // 仅用于droplet-ctl打印trident信息
	instances     map[TridentKey]*tridentInstance

	slaveCount uint8
	slaves     []*slave

	running  bool
	listener *net.UDPConn
}

func (p *packetBuffer) init(ip uint32) {
	p.tridentIp = ip
	p.decoder.initSequentialDecoder(p.buffer)
}

func (p *packetBuffer) calcHash() uint8 {
	hash := p.tridentIp ^ uint32(p.decoder.tridentIndex)
	p.hash = uint8(hash>>24) ^ uint8(hash>>16) ^ uint8(hash>>8) ^ uint8(hash)
	p.hash = (p.hash >> 6) ^ (p.hash >> 4) ^ (p.hash >> 2) ^ p.hash
	return p.hash
}

func NewTridentAdapter(queues []queue.QueueWriter, listenBufferSize, cacheSize int) *TridentAdapter {
	listener, err := net.ListenUDP("udp4", &net.UDPAddr{Port: LISTEN_PORT})
	if err != nil {
		log.Error(err)
		return nil
	}
	adapter := &TridentAdapter{
		listenBufferSize: listenBufferSize,
		cacheSize:        cacheSize,
		slaveCount:       uint8(len(queues)),
		slaves:           make([]*slave, len(queues)),

		instances: make(map[TridentKey]*tridentInstance),
	}
	for i := uint8(0); i < adapter.slaveCount; i++ {
		adapter.slaves[i] = newSlave(int(i), queues[i])
	}
	adapter.statsCounter.init()
	adapter.listener = listener
	adapter.command.init(adapter)
	stats.RegisterCountable("trident-adapter", adapter)
	debug.Register(dropletctl.DROPLETCTL_ADAPTER, adapter)
	return adapter
}

func (a *TridentAdapter) GetStatsCounter() interface{} {
	counter := &PacketCounter{}
	masterCounter := a.statsCounter.GetStatsCounter().(*PacketCounter)
	counter.add(masterCounter)
	for i := uint8(0); i < a.slaveCount; i++ {
		slaveCounter := a.slaves[i].statsCounter.GetStatsCounter().(*PacketCounter)
		counter.add(slaveCounter)
	}
	return counter
}

func (a *TridentAdapter) GetCounter() interface{} {
	counter := a.statsCounter.GetCounter().(*PacketCounter)
	for i := uint8(0); i < a.slaveCount; i++ {
		slaveCounter := a.slaves[i].statsCounter.GetCounter().(*PacketCounter)
		counter.add(slaveCounter)
	}
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

				packet := instance.cache[i]
				instance.timestamp = packet.decoder.timestamp
				index := packet.hash & (a.slaveCount - 1)
				a.slaves[index].put(packet)
				instance.cache[i] = nil
			}
		}
		instance.cacheCount = 0
	}
}

func (a *TridentAdapter) cacheLookup(instance *tridentInstance, packet *packetBuffer) bool {
	decoder := &packet.decoder
	seq := decoder.Seq()
	timestamp := decoder.timestamp
	a.counter.RxPackets += 1
	a.stats.RxPackets += 1
	// droplet重启或trident重启时，不考虑SEQ
	if (instance.cacheCount == 0 && seq-instance.seq == 1) || instance.seq == 0 || seq == 1 {
		instance.seq = seq
		instance.timestamp = timestamp
		return false
	} else {
		// seq-instance.seq > 0xf0000000条件是为了避免u32环回来，例如0-0xffffffff应该是正常的
		if (seq < instance.seq && seq-instance.seq > 0xf0000000) || seq == instance.seq {
			a.counter.RxErrors += 1
			a.stats.RxErrors += 1

			if timestamp > instance.timestamp+time.Minute { // trident故障后10s自动重启，增加一些Buffer避免误判
				log.Infof("trident(%v) restart since timestamp %v > %v + 1m, reset sequence from %d to %d",
					IpFromUint32(packet.tridentIp), timestamp, instance.timestamp, instance.seq, seq)
				a.cacheClear(instance, packet.tridentIp)
				instance.seq = seq
				instance.timestamp = timestamp
			} else {
				log.Warningf("trident(%v) recv seq %d is less than current %d, drop", IpFromUint32(packet.tridentIp), seq, instance.seq)
			}

			releasePacketBuffer(packet)
			return true
		}
		offset := seq - instance.seq - 1
		// cache满或乱序超过CACHE_SIZE, 清空cache
		if int(offset) >= a.cacheSize || int(instance.cacheCount) == a.cacheSize {
			a.cacheClear(instance, packet.tridentIp)

			offset = seq - instance.seq - 1
			if offset == 0 {
				instance.seq = seq
				instance.timestamp = timestamp
				return false
			} else if int(offset) >= a.cacheSize {
				drop := uint64(int(offset) - a.cacheSize + 1)
				a.counter.RxDropped += drop
				a.stats.RxDropped += drop

				offset = uint32(a.cacheSize) - 1
				instance.seq = seq - uint32(a.cacheSize)
			}
		}
		instance.cache[offset] = packet
		instance.cacheCount++
		instance.timestamp = timestamp
		a.counter.RxCached++
		a.stats.RxCached++
		return true
	}
}

func (a *TridentAdapter) findAndAdd(packet *packetBuffer) bool {
	instance := a.instances[packet.tridentIp]
	if instance == nil {
		instance = &tridentInstance{}
		instance.cache = make([]*packetBuffer, a.cacheSize)
		a.instancesLock.Lock()
		a.instances[packet.tridentIp] = instance
		a.instancesLock.Unlock()
	}
	return a.cacheLookup(instance, packet)
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

var packetBufferPool = pool.NewLockFreePool(
	func() interface{} {
		packet := new(packetBuffer)
		packet.buffer = make([]byte, UDP_BUFFER_SIZE)
		return packet
	},
	pool.OptionPoolSizePerCPU(16),
	pool.OptionInitFullPoolSize(16),
)

func acquirePacketBuffer() *packetBuffer {
	return packetBufferPool.Get().(*packetBuffer)
}

func releasePacketBuffer(b *packetBuffer) {
	// 此处无初始化
	packetBufferPool.Put(b)
}

func (a *TridentAdapter) run() {
	log.Infof("Starting trident adapter Listenning <%s>", a.listener.LocalAddr())
	a.listener.SetReadDeadline(time.Now().Add(TRIDENT_TIMEOUT))
	a.listener.SetReadBuffer(a.listenBufferSize)
	batch := [BATCH_SIZE]*packetBuffer{}
	count := 0
	for a.running {
		for i := 0; i < BATCH_SIZE; i++ {
			packet := acquirePacketBuffer()
			_, remote, err := a.listener.ReadFromUDP(packet.buffer)
			if err != nil {
				if err.(net.Error).Timeout() {
					a.listener.SetReadDeadline(time.Now().Add(TRIDENT_TIMEOUT))
					a.flushInstance()
					break
				}
				log.Errorf("trident adapter listener.ReadFromUDP err: %s", err)
				os.Exit(1)
			}
			packet.init(IpToUint32(remote.IP.To4()))
			batch[i] = packet
			count++
		}
		for i := 0; i < count; i++ {
			if invalid := batch[i].decoder.DecodeHeader(); invalid {
				releasePacketBuffer(batch[i])
				continue
			}
			if cached := a.findAndAdd(batch[i]); cached {
				continue
			}
			hash := batch[i].calcHash()
			index := hash & (a.slaveCount - 1)
			a.slaves[index].put(batch[i])
		}
		count = 0
	}
	a.listener.Close()
	log.Info("Stopped trident adapter")
}

func (a *TridentAdapter) startSlaves() {
	for i := uint8(0); i < a.slaveCount; i++ {
		go a.slaves[i].run()
	}
}

func (a *TridentAdapter) Start() error {
	if !a.running {
		log.Info("Start trident adapter")
		a.running = true
		a.startSlaves()
		go a.run()
	}
	return nil
}
