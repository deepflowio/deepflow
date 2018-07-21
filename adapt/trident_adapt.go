package adapt

import (
	"errors"
	"net"
	"os"
	"time"

	"github.com/op/go-logging"
	"gitlab.x.lan/yunshan/droplet-libs/stats"
	"gitlab.x.lan/yunshan/droplet/handler"
	. "gitlab.x.lan/yunshan/droplet/utils"
)

const (
	LISTEN_PORT = 20033
	CACHE_SIZE  = 16
)

var log = logging.MustGetLogger(os.Args[0])

type ErrorHandler func(*TridentAdapt, error)

type PacketCounter struct {
	RxPkt  uint64 `statsd:"rx_pkt"`
	RxDrop uint64 `statsd:"rx_drop"`
	RxErr  uint64 `statsd:"rx_err"`

	TxPkt  uint64 `statsd:"tx_pkt"`
	TxDrop uint64 `statsd:"tx_drop"`
	TxErr  uint64 `statsd:"tx_err"`
}

type TridentKey = uint32

type tridentInstance struct {
	trident net.IP
	seq     uint32

	cache    [CACHE_SIZE][]byte
	cacheCnt uint8
	cacheMap uint16
}

type TridentAdapt struct {
	errorHandler ErrorHandler
	chs          []chan<- handler.MetaPktHdr

	tridents map[TridentKey]*tridentInstance
	counter  *PacketCounter

	running bool
}

func (a *TridentAdapt) Init(errorHandler ErrorHandler, chs ...chan<- handler.MetaPktHdr) *TridentAdapt {
	a.counter = &PacketCounter{}
	a.errorHandler = errorHandler
	a.chs = chs
	a.tridents = make(map[TridentKey]*tridentInstance)
	stats.RegisterCountable("trident_adapt", stats.EMPTY_TAG, a)
	return a
}

func (a *TridentAdapt) GetCounter() interface{} {
	counter := &PacketCounter{}
	counter = a.counter
	return counter
}

func (a *TridentAdapt) IsRunning() bool {
	return a.running
}

func (a *TridentAdapt) cacheClear(data []byte, key uint32, seq uint32) {
	startSeq := a.tridents[key].seq
	instance := a.tridents[key]
	if instance.cacheCnt > 0 {
		for i := 0; i < CACHE_SIZE; i++ {
			if instance.cacheMap&(1<<uint32(i)) > 0 {
				dataSeq := uint32(i) + startSeq
				a.decode(a.tridents[key].cache[i], key)
				a.counter.RxDrop += uint64(dataSeq - instance.seq - 1)
				instance.seq = dataSeq
				a.counter.RxPkt += 1
			}
		}
	}
	a.counter.RxPkt += 1
	a.counter.RxDrop += uint64(seq - instance.seq)
	a.decode(data, key)
	instance.seq = seq
	instance.cacheCnt = 0
	instance.cacheMap = 0
}

func (a *TridentAdapt) cacheLookup(data []byte, key uint32, seq uint32) {
	instance := a.tridents[key]
	if (instance.cacheCnt == 0 && seq-instance.seq == 1) || instance.seq == 0 {
		instance.seq = seq
		a.decode(data, key)
		a.counter.RxPkt += 1
	} else {
		if seq <= instance.seq {
			a.counter.RxErr += 1
			log.Warningf("trident(%v) seq is less than current, drop", key)
			return
		}
		off := seq - instance.seq - 1
		if off > CACHE_SIZE || instance.cacheCnt == CACHE_SIZE {
			a.cacheClear(data, key, seq)
			return
		}
		instance.cache[off] = data
		instance.cacheCnt++
		instance.cacheMap |= 1 << off
	}
}

func (a *TridentAdapt) findAndAdd(data []byte, key uint32, seq uint32) {
	if a.tridents[key] == nil {
		a.tridents[key] = &tridentInstance{}
	}
	a.cacheLookup(data, key, seq)
}

func (a *TridentAdapt) decode(data []byte, ip uint32) {
	decoder := handler.NewSequentialDecoder(data)
	_, ifMacSuffix := decoder.DecodeHeader()

	for {
		meta := &(handler.MetaPktHdr{InPort: ifMacSuffix | handler.CAPTURE_REMOTE, Exporter: UInt32ToIP(ip)})
		output, _ := decoder.NextPacket(meta)
		if output == "" {
			break
		}

		for _, ch := range a.chs {
			ch <- *meta
		}
	}
}

func (a *TridentAdapt) run() {
	listener, err := net.ListenUDP("udp4", &net.UDPAddr{Port: LISTEN_PORT})
	if err != nil {
		log.Error(err)
		return
	}
	log.Infof("Starting trident adapt Listenning <%s>", listener.LocalAddr().String())
	a.running = true
	for a.running {
		data := make([]byte, 1500)
		_, remote, err := listener.ReadFromUDP(data)
		if err != nil {
			log.Warningf("trident adapt listener.ReadFromUDP err: %s", err)
		}

		decoder := handler.NewSequentialDecoder(data)
		decoder.DecodeHeader()
		a.findAndAdd(data, IPToUInt32(remote.IP), decoder.Seq())
	}
	listener.Close()
	log.Info("Stopped trident adapt")
}

func (a *TridentAdapt) wait(running bool) error {
	for i := 0; i < 4 && a.running != running; i++ {
		time.Sleep(5 * time.Second)
	}
	if a.running != running {
		if running {
			return errors.New("trident adapt didn't start within 5 second")
		} else {
			return errors.New("trident adapt didn't stop within 5 second")
		}
	}
	return nil
}

func (a *TridentAdapt) Start(running bool) error {
	if !a.running {
		log.Info("Start trident adapt")
		go a.run()
		return a.wait(true)
	}
	return nil
}

func (a *TridentAdapt) Stop(wait bool) error { // TODO: untested
	if a.running {
		log.Info("Stop trident adapt")
		a.running = false
		return a.wait(false)
	}
	return nil
}
