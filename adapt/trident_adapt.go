package adapt

import (
	"bytes"
	"encoding/gob"
	"errors"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/op/go-logging"
	"github.com/spf13/cobra"

	"gitlab.x.lan/yunshan/droplet-libs/queue"
	"gitlab.x.lan/yunshan/droplet-libs/stats"
	"gitlab.x.lan/yunshan/droplet/dpctl"
	"gitlab.x.lan/yunshan/droplet/handler"
	. "gitlab.x.lan/yunshan/droplet/utils"
)

const (
	LISTEN_PORT = 20033
	CACHE_SIZE  = 16
)

const (
	ADAPT_CMD_SHOW = iota
)

var log = logging.MustGetLogger(os.Args[0])

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
	queues     []queue.QueueWriter
	queueCount int

	tridents map[TridentKey]*tridentInstance
	counter  *PacketCounter

	running  bool
	listener *net.UDPConn
}

func NewTridentAdapt(queues ...queue.QueueWriter) *TridentAdapt {
	adapt := &TridentAdapt{}
	adapt.counter = &PacketCounter{}
	adapt.queues = queues
	adapt.queueCount = len(queues)
	adapt.tridents = make(map[TridentKey]*tridentInstance)
	listener, err := net.ListenUDP("udp4", &net.UDPAddr{Port: LISTEN_PORT})
	if err != nil {
		log.Error(err)
		return nil
	}
	adapt.listener = listener
	stats.RegisterCountable("trident_adapt", stats.EMPTY_TAG, adapt)
	dpctl.Register(dpctl.DPCTL_ADAPT, adapt)
	return adapt
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
	a.counter.RxDrop += uint64(seq - instance.seq - 1)
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
		if off >= CACHE_SIZE || instance.cacheCnt == CACHE_SIZE {
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
	ifMacSuffix := decoder.DecodeHeader()

	for {
		meta := &(handler.MetaPktHdr{InPort: ifMacSuffix | handler.CAPTURE_REMOTE, Exporter: UInt32ToIP(ip)})
		if decoder.NextPacket(meta) {
			break
		}

		a.counter.TxPkt++
		hash := meta.InPort + IPToUInt32(meta.IpSrc) + IPToUInt32(meta.IpDst) +
			uint32(meta.Proto) + uint32(meta.PortSrc) + uint32(meta.PortDst)
		a.queues[hash%uint32(a.queueCount)].Put(meta)
	}
}

func (a *TridentAdapt) run() {
	log.Infof("Starting trident adapt Listenning <%s>", a.listener.LocalAddr())
	for a.running {
		data := make([]byte, 1500)
		_, remote, err := a.listener.ReadFromUDP(data)
		if err != nil {
			log.Warningf("trident adapt listener.ReadFromUDP err: %s", err)
		}

		decoder := handler.NewSequentialDecoder(data)
		decoder.DecodeHeader()
		a.findAndAdd(data, IPToUInt32(remote.IP), decoder.Seq())
	}
	a.listener.Close()
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
		a.running = true
		go a.run()
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

func (a *TridentAdapt) RecvCommand(conn *net.UDPConn, port int, operate uint16, arg *bytes.Buffer) {
	buff := bytes.Buffer{}
	switch operate {
	case ADAPT_CMD_SHOW:
		encoder := gob.NewEncoder(&buff)
		if err := encoder.Encode(a.counter); err != nil {
			log.Error(err)
			return
		}
		dpctl.SendToDropletCtrl(conn, port, 0, &buff)
		break
	default:
		log.Warningf("Trident Adapt recv unknown command(%v).", operate)
	}
}

func CommmandGetCounter(count *PacketCounter) bool {
	result, err := dpctl.SendToDroplet(dpctl.DPCTL_ADAPT, ADAPT_CMD_SHOW, nil)
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
		Use:   "adapt",
		Short: "config droplet adapt module",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("please run with arguments 'show'.\n")
		},
	}
	show := &cobra.Command{
		Use:   "show",
		Short: "show module adapt infomation",
		Run: func(cmd *cobra.Command, args []string) {
			count := PacketCounter{}
			if CommmandGetCounter(&count) {
				fmt.Println("Trident-Adapt Module Running Status:")
				fmt.Printf("\tRX_PKT: 		%v\n", count.RxPkt)
				fmt.Printf("\tRX_DROP: 		%v\n", count.RxDrop)
				fmt.Printf("\tRX_ERR: 		%v\n", count.RxErr)
				fmt.Printf("\tTX_PKT: 		%v\n", count.TxPkt)
				fmt.Printf("\tTX_DROP: 		%v\n", count.TxDrop)
				fmt.Printf("\tTX_ERR: 		%v\n", count.TxErr)
			}
		},
	}
	showPerf := &cobra.Command{
		Use:   "show-perf",
		Short: "show adapt performance information",
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
			fmt.Println("Trident-Adapt Module Performance:")
			fmt.Printf("\tRX_PKT_PPS: 		%v\n", now.RxPkt-last.RxPkt)
			fmt.Printf("\tRX_DROP_PPS: 		%v\n", now.RxDrop-last.RxDrop)
			fmt.Printf("\tRX_ERR_PPS: 		%v\n", now.RxErr-last.RxErr)
			fmt.Printf("\tTX_PKT_PPS: 		%v\n", now.TxPkt-last.TxPkt)
			fmt.Printf("\tTX_DROP_PPS: 		%v\n", now.TxDrop-last.TxDrop)
			fmt.Printf("\tTX_ERR_PPS: 		%v\n", now.TxErr-last.TxErr)
		},
	}
	cmd.AddCommand(show)
	cmd.AddCommand(showPerf)
	return cmd
}
