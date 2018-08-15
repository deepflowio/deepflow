package adapter

import (
	"bytes"
	"encoding/gob"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/op/go-logging"
	"github.com/spf13/cobra"
	"gitlab.x.lan/yunshan/droplet-libs/queue"
	"gitlab.x.lan/yunshan/droplet-libs/stats"

	"gitlab.x.lan/yunshan/droplet/dropletctl"
	"gitlab.x.lan/yunshan/droplet/handler"
	. "gitlab.x.lan/yunshan/droplet/utils"
)

const (
	LISTEN_PORT = 20033
	CACHE_SIZE  = 16
)

const (
	ADAPTER_CMD_SHOW = iota
)

var log = logging.MustGetLogger("trident_adapter")

type PacketCounter struct {
	RxPackets uint64 `statsd:"rx_packets"`
	RxDrop    uint64 `statsd:"rx_drop"`
	RxError   uint64 `statsd:"rx_error"`

	TxPackets uint64 `statsd:"tx_packets"`
	TxDrop    uint64 `statsd:"tx_drop"`
	TxError   uint64 `statsd:"tx_error"`
}

type TridentKey = uint32

type tridentInstance struct {
	ip  net.IP // it seems not used
	seq uint32

	cache      [CACHE_SIZE][]byte
	cacheCount uint8
	cacheMap   uint16
}

type TridentAdapter struct {
	queues     []queue.QueueWriter
	queueCount int

	instances map[TridentKey]*tridentInstance
	counter   *PacketCounter

	running  bool
	listener *net.UDPConn
}

func NewTridentAdapter(queues ...queue.QueueWriter) *TridentAdapter {
	adapter := &TridentAdapter{}
	adapter.counter = &PacketCounter{}
	adapter.queues = queues
	adapter.queueCount = len(queues)
	adapter.instances = make(map[TridentKey]*tridentInstance)
	listener, err := net.ListenUDP("udp4", &net.UDPAddr{Port: LISTEN_PORT})
	if err != nil {
		log.Error(err)
		return nil
	}
	adapter.listener = listener
	stats.RegisterCountable("trident_adapter", stats.EMPTY_TAG, adapter)
	dropletctl.Register(dropletctl.DROPLETCTL_ADAPTER, adapter)
	return adapter
}

func (a *TridentAdapter) GetCounter() interface{} {
	counter := &PacketCounter{}
	counter = a.counter
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
				a.counter.RxDrop += uint64(dataSeq - instance.seq - 1)
				instance.seq = dataSeq
				a.counter.RxPackets += 1
			}
		}
	}
	a.counter.RxPackets += 1
	a.counter.RxDrop += uint64(seq - instance.seq - 1)
	a.decode(data, key)
	instance.seq = seq
	instance.cacheCount = 0
	instance.cacheMap = 0
}

func (a *TridentAdapter) cacheLookup(data []byte, key uint32, seq uint32) {
	instance := a.instances[key]
	if (instance.cacheCount == 0 && seq-instance.seq == 1) || instance.seq == 0 {
		instance.seq = seq
		a.decode(data, key)
		a.counter.RxPackets += 1
	} else {
		if seq <= instance.seq {
			a.counter.RxError += 1
			log.Warningf("trident(%v) seq is less than current, drop", key)
			return
		}
		offset := seq - instance.seq - 1
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
	decoder := handler.NewSequentialDecoder(data)
	ifMacSuffix := decoder.DecodeHeader()

	for {
		meta := &handler.MetaPacket{
			InPort:   ifMacSuffix | handler.CAPTURE_REMOTE,
			Exporter: IpFromUint32(ip),
		}
		if decoder.NextPacket(meta) {
			break
		}

		a.counter.TxPackets++
		hash := meta.InPort + meta.IpSrc + meta.IpDst +
			uint32(meta.Proto) + uint32(meta.PortSrc) + uint32(meta.PortDst)
		a.queues[hash%uint32(a.queueCount)].Put(meta)
	}
}

func (a *TridentAdapter) run() {
	log.Infof("Starting trident adapter Listenning <%s>", a.listener.LocalAddr())
	for a.running {
		data := make([]byte, 1500)
		_, remote, err := a.listener.ReadFromUDP(data)
		if err != nil {
			log.Warningf("trident adapter listener.ReadFromUDP err: %s", err)
		}

		decoder := handler.NewSequentialDecoder(data)
		decoder.DecodeHeader()
		a.findAndAdd(data, IpToUint32(remote.IP), decoder.Seq())
	}
	a.listener.Close()
	log.Info("Stopped trident adapter")
}

func (a *TridentAdapter) wait(running bool) error {
	for i := 0; i < 4 && a.running != running; i++ {
		time.Sleep(5 * time.Second)
	}
	if a.running != running {
		if running {
			return errors.New("trident adapter didn't start within 5 second")
		} else {
			return errors.New("trident adapter didn't stop within 5 second")
		}
	}
	return nil
}

func (a *TridentAdapter) Start(running bool) error {
	if !a.running {
		log.Info("Start trident adapter")
		a.running = true
		go a.run()
	}
	return nil
}

func (a *TridentAdapter) Stop(wait bool) error { // TODO: untested
	if a.running {
		log.Info("Stop trident adapter")
		a.running = false
		return a.wait(false)
	}
	return nil
}

func (a *TridentAdapter) RecvCommand(conn *net.UDPConn, port int, operate uint16, arg *bytes.Buffer) {
	buff := bytes.Buffer{}
	switch operate {
	case ADAPTER_CMD_SHOW:
		encoder := gob.NewEncoder(&buff)
		if err := encoder.Encode(a.counter); err != nil {
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
				fmt.Printf("\tRX_PACKETS:	%v\n", count.RxPackets)
				fmt.Printf("\tRX_DROP:		%v\n", count.RxDrop)
				fmt.Printf("\tRX_ERROR:		%v\n", count.RxError)
				fmt.Printf("\tTX_PACKETS:	%v\n", count.TxPackets)
				fmt.Printf("\tTX_DROP:		%v\n", count.TxDrop)
				fmt.Printf("\tTX_ERROR:		%v\n", count.TxError)
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
			fmt.Printf("\tRX_PACKETS/S:		%v\n", now.RxPackets-last.RxPackets)
			fmt.Printf("\tRX_DROP/S:		%v\n", now.RxDrop-last.RxDrop)
			fmt.Printf("\tRX_ERROR/S:		%v\n", now.RxError-last.RxError)
			fmt.Printf("\tTX_PACKETS/S:		%v\n", now.TxPackets-last.TxPackets)
			fmt.Printf("\tTX_DROP/S:		%v\n", now.TxDrop-last.TxDrop)
			fmt.Printf("\tTX_ERROR/S:		%v\n", now.TxError-last.TxError)
		},
	}
	cmd.AddCommand(show)
	cmd.AddCommand(showPerf)
	return cmd
}
