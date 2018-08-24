package packet

import (
	"errors"
	"net"
	"reflect"
	"runtime"
	"syscall"
	"time"

	"github.com/docker/go-units"
	"github.com/google/gopacket/afpacket"
	. "github.com/google/gopacket/layers"
	"github.com/op/go-logging"
	"gitlab.x.lan/yunshan/droplet-libs/datatype"
	"gitlab.x.lan/yunshan/droplet-libs/queue"
	"gitlab.x.lan/yunshan/droplet-libs/stats"
	"golang.org/x/net/bpf"

	. "gitlab.x.lan/yunshan/droplet/utils"
)

var log = logging.MustGetLogger("capture")

var afPacketBlocks = 128

func SetAfPacketBlocks(n int) {
	afPacketBlocks = n
}

const (
	DEFAULT_BLOCK_SIZE = 1 * units.MiB
	DEFAULT_FRAME_SIZE = 1 << 16 // only for AF_PACKET v2
	POLL_TIMEOUT       = 100 * time.Millisecond
)

type PacketCounter struct {
	Rx      uint64 `statsd:"rx"`
	Err     uint64 `statsd:"err"`
	Retired uint64 `statsd:"retired"`

	KernelPackets uint32 `statsd:"kernel_packets"`
	KernelDrops   uint32 `statsd:"kernel_drops"`
	KernelFreezes uint32 `statsd:"kernel_freezes"`

	pollError uint64
	intrError uint64
}

type Capture struct {
	tPacket     *afpacket.TPacket
	ip          datatype.IPv4Int
	rxInterface uint32
	outputQueue queue.QueueWriter

	counter     *PacketCounter
	issueStop   bool
	running     bool
	lastPollErr error
	lastIntrErr error
}

func (c *Capture) GetCounter() interface{} {
	counter := &PacketCounter{}
	counter, c.counter = c.counter, counter

	socketStats, socketStatsV3, _ := c.tPacket.SocketStats()
	c.tPacket.InitSocketStats()
	// SocketStats和SocketStatsV3的字段在golang中被识别为私有字段无法读出，
	// 因此需要通过reflect来获取私有字段
	refSocketStats := reflect.ValueOf(socketStats)
	refSocketStatsV3 := reflect.ValueOf(socketStatsV3)
	max := func(x, y uint64) uint32 {
		if x > y {
			return uint32(x)
		} else {
			return uint32(y)
		}
	}
	uintField := func(v reflect.Value, fieldName string) uint64 {
		return v.FieldByName(fieldName).Uint()
	}
	counter.KernelPackets = max(uintField(refSocketStatsV3, "tp_packets"), uintField(refSocketStats, "tp_packets"))
	counter.KernelDrops = max(uintField(refSocketStatsV3, "tp_drops"), uintField(refSocketStats, "tp_drops"))
	counter.KernelFreezes = uint32(uintField(refSocketStatsV3, "tp_freeze_q_cnt"))

	if counter.pollError > 0 {
		log.Warningf("Poll error %c times, last err: %s", counter.pollError, c.lastPollErr.Error())
	}
	if counter.intrError > 0 {
		log.Warningf("INTR error %c times, last err: %s", counter.intrError, c.lastIntrErr.Error())
	}

	log.Debugf(
		"#rx: %c #err: %c #k_packets: %c #k_drops: %c #k_freezed: %c",
		counter.Rx, counter.Err, counter.KernelPackets, counter.KernelDrops, counter.KernelFreezes,
	)
	return counter
}

func (c *Capture) IsRunning() bool {
	return c.running
}

func (c *Capture) run() (retErr error) {
	log.Info("Start capture")

	prevTimestamp := time.Duration(0)
	c.running = true
	poll := uint64(0)
	for !c.issueStop {
		poll++

		packet, ci, err := c.tPacket.ZeroCopyReadPacketData()
		if err != nil {
			if err == afpacket.ErrTimeout {
				continue
			} else if err == afpacket.ErrPoll {
				c.counter.pollError++
				c.lastPollErr = err
				continue
			} else if errno, ok := err.(syscall.Errno); ok && errno == syscall.EINTR {
				c.counter.intrError++
				c.lastIntrErr = err
				continue
			} else {
				retErr = err
				break
			}
		}

		timestamp := time.Duration(ci.Timestamp.UnixNano())
		if prevTimestamp-time.Millisecond > timestamp {
			// AF_PACKET v3在某些内核上存在缺陷，目前使用1ms判断是否为过期数据
			c.counter.Retired++
			continue
		}
		if prevTimestamp > timestamp {
			timestamp = prevTimestamp
		} else {
			prevTimestamp = timestamp
		}
		c.counter.Rx++
		metaPacket := &datatype.MetaPacket{
			Timestamp: timestamp,
			InPort:    c.rxInterface,
			Exporter:  c.ip,
			Raw:       packet,
		}
		if !metaPacket.Parse(packet) {
			continue
		}
		c.outputQueue.Put(metaPacket)
	}
	c.running = false
	c.issueStop = false
	log.Info("Stopped capture")
	return
}

func (c *Capture) wait(running bool) error {
	for i := 0; i < 4 && c.running != running; i++ {
		time.Sleep(5 * time.Second)
	}
	if c.running != running {
		if running {
			return errors.New("Capture didn't start within 5 second")
		} else {
			return errors.New("Capture didn't stop within 5 second")
		}
	}
	return nil
}

func (c *Capture) Start() {
	go func() {
		c.run()
	}()
}

func (c *Capture) Stop(wait bool) error { // TODO: untested
	log.Info("Stop capture")
	if c.running {
		c.issueStop = true
	}
	if wait {
		return c.wait(false)
	}
	return nil
}

func (c *Capture) Close() error {
	if err := c.Stop(true); err != nil {
		return err
	}
	c.tPacket.Close()
	stats.DeregisterCountable(c)
	return nil
}

func NewCapture(interfaceName string, ip net.IP, isTap bool, outputQueue queue.QueueWriter) (*Capture, error) {
	if _, err := net.InterfaceByName(interfaceName); err != nil {
		return nil, err
	}
	tPacket, err := afpacket.NewTPacket(
		afpacket.OptInterface(interfaceName),
		afpacket.OptPollTimeout(POLL_TIMEOUT),
		afpacket.OptBlockSize(DEFAULT_BLOCK_SIZE),
		afpacket.OptFrameSize(DEFAULT_FRAME_SIZE),
		afpacket.OptNumBlocks(afPacketBlocks),
	)
	if err != nil {
		log.Warning("AF_PACKET init error", err)
		return nil, err
	}

	instructions := []bpf.Instruction{
		bpf.LoadExtension{Num: bpf.ExtType},
		bpf.JumpIf{Cond: bpf.JumpNotEqual, Val: uint32(LinuxSLLPacketTypeOutgoing), SkipTrue: 1},
		bpf.RetConstant{Val: 0},
		bpf.RetConstant{Val: 65535}, // default accept up to 64KB
	}
	rawInstructions, err := bpf.Assemble(instructions)
	if err != nil {
		log.Warning("Assemble bpf failed, bpf won't work")
	}

	if err := tPacket.SetBPF(rawInstructions); err != nil {
		log.Warning("BPF inject failed:", err)
	}

	rxInterface := uint32(datatype.CAPTURE_LOCAL)
	if isTap {
		rxInterface = uint32(datatype.CAPTURE_REMOTE)
	}

	cap := &Capture{
		tPacket:     tPacket,
		ip:          IpToUint32(ip),
		rxInterface: rxInterface,
		counter:     &PacketCounter{},
		outputQueue: outputQueue,
	}
	stats.RegisterCountable("capture", stats.EMPTY_TAG, cap)
	runtime.SetFinalizer(cap, func(c *Capture) { c.Close() })
	return cap, nil
}
