package capture

import (
	"errors"
	"syscall"
	"time"
	"unsafe"

	"github.com/google/gopacket/afpacket"
	"github.com/op/go-logging"
	"gitlab.x.lan/yunshan/droplet-libs/stats"
)

/*
#include <linux/if_packet.h>  // AF_PACKET, sockaddr_ll
*/
import "C"

type SocketStats C.struct_tpacket_stats
type SocketStatsV3 C.struct_tpacket_stats_v3

var log = logging.MustGetLogger("capture")

type PacketCounter struct {
	Rx      uint64 `statsd:"rx"`
	Err     uint64 `statsd:"err"`
	Retired uint64 `statsd:"retired"`

	KernelPackets uint `statsd:"kernel_packets"`
	KernelDrops   uint `statsd:"kernel_drops"`
	KernelFreezes uint `statsd:"kernel_freezes"`

	pollError uint64
	intrError uint64
}

type Capture struct {
	PacketHandler

	ifName  string
	tPacket *afpacket.TPacket

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
	// 因此需要强制类型转换
	refSocketStats := (*SocketStats)(unsafe.Pointer(&socketStats))
	refSocketStatsV3 := (*SocketStatsV3)(unsafe.Pointer(&socketStatsV3))
	max := func(x, y C.uint) uint {
		if x > y {
			return uint(x)
		} else {
			return uint(y)
		}
	}
	counter.KernelPackets = max(refSocketStatsV3.tp_packets, refSocketStats.tp_packets)
	counter.KernelDrops = max(refSocketStatsV3.tp_drops, refSocketStats.tp_drops)
	counter.KernelFreezes = uint(refSocketStatsV3.tp_freeze_q_cnt)

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
	log.Info("Start capture on", c.ifName)

	prevTimestamp := time.Duration(0)
	c.running = true
	poll := uint64(0)
	for !c.issueStop {
		poll++

		packet, ci, err := c.tPacket.ZeroCopyReadPacketData()
		if err != nil {
			if err == afpacket.ErrTimeout {
				c.Flush()
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
		c.Handle(timestamp, packet, ci.Length)
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
	log.Info("Stop capture on", c.ifName)
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
