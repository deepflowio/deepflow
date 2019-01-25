package capture

import (
	"errors"
	"syscall"
	"time"

	"github.com/google/gopacket/afpacket"
	"github.com/op/go-logging"
)

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
	max := func(x, y uint) uint {
		if x > y {
			return x
		} else {
			return y
		}
	}
	counter.KernelPackets = max(socketStatsV3.Packets(), socketStats.Packets())
	counter.KernelDrops = max(socketStatsV3.Drops(), socketStats.Drops())
	counter.KernelFreezes = uint(socketStatsV3.QueueFreezes())

	if counter.pollError > 0 {
		log.Warningf("Poll error %d times, last err: %s", counter.pollError, c.lastPollErr.Error())
	}
	if counter.intrError > 0 {
		log.Warningf("INTR error %d times, last err: %s", counter.intrError, c.lastIntrErr.Error())
	}

	log.Debugf(
		"#rx: %c #err: %c #k_packets: %c #k_drops: %c #k_freezed: %c",
		counter.Rx, counter.Err, counter.KernelPackets, counter.KernelDrops, counter.KernelFreezes,
	)
	return counter
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
		if timestamp < prevTimestamp-time.Millisecond { // FIXME: just in case
			c.counter.Retired++
			continue
		}
		if timestamp < prevTimestamp {
			timestamp = prevTimestamp
		}
		prevTimestamp = timestamp

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
	c.tPacket = nil
	return nil
}

func (c *Capture) Closed() bool {
	return c.tPacket == nil
}
