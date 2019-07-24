// +build linux,xdp

package xdppacket

import (
	"fmt"
	"time"

	"golang.org/x/sys/unix"
)

type OptNumFrames uint32
type OptRingSize uint32
type OptXDPMode uint16

type OptQueueCount uint32
type OptPollTimeout time.Duration
type OptIoMode uint32

type XDPOptions struct {
	// rx,tx,fill,complete queues have same queue size and must be power of 2
	ringSize uint32
	// 包缓存大小
	numFrames uint32
	// 不可修改，暂定为2048
	frameSize uint32 // it must be power of 2, kernel limit 2048 or 4096
	// zerocopy需网卡支持
	xdpMode OptXDPMode // copy or zerocopy

	// 指定从网卡哪几个队列收包, 取前n个队列[0-queueCount)
	queueCount  uint32
	pollTimeout time.Duration // only valid when ioMode is IO_MODE_NONBLOCK
	ioMode      OptIoMode     // block or poll

	frameShift    uint32 // frameSize = 1<<frameShift
	frameMask     uint32 // 包大小的掩码
	frameHeadroom uint32 // reserved
	batchSize     int    // 批量发送时，每次发送的包数量
}

const (
	XDP_MODE_DRV OptXDPMode = unix.XDP_FLAGS_DRV_MODE
	XDP_MODE_SKB OptXDPMode = unix.XDP_FLAGS_SKB_MODE

	IO_MODE_BLOCK OptIoMode = iota
	IO_MODE_NONBLOCK

	MAX_QUEUE_COUNT = 64
)

const (
	DFLT_RING_SIZE  = 1024 // 默认队列大小：1024
	DFLT_NUM_FRAMES = 1024 // 默认包缓存大小：1024
	DFLT_FRAME_SIZE = 2048 // 默认包大小：2048B

	DFLT_IO_MODE      = IO_MODE_BLOCK          // 默认采用轮询模式收发包
	DFLT_XDP_MODE     = XDP_MODE_DRV           // 默认XDP采用NATIVE模式
	DFLT_POLL_TIMEOUT = 100 * time.Millisecond // 默认非阻塞IO时的poll超时：100us

	DFLT_QUEUE_COUNT    = 1  // 默认在网卡0号队列收包
	DFLT_FRAME_HEADROOM = 0  // 保留
	DFLT_BATCH_SIZE     = 16 // 默认批量发送包数量：16
)

var defaultOpt = XDPOptions{
	numFrames: DFLT_NUM_FRAMES,
	frameSize: DFLT_FRAME_SIZE,
	ringSize:  DFLT_RING_SIZE,
	xdpMode:   DFLT_XDP_MODE,

	queueCount:  DFLT_QUEUE_COUNT,
	pollTimeout: DFLT_POLL_TIMEOUT,
	ioMode:      DFLT_IO_MODE,

	frameShift: getFrameShift(DFLT_FRAME_SIZE),

	frameMask:     DFLT_FRAME_SIZE - 1,
	frameHeadroom: DFLT_FRAME_HEADROOM,
	batchSize:     DFLT_BATCH_SIZE,
}

func isPowerOfTwo(n uint32) bool {
	return (n != 0 && (n&(n-1)) == 0)
}

func getMSB(n uint32) uint32 {
	var i uint32
	for i = uint32(31); i >= 0; i-- {
		if n&(1<<i) != 0 {
			break
		}
	}
	return i
}

func getFrameShift(frameSize uint32) uint32 {
	return getMSB(frameSize)
}

func parseOptions(options ...interface{}) (*XDPOptions, error) {
	option := defaultOpt
	for _, opt := range options {
		switch v := opt.(type) {
		case OptNumFrames:
			option.numFrames = uint32(v)
		case OptRingSize:
			option.ringSize = uint32(v)
		case OptXDPMode:
			option.xdpMode = v
		case OptQueueCount:
			option.queueCount = uint32(v)
		case OptPollTimeout:
			option.pollTimeout = time.Duration(v)
		case OptIoMode:
			option.ioMode = v
		default:
			return nil, fmt.Errorf("unknown option(%v)", opt)
		}
	}

	err := option.check()
	if err != nil {
		return nil, err
	}
	return &option, nil
}

func (o *XDPOptions) check() error {
	switch {
	case o.numFrames&0x1 != 0:
		return fmt.Errorf("num frames(%d) must be even number", o.numFrames)
	case !isPowerOfTwo(o.ringSize):
		return fmt.Errorf("ring size(%d) must be power of 2", o.ringSize)
	case o.xdpMode != XDP_MODE_SKB && o.xdpMode != XDP_MODE_DRV:
		return fmt.Errorf("xdp mode(%d) must be \"XDP_MODE_DRV\" or \"XDP_MODE_SKB\"",
			o.xdpMode)
	case o.ioMode != IO_MODE_NONBLOCK && o.ioMode != IO_MODE_BLOCK:
		return fmt.Errorf("I/O mode(%d) must be ", o.ioMode)
	case o.ioMode == IO_MODE_NONBLOCK && o.pollTimeout < time.Millisecond:
		return fmt.Errorf("poll timeout(%d) must be greater or eqaul than %v", o.pollTimeout, time.Millisecond)
	case o.queueCount > MAX_QUEUE_COUNT:
		return fmt.Errorf("queueCount(%d) must be less or eqaul than %v", o.queueCount, MAX_QUEUE_COUNT)
	}

	if o.ringSize > o.numFrames {
		return fmt.Errorf("ring size(%v) must not greater than number of frames(%v)",
			o.ringSize, o.numFrames)
	}

	return nil
}

func (m OptXDPMode) String() string {
	var str string
	if m == XDP_MODE_DRV {
		str = fmt.Sprintf("XDP_DRV_MODE")
	} else if m == XDP_MODE_SKB {
		str = fmt.Sprintf("XDP_SKB_MODE")
	}
	return str
}

func (t OptPollTimeout) String() string {
	return t.String()
}

func (m OptIoMode) String() string {
	var str string
	if m == IO_MODE_BLOCK {
		str = fmt.Sprintf("BLOCK")
	} else if m == IO_MODE_NONBLOCK {
		str = fmt.Sprintf("NONBLOCK")
	}
	return str
}

func (o XDPOptions) String() string {
	return fmt.Sprintf("XDPOptions:\n\tringSize:%v, numFrames:%v, frameSize:%v, "+
		"xdpMode:%v, queueCount:%v, pollTimeout:%v, ioMode:%v, frameMask:%v, frameHeadroom:%v, "+
		"batchSize:%v", o.ringSize, o.numFrames, o.frameSize, o.xdpMode, o.queueCount,
		o.pollTimeout, o.ioMode, o.frameMask, o.frameHeadroom, o.batchSize)
}
