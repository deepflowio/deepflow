//go:build linux
// +build linux

/*
 * Copyright (c) 2024 Yunshan Networks
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

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
type OptQueueID uint32
type OptPollTimeout time.Duration
type OptIoMode uint32

type XDPOptions struct {
	// rx,tx,fill,complete queues have same queue size and must be power of 2
	ringSize uint32
	// 包缓存大小
	numFrames uint32
	// 不可修改，4096, it must be power of 2, kernel limit 2048 or 4096
	frameSize uint32
	// drv or skb, drv需网卡支持
	xdpMode OptXDPMode

	// 指定从网卡哪几个队列收包, 取前n个队列[0-queueCount)
	queueCount uint32
	// 当前队列ID
	queueID uint32
	// only valid when ioMode is IO_MODE_POLL
	pollTimeout time.Duration
	ioMode      OptIoMode

	// frameSize = 1<<frameShift
	frameShift uint32
	// 包大小的掩码
	frameMask uint32
	// reserved
	frameHeadroom uint32
	// 批量发送时，每次发送的包数量
	batchSize uint32
}

const (
	IO_MODE_NONPOLL OptIoMode = iota
	IO_MODE_POLL
	IO_MODE_MIX

	XDP_MODE_DRV OptXDPMode = unix.XDP_FLAGS_DRV_MODE
	XDP_MODE_SKB OptXDPMode = unix.XDP_FLAGS_SKB_MODE

	MAX_QUEUE_COUNT = 64
)

const (
	// 默认队列大小：1024
	DFLT_RING_SIZE = 1024
	// 默认包缓存大小：1024; 不宜过大，可能导致无法分配足够内存
	DFLT_NUM_FRAMES = 1024
	// 默认包大小：2048B, 否则会导致无法处理超过1024B的包
	// 参考：http://github.com/hpn/linux-kernel/wikis/xdp-zc-排查1400的数据包没有接收的问题
	DFLT_FRAME_SIZE = 4096
	// 内核网卡驱动headroom大小
	DFLT_KERNEL_FRAME_HEADROOM = 256
	// 实际最大可收发包大小
	DFLT_ACTUAL_FRAME_SIZE_MAX = DFLT_FRAME_SIZE - DFLT_KERNEL_FRAME_HEADROOM

	// 默认采用轮询模式收发包
	DFLT_IO_MODE = IO_MODE_NONPOLL
	// 默认XDP采用NATIVE模式
	DFLT_XDP_MODE = XDP_MODE_DRV
	// 默认非阻塞IO时的poll超时：1ms
	DFLT_POLL_TIMEOUT = 1 * time.Millisecond

	// 默认仅使用1个队列收或发所有流量
	DFLT_QUEUE_COUNT = 1
	// 默认在网卡0号队列收包
	DFLT_QUEUE_ID = 0
	// 保留
	DFLT_FRAME_HEADROOM = 0
	// 默认批量发送包数量：16
	DFLT_BATCH_SIZE = 16
)

var defaultOpt = XDPOptions{
	numFrames: DFLT_NUM_FRAMES,
	frameSize: DFLT_FRAME_SIZE,
	ringSize:  DFLT_RING_SIZE,
	xdpMode:   DFLT_XDP_MODE,

	queueCount:  DFLT_QUEUE_COUNT,
	queueID:     DFLT_QUEUE_ID,
	pollTimeout: DFLT_POLL_TIMEOUT,
	ioMode:      DFLT_IO_MODE,

	frameShift:    getFrameShift(DFLT_FRAME_SIZE),
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
			option.ringSize = option.numFrames
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
		case OptQueueID:
			option.queueID = uint32(v)
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
		return fmt.Errorf("xdp mode(%d) must be %d or %d",
			o.xdpMode, XDP_MODE_DRV, XDP_MODE_SKB)
	case o.ioMode > IO_MODE_MIX || o.ioMode < IO_MODE_NONPOLL:
		return fmt.Errorf("I/O mode(%d) must be in range of [%d, %d]", o.ioMode,
			IO_MODE_NONPOLL, IO_MODE_MIX)
	case o.ioMode != IO_MODE_NONPOLL && o.pollTimeout < time.Millisecond:
		return fmt.Errorf("poll timeout(%d) must be greater or eqaul than %v",
			o.pollTimeout, time.Millisecond)
	case o.queueCount > MAX_QUEUE_COUNT:
		return fmt.Errorf("queueCount(%d) must be less or eqaul than %v", o.queueCount, MAX_QUEUE_COUNT)
	case o.queueID >= o.queueCount:
		return fmt.Errorf("queueID(%d) must be less than queueCount(%d)", o.queueID, o.queueCount)
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

func (m OptIoMode) String() string {
	var str string
	if m == IO_MODE_NONPOLL {
		str = fmt.Sprintf("NONPOLL")
	} else if m == IO_MODE_POLL {
		str = fmt.Sprintf("POLL")
	} else if m == IO_MODE_MIX {
		str = fmt.Sprintf("MIX")
	} else {
		str = fmt.Sprintf("error XDP I/O mode")
	}
	return str
}

func (o XDPOptions) String() string {
	return fmt.Sprintf("XDPOptions:\n\tringSize:%v, numFrames:%v, frameSize:%v, "+
		"xdpMode:%v, queueCount:%v, queueID:%v, pollTimeout:%v, ioMode:%v, frameMask:%v, frameHeadroom:%v, "+
		"batchSize:%v", o.ringSize, o.numFrames, o.frameSize, o.xdpMode, o.queueCount, o.queueID,
		o.pollTimeout, o.ioMode, o.frameMask, o.frameHeadroom, o.batchSize)
}
