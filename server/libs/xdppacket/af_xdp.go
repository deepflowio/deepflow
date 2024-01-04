//go:build linux && xdp
// +build linux,xdp

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

// 对外提供函数接口

import (
	"encoding/hex"
	"fmt"
	"math"
	"net"
	"os"
	"os/signal"
	"runtime"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	. "github.com/google/gopacket"
	logging "github.com/op/go-logging"
	"github.com/pkg/errors"
	"golang.org/x/sys/unix"

	. "github.com/deepflowio/deepflow/server/libs/utils"
)

const (
	objPath  = "xdpsock_kern.o"
	bpffsDir = "/sys/fs/bpf"
)

var ZEROMSG = syscall.Msghdr{}
var ZEROCI = CaptureInfo{}

var log = logging.MustGetLogger("af_xdp")

var ErrPoll = errors.New("packet poll failed")
var ErrTimeout = errors.New("packet poll timeout")

var ErrRxQueueEmpty = errors.New("rx queue is empty")
var ErrTxQueueFull = errors.New("tx queue is full")
var ErrFqQueueFull = errors.New("fq queue is full")
var ErrCqQueueEmpty = errors.New("cq queue is empty")
var ErrTxQueueLessThanBatch = errors.New("tx queue is almost full, less than batch")
var ErrCqQueueLessThanBatch = errors.New("cq queue is almost empty, less than batch")

var ErrWriteFunctionNil = errors.New("write function is nil")
var ErrMultiWriteFunctionNil = errors.New("multiWrite function is nil")
var ErrReadFunctionNil = errors.New("read function is nil")

var ErrSocketClosed = errors.New("the socket is closed")
var ErrSengMsgReWrite = errors.New("need reWrite packet, when EBUSY returned while calling sendmsg")

type XDPStats struct {
	sync.Once
	queueID     uint32
	KernelStats unix.XDPStatistics // xdp提供的内核统计
	Polls       uint64             // 调用poll的次数

	RxPps uint64
	RxBps uint64
	TxPps uint64
	TxBps uint64

	RxEmpty uint64
	TxFull  uint64
	FqFull  uint64
	CqEmpty uint64

	SendBusy  uint64
	SendAgain uint64
}

// 内部收包函数
type readFunc func()

// 内部批量收包函数
type multiReadFunc func()

// 内部发包函数
type writeFunc func(pkt []byte)

// 内部批量发包函数
type multiWriteFunc func(pkt [][]byte) (int, int, error)

type XDPPacket struct {
	options      *XDPOptions // xdp-lib库所有的配置参数
	*XDPStats                // 收发包统计
	*XDPSocket               // 包含socket，interface, 包缓存，rx,tx,rq,cq队列
	progRefCount int32       // 多队列模式下不生效

	// common
	constTs unix.Timespec // 根据pollTimeout设置超时时间
	ts      unix.Timespec // Ppoll参数，每次调用后需reset

	rxErr error
	rxFds []unix.PollFd
	// 内部收包变量, 为了优化性能添加
	read   readFunc
	rxDesc unix.XDPDesc
	rxAddr uint64
	rxPkt  []byte
	ci     CaptureInfo

	// 内部批量收包变量, 为了优化性能添加
	multiRead multiReadFunc
	rxDescs   []unix.XDPDesc
	rxAddrs   []uint64
	rxPkts    [][]byte
	cis       []CaptureInfo
	rxN       int

	txErr error
	txN   int
	txFds []unix.PollFd
	// 内部发包变量, 为了优化性能添加
	write  writeFunc
	txDesc unix.XDPDesc
	txIdx  uint32
	txAddr uint64

	// 内部批量发包变量, 为了优化性能添加
	multiWrite multiWriteFunc
	txDescs    []unix.XDPDesc
	txAddrs    []uint64
	txPktsLen  int
	txPkt      []byte
}

// just for debug
func DumpPacket(pkt []byte) string {
	return fmt.Sprintf("rx one packet(len:%v):\n%s", len(pkt),
		hex.Dump(pkt[:Min(len(pkt), 128)]))
}

func htons(i uint16) uint16 {
	return i<<8 | i>>8
}

func (s *XDPStats) Add(b XDPStats) XDPStats {
	if s == nil {
		return XDPStats{}
	}
	return XDPStats{
		queueID: s.queueID,
		KernelStats: unix.XDPStatistics{
			Rx_dropped:       s.KernelStats.Rx_dropped + b.KernelStats.Rx_dropped,
			Rx_invalid_descs: s.KernelStats.Rx_invalid_descs + b.KernelStats.Rx_invalid_descs,
			Tx_invalid_descs: s.KernelStats.Tx_invalid_descs + b.KernelStats.Tx_invalid_descs,
		},
		Polls: s.Polls + b.Polls,
		RxPps: s.RxPps + b.RxPps,
		RxBps: s.RxBps + b.RxBps,
		TxPps: s.TxPps + b.TxPps,
		TxBps: s.TxBps + b.TxBps,

		RxEmpty:   s.RxEmpty + b.RxEmpty,
		CqEmpty:   s.CqEmpty + b.CqEmpty,
		FqFull:    s.FqFull + b.FqFull,
		TxFull:    s.TxFull + b.TxFull,
		SendBusy:  s.SendBusy + b.SendBusy,
		SendAgain: s.SendAgain + b.SendAgain,
	}
}

func (s *XDPStats) Minus(b XDPStats) XDPStats {
	if s == nil {
		return XDPStats{}
	}
	return XDPStats{
		queueID: s.queueID,
		KernelStats: unix.XDPStatistics{
			Rx_dropped:       s.KernelStats.Rx_dropped - b.KernelStats.Rx_dropped,
			Rx_invalid_descs: s.KernelStats.Rx_invalid_descs - b.KernelStats.Rx_invalid_descs,
			Tx_invalid_descs: s.KernelStats.Tx_invalid_descs - b.KernelStats.Tx_invalid_descs,
		},
		Polls: s.Polls - b.Polls,
		RxPps: s.RxPps - b.RxPps,
		RxBps: s.RxBps - b.RxBps,
		TxPps: s.TxPps - b.TxPps,
		TxBps: s.TxBps - b.TxBps,

		RxEmpty:   s.RxEmpty - b.RxEmpty,
		CqEmpty:   s.CqEmpty - b.CqEmpty,
		FqFull:    s.FqFull - b.FqFull,
		TxFull:    s.TxFull - b.TxFull,
		SendBusy:  s.SendBusy - b.SendBusy,
		SendAgain: s.SendAgain - b.SendAgain,
	}
}

func (s XDPStats) String() string {
	var titile string
	s.Do(func() {
		titile = fmt.Sprintf("%12s %12s %12s %12s %13s %4s %12s %12s %12s %4s %12s %12s %12s %12s %12s %12s %12s\n",
			"QID", "RX-BPS", "RX-PPS", "RX-Drop", "RX-INVAL_DESC",
			"||", "TX-BPS", "TX-PPS", "TX-ERR",
			"||", "RX-EMPTY", "FQ-FULL", "TX-FULL", "CQ-EMPTY", "SEND-BUSY", "SEND-AGAIN", "POLL-TIMES")
	})

	stats := fmt.Sprintf("%12d %12d %12d %12d %13d %4s %12d %12d %12d %4s %12d %12d %12d %12d %12d %12d %12d\n",
		s.queueID, s.RxBps, s.RxPps, s.KernelStats.Rx_dropped, s.KernelStats.Rx_invalid_descs,
		"||", s.TxBps, s.TxPps, s.KernelStats.Tx_invalid_descs,
		"||", s.RxEmpty, s.FqFull, s.TxFull, s.CqEmpty, s.SendBusy, s.SendAgain, s.Polls)

	return fmt.Sprintf("%v%v", titile, stats)
}

func (x *XDPPacket) readMultiPackets() {
	x.rxN = int(x.rx.dequeue(x.rxDescs, uint32(x.options.batchSize)))
	if x.rxN < 1 {
		x.RxEmpty++
		x.rxErr = ErrRxQueueEmpty
		return
	}
	x.rxErr = nil

	for i := 0; i < x.rxN; i++ {
		x.rxDesc = x.rxDescs[i]
		x.rxPkts = append(x.rxPkts, x.framesBulk[x.rxDesc.Addr:x.rxDesc.Addr+uint64(x.rxDesc.Len)])
		x.rxAddrs = append(x.rxAddrs, x.rxDesc.Addr)
	}
}

// 非阻塞模式的收包函数
func (x *XDPPacket) nonblockMultiRead() {
	x.rxErr = x.poll(x.rxFds)
	if x.rxErr != nil {
		return
	}

	x.readMultiPackets()
}

// 阻塞模式的收包函数
func (x *XDPPacket) blockMultiRead() {
retry:
	x.readMultiPackets()
	if x.rxErr != nil {
		goto retry
	}
}

// 混合模式的收包函数
func (x *XDPPacket) mixMultiRead() {
	if x.rxErr == ErrRxQueueEmpty {
		x.rxErr = x.poll(x.rxFds)
		if x.rxErr != nil {
			return
		}
	}

	x.readMultiPackets()
}

func (x *XDPPacket) releaseMultiPackets() error {
	if x.rxN > 0 {
	retry:
		x.rxErr = x.fq.enqueue(x.rxAddrs, uint32(x.rxN))
		if x.rxErr != nil {
			x.FqFull++
			goto retry
		}
	}
	x.rxN = 0
	x.rxAddrs = x.rxAddrs[:0]
	x.rxPkts = x.rxPkts[:0]
	x.cis = x.cis[:cap(x.cis)]
	return nil
}

// 收包接口，零拷贝, 每次尽最大努力收包，最多一次收16个包
// 函数返回后，请使用len([]CaptureInfo)获取读到的包数
func (x *XDPPacket) ZeroCopyReadMultiPackets() ([][]byte, []CaptureInfo, error) {
	if x.CheckIfXDPSocketClosed() {
		return nil, nil, ErrSocketClosed
	}

	x.releaseMultiPackets()

	x.multiRead()
	if x.rxErr == nil {
		totalBytes := uint32(0)
		x.ci.Timestamp = time.Now()
		for i := 0; i < x.rxN; i++ {
			x.rxDesc = x.rxDescs[i]
			totalBytes += x.rxDesc.Len
			x.cis[i].Timestamp = x.ci.Timestamp
			x.cis[i].CaptureLength = int(x.rxDesc.Len)
		}
		x.cis = x.cis[:x.rxN]
		x.RxPps += uint64(x.rxN)
		x.RxBps += uint64(totalBytes)
	}

	return x.rxPkts, x.cis, x.rxErr
}

// 从rx队列读取一个包
// 流程 enqueue fq --- dequeue rx --- read packet
func (x *XDPPacket) readOnePacket() {
	// 将前一个包的地址放回fq队列，供内核使用
	// 初始时，无地址可放, 故将x.rxAddr设为math.MaxUint64
	if x.rxAddr != math.MaxUint64 {
	retry:
		x.rxErr = x.fq.enqueueOne(x.rxAddr)
		// x.rxAddr已放回，下次无需重放
		if x.rxErr == nil {
			x.rxAddr = math.MaxUint64
		} else {
			// 如果fq队列满，则返回，x.rxAddr未改变
			x.FqFull++
			goto retry
		}
	}

	// 如果rx队列为空，则返回，x.rxAddr已重置
	if x.rx.dequeueOne(&x.rxDesc) < 1 {
		x.RxEmpty++
		x.rxErr = ErrRxQueueEmpty
		return
	}

	// 成功获取包描述后，更新x.rxAddr，并返回包数据
	x.rxAddr = x.rxDesc.Addr
	x.rxPkt = x.framesBulk[x.rxAddr : x.rxAddr+uint64(x.rxDesc.Len)]
	x.rxErr = nil
	return
}

func (x *XDPPacket) poll(fds []unix.PollFd) error {
retry:
	x.ts = x.constTs
	n, err := unix.Ppoll(fds, &x.ts, nil)
	x.Polls++
	if n > 0 {
		if fds[0].Revents&unix.POLLERR > 0 {
			return ErrPoll
		}
		return nil
	}
	if n == 0 {
		return ErrTimeout
	}

	if err == syscall.EINTR {
		goto retry
	}
	return err
}

// 非阻塞模式的收包函数
func (x *XDPPacket) nonblockReadPacket() {
	x.rxErr = x.poll(x.rxFds)
	if x.rxErr == nil {
		x.readOnePacket()
	}
}

// 阻塞模式的收包函数
func (x *XDPPacket) blockReadPacket() {
retry:
	x.readOnePacket()
	// readOnePacket仅产生ErrFqQueueFull, ErrRxQueueEmpty这2种错误
	// 收包失败后，一直重试，直到收包成功
	if x.rxErr != nil {
		goto retry
	}
}

// 混合模式的收包函数
func (x *XDPPacket) mixReadPacket() {
	if x.rxErr == ErrRxQueueEmpty {
		x.rxErr = x.poll(x.rxFds)
		if x.rxErr != nil {
			return
		}
	}
	x.readOnePacket()
}

// 收包接口，零拷贝
// 当error不为nil时，返回值中slice，CaptureInfo不可用
func (x *XDPPacket) ZeroCopyReadPacket() ([]byte, CaptureInfo, error) {
	if x.CheckIfXDPSocketClosed() {
		return nil, x.ci, ErrSocketClosed
	}

	x.read()
	// 收包成功后，给包打时间戳，并增加收包统计
	if x.rxErr == nil {
		x.RxPps++
		x.RxBps += uint64(len(x.rxPkt))
		x.ci.CaptureLength = int(x.rxDesc.Len)
		x.ci.Timestamp = time.Now()
	}
	// 打开debug将极大的降低收包性能
	// log.Debug(DumpPacket(rxPkt))

	return x.rxPkt, x.ci, x.rxErr
}

// 收包接口，内部有一次包拷贝, 如果len(data)小于包长，则ci.CaptureLength=len(data)
func (x *XDPPacket) ReadPacket(data []byte) (CaptureInfo, error) {
	if data == nil {
		return x.ci, errors.New("parameter is nil")
	}

	d, ci, err := x.ZeroCopyReadPacket()
	if err != nil {
		return ci, err
	}

	n := copy(data, d)
	ci.CaptureLength = n

	return ci, nil
}

// 实现sendmsg系统调用
func sendmsg(s int) (n int, err error) {
	if s < 0 {
		return 0, fmt.Errorf("error sockFd %v", s)
	}
	r0, _, e1 := syscall.Syscall(syscall.SYS_SENDMSG, uintptr(s),
		uintptr(unsafe.Pointer(&ZEROMSG)), uintptr(unix.MSG_DONTWAIT))

	n = int(r0)
	if e1 != 0 {
		err = error(e1)
	}
	return
}

func (x *XDPPacket) sendmsg() error {
retry:
	_, x.txErr = sendmsg(x.sockFd)

	if x.txErr == syscall.EAGAIN {
		x.SendAgain++
		goto retry
	} else if x.txErr == syscall.EBUSY {
		// 虚拟机SKB模式出现发包缓慢
		x.SendBusy++
		x.txErr = ErrSengMsgReWrite
	}
	return x.txErr
}

// 将包copy到指定的umem block;然后调用sendmsg将包从网卡发送出去
func (x *XDPPacket) writeOnePacketToKernel(pkt []byte) {
	x.txErr = x.tx.enqueueOne(x.txDesc)
	// 如果tx队列满，则停止发送
	if x.txErr != nil {
		x.TxFull++
		return
	}

	copy(x.framesBulk[x.txDesc.Addr:], pkt)
	x.sendmsg()
}

// 流程 dequeue cq --- enqueue tx --- copy --- sendmsg
// 发送单个包
func (x *XDPPacket) writeOnePacket(pkt []byte) {
reWrite:
	// 初始时，cq,tx队列为空, 无法从cq队列获取umem block为空的地址；
	// 但可认为umem 前ringSize个block均可用。
	// 因此, 前ringSize次发送，可依次使用umem的block
	if x.txIdx < x.options.ringSize {
		x.txDesc.Addr = uint64(x.txIdx&x.tx.mask) << x.options.frameShift
		x.txIdx++
	} else {
		// 之后，需每次从cq队列获取umem block地址
		// 如果cq队列为空，则停止发送
		x.cq.dequeueOne(&x.txAddr)
		if x.cq.entries < 1 {
			x.CqEmpty++
			x.txErr = ErrCqQueueEmpty
			return
		}
		x.txDesc.Addr = x.txAddr
	}
	x.txDesc.Len = uint32(len(pkt))

	x.writeOnePacketToKernel(pkt)
	if x.txErr == ErrSengMsgReWrite {
		goto reWrite
	}
}

// 阻塞模式的发包函数
func (x *XDPPacket) blockWrite(pkt []byte) {
retry:
	x.writeOnePacket(pkt)
	if x.txErr == nil {
		return
	} else if x.txErr == ErrCqQueueEmpty {
		goto retry
	} else if x.txErr == ErrTxQueueFull {
		goto retry
	}
}

// 非阻塞模式的发包函数
func (x *XDPPacket) nonblockWrite(pkt []byte) {
	if x.txErr = x.poll(x.txFds); x.txErr == nil {
		x.writeOnePacket(pkt)
	}
}

// 混合模式的发包函数
func (x *XDPPacket) mixWrite(pkt []byte) {
	if x.txErr != nil {
		x.txErr = x.poll(x.txFds)
		if x.txErr != nil {
			return
		}
	}
	x.writeOnePacket(pkt)
}

// 发单包接口
func (x *XDPPacket) WritePacket(pkt []byte) error {
	if x.CheckIfXDPSocketClosed() {
		return ErrSocketClosed
	}

	x.write(pkt)
	if x.txErr == nil {
		x.TxPps++
		x.TxBps += uint64(len(pkt))
	}

	return x.txErr
}

// 内部批量发送函数，每次发送batchSize个包
func (x *XDPPacket) writeMultiPacket(pkts [][]byte) (int, int, error) {
	// 因当sendmsg调用失败后，无法确认是哪个包发送失败，
	// 故为了保证发包的准确性，无法做到调一次sendmsg发送多个包
	x.txPktsLen = 0
	for x.txN, x.txPkt = range pkts {
		x.writeOnePacket(x.txPkt)
		if x.txErr != nil {
			return x.txN, x.txPktsLen, x.txErr
		}
		x.txPktsLen += len(x.txPkt)
	}
	return x.txN + 1, x.txPktsLen, x.txErr
}

// 阻塞模式的批量发包函数
func (x *XDPPacket) blockMultiWrite(pkts [][]byte) (int, int, error) {
retry:
	nPkt, nByte, err := x.writeMultiPacket(pkts)
	if err != nil && err != ErrCqQueueLessThanBatch {
		goto retry
	}
	return nPkt, nByte, err
}

// 非阻塞模式的批量发包函数
func (x *XDPPacket) nonblockMultiWrite(pkts [][]byte) (int, int, error) {
	err := x.poll(x.txFds)
	if err != nil {
		return 0, 0, err
	}

	return x.writeMultiPacket(pkts)
}

// 混合模式的发包函数
func (x *XDPPacket) mixMultiWrite(pkts [][]byte) (int, int, error) {
	if x.txErr != nil {
		x.txErr = x.poll(x.txFds)
		if x.txErr != nil {
			return 0, 0, x.txErr
		}
	}
	return x.writeMultiPacket(pkts)
}

// 批量发包接口,
func (x *XDPPacket) WriteMultiPackets(pkts [][]byte) (int, error) {
	if x.CheckIfXDPSocketClosed() {
		return 0, ErrSocketClosed
	}

	x.multiWrite(pkts)
	if x.txErr == nil {
		x.txN++
		x.TxPps += uint64(x.txN)
		x.TxBps += uint64(x.txPktsLen)
	}

	return x.txN, x.txErr
}

func initXDPPacket(ifIndex int, options *XDPOptions, queueId int) (*XDPPacket, error) {
	socket, err := newXDPSocket(ifIndex, options, queueId)
	if err != nil {
		return nil, err
	}

	rxFds := []unix.PollFd{
		unix.PollFd{
			Fd:     int32(socket.sockFd),
			Events: unix.POLLIN,
		},
	}
	txFds := []unix.PollFd{
		unix.PollFd{
			Fd:     int32(socket.sockFd),
			Events: unix.POLLOUT,
		},
	}

	xdp := &XDPPacket{
		options:   options,
		XDPSocket: socket,
		XDPStats:  &XDPStats{queueID: options.queueID},
		ci:        CaptureInfo{InterfaceIndex: ifIndex},

		rxFds:   rxFds,
		txFds:   txFds,
		txDescs: make([]unix.XDPDesc, options.batchSize),
		txAddrs: make([]uint64, options.batchSize),

		rxAddr:  math.MaxUint64,
		rxDescs: make([]unix.XDPDesc, options.batchSize),
		rxAddrs: make([]uint64, options.batchSize),
		rxPkts:  make([][]byte, options.batchSize),
		cis:     make([]CaptureInfo, options.batchSize),

		constTs: unix.Timespec{
			Sec:  int64(options.pollTimeout / time.Second),
			Nsec: int64(options.pollTimeout % time.Second)},
	}
	log.Debugf("poll timeout setting is %v", xdp.constTs)

	if xdp.options.ioMode == IO_MODE_POLL {
		xdp.read = xdp.nonblockReadPacket
		xdp.multiRead = xdp.nonblockMultiRead
		xdp.write = xdp.nonblockWrite
		xdp.multiWrite = xdp.nonblockMultiWrite
	} else if xdp.options.ioMode == IO_MODE_NONPOLL {
		xdp.read = xdp.blockReadPacket
		xdp.multiRead = xdp.blockMultiRead
		xdp.write = xdp.blockWrite
		xdp.multiWrite = xdp.blockMultiWrite
	} else {
		xdp.read = xdp.mixReadPacket
		xdp.multiRead = xdp.mixMultiRead
		xdp.write = xdp.mixWrite
		xdp.multiWrite = xdp.mixMultiWrite
	}

	log.Debugf("a new xdp packet %v", xdp)
	return xdp, nil
}

func NewXDPPacket(name string, opts ...interface{}) (*XDPPacket, error) {
	var config *IfaceConfig = nil
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return nil, fmt.Errorf("error Interface Name(%s) as %v", name, err)
	}

	options := &defaultOpt
	if len(opts) > 0 {
		options, err = parseOptions(opts...)
		if err != nil {
			return nil, err
		}
	}
	log.Debugf("XDPOptions:\n%v", options)

	loadProg := true
	exist, err := CheckAndInitIfaceConfigFile(iface.Index)
	if err != nil {
		return nil, err
	}

	if !exist {
		// 如果无网卡XDP config文件, 初始化XDP运行环境
		err = initXDPRunningEnv(name, options.xdpMode)
		if err != nil {
			return nil, err
		}
	} else {
		loadProg = false
		// 否则获取网卡XDP config
		config, err = GetAndCheckIfaceConfig(iface.Index, int(options.queueID))
		if err != nil {
			return nil, err
		}
		log.Debugf("interface %v(queueID:%v) xdp current config is:\n%v", name, options.queueID, config)
	}

	xdp, err := initXDPPacket(iface.Index, options, int(options.queueID))
	if err != nil {
		return nil, err
	}

	if loadProg == false {
		xdp.progFd = config.BpfFd
		xdp.xsksMapFd = config.MapFd
	}

	err = xdp.initXDPSocket(loadProg)
	if err != nil {
		xdp.Close()
		return nil, err
	}

	if config == nil || config.UsedQueueCount < xdp.options.queueCount {
		err = xdp.setInterfaceRecvQueues()
		if err != nil {
			xdp.Close()
			return nil, err
		}
	}

	if config == nil {
		config = &IfaceConfig{
			IfIndex: iface.Index,
			MapFd:   xdp.xsksMapFd,
			BpfFd:   xdp.progFd,

			UsedQueueCount: options.queueCount,
		}
	} else {
		config.UsedQueueCount = options.queueCount
	}

	curConfig, err := UpdateIfaceConfig(config, int(options.queueID))
	if err != nil {
		xdp.Close()
		return nil, err
	}
	log.Debugf("current interface (%s) config: %#v", name, curConfig)

	atomic.AddInt32(&xdp.progRefCount, 1)

	log.Infof("a usable XDPPacket %v", xdp)
	return xdp, nil
}

func (x *XDPPacket) setInterfaceRecvQueues() error {
	if x.options.xdpMode == XDP_MODE_SKB {
		n := uint32(runtime.NumCPU())
		log.Infof("the number of current host's CPU is %v", n)
		// 目前测试发现，vSphere虚拟机网卡收包队列数等于CPU核数
		if x.options.queueCount > n {
			return fmt.Errorf("interface queue count(%v) more than cpu count(%v) in vSphere vHost",
				x.options.queueCount, n)
		}
		if n == 1 {
			return nil
		}
	}
	return setInterfaceRecvQueues(x.ifIndex, x.options.queueCount)
}

func (x *XDPPacket) GetStats() XDPStats {
	stats := XDPStats{}
	if x == nil || x.sockFd < 0 {
		return stats
	}

	kStats, err := getOptXDPStats(x.sockFd)
	if err != nil {
		log.Warning("get XDP socket kernel statistics failed")
		return stats
	}

	stats = *x.XDPStats
	stats.KernelStats = *kStats

	return stats
}

// 创建xdp-socket后，需主动调用Close
// 释放xdp-socket资源
func (x *XDPPacket) Close() {
	if x == nil {
		return
	}
	log.Debug("closing xdppacket !!")

	DeleteIfaceQueue(x.ifIndex, int(x.options.queueID))

	x.close()

	if atomic.LoadInt32(&x.progRefCount) > 0 {
		atomic.AddInt32(&x.progRefCount, -1)
	}
	// 清除ebpf program
	if atomic.LoadInt32(&x.progRefCount) == 0 {
		x.clearResource()
		// 删除config文件
		DeleteIfaceConfig(x.ifIndex)
	}
}

// 信号处理，SIGKILL貌似无法捕获
func (x *XDPPacket) ClearEbpfProg() {
	if x == nil {
		return
	}

	signalChannel := make(chan os.Signal, 3)
	signal.Notify(signalChannel, syscall.SIGTERM, syscall.SIGKILL, syscall.SIGINT)
	sig := <-signalChannel
	log.Debugf("catch signal: %v", sig)
	x.Close()
}

func (x *XDPPacket) String() string {
	return fmt.Sprintf("\n%v%v\n"+
		"readFunc:%v, writeFunc:%v\n"+
		"rxAddr:0x%x, txIdx:%v, txAddr:0x%x\n"+
		"multiWriteFunc:%v, multiReadFunc:%v\n"+
		"stats-queueID:%v",
		x.options, x.XDPSocket,
		x.read, x.write,
		x.rxAddr, x.txIdx, x.txAddr,
		x.multiWrite, x.multiRead,
		x.queueID)
}

// 清除网卡上残留的XDP资源(map, prog, 配置文件)
func ClearIfaceResidueXDPResources(ifName string) error {
	iface, err := net.InterfaceByName(ifName)
	if err != nil {
		return fmt.Errorf("clear interface(%v)'s residue XDP resources failed as %v", ifName, err)
	}

	if CheckIfaceConfigFileExist(iface.Index) {
		_, err = DeleteIfaceConfig(iface.Index)
		if err != nil {
			return fmt.Errorf("clear interface(%v)'s residue XDP resources failed as %v", ifName, err)
		}
	}

	cmdString := fmt.Sprintf("ip link show %s | head -1 | grep -o 'xdp[a-z]*'", ifName)
	mode, err := executeCommand(cmdString)
	if err != nil {
		return fmt.Errorf("clear interface(%v)'s residue XDP resources failed as %v", ifName, err)
	}
	if mode != "" {
		cmdString = fmt.Sprintf("ip link set %s down; ip link set %s %s off; ip link set %s up", ifName, ifName, mode, ifName)
		if err != nil {
			return fmt.Errorf("clear interface(%v)'s residue XDP resources failed as %v", ifName, err)
		}
	}

	return nil
}
