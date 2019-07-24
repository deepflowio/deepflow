// +build linux,xdp

package xdppacket

// 对外提供函数接口

import (
	"encoding/hex"
	"fmt"
	"math"
	"net"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	. "github.com/google/gopacket"
	logging "github.com/op/go-logging"
	"github.com/pkg/errors"
	. "gitlab.x.lan/yunshan/droplet-libs/utils"
	"golang.org/x/sys/unix"
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

type XDPStats struct {
	sync.Once
	kernelStats unix.XDPStatistics // xdp提供的内核统计
	polls       uint64             // 调用poll的次数

	rxPps uint64
	rxBps uint64
	txPps uint64
	txBps uint64

	rxEmpty  uint64
	txFull   uint64
	fqFull   uint64
	cqEmpty  uint64
	sendBusy uint64
}

// 内部收包函数
type readFunc func(x *XDPPacket) ([]byte, error)

// 内部发包函数
type writeFunc func(x *XDPPacket, pkt []byte) error

// 内部批量发包函数
type multiWriteFunc func(x *XDPPacket, pkt [][]byte) (int, int, error)

// 内部批量收包函数
type multiReadFunc func(x *XDPPacket) (int, error)

type XDPPacket struct {
	options      *XDPOptions // xdp-lib库所有的配置参数
	*XDPStats                // 收发包统计
	*XDPSocket               // 包含socket，interface, 包缓存，rx,tx,rq,cq队列
	progRefCount int32       // 多队列模式下不生效

	// 内部收包变量, 为了优化性能添加
	read   readFunc
	rxFds  []unix.PollFd
	rxDesc unix.XDPDesc
	rxAddr uint64
	ci     CaptureInfo

	// 内部发包变量, 为了优化性能添加
	write  writeFunc
	txFds  []unix.PollFd
	txDesc unix.XDPDesc
	txIdx  uint64
	txAddr uint64

	// 内部批量发包变量, 为了优化性能添加
	multiWrite multiWriteFunc
	txDescs    []unix.XDPDesc
	txAddrs    []uint64

	// 内部批量收包变量, 为了优化性能添加
	multiRead multiReadFunc
	rxDescs   []unix.XDPDesc
	rxAddrs   []uint64
	packets   [][]byte
	cis       []CaptureInfo
}

// just for debug
func dumpPacket(pkt []byte) string {
	return fmt.Sprintf("rx one packet(len:%v):\n%s", len(pkt),
		hex.Dump(pkt[:Min(len(pkt), 128)]))
}

func htons(i uint16) uint16 {
	return i<<8 | i>>8
}

func (s *XDPStats) Add(b *XDPStats) *XDPStats {
	if s == nil || b == nil {
		return &XDPStats{}
	}
	return &XDPStats{
		kernelStats: unix.XDPStatistics{
			Rx_dropped:       s.kernelStats.Rx_dropped + b.kernelStats.Rx_dropped,
			Rx_invalid_descs: s.kernelStats.Rx_invalid_descs + b.kernelStats.Rx_invalid_descs,
			Tx_invalid_descs: s.kernelStats.Tx_invalid_descs + b.kernelStats.Tx_invalid_descs,
		},
		polls: s.polls + b.polls,
		rxPps: s.rxPps + b.rxPps,
		rxBps: s.rxBps + b.rxBps,
		txPps: s.txPps + b.txPps,
		txBps: s.txBps + b.txBps,

		rxEmpty:  s.rxEmpty + b.rxEmpty,
		cqEmpty:  s.cqEmpty + b.cqEmpty,
		fqFull:   s.fqFull + b.fqFull,
		txFull:   s.txFull + b.txFull,
		sendBusy: s.sendBusy + b.sendBusy,
	}
}

func (s *XDPStats) Minus(b *XDPStats) *XDPStats {
	if s == nil || b == nil {
		return nil
	}
	return &XDPStats{
		kernelStats: unix.XDPStatistics{
			Rx_dropped:       s.kernelStats.Rx_dropped - b.kernelStats.Rx_dropped,
			Rx_invalid_descs: s.kernelStats.Rx_invalid_descs - b.kernelStats.Rx_invalid_descs,
			Tx_invalid_descs: s.kernelStats.Tx_invalid_descs - b.kernelStats.Tx_invalid_descs,
		},
		polls: s.polls - b.polls,
		rxPps: s.rxPps - b.rxPps,
		rxBps: s.rxBps - b.rxBps,
		txPps: s.txPps - b.txPps,
		txBps: s.txBps - b.txBps,

		rxEmpty:  s.rxEmpty - b.rxEmpty,
		cqEmpty:  s.cqEmpty - b.cqEmpty,
		fqFull:   s.fqFull - b.fqFull,
		txFull:   s.txFull - b.txFull,
		sendBusy: s.sendBusy - b.sendBusy,
	}
}

func (s *XDPStats) String() string {
	if s == nil {
		return ""
	}
	var titile string
	s.Do(func() {
		titile = fmt.Sprintf("%12s\t%12s\t%12s\t%8s\t%8s\t%12s\t%12s\t%12s\t%8s\t%12s\t%12s\t%12s\t%12s\t%12s\n",
			"RX-BPS", "RX-PPS", "RX-Drop", "RX-INVAL_DESC", "||", "TX-BPS", "TX-PPS", "TX-ERR",
			"||", "RX-EMPTY", "FQ-FULL", "TX-FULL", "CQ-EMPTY", "SEND-BUSY")
	})

	stats := fmt.Sprintf("%12d\t%12d\t%12d\t%8d\t%8s\t%12d\t%12d\t%12d\t%8s\t%12d\t%12d\t%12d\t%12d\t%12d\n",
		s.rxBps, s.rxPps, s.kernelStats.Rx_dropped, s.kernelStats.Rx_invalid_descs,
		"||", s.txBps, s.txPps, s.kernelStats.Tx_invalid_descs,
		"||", s.rxEmpty, s.fqFull, s.txFull, s.cqEmpty, s.sendBusy)

	return fmt.Sprintf("%v%v", titile, stats)
}

func (x *XDPPacket) readMultiPackets() (int, error) {
	entries := int(x.rx.dequeue(x.rxDescs, uint32(x.options.batchSize)))
	if entries < 1 {
		x.rxEmpty += 1
		return 0, ErrRxQueueEmpty
	}

	for i := 0; i < entries; i++ {
		x.rxDesc = x.rxDescs[i]
		x.packets[i] = x.framesBulk[x.rxDesc.Addr : x.rxDesc.Addr+uint64(x.rxDesc.Len)]
		x.rxAddrs = append(x.rxAddrs, x.rxDesc.Addr)
	}

	return entries, nil
}

// 非阻塞模式的收包函数
func nonblockMultiRead(x *XDPPacket) (int, error) {
	err := x.poll(x.rxFds)
	if err != nil {
		return 0, err
	}

	return x.readMultiPackets()
}

// 阻塞模式的收包函数
func blockMultiRead(x *XDPPacket) (int, error) {
retry:
	n, err := x.readMultiPackets()
	if err != nil {
		goto retry
	}

	return n, err
}

func (x *XDPPacket) releaseMultiPackets() error {
	var err error
	n := len(x.rxAddrs)
	if n > 0 {
	retry:
		err = x.fq.enqueue(x.rxAddrs, uint32(n))
		if err != nil {
			x.fqFull += 1
			goto retry
		}
	}
	x.rxAddrs = x.rxAddrs[:0]
	x.cis = x.cis[:0]
	return nil
}

// 收包接口，零拷贝, 每次尽最大努力收包，最多一次收16个包
// 函数返回后，请使用len([]CaptureInfo)获取读到的包数
func (x *XDPPacket) ZeroCopyReadMultiPackets() ([][]byte, []CaptureInfo, error) {
	if x.multiRead == nil {
		return nil, x.cis, ErrReadFunctionNil
	}
	if x.checkIfXDPSocketClosed() {
		return nil, x.cis, ErrSocketClosed
	}

	x.releaseMultiPackets()

	n, err := x.multiRead(x)
	if err == nil {
		totalBytes := uint32(0)
		for i := 0; i < n; i++ {
			x.rxDesc = x.rxDescs[i]
			totalBytes += x.rxDesc.Len
			x.ci.CaptureLength = int(x.rxDesc.Len)
			x.ci.Timestamp = time.Now()
		}
		x.rxPps += uint64(n)
		x.rxBps += uint64(totalBytes)
	}

	return x.packets, x.cis, err
}

// 从rx队列读取一个包
func (x *XDPPacket) readOnePacket() ([]byte, error) {
	entries := x.rx.dequeueOne(&x.rxDesc)
	if entries < 1 {
		x.rxEmpty += 1
		return nil, ErrRxQueueEmpty
	}

	x.rxAddr = x.rxDesc.Addr
	return x.framesBulk[x.rxDesc.Addr : x.rxDesc.Addr+uint64(x.rxDesc.Len)], nil
}

func (x *XDPPacket) poll(fds []unix.PollFd) error {
	timeout := int(x.options.pollTimeout / time.Millisecond)
retry:
	n, err := unix.Poll(fds, timeout)
	if n == 0 {
		return ErrTimeout
	}

	x.polls += 1
	if fds[0].Revents&unix.POLLERR > 0 {
		return ErrPoll
	}
	if err == syscall.EINTR {
		goto retry
	}
	return err
}

// 非阻塞模式的收包函数
func nonblockReadPacket(x *XDPPacket) ([]byte, error) {
	err := x.poll(x.rxFds)
	if err != nil {
		return nil, err
	}

	return x.readOnePacket()
}

// 阻塞模式的收包函数
func blockReadPacket(x *XDPPacket) ([]byte, error) {
retry:
	pkt, err := x.readOnePacket()
	if err != nil {
		goto retry
	}

	return pkt, err
}

// 调用ZeroCopyReadPacket函数收包后，需要主动调用ReleaseReadPacket()函数释放资源
// 收包接口，零拷贝
func (x *XDPPacket) ZeroCopyReadPacket() ([]byte, CaptureInfo, error) {
	if x.read == nil {
		return nil, x.ci, ErrReadFunctionNil
	}
	if x.checkIfXDPSocketClosed() {
		return nil, x.ci, ErrSocketClosed
	}

	x.ReleaseReadPacket()

	pkt, err := x.read(x)
	if err == nil {
		x.rxPps += 1
		x.rxBps += uint64(len(pkt))
		x.ci.CaptureLength = int(x.rxDesc.Len)
		x.ci.Timestamp = time.Now()
	}
	// 打开debug将极大的降低收包性能
	// log.Debug(dumpPacket(pkt))

	return pkt, x.ci, err
}

// 调用ReadPacket函数收包后，无需调用ReleaseReadPacket()函数释放资源
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
	var err error
retry:
	_, err = sendmsg(x.sockFd)
	if err == syscall.EBUSY { // 虚拟机SKB模式出现发包缓慢
		x.sendBusy += 1
		if x.xdpMode == XDP_MODE_SKB {
			time.Sleep(1 * time.Microsecond)
		}
		goto retry
	}
	if err == syscall.EAGAIN {
		x.sendBusy += 1
		goto retry
	}
	return err
}

// 流程enqueue tx --- copy --- write --- dequeue cq
// 发送单个包
func (x *XDPPacket) writeOnePacket(pkt []byte) error {
	x.txDesc.Addr = (x.txIdx & uint64(x.tx.mask)) << x.options.frameShift
	x.txDesc.Len = uint32(len(pkt))

	copy(x.framesBulk[x.txDesc.Addr:], pkt)

	err := x.tx.enqueueOne(x.txDesc)
	if err != nil {
		x.txFull += 1
		log.Debugf("tx queue is full")
		return err
	}

	err = x.sendmsg()
	if err != nil {
		// rollback
		desc, n, idx := x.tx.rollback()
		log.Debugf("send failed(err:%d), rollback (x.Idx:%v, tx.idx:%v, n:%v) desc:%v",
			err, x.txIdx, idx, n, desc)
		return fmt.Errorf("sendmsg failed as %v", err)
	}
	x.txIdx += 1

wait:
	if x.cq.dequeueOne(&x.txAddr) < 1 {
		x.cqEmpty += 1
		goto wait
	}

	return nil
}

// 阻塞模式的发包函数
func blockWrite(x *XDPPacket, pkt []byte) error {
retry:
	err := x.writeOnePacket(pkt)
	if err == ErrTxQueueFull {
		goto retry
	}
	return err
}

// 非阻塞模式的发包函数
func nonblockWrite(x *XDPPacket, pkt []byte) error {
	err := x.poll(x.txFds)
	if err != nil {
		return err
	}

	err = x.writeOnePacket(pkt)
	return err
}

// 发单包接口
func (x *XDPPacket) WritePacket(pkt []byte) error {
	if x.write == nil {
		return ErrWriteFunctionNil
	}

	if x.checkIfXDPSocketClosed() {
		return errors.New("xdp socket closed")
	}

	err := x.write(x, pkt)
	if err == nil || err == ErrCqQueueEmpty {
		x.txPps += uint64(1)
		x.txBps += uint64(len(pkt))
	}

	return err
}

// 内部批量发送函数，每次发送batchSize个包
func (x *XDPPacket) writeMultiPacket(pkts [][]byte) (int, int, error) {
	var err error
	var nPkt, n uint32
	var nByte, pktLen int = 0, 0

	pktNum := len(pkts)
	if pktNum > x.options.batchSize {
		return 0, 0, fmt.Errorf("too many packets, must <= %v packets", x.options.batchSize)
	}

	txEntries := x.tx.freeEntries(uint32(pktNum))
	if txEntries < uint32(pktNum) {
		x.txFull += 1
		return 0, 0, ErrTxQueueLessThanBatch
	}

	for i := 0; i < pktNum; i++ {
		pktLen = len(pkts[i])
		x.txDescs[i].Addr = (x.txIdx & uint64(x.tx.mask)) << x.options.frameShift
		x.txDescs[i].Len = uint32(pktLen)
		copy(x.framesBulk[x.txDescs[i].Addr:], pkts[i])

		x.txIdx += 1
		nByte += pktLen
		nPkt += 1
	}

	err = x.tx.enqueue(x.txDescs, uint32(pktNum))
	if err != nil {
		x.txIdx -= uint64(pktNum)
		return 0, 0, err
	}

	err = x.sendmsg()
	if err != nil {
		return 0, 0, fmt.Errorf("sendmsg failed as %v", err)
	}

	for n < nPkt {
		n += x.cq.dequeue(x.txAddrs, nPkt-n)
		x.cqEmpty += 1
	}

	return int(nPkt), nByte, err
}

// 阻塞模式的批量发包函数
func blockMultiWrite(x *XDPPacket, pkts [][]byte) (int, int, error) {
retry:
	nPkt, nByte, err := x.writeMultiPacket(pkts)
	if err != nil && err != ErrCqQueueLessThanBatch {
		goto retry
	}
	return nPkt, nByte, err
}

// 非阻塞模式的批量发包函数
func nonblockMultiWrite(x *XDPPacket, pkts [][]byte) (int, int, error) {
	err := x.poll(x.txFds)
	if err != nil {
		return 0, 0, err
	}

	return x.writeMultiPacket(pkts)
}

// 批量发包接口,
func (x *XDPPacket) WriteMultiPackets(pkts [][]byte) (int, error) {
	var err error
	var start, end, pktNum int = 0, 0, 0
	var nPkt, nByte int = 0, 0

	if x.multiWrite == nil {
		return 0, ErrMultiWriteFunctionNil
	}

	if x.checkIfXDPSocketClosed() {
		return 0, errors.New("xdp socket closed")
	}

	pktNum = len(pkts)
	for start = 0; start < pktNum; {
		end = start + x.options.batchSize
		if end > pktNum {
			end = pktNum
		}
		nPkt, nByte, err = x.multiWrite(x, pkts[start:end])
		if err == ErrTxQueueLessThanBatch {
			// FIXME 考虑是否sleep
			continue
		} else if err != nil && err != ErrCqQueueLessThanBatch {
			return start, err
		}

		x.txPps += uint64(nPkt)
		x.txBps += uint64(nByte)
		start += nPkt
	}

	return pktNum, err
}

func (x *XDPPacket) ReleaseReadPacket() error {
	var err error
	if x.rxAddr != math.MaxUint64 {
	retry:
		err = x.fq.enqueueOne(x.rxAddr)
		if err != nil {
			x.fqFull += 1
			goto retry
		}
	}
	x.rxAddr = math.MaxUint64
	x.ci = ZEROCI
	return nil
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
		XDPStats:  &XDPStats{},
		ci:        CaptureInfo{InterfaceIndex: ifIndex},

		rxFds:   rxFds,
		txFds:   txFds,
		txDescs: make([]unix.XDPDesc, options.batchSize),
		txAddrs: make([]uint64, options.batchSize),

		rxAddr:  math.MaxUint64,
		rxDescs: make([]unix.XDPDesc, options.batchSize),
		rxAddrs: make([]uint64, options.batchSize),
		packets: make([][]byte, options.batchSize),
		cis:     make([]CaptureInfo, options.batchSize),
	}

	if xdp.options.ioMode == IO_MODE_NONBLOCK {
		xdp.read = nonblockReadPacket
		xdp.write = nonblockWrite
		xdp.multiWrite = nonblockMultiWrite
		xdp.multiRead = nonblockMultiRead
	} else {
		xdp.read = blockReadPacket
		xdp.write = blockWrite
		xdp.multiWrite = blockMultiWrite
		xdp.multiRead = blockMultiRead
	}

	log.Debugf("a new xdp packet %v", xdp)
	return xdp, nil
}

func NewXDPPacket(name string, opts ...interface{}) (*XDPPacket, error) {
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
	if options.queueCount != 1 {
		return nil, errors.New("only support one queue")
	}

	if !initXDPRunningEnv(name, options.xdpMode, options.queueCount) {
		return nil, errors.New("an error XDP running environment")
	}

	// only can use queue 0
	xdp, err := initXDPPacket(iface.Index, options, int(options.queueCount)-1)
	if err != nil {
		return nil, err
	}

	err = xdp.initXDPSocket(true, options.queueCount)
	if err != nil {
		xdp.Close()
		return nil, err
	}
	atomic.AddInt32(&xdp.progRefCount, 1)

	log.Debugf("a usable XDPPacket %v", xdp)
	return xdp, nil
}

func (x *XDPPacket) GetStats() *XDPStats {
	if x == nil || x.sockFd < 0 {
		return &XDPStats{}
	}

	kStats, err := getOptXDPStats(x.sockFd)
	if err != nil {
		log.Warning("get XDP socket kernel statistics failed")
		return nil
	}

	stats := &XDPStats{}
	*stats = *x.XDPStats
	stats.kernelStats = *kStats

	return stats
}

// 创建xdp-socket后，需主动调用Close
// 释放xdp-socket资源
func (x *XDPPacket) Close() {
	if x == nil {
		return
	}
	x.close()

	if atomic.LoadInt32(&x.progRefCount) > 0 {
		atomic.AddInt32(&x.progRefCount, -1)
	}
	// 清除ebpf program
	if atomic.LoadInt32(&x.progRefCount) == 0 {
		x.clearResource()
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
	return fmt.Sprintf("\n%v%v", x.options.String(), x.XDPSocket.String())
}
