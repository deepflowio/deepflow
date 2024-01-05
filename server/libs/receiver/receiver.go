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

package receiver

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	logging "github.com/op/go-logging"

	"github.com/deepflowio/deepflow/server/libs/app"
	"github.com/deepflowio/deepflow/server/libs/cache"
	"github.com/deepflowio/deepflow/server/libs/datatype"
	"github.com/deepflowio/deepflow/server/libs/debug"
	"github.com/deepflowio/deepflow/server/libs/pool"
	"github.com/deepflowio/deepflow/server/libs/queue"
	"github.com/deepflowio/deepflow/server/libs/stats"
	. "github.com/deepflowio/deepflow/server/libs/utils"
)

const (
	RECV_BUFSIZE_2K           = 1 << 11 // 2k for UDP
	RECV_BUFSIZE_8K           = 1 << 13 // 8k
	RECV_BUFSIZE_64K          = 1 << 16 // 64k
	RECV_BUFSIZE_256K         = 1 << 18 // 256k
	RECV_BUFSIZE_512K         = 1 << 19 // 512k
	RECV_BUFSIZE_MAX          = 1 << 24 // 16M, the maximum size of the PCAP packet will be greater than 8M
	RECV_TIMEOUT              = 30 * time.Second
	QUEUE_CACHE_FLUSH_TIMEOUT = 3
	DROP_DETECT_WINDOW_SIZE   = 1024
	QUEUE_BATCH_NUM           = 16
	LOG_INTERVAL              = 60
	RECORD_STATUS_TIMEOUT     = 30 // 每30秒记录下trident的活跃信息，platformData模块每分钟会上报trisolaris
	SOCKET_READ_ERROR         = "maybe trident restart."
	ONE_HOUR                  = 3600
)

var log = logging.MustGetLogger("receiver")

type RecvBuffer struct {
	Begin      int // 开始位置
	End        int
	Buffer     []byte
	IP         net.IP // 保存消息的发送方IP
	VtapID     uint16
	SocketType ServerType
}

// 实现空接口，仅用于队列调试打印
func (r *RecvBuffer) AddReferenceCount() {
}

func (r *RecvBuffer) SubReferenceCount() bool {
	return false
}

func (r *RecvBuffer) String() string {
	return fmt.Sprintf("IP:%s %s\n", r.IP, string(r.Buffer))
}

func newBufferPool(bufferSize, poolSizePerCPU int) *pool.LockFreePool {
	return pool.NewLockFreePool(
		func() interface{} {
			return &RecvBuffer{
				Buffer: make([]byte, bufferSize),
			}
		},
		pool.OptionPoolSizePerCPU(poolSizePerCPU),
		pool.OptionInitFullPoolSize(poolSizePerCPU),
		pool.OptionCounterNameSuffix(fmt.Sprintf("_%dK", bufferSize>>10)),
	)
}

var recvBufferPools = []*pool.LockFreePool{
	newBufferPool(RECV_BUFSIZE_2K, 16),
	newBufferPool(RECV_BUFSIZE_8K, 32),
	newBufferPool(RECV_BUFSIZE_64K, 8),
	newBufferPool(RECV_BUFSIZE_256K, 8),
	newBufferPool(RECV_BUFSIZE_512K, 8),
	// if the required buffer > 512k, the memory will not be pre-allocated, and the memory will be allocated when it is used
	newBufferPool(0, 8),
}

func getBufferPoolIndex(length int) int {
	for i, v := range []int{RECV_BUFSIZE_2K, RECV_BUFSIZE_8K, RECV_BUFSIZE_64K, RECV_BUFSIZE_256K, RECV_BUFSIZE_512K} {
		if length <= v {
			return i
		}
	}
	return len(recvBufferPools) - 1
}

func minPowerOfTwo(v int) int {
	for i := 0; i < 30; i++ {
		if v <= 1<<uint64(i) {
			return 1 << uint64(i)
		}
	}
	return v
}

func AcquireRecvBuffer(length int, socketType ServerType) (*RecvBuffer, bool) {
	isNew := false
	index := getBufferPoolIndex(length)
	buf := recvBufferPools[index].Get().(*RecvBuffer)
	buf.SocketType = socketType
	if len(buf.Buffer) < length {
		length = minPowerOfTwo(length)
		buf.Buffer = make([]byte, length)
		isNew = true
	}

	return buf, isNew
}

func ReleaseRecvBuffer(b *RecvBuffer) {
	b.Begin = 0
	b.End = 0
	b.IP = nil
	b.VtapID = 0
	recvBufferPools[getBufferPoolIndex(len(b.Buffer))].Put(b)
}

type QueueCache struct {
	sync.Mutex
	values    []interface{}
	timestamp int64
}

type ServerType byte

const (
	UDP ServerType = iota
	TCP
	BOTH
)

func (s ServerType) String() string {
	if s == UDP {
		return "UDP"
	} else if s == TCP {
		return "TCP"
	} else if s == BOTH {
		return "TCP && UDP"
	}
	return "Unknown"
}

type Status struct {
	msgType              datatype.MessageType
	VTAPID               uint16
	serverType           ServerType
	ip                   net.IP
	lastSeq              uint64
	lastRemoteTimestamp  uint32 // 最后一次收到数据时数据中的时间戳
	LastLocalTimestamp   uint32 // 最后一次收到数据时的本地时间
	firstSeq             uint64
	firstRemoteTimestamp uint32 // 第一次收到数据时数据中的时间戳
	firstLocalTimestamp  uint32 // 第一次收到数据时的本地时间
}

func NewStatus(now uint32, msgType datatype.MessageType, vtapID uint16, ip net.IP, seq uint64, timestamp uint32, serverType ServerType) *Status {
	return &Status{
		msgType:              msgType,
		serverType:           serverType,
		VTAPID:               vtapID,
		ip:                   ip,
		lastSeq:              seq,
		lastRemoteTimestamp:  timestamp,
		LastLocalTimestamp:   now,
		firstSeq:             seq,
		firstRemoteTimestamp: timestamp,
		firstLocalTimestamp:  now,
	}
}

func (s *Status) update(now uint32, msgType datatype.MessageType, vtapID uint16, ip net.IP, seq uint64, timestamp uint32, serverType ServerType) {
	s.msgType = msgType
	s.VTAPID = vtapID
	s.ip = ip
	s.lastSeq = seq
	s.lastRemoteTimestamp = timestamp
	s.LastLocalTimestamp = now
	s.serverType = serverType
}

type AdapterStatus struct {
	lastUDPUpdate   uint32 // 记录更新时间
	lastTCPUpdate   uint32
	UDPMetrisStatus []*Status // 定期获取trident遥测数据的活跃信息,上报trisolaris
	TCPMetrisStatus []*Status
	UDPStatusLocks  [datatype.MESSAGE_TYPE_MAX]sync.Mutex
	TCPStatusLocks  [datatype.MESSAGE_TYPE_MAX]sync.RWMutex
	UDPStatusFlow   [datatype.MESSAGE_TYPE_MAX]map[uint16]*Status
	TCPStatusFlow   [datatype.MESSAGE_TYPE_MAX]map[uint16]*Status // vtapID非0, 使用vtapID作为key: 遥测数据，l4流日志数据，l7-http-dns流日志数据
	UDPStatusOthers [datatype.MESSAGE_TYPE_MAX]map[string]*Status
	TCPStatusOthers [datatype.MESSAGE_TYPE_MAX]map[string]*Status // vtapID为0, 使用IP作为key: pcap数据，系统日志数据，statd统计数据
}

func (s *AdapterStatus) init() {
	for i := 0; i < int(datatype.MESSAGE_TYPE_MAX); i++ {
		s.TCPStatusFlow[i] = make(map[uint16]*Status)
		s.UDPStatusFlow[i] = make(map[uint16]*Status)
		s.TCPStatusOthers[i] = make(map[string]*Status)
		s.UDPStatusOthers[i] = make(map[string]*Status)
	}
}

func (s *AdapterStatus) Update(now uint32, msgType datatype.MessageType, vtapID uint16, ip net.IP, seq uint64, timestamp uint32, serverType ServerType) {
	if serverType == UDP { // UDP大部分时间无锁，只有在更新map时加锁, 防止调试命令读取时可能导致异常
		if vtapID != 0 {
			if status, ok := s.UDPStatusFlow[msgType][vtapID]; ok {
				status.update(now, msgType, vtapID, ip, seq, timestamp, serverType)
			} else {
				s.UDPStatusLocks[msgType].Lock()
				s.UDPStatusFlow[msgType][vtapID] = NewStatus(now, msgType, vtapID, ip, seq, timestamp, serverType)
				s.UDPStatusLocks[msgType].Unlock()
			}
		} else {
			if status, ok := s.UDPStatusOthers[msgType][ip.String()]; ok {
				status.update(now, msgType, vtapID, ip, seq, timestamp, serverType)
			} else {
				s.UDPStatusLocks[msgType].Lock()
				s.UDPStatusOthers[msgType][ip.String()] = NewStatus(now, msgType, vtapID, ip, seq, timestamp, serverType)
				s.UDPStatusLocks[msgType].Unlock()
			}
		}
		// 定期获取trident活跃信息，上报trisolaris
		if now-s.lastUDPUpdate > RECORD_STATUS_TIMEOUT {
			s.lastUDPUpdate = now
			UDPStatus := make([]*Status, 0, len(s.UDPStatusFlow))
			for _, status := range s.UDPStatusFlow[datatype.MESSAGE_TYPE_METRICS] {
				UDPStatus = append(UDPStatus, status)
			}
			s.UDPMetrisStatus = UDPStatus
		}

	} else { // TCP有锁,主要是读锁，但并行处理，基本不影响接收性能
		if vtapID != 0 {
			s.TCPStatusLocks[msgType].RLock()
			status, ok := s.TCPStatusFlow[msgType][vtapID]
			s.TCPStatusLocks[msgType].RUnlock()
			if ok {
				status.update(now, msgType, vtapID, ip, seq, timestamp, serverType)
			} else {
				newStatus := NewStatus(now, msgType, vtapID, ip, seq, timestamp, serverType)
				s.TCPStatusLocks[msgType].Lock()
				s.TCPStatusFlow[msgType][vtapID] = newStatus
				s.TCPStatusLocks[msgType].Unlock()
			}

		} else {
			s.TCPStatusLocks[msgType].RLock()
			status, ok := s.TCPStatusOthers[msgType][ip.String()]
			s.TCPStatusLocks[msgType].RUnlock()
			if ok {
				status.update(now, msgType, vtapID, ip, seq, timestamp, serverType)
			} else {
				newStatus := NewStatus(now, msgType, vtapID, ip, seq, timestamp, serverType)
				s.TCPStatusLocks[msgType].Lock()
				s.TCPStatusOthers[msgType][ip.String()] = newStatus
				s.TCPStatusLocks[msgType].Unlock()
			}
		}
		// 定期获取trident活跃信息，上报trisolaris
		if now-s.lastTCPUpdate > RECORD_STATUS_TIMEOUT {
			s.lastTCPUpdate = now
			TCPStatus := make([]*Status, 0, len(s.TCPStatusFlow))
			s.TCPStatusLocks[datatype.MESSAGE_TYPE_METRICS].Lock()
			for _, status := range s.TCPStatusFlow[datatype.MESSAGE_TYPE_METRICS] {
				TCPStatus = append(TCPStatus, status)
			}
			s.TCPStatusLocks[datatype.MESSAGE_TYPE_METRICS].Unlock()
			s.TCPMetrisStatus = TCPStatus
		}
	}
}

func (s *AdapterStatus) GetStatus(msgType datatype.MessageType) string {
	if msgType.HeaderType() == datatype.HEADER_TYPE_LT_VTAP {
		UDPStatus := s.UDPStatusFlow[msgType]
		TCPStatus := s.TCPStatusFlow[msgType]
		allStatus := make([]*Status, 0, len(UDPStatus)+len(TCPStatus))
		s.UDPStatusLocks[msgType].Lock()
		for _, instance := range UDPStatus {
			allStatus = append(allStatus, instance)
		}
		s.UDPStatusLocks[msgType].Unlock()
		s.TCPStatusLocks[msgType].RLock()
		for _, instance := range TCPStatus {
			allStatus = append(allStatus, instance)
		}
		s.TCPStatusLocks[msgType].RUnlock()
		sort.Slice(allStatus, func(i, j int) bool {
			return allStatus[i].ip.String() < allStatus[j].ip.String()
		})
		status := fmt.Sprintf("MsgType VTAPID TridentIP                                Type LastSeq  LastRemoteTimestamp LastLocalTimestamp  LastDelay LastRecvFromNow FirstSeq FirstRemoteTimestamp FirstLocalTimestamp\n")
		status += fmt.Sprintf("------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------\n")
		for _, instance := range allStatus {
			status += fmt.Sprintf("%-7s %-6d %-40s %-4s %-8d %-19.19s %-19.19s %-9d %-15d %-8d %-19.19s  %-19.19s\n",
				datatype.MessageTypeString[int(instance.msgType)], instance.VTAPID, instance.ip, instance.serverType,
				instance.lastSeq, time.Unix(int64(instance.lastRemoteTimestamp), 0), time.Unix(int64(instance.LastLocalTimestamp), 0),
				instance.LastLocalTimestamp-instance.lastRemoteTimestamp, uint32(time.Now().Unix())-instance.LastLocalTimestamp,
				instance.firstSeq, time.Unix(int64(instance.firstRemoteTimestamp), 0), time.Unix(int64(instance.firstLocalTimestamp), 0))
		}
		return status
	}

	UDPStatus := s.UDPStatusOthers[msgType]
	TCPStatus := s.TCPStatusOthers[msgType]
	allStatus := make([]*Status, 0, len(UDPStatus)+len(TCPStatus))
	s.UDPStatusLocks[msgType].Lock()
	for _, instance := range UDPStatus {
		allStatus = append(allStatus, instance)
	}
	s.UDPStatusLocks[msgType].Unlock()
	s.TCPStatusLocks[msgType].RLock()
	for _, instance := range TCPStatus {
		allStatus = append(allStatus, instance)
	}
	s.TCPStatusLocks[msgType].RUnlock()
	sort.Slice(allStatus, func(i, j int) bool {
		return allStatus[i].ip.String() < allStatus[j].ip.String()
	})
	status := fmt.Sprintf("MsgType TridentIP                                Type LastLocalTimestamp LastRecvFromNow FirstLocalTimestamp\n")
	status += fmt.Sprintf("-----------------------------------------------------------------------------------------------------\n")
	for _, instance := range allStatus {
		status += fmt.Sprintf("%-7s %-40s %-4s %-19.19s %-15d %-19.19s\n",
			datatype.MessageTypeString[int(instance.msgType)], instance.ip, instance.serverType,
			time.Unix(int64(instance.LastLocalTimestamp), 0),
			uint32(time.Now().Unix())-instance.LastLocalTimestamp,
			time.Unix(int64(instance.firstLocalTimestamp), 0))
	}
	return status
}

type Handler struct {
	msgType        datatype.MessageType // 在datatype/droplet-message.go中定义
	queues         queue.MultiQueueWriter
	nQueues        int
	queueUDPCaches []QueueCache // UDP单线程处理，免锁
	queueTCPCaches []QueueCache // TCP多线程处理，需加锁
}

type Receiver struct {
	cache.DropDetection

	handlers []*Handler

	serverType       ServerType
	UDPAddress       *net.UDPAddr
	UDPConn          *net.UDPConn
	UDPReadBuffer    int
	TCPReadBuffer    int
	TCPReaderBuffer  int
	TCPListener      net.Listener
	TCPAddress       string
	lastUDPFlushTime int64
	lastTCPFlushTime int64
	timeNow          int64
	lastLogTime      int64
	lastTCPLogTime   int64
	dropLogCount     int64

	exit   bool
	closed bool

	counter *ReceiverCounter

	status *AdapterStatus
}

type ReceiverCounter struct {
	Invalid         uint64 `statsd:"invalid"`
	Unregistered    uint64 `statsd:"unregistered"`
	RxPackets       uint64 `statsd:"rx_packets"`
	MaxDelay        int64  `statsd:"max_delay"`
	MinDelay        int64  `statsd:"min_delay"`
	UDPDropped      uint64 `statsd:"udp_dropped"`
	UDPDisorder     uint64 `statsd:"udp_disorder"`      // 乱序个数
	UDPDisorderSize uint64 `statsd:"udp_disorder_size"` // 乱序最大范围
	NewBufferCount  uint64 `statsd:"new_buffer_count"`  // If the received data is large, you need to alloc memory, record the times.
}

func NewReceiver(
	listenPort, UDPReadBuffer, TCPReadBuffer, TCPReaderBuffer int, // 监听端口，默认同时监听tcp和upd的端口
) *Receiver {
	receiver := &Receiver{
		handlers:        make([]*Handler, datatype.MESSAGE_TYPE_MAX),
		serverType:      BOTH,
		UDPAddress:      &net.UDPAddr{Port: listenPort},
		UDPReadBuffer:   UDPReadBuffer,
		TCPReadBuffer:   TCPReadBuffer,
		TCPReaderBuffer: TCPReaderBuffer,
		TCPAddress:      fmt.Sprintf("0.0.0.0:%d", listenPort),
		timeNow:         time.Now().Unix(),
		counter:         &ReceiverCounter{},
		status:          &AdapterStatus{},
	}
	receiver.status.init()

	debug.ServerRegisterSimple(TRIDENT_ADAPTER_STATUS_CMD, receiver)
	receiver.DropDetection.Init("receiver", DROP_DETECT_WINDOW_SIZE)
	go receiver.timeNowAndFlushTicker()
	return receiver
}

// 注册处理函数，收到msgType的数据，放到outQueues中
func (r *Receiver) RegistHandler(msgType datatype.MessageType, outQueues queue.MultiQueueWriter, nQueues int) error {
	queueUDPCaches := make([]QueueCache, nQueues)
	queueTCPCaches := make([]QueueCache, nQueues)
	for i := 0; i < nQueues; i++ {
		queueUDPCaches[i].values = make([]interface{}, 0, QUEUE_BATCH_NUM)
		queueTCPCaches[i].values = make([]interface{}, 0, QUEUE_BATCH_NUM)
	}
	r.handlers[msgType] = &Handler{
		msgType:        msgType,
		queues:         outQueues,
		nQueues:        nQueues,
		queueUDPCaches: queueUDPCaches,
		queueTCPCaches: queueTCPCaches,
	}
	return nil
}

func (r *Receiver) HandleSimpleCommand(op uint16, arg string) string {
	msgType := datatype.MessageType(op)
	if msgType < datatype.MESSAGE_TYPE_MAX {
		return r.status.GetStatus(msgType)
	}
	if msgType == datatype.MESSAGE_TYPE_MAX { // 兼容原来的status参数
		return r.status.GetStatus(datatype.MESSAGE_TYPE_METRICS)
	}
	ret := ""
	for i := 0; i < int(datatype.MESSAGE_TYPE_MAX); i++ {
		ret += r.status.GetStatus(datatype.MessageType(i))
		ret += "\n"
	}
	return ret
}

func (r *Receiver) SetServerType(serverType ServerType) {
	r.serverType = serverType
}

func (r *Receiver) GetCounter() interface{} {
	counter := &ReceiverCounter{MaxDelay: -ONE_HOUR, MinDelay: ONE_HOUR}
	counter, r.counter = r.counter, counter

	dropCounter := r.DropDetection.GetCounter().(*cache.DropCounter)
	counter.UDPDropped = dropCounter.Dropped
	counter.UDPDisorder = dropCounter.Disorder
	counter.UDPDisorderSize = dropCounter.DisorderSize
	return counter
}

func (r *Receiver) updateCounter(metriTimestamp uint32) {
	delay := r.timeNow - int64(metriTimestamp)
	if r.counter.MaxDelay < delay {
		r.counter.MaxDelay = delay
	}
	if r.counter.MinDelay > delay {
		r.counter.MinDelay = delay
	}
}

func (r *Receiver) timeNowAndFlushTicker() {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	for range ticker.C {
		if r.exit {
			return
		}
		r.timeNow = time.Now().Unix()
		r.flushPutTCPQueues()
	}
}

func (r *Receiver) putUDPQueue(hash int, handler *Handler, buffer *RecvBuffer) {
	hashKey := hash % handler.nQueues

	queueCache := &handler.queueUDPCaches[hashKey]
	queueCache.values = append(queueCache.values, buffer)
	if len(queueCache.values) >= QUEUE_BATCH_NUM || r.timeNow-queueCache.timestamp > QUEUE_CACHE_FLUSH_TIMEOUT {
		queueCache.timestamp = r.timeNow
		handler.queues.Put(queue.HashKey(hashKey), queueCache.values...)
		queueCache.values = queueCache.values[:0]
	}
}

func (r *Receiver) putTCPQueue(hash int, handler *Handler, buffer *RecvBuffer) {
	hashKey := hash % handler.nQueues

	queueCache := &handler.queueTCPCaches[hashKey]
	queueCache.Lock() // 存在多个tcp连接同时put，故需要加锁
	queueCache.values = append(queueCache.values, buffer)
	if len(queueCache.values) >= QUEUE_BATCH_NUM || r.timeNow-queueCache.timestamp > QUEUE_CACHE_FLUSH_TIMEOUT {
		queueCache.timestamp = r.timeNow
		handler.queues.Put(queue.HashKey(hashKey), queueCache.values...)
		queueCache.values = queueCache.values[:0]
	}
	queueCache.Unlock()
}

func (r *Receiver) flushPutUDPQueues() {
	// 防止频繁flush
	if r.timeNow-r.lastUDPFlushTime < QUEUE_CACHE_FLUSH_TIMEOUT {
		return
	}
	for _, handler := range r.handlers {
		if handler == nil {
			continue
		}
		for i := 0; i < handler.nQueues; i++ {
			queueCache := &handler.queueUDPCaches[i]
			if len(queueCache.values) > 0 && r.timeNow-queueCache.timestamp > QUEUE_CACHE_FLUSH_TIMEOUT {
				queueCache.timestamp = r.timeNow
				handler.queues.Put(queue.HashKey(i), queueCache.values...)
				queueCache.values = queueCache.values[:0]
			}
		}
	}
	r.lastUDPFlushTime = r.timeNow
}

func (r *Receiver) flushPutTCPQueues() {
	// 防止频繁flush
	if r.timeNow-r.lastTCPFlushTime < QUEUE_CACHE_FLUSH_TIMEOUT {
		return
	}
	for _, handler := range r.handlers {
		if handler == nil {
			continue
		}
		for i := 0; i < handler.nQueues; i++ {
			queueCache := &handler.queueTCPCaches[i]
			if len(queueCache.values) == 0 || r.timeNow-queueCache.timestamp <= QUEUE_CACHE_FLUSH_TIMEOUT {
				continue
			}
			queueCache.Lock()
			queueCache.timestamp = r.timeNow
			handler.queues.Put(queue.HashKey(i), queueCache.values...)
			queueCache.values = queueCache.values[:0]
			queueCache.Unlock()
		}
	}
	r.lastTCPFlushTime = r.timeNow
}

// 用来上报trisolaris, trident最后的活跃时间
func (r *Receiver) GetTridentStatus() []*Status {
	UDPStatus, TCPStatus := r.status.UDPMetrisStatus, r.status.TCPMetrisStatus
	status := make([]*Status, 0, len(UDPStatus)+len(TCPStatus))
	for _, us := range UDPStatus {
		find := false
		for _, ts := range TCPStatus {
			if us.VTAPID == ts.VTAPID {
				find = true
				if us.lastRemoteTimestamp > ts.lastRemoteTimestamp {
					status = append(status, us)
				} else {
					status = append(status, ts)
				}
				break
			}
		}
		if !find {
			status = append(status, us)
		}
	}

	for _, ts := range TCPStatus {
		find := false
		for _, us := range UDPStatus {
			if ts.VTAPID == us.VTAPID {
				find = true
				break
			}
		}
		if !find {
			status = append(status, ts)
		}
	}

	return status
}

// 由于引用了app，导致递归引用,不能在datatype中定义类函数，故放到这里
func ValidateFlowVersion(t datatype.MessageType, version uint32) error {
	var expectVersion uint32
	switch t {
	case datatype.MESSAGE_TYPE_METRICS:
		expectVersion = app.VERSION
	case datatype.MESSAGE_TYPE_TAGGEDFLOW, datatype.MESSAGE_TYPE_PROTOCOLLOG:
		expectVersion = datatype.VERSION
	default:
		return nil
	}

	if version != expectVersion {
		return fmt.Errorf("message version incorrect, expect %d, found %d.", expectVersion, version)
	}
	return nil
}

func (r *Receiver) setUDPTimeout() {
	// 每隔RECV_TIMEOUT 时间触发一次timeout，保证队列的数据都flush出去
	r.UDPConn.SetReadDeadline(time.Now().Add(RECV_TIMEOUT))
}

func (r *Receiver) logReceiveError(size int, remoteAddr *net.UDPAddr, err error) {
	atomic.AddUint64(&r.counter.Invalid, 1)
	// 防止日志刷屏
	if r.timeNow-r.lastLogTime < LOG_INTERVAL {
		r.dropLogCount++
		return
	}
	r.lastLogTime = r.timeNow

	if remoteAddr != nil {
		if err == nil && size == 0 {
			log.Infof("UDP socket recv size %d from %s:%d, %s Already drop log count %d", size, remoteAddr.IP, remoteAddr.Port, SOCKET_READ_ERROR, r.dropLogCount)
		} else {
			log.Warningf("UDP socket recv size %d from %s:%d, err:%s, already drop log count %d", size, remoteAddr.IP, remoteAddr.Port, err, r.dropLogCount)
		}
	} else {
		log.Warningf("UDP socket recv size %d, %s, already drop log count %d", size, err, r.dropLogCount)
	}
}

func (r *Receiver) logTCPReceiveInvalidData(str string) {
	atomic.AddUint64(&r.counter.Invalid, 1)
	// 防止日志刷屏
	if r.timeNow-r.lastTCPLogTime < LOG_INTERVAL {
		r.dropLogCount++
		return
	}
	r.lastTCPLogTime = r.timeNow
	log.Warningf(fmt.Sprintf("%s, already drop log count %d", str, r.dropLogCount))
}

func (r *Receiver) ProcessUDPServer() {
	defer r.UDPConn.Close()
	baseHeader := &datatype.BaseHeader{}
	flowHeader := &datatype.FlowHeader{}
	r.setUDPTimeout()
	for !r.exit {
		recvBuffer, _ := AcquireRecvBuffer(RECV_BUFSIZE_2K, UDP)
		size, remoteAddr, err := r.UDPConn.ReadFromUDP(recvBuffer.Buffer)
		if err != nil || size < datatype.MESSAGE_HEADER_LEN {
			ReleaseRecvBuffer(recvBuffer)
			r.flushPutUDPQueues()
			if err == nil {
				r.logReceiveError(size, remoteAddr, err)
				continue
			}
			if netErr, ok := err.(net.Error); ok {
				if netErr.Timeout() {
					r.setUDPTimeout()
					continue
				}
			}
			r.logReceiveError(size, remoteAddr, err)
			time.Sleep(time.Second)
			continue
		}

		if err := baseHeader.Decode(recvBuffer.Buffer); err != nil {
			ReleaseRecvBuffer(recvBuffer)
			r.logReceiveError(size, remoteAddr, err)
			continue
		}
		if baseHeader.Type >= datatype.MESSAGE_TYPE_MAX {
			ReleaseRecvBuffer(recvBuffer)
			r.logReceiveError(size, remoteAddr, fmt.Errorf("unknown message type %d", baseHeader.Type))
			continue
		}

		headerLen := datatype.MESSAGE_HEADER_LEN
		metricsTimestamp, vtapID, sequence := uint32(0), uint16(0), uint64(0)
		if baseHeader.Type.HeaderType() == datatype.HEADER_TYPE_LT_VTAP {
			flowHeader.Decode(recvBuffer.Buffer[datatype.MESSAGE_HEADER_LEN:])
			headerLen += datatype.FLOW_HEADER_LEN

			if err := ValidateFlowVersion(baseHeader.Type, flowHeader.Version); err != nil {
				r.logReceiveError(size, remoteAddr, fmt.Errorf("%s msgType: %s ", err, datatype.MessageTypeString[baseHeader.Type]))
				// 但版本不匹配，且版本小于app.LAST_SIMPLE_CODEC_VERSION时，才会拒绝连接
				if flowHeader.Version <= app.LAST_SIMPLE_CODEC_VERSION {
					ReleaseRecvBuffer(recvBuffer)
					continue
				}
			}

			vtapID = flowHeader.VTAPID
			sequence = flowHeader.Sequence
			if baseHeader.Type == datatype.MESSAGE_TYPE_METRICS {
				metricsTimestamp = r.getMetricsTimestamp(recvBuffer.Buffer[headerLen:])
				r.updateCounter(metricsTimestamp)
				r.DropDetection.Detect(getIpHash(remoteAddr.IP), flowHeader.Sequence, metricsTimestamp)
			}
		}
		r.status.Update(uint32(r.timeNow), baseHeader.Type, vtapID, remoteAddr.IP, sequence, metricsTimestamp, UDP)

		// Unregistered messages are discarded directly after receiving them, but the connection is not disconnected to prevent the Agent from printing exception logs
		if r.handlers[baseHeader.Type] == nil {
			atomic.AddUint64(&r.counter.Unregistered, 1)
			ReleaseRecvBuffer(recvBuffer)
		} else {
			recvBuffer.Begin = headerLen
			recvBuffer.End = size // syslog,statsd数据的FrameSize长度是0,需要以实际长度为准
			if baseHeader.Type == datatype.MESSAGE_TYPE_COMPRESS {
				recvBuffer.End = int(baseHeader.FrameSize) // 可能收到的包长会大于FrameSize, 以FrameSize为准
			}
			recvBuffer.IP = remoteAddr.IP
			recvBuffer.VtapID = vtapID
			r.putUDPQueue(int(r.counter.RxPackets), r.handlers[baseHeader.Type], recvBuffer)
		}
	}
}

func (r *Receiver) ProcessTCPServer() {
	defer r.TCPListener.Close()
	for !r.exit {
		conn, err := r.TCPListener.Accept()
		if err != nil {
			log.Errorf("Accept error.%s ", err.Error())
			time.Sleep(3 * time.Second)
			continue
		}
		if tcpConn, ok := conn.(*net.TCPConn); ok {
			if err := tcpConn.SetReadBuffer(r.TCPReadBuffer); err != nil {
				log.Warningf("TCP client(%s) set read buffer failed, err: %s", conn.RemoteAddr().String(), err)
			} else {
				log.Infof("TCP client(%s) connect success, set read buffer %d.", conn.RemoteAddr().String(), r.TCPReadBuffer)
			}
		} else {
			log.Infof("TCP client(%s) connect success.", conn.RemoteAddr().String())
		}
		go r.handleTCPConnection(conn)
	}
}

func parseRemoteIP(conn net.Conn) net.IP {
	remoteAddr := conn.RemoteAddr().String() //  "192.0.2.1:25"  or [2001:db8::1]:80
	left := strings.Index(remoteAddr, "[")
	if left != -1 {
		right := strings.Index(remoteAddr, "]")
		if right > left {
			return net.ParseIP(remoteAddr[left+1 : right]) // ip6
		} else {
			return nil
		}
	} else {
		return net.ParseIP(strings.Split(remoteAddr, ":")[0]) // ip4
	}
}

func getIpHash(ip net.IP) uint32 {
	if ipU32 := IpToUint32(ip.To4()); ipU32 != 0 {
		return ipU32
	}

	return GetIpHash(ip)
}

func (r *Receiver) getMetricsTimestamp(buffer []byte) uint32 {
	now := uint32(time.Now().Unix())
	if len(buffer) >= 4 {
		// FIXME metrics time is encoded in probuf, may not be available
		metricsTime := binary.LittleEndian.Uint32(buffer) // doc的前4个字节是时间
		if metricsTime > now-ONE_HOUR && metricsTime < now+ONE_HOUR {
			return metricsTime
		}
	}
	return now
}

// 固定读取buffer长度的数据
func ReadN(r *bufio.Reader, buffer []byte) error {
	total := 0
	for total < len(buffer) {
		n, err := r.Read(buffer[total:])
		if err != nil {
			if err == io.EOF {
				return fmt.Errorf("%s, %s", err.Error(), SOCKET_READ_ERROR)
			}
			return err
		}
		total += n
	}
	return nil
}

func (r *Receiver) handleTCPConnection(conn net.Conn) {
	defer conn.Close()
	defer r.flushPutTCPQueues()
	ip := parseRemoteIP(conn)

	baseHeader := &datatype.BaseHeader{}
	baseHeaderBuffer := make([]byte, datatype.MESSAGE_HEADER_LEN)
	flowHeader := &datatype.FlowHeader{}
	flowHeaderBuffer := make([]byte, datatype.FLOW_HEADER_LEN)
	reader := bufio.NewReaderSize(conn, r.TCPReaderBuffer)
	for !r.exit {
		if err := ReadN(reader, baseHeaderBuffer); err != nil {
			log.Warningf("TCP client(%s) connection read error.%s", conn.RemoteAddr().String(), err.Error())
			return
		}

		if err := baseHeader.Decode(baseHeaderBuffer); err != nil {
			log.Warningf("TCP client(%s) decode error.%s", conn.RemoteAddr().String(), err.Error())
			return
		}
		// 收到只含包头的空包丢弃
		if baseHeader.FrameSize == datatype.MESSAGE_HEADER_LEN+datatype.FLOW_HEADER_LEN {
			if err := ReadN(reader, flowHeaderBuffer); err != nil {
				log.Warningf("TCP client(%s) connection read error.%s", conn.RemoteAddr().String(), err.Error())
			} else if r.counter.Invalid == 0 {
				log.Infof("TCP client(%s) connection read empty content packet", conn.RemoteAddr().String())
			}
			atomic.AddUint64(&r.counter.Invalid, 1)
			continue
		}
		if baseHeader.Type >= datatype.MESSAGE_TYPE_MAX {
			if r.counter.Invalid == 0 {
				log.Warningf("recv from %s, unknown message type %d", conn.RemoteAddr().String(), baseHeader.Type)
			}
			atomic.AddUint64(&r.counter.Invalid, 1)
			time.Sleep(10 * time.Second)
			return
		}

		headerLen := datatype.MESSAGE_HEADER_LEN
		metricsTimestamp, vtapID, sequence := uint32(0), uint16(0), uint64(0)
		if baseHeader.Type.HeaderType() == datatype.HEADER_TYPE_LT_VTAP {
			if err := ReadN(reader, flowHeaderBuffer); err != nil {
				atomic.AddUint64(&r.counter.Invalid, 1)
				log.Warningf("TCP client(%s) connection read error.%s", conn.RemoteAddr().String(), err.Error())
				return
			}
			flowHeader.Decode(flowHeaderBuffer)
			headerLen += datatype.FLOW_HEADER_LEN

			if err := ValidateFlowVersion(baseHeader.Type, flowHeader.Version); err != nil {
				atomic.AddUint64(&r.counter.Invalid, 1)
				// 但版本不匹配，且版本小于app.LAST_SIMPLE_CODEC_VERSION时，才会拒绝连接
				if flowHeader.Version <= app.LAST_SIMPLE_CODEC_VERSION {
					log.Warningf("recv from %s, %s", conn.RemoteAddr().String(), fmt.Errorf("error: %s msgType: %s", err, datatype.MessageTypeString[baseHeader.Type]))
					time.Sleep(10 * time.Second) // 等待10秒，防止日志刷屏
					return
				}
				if r.timeNow-r.lastLogTime > LOG_INTERVAL {
					log.Infof("recv from %s, %s", conn.RemoteAddr().String(), fmt.Errorf("error: %s msgType: %s", err, datatype.MessageTypeString[baseHeader.Type]))
					r.lastLogTime = r.timeNow
				}
			}
			vtapID = flowHeader.VTAPID
			sequence = flowHeader.Sequence
		}

		dataLen := int(baseHeader.FrameSize) - headerLen
		if dataLen > RECV_BUFSIZE_MAX {
			r.logTCPReceiveInvalidData(fmt.Sprintf("TCP client(%s) wrong frame size(%d)", conn.RemoteAddr().String(), baseHeader.FrameSize))
			return
		}
		recvBuffer, isNew := AcquireRecvBuffer(dataLen, TCP)
		if isNew {
			r.counter.NewBufferCount++
		}
		if err := ReadN(reader, recvBuffer.Buffer[:dataLen]); err != nil {
			atomic.AddUint64(&r.counter.Invalid, 1)
			ReleaseRecvBuffer(recvBuffer)
			log.Warningf("TCP client(%s) connection read error.%s", conn.RemoteAddr().String(), err.Error())
			return
		}

		if baseHeader.Type == datatype.MESSAGE_TYPE_METRICS {
			metricsTimestamp = r.getMetricsTimestamp(recvBuffer.Buffer)
			r.updateCounter(metricsTimestamp)
		}
		r.status.Update(uint32(r.timeNow), baseHeader.Type, vtapID, ip, sequence, metricsTimestamp, TCP)
		atomic.AddUint64(&r.counter.RxPackets, 1)

		// Unregistered messages are discarded directly after receiving them, but the connection is not disconnected to prevent the Agent from printing exception logs
		if r.handlers[baseHeader.Type] == nil {
			atomic.AddUint64(&r.counter.Unregistered, 1)
			ReleaseRecvBuffer(recvBuffer)
		} else {
			recvBuffer.Begin = 0
			recvBuffer.End = int(baseHeader.FrameSize) - headerLen
			recvBuffer.IP = ip
			recvBuffer.VtapID = vtapID
			r.putTCPQueue(int(r.counter.RxPackets), r.handlers[baseHeader.Type], recvBuffer)
		}
	}
}

func (r *Receiver) Start() {
	var err error
	if r.serverType == UDP || r.serverType == BOTH {
		if r.UDPConn, err = net.ListenUDP("udp", r.UDPAddress); err != nil {
			log.Errorf("UDP listen at %s failed: %s", r.UDPAddress, err)
			os.Exit(-1)
		}
		r.UDPConn.SetReadBuffer(r.UDPReadBuffer)
		go r.ProcessUDPServer()
	}
	if r.serverType == TCP || r.serverType == BOTH {
		if r.TCPListener, err = net.Listen("tcp", r.TCPAddress); err != nil {
			log.Errorf("TCP listen at %s failed: %s", r.TCPAddress, err)
			os.Exit(-1)
		}
		go r.ProcessTCPServer()
	}

	stats.RegisterCountableWithModulePrefix("ingester_", "recviver", r)
}

func (r *Receiver) Close() error {
	r.exit = true
	log.Info("Stopped receiver")
	r.closed = true
	return nil
}

func (r *Receiver) Closed() bool {
	return r.closed
}
