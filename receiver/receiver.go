package receiver

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	logging "github.com/op/go-logging"

	"gitlab.x.lan/yunshan/droplet-libs/app"
	"gitlab.x.lan/yunshan/droplet-libs/cache"
	"gitlab.x.lan/yunshan/droplet-libs/datatype"
	"gitlab.x.lan/yunshan/droplet-libs/debug"
	"gitlab.x.lan/yunshan/droplet-libs/pool"
	"gitlab.x.lan/yunshan/droplet-libs/queue"
	"gitlab.x.lan/yunshan/droplet-libs/stats"
	. "gitlab.x.lan/yunshan/droplet-libs/utils"
)

const (
	RECV_BUFSIZE              = 1 << 16 // 默认trident发送时，不会超过MTU的大小,当local发送时, MTU是64k
	RECV_TIMEOUT              = 30 * time.Second
	QUEUE_CACHE_FLUSH_TIMEOUT = 3
	DROP_DETECT_WINDOW_SIZE   = 1024
	QUEUE_BATCH_NUM           = 16
	LOG_INTERVAL              = 3
)

var log = logging.MustGetLogger("receiver")

type RecvBuffer struct {
	Begin  int // 开始位置
	End    int
	Buffer []byte
	IP     net.IP // 保存消息的发送方IP
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

var recvBufferPool = pool.NewLockFreePool(
	func() interface{} {
		return &RecvBuffer{
			Buffer: make([]byte, RECV_BUFSIZE),
		}
	},
	pool.OptionPoolSizePerCPU(32),
	pool.OptionInitFullPoolSize(32),
)

func AcquireRecvBuffer() *RecvBuffer {
	return recvBufferPool.Get().(*RecvBuffer)
}

func ReleaseRecvBuffer(b *RecvBuffer) {
	b.Begin = 0
	b.End = 0
	b.IP = nil
	recvBufferPool.Put(b)
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
	VTAPID               uint16
	serverType           ServerType
	ip                   net.IP
	firstSeq             uint64
	lastSeq              uint64
	firstRemoteTimestamp uint32 // 第一次收到数据时数据中的时间戳
	firstLocalTimestamp  uint32 // 第一次收到数据时的本地时间
	lastRemoteTimestamp  uint32 // 最后一次收到数据时数据中的时间戳
	LastLocalTimestamp   uint32 // 最后一次收到数据时的本地时间
}

type Handler struct {
	msgType        uint8 // 在datatype/droplet-message.go中定义
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
	TCPListener      net.Listener
	TCPAddress       string
	lastUDPFlushTime int64
	lastTCPFlushTime int64
	timeNow          int64
	lastLogTime      int64
	dropLogCount     int64

	exit   bool
	closed bool

	counter *ReceiverCounter

	statusLock sync.Mutex
	status     map[uint16]*Status
}

type ReceiverCounter struct {
	Invalid         uint64 `statsd:"invalid"` // version不匹配
	RxPackets       uint64 `statsd:"rx_packets"`
	MaxDelay        int64  `statsd:"max_delay"`
	MinDelay        int64  `statsd:"min_delay"`
	UDPDropped      uint64 `statsd:"udp_dropped"`
	UDPDisorder     uint64 `statsd:"udp_disorder"`      // 乱序个数
	UDPDisorderSize uint64 `statsd:"udp_disorder_size"` // 乱序最大范围

}

func NewReceiver(
	listenPort, UDPReadBuffer int, // 监听端口，默认同时监听tcp和upd的端口
) *Receiver {
	receiver := &Receiver{
		handlers:      make([]*Handler, datatype.MESSAGE_TYPE_MAX),
		serverType:    BOTH,
		UDPAddress:    &net.UDPAddr{Port: listenPort},
		UDPReadBuffer: UDPReadBuffer,
		TCPAddress:    fmt.Sprintf("0.0.0.0:%d", listenPort),
		counter:       &ReceiverCounter{},
		status:        make(map[uint16]*Status),
	}

	debug.Register(TRIDENT_ADAPTER_STATUS_CMD, receiver)
	receiver.DropDetection.Init("receiver", DROP_DETECT_WINDOW_SIZE)
	go receiver.timeNowTicker()
	return receiver
}

// 注册处理函数，收到msgType的数据，放到outQueues中
func (r *Receiver) RegistHandler(msgType uint8, outQueues queue.MultiQueueWriter, nQueues int) error {
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

func (r *Receiver) SetServerType(serverType ServerType) {
	r.serverType = serverType
}

func (r *Receiver) GetCounter() interface{} {
	counter := &ReceiverCounter{MaxDelay: -3600, MinDelay: 3600}
	counter, r.counter = r.counter, counter

	dropCounter := r.DropDetection.GetCounter().(*cache.DropCounter)
	counter.UDPDropped = dropCounter.Dropped
	counter.UDPDisorder = dropCounter.Disorder
	counter.UDPDisorderSize = dropCounter.DisorderSize
	return counter
}

func (r *Receiver) timeNowTicker() {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	for range ticker.C {
		if r.exit {
			return
		}
		r.timeNow = time.Now().Unix()
	}
}

func (r *Receiver) putUDPQueue(hash int, handler *Handler, buffer *RecvBuffer) {
	hashKey := hash % handler.nQueues

	queueCache := &handler.queueUDPCaches[hashKey]
	if len(queueCache.values) >= QUEUE_BATCH_NUM || r.timeNow-queueCache.timestamp > QUEUE_CACHE_FLUSH_TIMEOUT {
		queueCache.timestamp = r.timeNow
		if len(queueCache.values) > 0 {
			handler.queues.Put(queue.HashKey(hashKey), queueCache.values...)
			queueCache.values = queueCache.values[:0]
		}
	}
	queueCache.values = append(queueCache.values, buffer)
}

func (r *Receiver) putTCPQueue(hash int, handler *Handler, buffer *RecvBuffer) {
	hashKey := hash % handler.nQueues

	queueCache := &handler.queueTCPCaches[hashKey]
	queueCache.Lock() // 存在多个tcp连接同时put，故需要加锁
	if len(queueCache.values) >= QUEUE_BATCH_NUM || r.timeNow-queueCache.timestamp > QUEUE_CACHE_FLUSH_TIMEOUT {
		queueCache.timestamp = r.timeNow
		if len(queueCache.values) > 0 {
			handler.queues.Put(queue.HashKey(hashKey), queueCache.values...)
			queueCache.values = queueCache.values[:0]
		}
	}
	queueCache.values = append(queueCache.values, buffer)
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
			if len(queueCache.values) > 0 {
				queueCache.timestamp = time.Now().Unix()
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
			queueCache.Lock()
			if len(queueCache.values) > 0 {
				queueCache.timestamp = time.Now().Unix()
				handler.queues.Put(queue.HashKey(i), queueCache.values...)
				queueCache.values = queueCache.values[:0]
			}
			queueCache.Unlock()
		}
	}
	r.lastTCPFlushTime = r.timeNow
}

func (r *Receiver) tridentStatus(vtapID uint16, ip net.IP, seq uint64, timestamp uint32, serverType ServerType) {
	now := uint32(time.Now().Unix())
	delay := int64(now) - int64(timestamp)
	if r.counter.MaxDelay < delay {
		r.counter.MaxDelay = delay
	}
	if r.counter.MinDelay > delay {
		r.counter.MinDelay = delay
	}
	r.statusLock.Lock()
	if status, ok := r.status[vtapID]; ok {
		r.statusLock.Unlock()
		status.VTAPID = vtapID
		status.ip = ip
		status.lastSeq = seq
		status.lastRemoteTimestamp = timestamp
		status.LastLocalTimestamp = now
		status.serverType = serverType
	} else {
		r.status[vtapID] = &Status{
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
		r.statusLock.Unlock()
	}
}

// 用来上报trisolaris, trident最后的活跃时间
func (r *Receiver) GetTridentStatus() []*Status {
	r.statusLock.Lock()
	status := make([]*Status, 0, len(r.status))
	for _, s := range r.status {
		status = append(status, s)
	}
	r.statusLock.Unlock()
	return status
}

// 由于引用了app，导致递归引用,不能在datatype中定义类函数，故放到这里
func ValidateFlowVersion(t uint8, version uint32) error {
	var expectVersion uint32
	switch t {
	case datatype.MESSAGE_TYPE_METRICS:
		expectVersion = app.VERSION
	case datatype.MESSAGE_TYPE_TAGGEDFLOW, datatype.MESSAGE_TYPE_PROTOCOLLOG:
		expectVersion = datatype.VERSION
	default:
		return fmt.Errorf("invalid message type %d", t)
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
		log.Warningf("UDP socket recv size %d from %s, %s, already drop log count %d", size, remoteAddr.IP, err, r.dropLogCount)
	} else {
		log.Warningf("UDP socket recv size %d, %s, already drop log count %d", size, err, r.dropLogCount)
	}
}

func (r *Receiver) ProcessUDPServer() {
	defer r.UDPConn.Close()
	baseHeader := &datatype.BaseHeader{}
	flowHeader := &datatype.FlowHeader{}
	r.setUDPTimeout()
	for !r.exit {
		recvBuffer := AcquireRecvBuffer()
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
		if r.handlers[baseHeader.Type] == nil {
			ReleaseRecvBuffer(recvBuffer)
			r.logReceiveError(size, remoteAddr, fmt.Errorf("unregist message type %d", baseHeader.Type))
			continue
		}

		headerLen := datatype.MESSAGE_HEADER_LEN
		// 对Metrics和TaggedFlow,AppProtoLogData处理
		if baseHeader.Type == datatype.MESSAGE_TYPE_METRICS ||
			baseHeader.Type == datatype.MESSAGE_TYPE_TAGGEDFLOW ||
			baseHeader.Type == datatype.MESSAGE_TYPE_PROTOCOLLOG {
			flowHeader.Decode(recvBuffer.Buffer[datatype.MESSAGE_HEADER_LEN:])
			headerLen += datatype.FLOW_HEADER_LEN

			if err := ValidateFlowVersion(baseHeader.Type, flowHeader.Version); err != nil {
				ReleaseRecvBuffer(recvBuffer)
				r.logReceiveError(size, remoteAddr, err)
				continue
			}

			if baseHeader.Type == datatype.MESSAGE_TYPE_METRICS {
				timestamp := r.getMetricsTimestamp(recvBuffer.Buffer[headerLen:])
				ipHash := getIpHash(remoteAddr.IP)
				r.DropDetection.Detect(ipHash, flowHeader.Sequence, timestamp)
				r.tridentStatus(flowHeader.VTAPID, remoteAddr.IP, flowHeader.Sequence, timestamp, UDP)
			}
		}
		atomic.AddUint64(&r.counter.RxPackets, 1)

		recvBuffer.Begin = headerLen
		recvBuffer.End = size // syslog,statsd数据的FrameSize长度是0,需要以实际长度为准
		if baseHeader.Type == datatype.MESSAGE_TYPE_COMPRESS {
			recvBuffer.End = int(baseHeader.FrameSize) // 可能收到的包长会大于FrameSize, 以FrameSize为准
		}
		recvBuffer.IP = remoteAddr.IP
		r.putUDPQueue(int(r.counter.RxPackets), r.handlers[baseHeader.Type], recvBuffer)
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
		log.Infof("TCP client(%s) connect success.", conn.RemoteAddr().String())
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
	if len(buffer) >= 4 {
		return binary.LittleEndian.Uint32(buffer) // doc的前4个字节是时间
	} else {
		return uint32(time.Now().Unix())
	}
}

// 固定读取buffer长度的数据
func ReadN(conn net.Conn, buffer []byte) error {
	total := 0
	for total < len(buffer) {
		n, err := conn.Read(buffer[total:])
		if err != nil {
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
	for !r.exit {
		if err := ReadN(conn, baseHeaderBuffer); err != nil {
			log.Warningf("TCP client(%s) connection read error.%s", conn.RemoteAddr().String(), err.Error())
			return
		}

		if err := baseHeader.Decode(baseHeaderBuffer); err != nil {
			log.Warningf("TCP client(%s) decode error.%s", conn.RemoteAddr().String(), err.Error())
			return

		}
		if r.handlers[baseHeader.Type] == nil {
			atomic.AddUint64(&r.counter.Invalid, 1)
			log.Warningf("recv from %s, unregist message type %d", conn.RemoteAddr().String(), baseHeader.Type)
			return
		}

		headerLen := datatype.MESSAGE_HEADER_LEN
		// 对metrics和TaggedFlow处理
		if baseHeader.Type == datatype.MESSAGE_TYPE_METRICS ||
			baseHeader.Type == datatype.MESSAGE_TYPE_TAGGEDFLOW ||
			baseHeader.Type == datatype.MESSAGE_TYPE_PROTOCOLLOG {
			if err := ReadN(conn, flowHeaderBuffer); err != nil {
				atomic.AddUint64(&r.counter.Invalid, 1)
				log.Warningf("TCP client(%s) connection read error.%s", conn.RemoteAddr().String(), err.Error())
				return
			}
			flowHeader.Decode(flowHeaderBuffer)
			headerLen += datatype.FLOW_HEADER_LEN

			if err := ValidateFlowVersion(baseHeader.Type, flowHeader.Version); err != nil {
				atomic.AddUint64(&r.counter.Invalid, 1)
				log.Warningf("recv from %s, %s", conn.RemoteAddr().String(), err)
				return
			}
		}

		recvBuffer := AcquireRecvBuffer()
		if err := ReadN(conn, recvBuffer.Buffer[:int(baseHeader.FrameSize)-headerLen]); err != nil {
			atomic.AddUint64(&r.counter.Invalid, 1)
			ReleaseRecvBuffer(recvBuffer)
			log.Warningf("TCP client(%s) connection read error.%s", conn.RemoteAddr().String(), err.Error())
			return
		}

		if baseHeader.Type == datatype.MESSAGE_TYPE_METRICS {
			r.tridentStatus(flowHeader.VTAPID, ip,
				flowHeader.Sequence,
				r.getMetricsTimestamp(recvBuffer.Buffer),
				TCP)
		}

		atomic.AddUint64(&r.counter.RxPackets, 1)
		recvBuffer.Begin = 0
		recvBuffer.End = int(baseHeader.FrameSize) - headerLen
		recvBuffer.IP = ip
		r.putTCPQueue(int(r.counter.RxPackets), r.handlers[baseHeader.Type], recvBuffer)
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

	stats.RegisterCountable("recviver", r)
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
