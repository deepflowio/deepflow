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

	"gitlab.x.lan/yunshan/droplet-libs/cache"
	"gitlab.x.lan/yunshan/droplet-libs/debug"
	"gitlab.x.lan/yunshan/droplet-libs/pool"
	"gitlab.x.lan/yunshan/droplet-libs/queue"
	"gitlab.x.lan/yunshan/droplet-libs/stats"
	. "gitlab.x.lan/yunshan/droplet-libs/utils"
)

const (
	RECV_BUFSIZE              = 16 << 10 // 默认trident发送时，不会超过MTU的大小, 除非某个DOC超过了MTU，可能收到大的包
	QUEUE_CACHE_FLUSH_TIMEOUT = 3
	SOCKET_READ_BUFFER_SIZE   = 32 << 20
	DROP_DETECT_WINDOW_SIZE   = 1024
)

var log = logging.MustGetLogger("receiver")

type RecvBytes []byte

// 实现空接口，仅用于队列调试打印
func (r RecvBytes) AddReferenceCount() {
}

func (r RecvBytes) SubReferenceCount() bool {
	return false
}

var recvBufferPool = pool.NewLockFreePool(
	func() interface{} {
		return make([]byte, 0, RECV_BUFSIZE)
	},
	pool.OptionPoolSizePerCPU(8),
	pool.OptionInitFullPoolSize(8),
)

func AcquireRecvBuffer() []byte {
	return recvBufferPool.Get().([]byte)
}

func ReleaseRecvBuffer(b []byte) {
	b = b[:0]
	recvBufferPool.Put(b)
}

type QueueCache struct {
	sync.Mutex
	values    []byte
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
	serverType           ServerType
	ip                   net.IP
	firstSeq             uint64
	lastSeq              uint64
	firstRemoteTimestamp uint32 // 第一次收到数据时数据中的时间戳
	firstLocalTimestamp  uint32 // 第一次收到数据时的本地时间
	lastRemoteTimestamp  uint32 // 最后一次收到数据时数据中的时间戳
	lastLocalTimestamp   uint32 // 最后一次收到数据时的本地时间
}

type Receiver struct {
	cache.DropDetection

	dataType DataType

	outQueues        queue.MultiQueueWriter
	nQueues          int
	queueBatchCaches []QueueCache

	serverType  ServerType
	UDPAddress  *net.UDPAddr
	UDPConn     *net.UDPConn
	TCPListener net.Listener
	TCPAddress  string

	exit   bool
	closed bool

	counter *ReceiverCounter

	statusLock sync.Mutex
	status     map[uint32]*Status
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
	dataType DataType, // 目前支持ZeroDoc和TaggedFlow 处理上不同点 1, 版本校验  2, 时间戳获取方式
	listenPort int, // 监听端口，默认同时监听tcp和upd的端口
	outQueues queue.MultiQueueWriter,
	nQueues int) *Receiver {

	queueBatchCaches := make([]QueueCache, nQueues)
	for i := 0; i < nQueues; i++ {
		queueBatchCaches[i].values = AcquireRecvBuffer()
	}

	receiver := &Receiver{
		dataType:         dataType,
		outQueues:        outQueues,
		nQueues:          nQueues,
		queueBatchCaches: queueBatchCaches,
		serverType:       BOTH,
		UDPAddress:       &net.UDPAddr{Port: listenPort},
		TCPAddress:       fmt.Sprintf("0.0.0.0:%d", listenPort),
		counter:          &ReceiverCounter{},
		status:           make(map[uint32]*Status),
	}

	debug.Register(TRIDENT_ADAPTER_STATUS_CMD, receiver)
	receiver.DropDetection.Init("receiver", DROP_DETECT_WINDOW_SIZE)
	return receiver
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

func (r *Receiver) putQueue(hashKey queue.HashKey, bytes []byte) {
	queueCache := &r.queueBatchCaches[hashKey]

	now := time.Now().Unix()
	queueCache.Lock() // 存在多个tcp连接同时put，故需要加锁
	if len(queueCache.values)+len(bytes) >= RECV_BUFSIZE || now-queueCache.timestamp > QUEUE_CACHE_FLUSH_TIMEOUT {
		queueCache.timestamp = now
		if len(queueCache.values) > 0 {
			r.outQueues.Put(hashKey, RecvBytes(queueCache.values))
			queueCache.values = AcquireRecvBuffer()
		}
	}

	queueCache.values = append(queueCache.values, bytes...)
	queueCache.Unlock()
}

func (r *Receiver) flushPutQueues() {
	for i := 0; i < r.nQueues; i++ {
		queueCache := &r.queueBatchCaches[i]
		if len(queueCache.values) > 0 {
			queueCache.timestamp = time.Now().Unix()
			r.outQueues.Put(queue.HashKey(i), RecvBytes(queueCache.values))
			queueCache.values = AcquireRecvBuffer()
		}
	}
}

func (r *Receiver) tridentStatus(ipHash uint32, ip net.IP, seq uint64, timestamp uint32, serverType ServerType) {
	now := uint32(time.Now().Unix())
	delay := int64(now) - int64(timestamp)
	if r.counter.MaxDelay < delay {
		r.counter.MaxDelay = delay
	}
	if r.counter.MinDelay > delay {
		r.counter.MinDelay = delay
	}
	r.statusLock.Lock()
	if status, ok := r.status[ipHash]; ok {
		r.statusLock.Unlock()
		status.ip = ip
		status.lastSeq = seq
		status.lastRemoteTimestamp = timestamp
		status.lastLocalTimestamp = now
		status.serverType = serverType
	} else {
		r.status[ipHash] = &Status{
			serverType:           serverType,
			ip:                   ip,
			lastSeq:              seq,
			lastRemoteTimestamp:  timestamp,
			lastLocalTimestamp:   now,
			firstSeq:             seq,
			firstRemoteTimestamp: timestamp,
			firstLocalTimestamp:  now,
		}
		r.statusLock.Unlock()
	}
}

func (r *Receiver) ProcessUDPServer() {
	defer r.UDPConn.Close()
	recvBuffer := make([]byte, RECV_BUFSIZE)
	header := &Header{}
	for !r.exit {
		size, remoteAddr, err := r.UDPConn.ReadFromUDP(recvBuffer)
		if err != nil || size < HEADER_LEN {
			log.Warningf("recv from udp socket failed: size=%d, %s", size, err)
			r.flushPutQueues()
			time.Sleep(10 * time.Second)
			continue
		}

		header.Decode(recvBuffer)
		if err := header.CheckVersion(r.dataType); err != nil {
			atomic.AddUint64(&r.counter.Invalid, 1)
			if remoteAddr != nil {
				log.Warningf("recv from %s, %s", remoteAddr.IP, err)
			} else {
				log.Warning(err)
			}
			continue
		}
		atomic.AddUint64(&r.counter.RxPackets, 1)

		timestamp := r.getTimestamp(recvBuffer[HEADER_LEN:])
		ipHash := getIpHash(remoteAddr.IP)
		r.DropDetection.Detect(ipHash, header.Sequence, timestamp)
		r.tridentStatus(ipHash, remoteAddr.IP, header.Sequence, timestamp, UDP)

		r.putQueue(queue.HashKey(uint32(r.counter.RxPackets)%(uint32(r.nQueues))), recvBuffer[HEADER_LEN:size])
	}
}

func (r *Receiver) ProcessTCPServer() {
	defer r.TCPListener.Close()
	for !r.exit {
		conn, err := r.TCPListener.Accept()
		if err != nil {
			log.Errorf("Accept error.%s ", err.Error())
			time.Sleep(10 * time.Second)
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

func (r *Receiver) getTimestamp(buffer []byte) uint32 {
	if r.dataType == ZeroDoc {
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

	ip := parseRemoteIP(conn)
	ipHash := getIpHash(ip)

	recvBuffer := make([]byte, RECV_BUFSIZE)
	header := &Header{}
	headerBuffer := make([]byte, HEADER_LEN)
	for !r.exit {
		if err := ReadN(conn, headerBuffer); err != nil {
			log.Errorf("TCP client(%s) connection read error.%s", conn.RemoteAddr().String(), err.Error())
			return
		}

		header.Decode(headerBuffer)
		if err := header.CheckVersion(r.dataType); err != nil {
			atomic.AddUint64(&r.counter.Invalid, 1)
			log.Warningf("recv from %s, %s", conn.RemoteAddr().String(), err)
			continue
		}

		dataLen := int(header.Length)
		if dataLen > len(recvBuffer) {
			log.Errorf("data len is(%d) exceed(%d)", dataLen, len(recvBuffer))
			return
		}

		if err := ReadN(conn, recvBuffer[:dataLen]); err != nil {
			log.Errorf("TCP client(%s) connection read error.%s", conn.RemoteAddr().String(), err.Error())
			return
		}

		r.tridentStatus(ipHash, ip,
			header.Sequence,
			r.getTimestamp(recvBuffer),
			TCP)

		atomic.AddUint64(&r.counter.RxPackets, 1)
		r.putQueue(queue.HashKey(uint32(r.counter.RxPackets)%(uint32(r.nQueues))), recvBuffer[:dataLen])
	}
}

func (r *Receiver) Start() {
	var err error
	if r.serverType == UDP || r.serverType == BOTH {
		if r.UDPConn, err = net.ListenUDP("udp", r.UDPAddress); err != nil {
			log.Errorf("UDP listen at %s failed: %s", r.UDPAddress, err)
			os.Exit(-1)
		}
		r.UDPConn.SetReadBuffer(SOCKET_READ_BUFFER_SIZE)
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
