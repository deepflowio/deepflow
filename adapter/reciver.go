package adapter

import (
	. "encoding/binary"
	"math"
	"net"
	"os"
	"sync"
	"time"

	"github.com/mailru/easygo/netpoll"
	"gitlab.x.lan/yunshan/droplet-libs/datatype"
	"golang.org/x/sys/unix"
)

const (
	_LISTEN_PORT_UDP = 20033
	_LISTEN_PORT_TCP = 20033
	_RECV_TIMEOUT    = 2 * time.Second
)

const (
	_UDP_RECIVER = iota
	_TCP_RECIVER
	_MAX_RECIVER

	_MIN_RECIVER = _UDP_RECIVER
)

type reciverError interface {
	error
	Timeout() bool
}

type timeoutError string

func (e timeoutError) Error() string { return string(e) }
func (e timeoutError) Timeout() bool { return true }

type compressReciver interface {
	start()
	GetStatsCounter() *PacketCounter
	GetCounter() *PacketCounter
	GetInstances() []*tridentInstance
}

type reciver struct {
	statsCounter
	slaves []*slave

	cacheSize uint64

	instancesLock sync.Mutex // 仅用于droplet-ctl打印trident信息
	instances     [math.MaxUint16 + 1]*tridentInstance
}

func (r *reciver) GetStatsCounter() *PacketCounter {
	counter, _ := r.statsCounter.GetStatsCounter().(*PacketCounter)
	return counter
}

func (r *reciver) GetCounter() *PacketCounter {
	counter, _ := r.statsCounter.GetCounter().(*PacketCounter)
	return counter
}

func (r *reciver) GetInstances() []*tridentInstance {
	instances := make([]*tridentInstance, 0, 8)
	r.instancesLock.Lock()
	for _, instance := range r.instances {
		if instance != nil {
			instances = append(instances, instance)
		}
	}
	r.instancesLock.Unlock()
	return instances
}

func (r *reciver) init(cacheSize uint64, slaves []*slave) {
	r.slaves = slaves
	r.cacheSize = cacheSize
}

func (r *reciver) deleteInstance(ip net.IP) {
	r.instancesLock.Lock()
	for i := 0; i < math.MaxUint16; i++ {
		if r.instances[i] != nil && r.instances[i].ip.Equal(ip) {
			r.instances[i] = nil
		}
	}
	r.instancesLock.Unlock()
}

func (r *reciver) addInstance(vtapId uint16, instance *tridentInstance) {
	instance.inTable = true
	r.instancesLock.Lock()
	r.instances[vtapId] = instance
	r.instancesLock.Unlock()
}

func (r *reciver) cacheInstance(instance *tridentInstance, packet *packetBuffer) {
	index := packet.decoder.tridentDispatcherIndex
	dispatcher := &instance.dispatchers[index]
	if dispatcher.cache == nil {
		dispatcher.cache = make([]*packetBuffer, r.cacheSize)
		dispatcher.timestamp = make([]time.Duration, r.cacheSize)
	}
	if !instance.inTable {
		r.addInstance(packet.vtapId, instance)
	}

	rxDropped, rxErrors := cacheLookup(dispatcher, packet, r.cacheSize, r.slaves)
	r.counter.RxPackets++
	r.counter.RxDropped += rxDropped
	r.counter.RxErrors += rxErrors
	r.stats.RxPackets++
	r.stats.RxDropped += rxDropped
	r.stats.RxErrors += rxErrors
}

func (r *reciver) findAndAdd(packet *packetBuffer) {
	instance := r.instances[packet.vtapId]
	if instance == nil {
		instance = &tridentInstance{inTable: true}
		instance.ip = packet.tridentIp
		r.instancesLock.Lock()
		r.instances[packet.vtapId] = instance
		r.instancesLock.Unlock()
	}
	r.cacheInstance(instance, packet)
}

type udpDecoder interface {
	decode(packet *packetBuffer)
}

type udpReciver struct {
	reciver

	listener *net.UDPConn
	decoders [datatype.MESSAGE_TYPE_MAX]udpDecoder
}

func newUdpReciver(bufferSize int, cacheSize uint64, slaves []*slave) compressReciver {
	reciver := &udpReciver{}

	listener, err := net.ListenUDP("udp", &net.UDPAddr{Port: _LISTEN_PORT_UDP})
	if err != nil {
		log.Error(err)
		return nil
	}
	listener.SetReadBuffer(bufferSize)
	listener.SetReadDeadline(time.Now().Add(_RECV_TIMEOUT))
	reciver.listener = listener

	reciver.statsCounter.init()
	reciver.reciver.init(cacheSize, slaves)

	reciver.decoders[datatype.MESSAGE_TYPE_SYSLOG] = newSyslogWriter()
	reciver.decoders[datatype.MESSAGE_TYPE_STATSD] = newStatsdWriter()
	return reciver
}

func (r *udpReciver) updateTimeout() {
	r.listener.SetReadDeadline(time.Now().Add(_RECV_TIMEOUT))
}

func (r *udpReciver) recv() (*packetBuffer, error) {
	packet := acquirePacketBuffer()
	n, remote, err := r.listener.ReadFromUDP(packet.buffer)
	if err != nil {
		if err.(net.Error).Timeout() {
			r.updateTimeout()
			return nil, timeoutError("udp reciver recv timeout")
		}
		return nil, err
	}
	packet.bufferLength = n
	packet.init(remote.IP)
	return packet, nil
}

func (r *udpReciver) decodeCompress(packet *packetBuffer) {
	invalid, _, vtapId := packet.decoder.DecodeHeader()
	if invalid {
		r.counter.RxInvalid++
		r.stats.RxInvalid++
		releasePacketBuffer(packet)
		return
	}

	packet.calcHash(vtapId)
	r.findAndAdd(packet)
}

func (r *udpReciver) decode(packet *packetBuffer) {
	messageType := packet.buffer[datatype.MESSAGE_TYPE_OFFSET]

	switch messageType {
	case datatype.MESSAGE_TYPE_COMPRESS:
		r.decodeCompress(packet)
	default:
		if messageType < datatype.MESSAGE_TYPE_MAX {
			r.decoders[messageType].decode(packet)
		}
	}
}

func (r *udpReciver) start() {
	go func() {
		batch := [BATCH_SIZE]*packetBuffer{}
		count := 0

		for {
			for i := 0; i < BATCH_SIZE; i++ {
				packet, err := r.recv()
				if err != nil {
					if errno, ok := err.(reciverError); ok && errno.Timeout() {
						break
					}
					log.Errorf("trident adapter udp reicver err: %s", err)
					os.Exit(1)
				}
				batch[i] = packet
				count++
			}
			for i := 0; i < count; i++ {
				r.decode(batch[i])
			}
			count = 0
		}
	}()
}

type tcpReciver struct {
	reciver
}

func listen(port int) (ln int, err error) {
	// 这个连接会同时支持IPv4和IPv6
	ln, err = unix.Socket(unix.AF_INET6, unix.O_NONBLOCK|unix.SOCK_STREAM, 0)
	if err != nil {
		return
	}

	// Need for avoid receiving EADDRINUSE error.
	// Closed listener could be in TIME_WAIT state some time.
	unix.SetsockoptInt(ln, unix.SOL_SOCKET, unix.SO_REUSEADDR, 1)

	addr := &unix.SockaddrInet6{Port: port}
	if err = unix.Bind(ln, addr); err != nil {
		return
	}
	err = unix.Listen(ln, 4)
	return
}

func getIp(sa unix.Sockaddr) net.IP {
	switch sa.(type) {
	case *unix.SockaddrInet4:
		sa4 := sa.(*unix.SockaddrInet4)
		return net.IP(sa4.Addr[:])
	case *unix.SockaddrInet6:
		sa6 := sa.(*unix.SockaddrInet6)
		return net.IP(sa6.Addr[:])
	}
	return nil
}

func newTcpReciver(cacheSize uint64, slaves []*slave) compressReciver {
	reciver := &tcpReciver{}

	reciver.statsCounter.init()
	reciver.reciver.init(cacheSize, slaves)
	return reciver
}

func (r *tcpReciver) decodeCompress(tridentIp net.IP, instance *tridentInstance, packet *packetBuffer) {
	packet.init(tridentIp)
	invalid, _, vtapId := packet.decoder.DecodeHeader()
	if invalid {
		r.counter.RxInvalid++
		r.stats.RxInvalid++
		releasePacketBuffer(packet)
		return
	}
	packet.calcHash(vtapId)
	r.cacheInstance(instance, packet)
}

func (r *tcpReciver) decode(tridentIp net.IP, instance *tridentInstance, packet *packetBuffer) {
	messageType := packet.buffer[datatype.MESSAGE_TYPE_OFFSET]

	switch messageType {
	case datatype.MESSAGE_TYPE_COMPRESS:
		r.decodeCompress(tridentIp, instance, packet)
	default: // TODO
		return
	}
}

func (r *tcpReciver) start() {
	go func() {

		ep, err := netpoll.EpollCreate(&netpoll.EpollConfig{func(error) {}})
		if err != nil {
			log.Error(err)
			os.Exit(1)
		}

		fd, err := listen(_LISTEN_PORT_TCP)
		if err != nil {
			log.Error(err)
			os.Exit(1)
		}

		err = ep.Add(fd, netpoll.EPOLLIN, func(event netpoll.EpollEvent) {
			if event != netpoll.EPOLLIN {
				return
			}
			conn, remote, err := unix.Accept(fd)
			if err != nil {
				log.Warning("could not accept: %s", err)
				return
			}

			unix.SetNonblock(conn, true)

			tridentIp := getIp(remote)
			instance := &tridentInstance{inTable: false, ip: tridentIp}
			log.Infof("trident(%s) connect to host, use fd %d", tridentIp, conn)
			var packet *packetBuffer
			var offset int

			ep.Add(conn, netpoll.EPOLLIN|netpoll.EPOLLET|netpoll.EPOLLHUP|netpoll.EPOLLRDHUP,
				func(event netpoll.EpollEvent) {
					if event != netpoll.EPOLLIN {
						ep.Del(conn)
						unix.Close(conn)
						r.deleteInstance(tridentIp)
						return
					}

					for {
						if packet == nil {
							packet = acquirePacketBuffer()

							n, _ := unix.Read(conn, packet.buffer[:2])
							if n < 2 {
								releasePacketBuffer(packet)
								packet = nil
								break
							}
							offset = 2
						}
						frameSize := BigEndian.Uint16(packet.buffer)

						var n int
						for ; offset < int(frameSize); offset += n {
							n, _ = unix.Read(conn, packet.buffer[offset:frameSize])
							if n <= 0 {
								return
							}
						}
						r.decode(tridentIp, instance, packet)
						packet = nil
					}
				})
		})
	}()
}
