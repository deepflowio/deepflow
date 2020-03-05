package adapter

import (
	"encoding/binary"
	"net"
	"os"
	"sync"
	"time"

	"github.com/mailru/easygo/netpoll"
	. "gitlab.x.lan/yunshan/droplet-libs/utils"
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
	instances     map[TridentKey]*tridentInstance
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
		instances = append(instances, instance)
	}
	r.instancesLock.Unlock()
	return instances
}

func (r *reciver) init(cacheSize uint64, slaves []*slave) {
	r.slaves = slaves
	r.cacheSize = cacheSize
	r.instances = make(map[TridentKey]*tridentInstance)
}

func (r *reciver) deleteInstance(key TridentKey) {
	r.instancesLock.Lock()
	delete(r.instances, key)
	r.instancesLock.Unlock()
}

func (r *reciver) addInstance(key TridentKey) *tridentInstance {
	instance := &tridentInstance{ip: IpFromUint32(key)}
	r.instancesLock.Lock()
	r.instances[key] = instance
	r.instancesLock.Unlock()
	return instance
}

func (r *reciver) cacheInstance(dispatcher *tridentDispatcher, packet *packetBuffer) {
	if dispatcher.cache == nil {
		dispatcher.cache = make([]*packetBuffer, r.cacheSize)
		dispatcher.timestamp = make([]time.Duration, r.cacheSize)
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
	instance := r.instances[packet.tridentIp]
	index := packet.decoder.tridentDispatcherIndex
	if instance == nil {
		instance = &tridentInstance{}
		instance.ip = IpFromUint32(packet.tridentIp)
		dispatcher := &instance.dispatchers[index]
		dispatcher.cache = make([]*packetBuffer, r.cacheSize)
		dispatcher.timestamp = make([]time.Duration, r.cacheSize)
		r.instancesLock.Lock()
		r.instances[packet.tridentIp] = instance
		r.instancesLock.Unlock()
	}
	r.cacheInstance(&instance.dispatchers[index], packet)
}

type udpReciver struct {
	reciver

	listener *net.UDPConn
}

func newUdpReciver(bufferSize int, cacheSize uint64, slaves []*slave) compressReciver {
	reciver := &udpReciver{}

	listener, err := net.ListenUDP("udp4", &net.UDPAddr{Port: _LISTEN_PORT_UDP})
	if err != nil {
		log.Error(err)
		return nil
	}
	listener.SetReadBuffer(bufferSize)
	listener.SetReadDeadline(time.Now().Add(_RECV_TIMEOUT))
	reciver.listener = listener

	reciver.statsCounter.init()
	reciver.reciver.init(cacheSize, slaves)
	return reciver
}

func (r *udpReciver) updateTimeout() {
	r.listener.SetReadDeadline(time.Now().Add(_RECV_TIMEOUT))
}

func (r *udpReciver) recv() (*packetBuffer, error) {
	packet := acquirePacketBuffer()
	_, remote, err := r.listener.ReadFromUDP(packet.buffer)
	if err != nil {
		if err.(net.Error).Timeout() {
			r.updateTimeout()
			return nil, timeoutError("udp reciver recv timeout")
		}
		return nil, err
	}
	ip := IpToUint32(remote.IP.To4())
	packet.init(ip)
	return packet, nil
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
				if invalid, _ := batch[i].decoder.DecodeHeader(); invalid {
					r.counter.RxInvalid++
					r.stats.RxInvalid++
					releasePacketBuffer(batch[i])
					continue
				}
				batch[i].calcHash()
				r.findAndAdd(batch[i])
			}
			count = 0
		}
	}()
}

type tcpReciver struct {
	reciver
}

func listen(port int) (ln int, err error) {
	ln, err = unix.Socket(unix.AF_INET, unix.O_NONBLOCK|unix.SOCK_STREAM, 0)
	if err != nil {
		return
	}

	// Need for avoid receiving EADDRINUSE error.
	// Closed listener could be in TIME_WAIT state some time.
	unix.SetsockoptInt(ln, unix.SOL_SOCKET, unix.SO_REUSEADDR, 1)

	addr := &unix.SockaddrInet4{
		Port: port,
		Addr: [4]byte{0, 0, 0, 0},
	}

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

			ip := getIp(remote)
			ipInt := IpToUint32(ip)
			instance := r.addInstance(ipInt)
			log.Infof("trident(%s) connect to host, use fd %d", ip, conn)

			ep.Add(conn, netpoll.EPOLLIN|netpoll.EPOLLET|netpoll.EPOLLHUP|netpoll.EPOLLRDHUP,
				func(event netpoll.EpollEvent) {
					if event != netpoll.EPOLLIN {
						ep.Del(conn)
						unix.Close(conn)
						r.deleteInstance(ipInt)
						return
					}

					for {
						packet := acquirePacketBuffer()
						n, _ := unix.Read(conn, packet.buffer)
						if n <= 0 {
							releasePacketBuffer(packet)
							break
						}
						packet.init(ipInt)
						invalid, frameSize := packet.decoder.DecodeHeader()
						if invalid {
							r.counter.RxInvalid++
							r.stats.RxInvalid++
							releasePacketBuffer(packet)
							continue
						}
						if n == int(frameSize) {
							packet.calcHash()
							r.cacheInstance(&instance.dispatchers[packet.decoder.tridentDispatcherIndex], packet)
						} else if n > int(frameSize) {
							buffer := packet.buffer
							packets := make([]*packetBuffer, 0, 4)
							packets = append(packets, packet)

							for decodeLen := frameSize; int(decodeLen) < n; decodeLen += frameSize {
								packet := acquirePacketBuffer()

								frameSize = binary.BigEndian.Uint16(buffer[decodeLen:])
								copy(packet.buffer, buffer[decodeLen:decodeLen+frameSize])

								packet.init(ipInt)
								if invalid, _ := packet.decoder.DecodeHeader(); invalid {
									r.counter.RxInvalid++
									r.stats.RxInvalid++
									releasePacketBuffer(packet)
									continue
								}

								packets = append(packets, packet)
							}

							for _, packet := range packets {
								packet.calcHash()
								r.cacheInstance(&instance.dispatchers[packet.decoder.tridentDispatcherIndex], packet)
							}
						}
					}
				})
		})
	}()
}
