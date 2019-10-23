package adapter

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"

	zmq "github.com/pebbe/zmq4"
	. "gitlab.x.lan/yunshan/droplet-libs/utils"
)

const (
	_LISTEN_PORT  = 20033
	_RECV_TIMEOUT = 2 * time.Second
)

const (
	_UDP_RECIVER = iota
	_ZMQ_RECIVER
	_MAX_RECIVER
)

type reciverError interface {
	error
	Timeout() bool
}

type timeoutError string

func (e timeoutError) Error() string { return string(e) }
func (e timeoutError) Timeout() bool { return true }

type compressReciver interface {
	recv() (*packetBuffer, error)
	io.Closer
}

type udpReciver struct {
	listener *net.UDPConn
}

func newUdpReciver(bufferSize int) *udpReciver {
	reciver := &udpReciver{}
	listener, err := net.ListenUDP("udp4", &net.UDPAddr{Port: _LISTEN_PORT})
	if err != nil {
		log.Error(err)
		return nil
	}
	listener.SetReadBuffer(bufferSize)
	listener.SetReadDeadline(time.Now().Add(_RECV_TIMEOUT))
	reciver.listener = listener
	return reciver
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

func (r *udpReciver) updateTimeout() {
	r.listener.SetReadDeadline(time.Now().Add(_RECV_TIMEOUT))
}

func (r *udpReciver) Close() error {
	if r.listener != nil {
		r.listener.Close()
	}
	return nil
}

type zmqReciver struct {
	zmqListener *zmq.Socket
}

func newZmqReciver() *zmqReciver {
	router, err := zmq.NewSocket(zmq.ROUTER)
	if err != nil {
		log.Error(err)
		return nil
	}

	if err := router.Bind(fmt.Sprintf("tcp://*:%d", _LISTEN_PORT)); err != nil {
		log.Error(err)
		router.Close()
		return nil
	}

	if err := router.SetRcvhwm(1000000); err != nil {
		log.Error(err)
		router.Close()
		return nil
	}
	if err := router.SetRcvtimeo(_RECV_TIMEOUT / 1000); err != nil {
		log.Error(err)
		router.Close()
		return nil
	}
	return &zmqReciver{router}
}

func (r *zmqReciver) recv() (*packetBuffer, error) {
	buffers, err := r.zmqListener.RecvMessageBytes(0)
	if err != nil || len(buffers) != 2 { // ID + Data
		if err.(zmq.Errno) == zmq.ETIMEDOUT || err.(zmq.Errno) == zmq.Errno(11) { // EAGAIN
			return nil, timeoutError("zmq reciver recv timeout")
		}
		return nil, err
	}
	packet := acquirePacketBufferForTcp()
	ip := binary.BigEndian.Uint32(buffers[0])
	packet.buffer = buffers[1]
	packet.init(ip)
	return packet, nil
}

func (r *zmqReciver) Close() error {
	if r.zmqListener != nil {
		return r.zmqListener.Close()
	}
	return nil
}
