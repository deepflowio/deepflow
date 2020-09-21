package adapter

import (
	"net"

	"gitlab.x.lan/yunshan/droplet-libs/datatype"
)

const (
	_INFLUXDB_RELAY_PORT = 20040
)

type statsdWriter struct {
	remote *net.UDPAddr
	conn   *net.UDPConn
	in     chan *packetBuffer
}

func (w *statsdWriter) connect() {
	if w.conn == nil {
		conn, err := net.DialUDP("udp", nil, w.remote)
		if err != nil {
			log.Warningf("Connect to %s error: %v\n", w.remote, err)
			return
		}
		w.conn = conn
	}
}

func (w *statsdWriter) forward(packet *packetBuffer) {
	if w.conn == nil {
		w.connect()
	}
	if w.conn != nil && packet.bufferLength > datatype.MESSAGE_VALUE_OFFSET {
		// 剥离dropelt message header后，直接转发
		w.conn.Write(packet.buffer[datatype.MESSAGE_VALUE_OFFSET:packet.bufferLength])
	}
}

func (w *statsdWriter) run() {
	for {
		packet := <-w.in
		// statsdWriter将statsd数据转发给telegraf
		w.forward(packet)
		releasePacketBuffer(packet)
	}
}

func (w *statsdWriter) decode(packet *packetBuffer) {
	w.in <- packet
}

func newStatsdWriter() *statsdWriter {
	writer := &statsdWriter{
		remote: &net.UDPAddr{net.ParseIP("127.0.0.1"), _INFLUXDB_RELAY_PORT, ""},
		in:     make(chan *packetBuffer, 1024),
	}
	go writer.run()
	return writer
}
