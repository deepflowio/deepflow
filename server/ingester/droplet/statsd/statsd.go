package statsd

import (
	"net"

	logging "github.com/op/go-logging"

	"github.com/metaflowys/metaflow/server/libs/queue"
	"github.com/metaflowys/metaflow/server/libs/receiver"
)

var log = logging.MustGetLogger("droplet.statsd")

const (
	TELEGRAF_PORT    = 20040
	QUEUE_BATCH_SIZE = 1024
)

type statsdWriter struct {
	remote *net.UDPAddr
	conn   *net.UDPConn
	in     queue.QueueReader
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

func (w *statsdWriter) forward(packet *receiver.RecvBuffer) {
	if w.conn == nil {
		w.connect()
	}
	if w.conn != nil && packet.End-packet.Begin > 0 {
		// 剥离dropelt message header后，直接转发
		w.conn.Write(packet.Buffer[packet.Begin:packet.End])
	}
}

func (w *statsdWriter) run() {
	packets := make([]interface{}, QUEUE_BATCH_SIZE)

	for {
		n := w.in.Gets(packets)
		for i := 0; i < n; i++ {
			if packet, ok := packets[i].(*receiver.RecvBuffer); ok {
				// statsdWriter将statsd数据转发给telegraf
				w.forward(packet)
				receiver.ReleaseRecvBuffer(packet)
			}
		}
	}
}

func NewStatsdWriter(in queue.QueueReader) *statsdWriter {
	writer := &statsdWriter{
		remote: &net.UDPAddr{net.ParseIP("127.0.0.1"), TELEGRAF_PORT, ""},
		in:     in,
	}
	go writer.run()
	return writer
}
