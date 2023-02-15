/*
 * Copyright (c) 2022 Yunshan Networks
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

package statsd

import (
	"net"
	"strconv"

	logging "github.com/op/go-logging"

	"github.com/deepflowio/deepflow/server/libs/queue"
	"github.com/deepflowio/deepflow/server/libs/receiver"
)

var log = logging.MustGetLogger("droplet.statsd")

const (
	TELEGRAF_SVC     = "telegraf"
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
	addrResolved, err := net.ResolveUDPAddr("udp", net.JoinHostPort(TELEGRAF_SVC, strconv.Itoa(TELEGRAF_PORT)))
	if err != nil {
		log.Warningf("stats can not find addr %s, err: %s ", net.JoinHostPort(TELEGRAF_SVC, strconv.Itoa(TELEGRAF_PORT)), err)
		addrResolved = &net.UDPAddr{net.ParseIP("127.0.0.1"), TELEGRAF_PORT, ""}
	}
	writer := &statsdWriter{
		remote: addrResolved,
		in:     in,
	}
	go writer.run()
	return writer
}
