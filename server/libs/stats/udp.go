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

package stats

import (
	"io"
	"net"

	"github.com/deepflowio/deepflow/server/libs/datatype"
)

const (
	// UDPPayloadSize is a reasonable default payload size for UDP packets that
	// could be travelling over the internet.
	UDPPayloadSize = 1024
)

// UDPConfig is the config data needed to create a UDP Client.
type UDPConfig struct {
	// Addr should be of the form "host:port"
	// or "[ipv6-host%zone]:port".
	Addr string

	// PayloadSize is the maximum size of a UDP client message, optional
	// Tune this based on your network. Defaults to UDPPayloadSize.
	PayloadSize int
}

// NewUDPClient returns a client interface for writing to an InfluxDB UDP
// service from the given config.
func NewUDPClient(conf UDPConfig) (*UDPClient, error) {
	var udpAddr *net.UDPAddr
	udpAddr, err := net.ResolveUDPAddr("udp", conf.Addr)
	if err != nil {
		return nil, err
	}

	conn, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		return nil, err
	}

	payloadSize := conf.PayloadSize
	if payloadSize == 0 {
		payloadSize = UDPPayloadSize
	}

	h := datatype.BaseHeader{
		FrameSize: datatype.MESSAGE_HEADER_LEN + datatype.FLOW_HEADER_LEN,
		Type:      datatype.MESSAGE_TYPE_DFSTATS,
	}
	flowHeader := datatype.FlowHeader{}
	header := make([]byte, datatype.MESSAGE_HEADER_LEN+datatype.FLOW_HEADER_LEN)
	h.Encode(header)
	flowHeader.Encode(header[datatype.MESSAGE_HEADER_LEN:])

	return &UDPClient{
		conn:        conn,
		payloadSize: payloadSize,
		buffer:      make([]byte, 0, payloadSize),
		header:      header,
	}, nil
}

// Close releases the UDPClient's resources.
func (uc *UDPClient) Close() error {
	return uc.conn.Close()
}

type UDPClient struct {
	conn        io.WriteCloser
	payloadSize int
	buffer      []byte
	header      []byte // 需要封装消息类型头
}

func (uc *UDPClient) Write(bs []byte) error {
	var err error
	n := len(bs)

	if len(uc.buffer) == 0 {
		uc.buffer = append(uc.buffer, uc.header...)
	}

	if len(uc.buffer)+n > uc.payloadSize {
		_, err = uc.conn.Write(uc.buffer)
		uc.buffer = uc.buffer[:0]
		uc.buffer = append(uc.buffer, uc.header...)
	}
	uc.buffer = append(uc.buffer, bs...)

	return err
}
