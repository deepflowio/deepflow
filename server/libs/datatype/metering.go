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

package datatype

import (
	"fmt"
	"time"

	"github.com/google/gopacket/layers"
)

type Metering struct { // FIXME: Deprecated!!!
	Timestamp    time.Duration
	InPort0      uint32
	VLAN         uint16
	IPSrc        IP
	IPDst        IP
	Proto        layers.IPProtocol
	PortSrc      uint16
	PortDst      uint16
	ByteCount0   uint64
	ByteCount1   uint64
	PacketCount0 uint64
	PacketCount1 uint64
	L3EpcID0     uint32
	L3EpcID1     uint32
}

func (m *Metering) String() string {
	return fmt.Sprintf("TIMESTAMP: %d INPORT: 0x%X VLAN: %d\n"+
		"    IP: %v -> %v PROTO: %d L3EpcID: %d -> %d PORT: %d -> %d\n"+
		"    ByteCount: %d -> %d PacketCount: %d -> %d",
		m.Timestamp, m.InPort0, m.VLAN,
		m.IPSrc, m.IPDst, m.Proto, m.L3EpcID0, m.L3EpcID1, m.PortSrc, m.PortDst,
		m.ByteCount0, m.ByteCount1, m.PacketCount0, m.PacketCount1)
}
