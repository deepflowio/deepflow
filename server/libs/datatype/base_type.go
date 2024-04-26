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
	"bytes"
	"encoding/binary"
	"encoding/gob"
	"net"

	. "github.com/deepflowio/deepflow/server/libs/utils"
)

type IP struct {
	ip    net.IP
	ipStr string
	ipInt uint32
}

func NewIPFromString(ipStr string) *IP {
	if ip := net.ParseIP(ipStr); ip != nil {
		if p := ip.To4(); len(p) != net.IPv4len { // not IPv4
			return nil
		}
		return &IP{ip, ipStr, binary.BigEndian.Uint32(ip.To4())}
	}
	return nil
}

func NewIPFromInt(ipInt uint32) *IP {
	ip := net.IPv4(byte(ipInt>>24), byte(ipInt>>16), byte(ipInt>>8), byte(ipInt))
	return &IP{ip, ip.String(), ipInt}
}

func (ip *IP) Equals(other *IP) bool {
	return ip.ipInt == other.ipInt
}

func (ip *IP) String() string {
	return ip.ipStr
}

func (ip *IP) Int() uint32 {
	return ip.ipInt
}

func (ip *IP) GobDecode(buffer []byte) error {
	decoder := gob.NewDecoder(bytes.NewBuffer(buffer))
	if err := decoder.Decode(&ip.ipStr); err != nil {
		return err
	}
	return nil
}

func (ip *IP) GobEncode() ([]byte, error) {
	buffer := bytes.Buffer{}
	encoder := gob.NewEncoder(&buffer)
	if err := encoder.Encode(ip.ipStr); err != nil {
		return []byte{}, err
	}
	return buffer.Bytes(), nil
}

type MACAddr struct {
	addr    net.HardwareAddr
	addrStr string
	addrInt uint64
}

func NewMACAddrFromString(addrStr string) *MACAddr {
	if addr, err := net.ParseMAC(addrStr); err == nil {
		if len(addr) != MAC_ADDR_LEN {
			return nil
		}
		return &MACAddr{addr, addrStr, Mac2Uint64(addr)}
	}
	return nil
}

func NewMACAddrFromInt(addrInt uint64) *MACAddr {
	mac := Uint64ToMac(addrInt)
	return &MACAddr{mac, mac.String(), addrInt}
}

func (m *MACAddr) Equals(other *MACAddr) bool {
	return m.addrInt == other.addrInt
}

func (m *MACAddr) String() string {
	return m.addrStr
}

func (m *MACAddr) Int() uint64 {
	return m.addrInt
}

type IP4 uint32

func (ip4 IP4) String() string {
	ip := make(net.IP, 4)
	ip[0] = byte(ip4 >> 24)
	ip[1] = byte(ip4 >> 16)
	ip[2] = byte(ip4 >> 8)
	ip[3] = byte(ip4)
	return ip.String()
}
