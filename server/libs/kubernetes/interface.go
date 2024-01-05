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

package kubernetes

import (
	"bytes"
	"fmt"
	"net"
	"strings"

	"github.com/deepflowio/deepflow/server/libs/utils"
)

type PollerType uint8

const (
	POLLER_ADAPTIVE PollerType = iota
	POLLER_ACTIVE
	POLLER_PASSIVE
)

type InterfaceInfo struct {
	TapIndex int
	MAC      uint64
	// 按IP升序, passive模式下只填写IP, 不写Mask
	IPs      []*net.IPNet
	Name     string
	DeviceID string
}

func (n *InterfaceInfo) Less(other *InterfaceInfo) bool {
	if n.TapIndex != other.TapIndex {
		return n.TapIndex < other.TapIndex
	}
	if n.Name != other.Name {
		return n.Name < other.Name
	}
	if n.MAC != other.MAC {
		return n.MAC < other.MAC
	}
	if n.DeviceID != other.DeviceID {
		return n.DeviceID < other.DeviceID
	}
	if nL, oL := len(n.IPs), len(other.IPs); nL != oL {
		return nL < oL
	}
	for i := range n.IPs {
		nIP, oIP := n.IPs[i].IP, other.IPs[i].IP
		if !bytes.Equal(nIP, oIP) {
			return bytes.Compare(nIP, oIP) < 0
		}
		nMask, oMask := n.IPs[i].Mask, other.IPs[i].Mask
		if !bytes.Equal(nMask, oMask) {
			return bytes.Compare(nMask, oMask) < 0
		}
	}
	return false
}

func (n *InterfaceInfo) Equal(other *InterfaceInfo) bool {
	if n.TapIndex != other.TapIndex {
		return false
	}
	if n.Name != other.Name {
		return false
	}
	if n.MAC != other.MAC {
		return false
	}
	if n.DeviceID != other.DeviceID {
		return false
	}
	if nL, oL := len(n.IPs), len(other.IPs); nL != oL {
		return false
	}
	for i := range n.IPs {
		nIP, oIP := n.IPs[i].IP, other.IPs[i].IP
		if !bytes.Equal(nIP, oIP) {
			return false
		}
		nMask, oMask := n.IPs[i].Mask, other.IPs[i].Mask
		if !bytes.Equal(nMask, oMask) {
			return false
		}
	}
	return true
}

func (n *InterfaceInfo) String() string {
	ipStr := make([]string, 0, len(n.IPs))
	for _, ip := range n.IPs {
		if ip.Mask != nil {
			ipStr = append(ipStr, ip.String())
		} else {
			ipStr = append(ipStr, ip.IP.String())
		}
	}
	return fmt.Sprintf("%d: %s: %s [%s] device %s", n.TapIndex, n.Name, utils.Uint64ToMac(n.MAC).String(), strings.Join(ipStr, ","), n.DeviceID)
}

type Poller interface {
	Start() error
	Stop() error
	GetVersion() uint64
	GetInterfaceInfo() []InterfaceInfo
}
