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

package policy

import (
	"math"

	. "github.com/deepflowio/deepflow/server/libs/datatype"
)

type InterestTable struct {
	InterestPortMaps *[math.MaxUint16 + 1]PortRange
}

func (t *InterestTable) Init() {
	t.InterestPortMaps = &[math.MaxUint16 + 1]PortRange{}
}

func (t *InterestTable) generateInterestPortMap(acls []*Acl) {
	interestPortMaps := &[math.MaxUint16 + 1]PortRange{}
	ports := make([]PortRange, 0, 1000)

	for _, acl := range acls {
		ports = append(ports, acl.SrcPortRange...)
		ports = append(ports, acl.DstPortRange...)
	}

	ports = GetPortRanges(ports)

	lastMax, portOther := uint16(0), uint16(0)
	for index, port := range ports {
		if index == 0 {
			lastMax = port.Max()
		} else if portOther != 0 {
			if port.Min()-lastMax > 1 {
				portOther = lastMax + 1
			}
			lastMax = port.Max()
		}

		for i := int(port.Min()); i <= int(port.Max()); i++ {
			interestPortMaps[i] = port
		}
	}
	if portOther == 0 && math.MaxUint16-lastMax > 1 {
		portOther = lastMax + 1
	}

	if portOther != 0 {
		// portOther为非策略端口中的的第一个端口
		// 为了减少内存，减少fastPath项， 所有不在策略中的端口使用portOther来建立查询fastPath
		for i := 1; i <= math.MaxUint16; i++ {
			if 0 == interestPortMaps[i] {
				interestPortMaps[i] = NewPortRange(portOther, portOther)
			}
		}
	}
	t.InterestPortMaps = interestPortMaps
}

func (t *InterestTable) GenerateInterestMaps(acls []*Acl) {
	t.generateInterestPortMap(acls)
}

func (t *InterestTable) getFastInterestKeys(packet *LookupKey) {
	ports := t.InterestPortMaps[packet.SrcPort]
	packet.SrcPort = ports.Min()
	ports = t.InterestPortMaps[packet.DstPort]
	packet.DstPort = ports.Min()
}
