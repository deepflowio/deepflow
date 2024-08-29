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

package agentmetadata

import (
	"gorm.io/gorm"

	"github.com/golang/protobuf/proto"

	"github.com/deepflowio/deepflow/message/agent"
	. "github.com/deepflowio/deepflow/server/controller/trisolaris/dbcache"
)

type CaptureNetworkTypeOP struct {
	captureNetworkTypePoto []*agent.CaptureNetworkType
	db                     *gorm.DB
}

func newCaptureNetworkTypeOP(db *gorm.DB) *CaptureNetworkTypeOP {
	return &CaptureNetworkTypeOP{
		captureNetworkTypePoto: []*agent.CaptureNetworkType{},
		db:                     db,
	}
}

func (t *CaptureNetworkTypeOP) generateCaptureNetworkTypes() {
	tapTypes := GetTapTypesFromDB(t.db)
	if tapTypes == nil {
		return
	}
	captureNetworkTypePoto := make([]*agent.CaptureNetworkType, 0, len(tapTypes))
	for _, tapType := range tapTypes {
		packetType := agent.PacketType(tapType.Type)
		data := &agent.CaptureNetworkType{
			CaptureNetworkType: proto.Uint32(uint32(tapType.Value)),
			PacketType:         &packetType,
			Vlan:               proto.Uint32(uint32(tapType.VLAN)),
			SourceIp:           proto.String(tapType.SrcIP),
			CaptureNetworkPort: proto.Uint32(uint32(tapType.InterfaceIndex)),
		}
		captureNetworkTypePoto = append(captureNetworkTypePoto, data)
	}

	t.updateCaptureNetworkTypeProto(captureNetworkTypePoto)
}

func (t *CaptureNetworkTypeOP) updateCaptureNetworkTypeProto(captureNetworkTypePoto []*agent.CaptureNetworkType) {
	t.captureNetworkTypePoto = captureNetworkTypePoto
}

func (t *CaptureNetworkTypeOP) getCaptureNetworkTypes() []*agent.CaptureNetworkType {
	return t.captureNetworkTypePoto
}
