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

package metadata

import (
	"gorm.io/gorm"

	"github.com/golang/protobuf/proto"

	"github.com/deepflowio/deepflow/message/trident"
)

type TapType struct {
	tapTypePoto []*trident.TapType
	db          *gorm.DB
}

func newTapType(db *gorm.DB) *TapType {
	return &TapType{
		tapTypePoto: []*trident.TapType{},
		db:          db,
	}
}

func (t *TapType) generateTapTypes() {
	tapTypes := GetTapTypesFromDB(t.db)
	if tapTypes == nil {
		return
	}
	tapTypePoto := make([]*trident.TapType, 0, len(tapTypes))
	for _, tapType := range tapTypes {
		packetType := trident.PacketType(tapType.Type)
		data := &trident.TapType{
			TapType:    proto.Uint32(uint32(tapType.Value)),
			PacketType: &packetType,
			Vlan:       proto.Uint32(uint32(tapType.VLAN)),
			SourceIp:   proto.String(tapType.SrcIP),
			TapPort:    proto.Uint32(uint32(tapType.InterfaceIndex)),
		}
		tapTypePoto = append(tapTypePoto, data)
	}

	t.updateTapTypeProto(tapTypePoto)
}

func (t *TapType) updateTapTypeProto(tapTypeProto []*trident.TapType) {
	t.tapTypePoto = tapTypeProto
}

func (t *TapType) getTapTypes() []*trident.TapType {
	return t.tapTypePoto
}
