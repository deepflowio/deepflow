package metadata

import (
	"gorm.io/gorm"

	"github.com/golang/protobuf/proto"

	"github.com/metaflowys/metaflow/message/trident"
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
