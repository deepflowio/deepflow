package msg

import (
	"fmt"

	"encoding/binary"

	logging "github.com/op/go-logging"

	"gitlab.x.lan/yunshan/droplet-libs/app"
	"gitlab.x.lan/yunshan/droplet-libs/pool"
	"gitlab.x.lan/yunshan/droplet-libs/store"
	"gitlab.x.lan/yunshan/droplet-libs/zerodoc"
	"gitlab.x.lan/yunshan/droplet/roze/config"
)

var log = logging.MustGetLogger("roze.msg")

const (
	INVALID_INDEX = iota
	VTAP_FLOW
	VTAP_FLOW_PORT
	VTAP_FLOW_EDGE
	VTAP_FLOW_EDGE_PORT
	VTAP_PACKET
	VTAP_PACKET_EDGE
	VTAP_ACL
	VTAP_WAN
	VTAP_WAN_PORT

	VTAP_FLOW_1S
	VTAP_FLOW_PORT_1S
	VTAP_FLOW_EDGE_1S
	VTAP_FLOW_EDGE_PORT_1S
	VTAP_PACKET_1S
	VTAP_PACKET_EDGE_1S

	MAX_INDEX
)

type RozeDocument struct {
	database    string
	measurement string
	appCodeID   uint64
	*app.Document

	pool.ReferenceCount
}

var rozeDocumentPool = pool.NewLockFreePool(func() interface{} {
	return &RozeDocument{}
})

func AcquireRozeDocument() *RozeDocument {
	rd := rozeDocumentPool.Get().(*RozeDocument)
	rd.ReferenceCount.Reset()
	return rd
}

func ReleaseRozeDocument(rd *RozeDocument) {
	if rd == nil || rd.SubReferenceCount() {
		return
	}

	if rd.Document != nil {
		app.ReleaseDocument(rd.Document)
	}
	*rd = RozeDocument{}
	rozeDocumentPool.Put(rd)
}

func CloneRozeDocument(rd *RozeDocument) *RozeDocument {
	// 目前不复制database和measurement, 会导致多线程下的core
	cloneZd := AcquireRozeDocument()
	cloneZd.Document = app.CloneDocument(rd.Document)
	return cloneZd
}

/* for queue monitor */
func (rd *RozeDocument) String() string {
	return fmt.Sprintf(
		"\n db: %s table: %s {\n\ttimestamp: %d\tFlags: b%b\n\ttag: %s\n\tmeter: %#v\n}\n",
		rd.Database(), rd.Measurement(), rd.Timestamp, rd.Flags, rd.Tag, rd.Meter)
}

func (rd *RozeDocument) SortKey() uint64 {
	return rd.Document.Meter.SortKey()
}

func (rd *RozeDocument) AppID() int {
	return int(rd.Document.Meter.ID())
}

func GenAppCodeID(databaseNameID uint16, measurementNameID uint8) uint64 {
	return uint64(databaseNameID)<<16 | uint64(measurementNameID)
}

func (rd *RozeDocument) AppCodeID() uint64 {
	if rd.appCodeID != 0 {
		return rd.appCodeID
	}
	rd.appCodeID = GenAppCodeID(rd.DatabaseNameID(), rd.MeasurementNameID())
	return rd.appCodeID
}

func (rd *RozeDocument) AppName() string {
	return rd.Document.Meter.VTAPName()
}

// 用于统计各个数据库写入的数据量
func (rd *RozeDocument) DatabaseIndex() int {
	suffixID := 0
	if tag, ok := rd.Document.Tag.(*zerodoc.Tag); ok {
		suffixID = tag.DatabaseSuffixID()
	}
	if suffixID == zerodoc.SUFFIX_ACL && rd.Document.Meter.ID() == zerodoc.PACKET_ID {
		return VTAP_ACL
	}

	index := INVALID_INDEX
	switch rd.Document.Meter.ID() {
	case zerodoc.FLOW_ID:
		index = VTAP_FLOW
		if suffixID == zerodoc.SUFFIX_EDGE {
			index = VTAP_FLOW_EDGE
		} else if suffixID == zerodoc.SUFFIX_PORT {
			index = VTAP_FLOW_PORT
		} else if suffixID == zerodoc.SUFFIX_EDGE_PORT {
			index = VTAP_FLOW_EDGE_PORT
		}
	case zerodoc.GEO_ID:
		index = VTAP_WAN
		if suffixID == zerodoc.SUFFIX_PORT {
			index = VTAP_WAN_PORT
		}
		return index
	case zerodoc.PACKET_ID:
		index = VTAP_PACKET
		if suffixID == zerodoc.SUFFIX_EDGE {
			index = VTAP_PACKET_EDGE
		}
	}

	if index != INVALID_INDEX && rd.Document.Flags&app.FLAG_PER_SECOND_METRICS != 0 {
		return index + (VTAP_FLOW_1S - VTAP_FLOW)
	}
	return index
}

func (rd *RozeDocument) Database() string {
	if rd.database != "" {
		return rd.database
	}

	suffix := ""
	suffixID := 0
	if tag, ok := rd.Document.Tag.(*zerodoc.Tag); ok {
		suffix = tag.DatabaseSuffix()
		suffixID = tag.DatabaseSuffixID()
	}

	// 对于 vtap_packet_acl的数据写入 vtap_acl
	if suffixID == zerodoc.SUFFIX_ACL && rd.Document.Meter.ID() == zerodoc.PACKET_ID {
		rd.database = zerodoc.MeterVTAPNames[zerodoc.ACL_ID]
	} else {
		rd.database = rd.AppName() + suffix
	}

	return rd.database
}

func (rd *RozeDocument) DatabaseNameID() uint16 {
	if tag, ok := rd.Document.Tag.(*zerodoc.Tag); ok {
		return uint16((rd.AppID() << 8) | tag.DatabaseSuffixID())
	}
	return uint16(rd.AppID())
}

func (rd *RozeDocument) Measurement() string {
	if rd.measurement != "" {
		return rd.measurement
	}
	rd.measurement = zerodoc.MeasurementNames[rd.MeasurementNameID()]
	return rd.measurement
}

func (rd *RozeDocument) MeasurementNameID() uint8 {
	if _, ok := rd.Document.Tag.(*zerodoc.Tag); ok {
		return zerodoc.MAIN
	} else {
		panic("Document.Tag is not the struct zerodoc.Tag")
	}
	return zerodoc.MAIN
}

func (rd *RozeDocument) GetDBName() string {
	return rd.Database()
}

func (rd *RozeDocument) GetMeasurement() string {
	return rd.Measurement()
}

func (rd *RozeDocument) GetTimestamp() uint32 {
	return rd.Document.Timestamp
}

func (rd *RozeDocument) MarshalToBytes(buffer []byte) int {
	offset := 0

	size := copy(buffer[offset+4:], rd.Measurement())
	size += copy(buffer[offset+4+size:], ",_id="+rd.GetShardID())
	size += rd.Tag.MarshalTo(buffer[offset+4+size:])

	binary.BigEndian.PutUint32(buffer[offset:], uint32(size))
	offset += (4 + size)

	size = rd.Meter.MarshalTo(buffer[offset+4:])
	binary.BigEndian.PutUint32(buffer[offset:], uint32(size))
	offset += (4 + size)

	offset += store.MarshalTimestampTo(rd.Document.Timestamp, buffer[offset:])

	return offset
}

func (rd *RozeDocument) Release() {
	ReleaseRozeDocument(rd)
}

func (rd *RozeDocument) GetShardID() string {
	return config.GetShardID()

}
