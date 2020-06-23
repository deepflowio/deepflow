package zerodoc

import (
	"errors"
	"fmt"

	"strings"

	"gitlab.x.lan/yunshan/droplet-libs/app"
	"gitlab.x.lan/yunshan/droplet-libs/codec"
)

// The return Document, must call app.ReleaseDocument to release after used
func Decode(decoder *codec.SimpleDecoder) (*app.Document, error) {
	if decoder == nil {
		return nil, errors.New("No input decoder")
	}

	doc := app.AcquireDocument()
	doc.Timestamp = decoder.ReadU32()

	tag := AcquireTag()
	tag.Field = AcquireField()
	tag.Decode(decoder)
	doc.Tag = tag

	meterID := decoder.ReadU8()
	switch meterID {
	case GEO_ID:
		doc.Meter = AcquireGeoMeter()
	case FLOW_ID:
		doc.Meter = AcquireFlowMeter()
	case PACKET_ID, ACL_ID:
		doc.Meter = AcquireVTAPUsageMeter()
	default:
		doc.Release()
		return nil, errors.New(fmt.Sprintf("Error meter ID %v", meterID))
	}
	doc.Meter.Decode(decoder)
	doc.Flags = app.DocumentFlag(decoder.ReadU32())

	if decoder.Failed() {
		doc.Release()
		return nil, errors.New("Decode failed")
	}

	return doc, nil
}

// queue monitor 打印时使用
func DecodeForQueueMonitor(decoder *codec.SimpleDecoder) (*app.Document, error) {
	doc := &app.Document{}
	doc.Timestamp = decoder.ReadU32()

	tag := &Tag{}
	tag.Field = &Field{}
	tag.Decode(decoder)
	doc.Tag = tag

	meterID := decoder.ReadU8()
	switch meterID {
	case GEO_ID:
		doc.Meter = &GeoMeter{}
	case FLOW_ID:
		doc.Meter = &FlowMeter{}
	case PACKET_ID, ACL_ID:
		doc.Meter = &VTAPUsageMeter{}
	default:
		return nil, errors.New(fmt.Sprintf("Error meter ID %d", meterID))
	}
	doc.Meter.Decode(decoder)
	doc.Flags = app.DocumentFlag(decoder.ReadU32())

	if decoder.Failed() {
		return nil, errors.New("Decode failed")
	}
	return doc, nil
}

func GetDbMeterID(db, rp string) (uint8, error) {
	// vtap_flow数据库，不使用flow_second_id返回数据
	for meterID := FLOW_ID; meterID < MAX_APP_ID; meterID++ {
		if strings.HasPrefix(db, MeterVTAPNames[meterID]) {
			return meterID, nil
		}
	}
	return MAX_APP_ID, fmt.Errorf("unsupport db %s", db)
}

func EncodeTsdbRow(db string, encoder *codec.SimpleEncoder, timestamp uint32, meterID uint8, columnIDs []uint8, columnValues []interface{}) error {
	encoder.WriteU32(app.VERSION)
	encoder.WriteU32(timestamp)

	tag := &Tag{}
	tag.Field = &Field{}
	if err := tag.FillValues(columnIDs, columnValues); err != nil {
		return err
	}

	if tag.Code&IP != 0 || tag.Code&IPPath != 0 {
		// 根据db名中是否包含'_edge'
		if strings.Contains(db, DatabaseSuffix[2]) {
			tag.Code &= ^IP
			tag.Code |= IPPath
		} else {
			tag.Code &= ^IPPath
			tag.Code |= IP
		}
	}

	tag.Encode(encoder)

	encoder.WriteU8(meterID)
	switch meterID {
	case GEO_ID:
		var m GeoMeter
		m.Fill(columnIDs, columnValues)
		m.Encode(encoder)
	case FLOW_ID:
		var m FlowMeter
		m.Fill(columnIDs, columnValues)
		m.Encode(encoder)
	case PACKET_ID, ACL_ID:
		var m VTAPUsageMeter
		m.Fill(columnIDs, columnValues)
		m.Encode(encoder)
	default:
		return fmt.Errorf("Unknown supported meterID %d", meterID)
	}
	encoder.WriteU32(0) // Flags

	return nil
}

func DecodeTsdbRow(decoder *codec.SimpleDecoder) (*app.Document, error) {
	version := decoder.ReadU32()
	if version != app.VERSION {
		return nil, fmt.Errorf("message version incorrect, expect %d, found %d.", app.VERSION, version)
	}
	return Decode(decoder)
}
