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
	case FLOW_SECOND_ID:
		doc.Meter = AcquireFlowSecondMeter()
	case FLOW_ID:
		doc.Meter = AcquireFlowMeter()
	case PACKET_ID:
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
	case FLOW_SECOND_ID:
		doc.Meter = &FlowSecondMeter{}
	case FLOW_ID:
		doc.Meter = &FlowMeter{}
	case PACKET_ID:
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
	if strings.HasPrefix(db, MeterVTAPNames[PACKET_ID]) {
		return PACKET_ID, nil
	} else if strings.HasPrefix(db, MeterVTAPNames[GEO_ID]) {
		return GEO_ID, nil
	} else if strings.HasPrefix(db, MeterVTAPNames[FLOW_ID]) {
		if rp == "s1" {
			return FLOW_SECOND_ID, nil
		} else if rp == "autogen" {
			// 对于写入vtap_360_acl的数据，使用的是PACKET_ID
			if strings.HasSuffix(db, DatabaseSuffix[1]) {
				return PACKET_ID, nil
			} else {
				return FLOW_ID, nil
			}
		} else {
			return MAX_APP_ID, fmt.Errorf("unsupport rp %s", rp)
		}
	}

	return MAX_APP_ID, fmt.Errorf("unsupport db %s", db)
}

func EncodeTsdbRow(encoder *codec.SimpleEncoder, timestamp uint32, meterID uint8, columnIDs []uint8, columnValues []interface{}) error {
	encoder.WriteU32(app.VERSION)
	encoder.WriteU32(timestamp)

	tag := &Tag{}
	tag.Field = &Field{}
	if err := tag.FillValues(columnIDs, columnValues); err != nil {
		return err
	}
	tag.Encode(encoder)

	encoder.WriteU8(meterID)
	switch meterID {
	case GEO_ID:
		var m GeoMeter
		m.Fill(columnIDs, columnValues)
		m.Encode(encoder)
	case FLOW_SECOND_ID:
		var m FlowSecondMeter
		m.Fill(columnIDs, columnValues)
		m.Encode(encoder)
	case FLOW_ID:
		var m FlowMeter
		m.Fill(columnIDs, columnValues)
		m.Encode(encoder)
	case PACKET_ID:
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
