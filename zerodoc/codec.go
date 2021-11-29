package zerodoc

import (
	"errors"
	"fmt"

	"strings"

	"gitlab.yunshan.net/yunshan/droplet-libs/app"
	"gitlab.yunshan.net/yunshan/droplet-libs/codec"
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
	case FLOW_ID:
		doc.Meter = AcquireFlowMeter()
	case ACL_ID:
		doc.Meter = AcquireUsageMeter()
	case APP_ID:
		doc.Meter = AcquireAppMeter()
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
	case FLOW_ID:
		doc.Meter = &FlowMeter{}
	case ACL_ID:
		doc.Meter = &UsageMeter{}
	case APP_ID:
		doc.Meter = &AppMeter{}
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

func DecodeTsdbRow(decoder *codec.SimpleDecoder) (*app.Document, error) {
	version := decoder.ReadU32()
	if version != app.VERSION {
		return nil, fmt.Errorf("message version incorrect, expect %d, found %d.", app.VERSION, version)
	}
	return Decode(decoder)
}

// TCP连接下发查询语句
func EncodeQuery(encoder *codec.SimpleEncoder, queryID uint64, tracing string, SQL string) {
	encoder.WriteU64(queryID)
	encoder.WriteBytes([]byte(tracing))
	encoder.WriteBytes([]byte(SQL))
}

func DecodeQuey(decoder *codec.SimpleDecoder) (uint64, string, string, error) {
	queryID := decoder.ReadU64()
	tracing := decoder.ReadBytes()
	SQL := decoder.ReadBytes()
	if decoder.Failed() {
		return 0, "", "", fmt.Errorf("decode failed")
	}
	return queryID, string(tracing), string(SQL), nil
}
