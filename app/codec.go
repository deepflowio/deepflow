package app

import (
	"errors"
	"fmt"

	"strings"

	"gitlab.yunshan.net/yunshan/droplet-libs/codec"
	"gitlab.yunshan.net/yunshan/droplet-libs/zerodoc"
	"gitlab.yunshan.net/yunshan/droplet-libs/zerodoc/pb"
)

// The return Document, must call app.ReleaseDocument to release after used
func Decode(decoder *codec.SimpleDecoder) (*Document, error) {
	if decoder == nil {
		return nil, errors.New("No input decoder")
	}

	doc := AcquireDocument()
	doc.Timestamp = decoder.ReadU32()

	tag := zerodoc.AcquireTag()
	tag.Field = zerodoc.AcquireField()
	tag.Decode(decoder)
	doc.Tagger = tag

	meterID := decoder.ReadU8()
	switch meterID {
	case zerodoc.FLOW_ID:
		doc.Meter = zerodoc.AcquireFlowMeter()
	case zerodoc.ACL_ID:
		doc.Meter = zerodoc.AcquireUsageMeter()
	case zerodoc.APP_ID:
		doc.Meter = zerodoc.AcquireAppMeter()
	default:
		doc.Release()
		return nil, errors.New(fmt.Sprintf("Error meter ID %v", meterID))
	}
	doc.Meter.Decode(decoder)
	doc.Flags = DocumentFlag(decoder.ReadU32())

	if decoder.Failed() {
		doc.Release()
		return nil, errors.New("Decode failed")
	}

	return doc, nil
}

func DecodePB(decoder *codec.SimpleDecoder, pbDoc *pb.Document) (*Document, error) {
	if decoder == nil {
		return nil, errors.New("No input decoder")
	}

	err := decoder.ReadPB(pbDoc)
	if decoder.Failed() || err != nil {
		return nil, fmt.Errorf("Decode failed: %s", err)
	}

	doc := AcquireDocument()
	doc.Timestamp = pbDoc.Timestamp

	tag := zerodoc.AcquireTag()
	tag.Field = zerodoc.AcquireField()
	tag.ReadFromPB(pbDoc.Minitag)
	doc.Tagger = tag

	meterID := uint8(pbDoc.Meter.MeterID)
	switch meterID {
	case zerodoc.FLOW_ID:
		flowMeter := zerodoc.AcquireFlowMeter()
		flowMeter.ReadFromPB(pbDoc.Meter.Flow)
		doc.Meter = flowMeter
	case zerodoc.ACL_ID:
		usageMeter := zerodoc.AcquireUsageMeter()
		usageMeter.ReadFromPB(pbDoc.Meter.Usage)
		doc.Meter = usageMeter
	case zerodoc.APP_ID:
		appMeter := zerodoc.AcquireAppMeter()
		appMeter.ReadFromPB(pbDoc.Meter.App)
		doc.Meter = appMeter
	default:
		return nil, fmt.Errorf("Unknow meter ID %d", meterID)

	}

	doc.Flags = DocumentFlag(pbDoc.Flags)
	return doc, nil
}

// queue monitor 打印时使用
func DecodeForQueueMonitor(decoder *codec.SimpleDecoder) (*Document, error) {
	pbDoc := &pb.Document{}
	decoder.ReadPB(pbDoc)
	if decoder.Failed() {
		return nil, errors.New("Decode failed")
	}

	doc := &Document{}
	doc.Timestamp = pbDoc.Timestamp

	tag := &zerodoc.Tag{}
	tag.Field = &zerodoc.Field{}
	tag.ReadFromPB(pbDoc.Minitag)
	doc.Tagger = tag

	meterID := uint8(pbDoc.Meter.MeterID)
	switch meterID {
	case zerodoc.FLOW_ID:
		flowMeter := zerodoc.AcquireFlowMeter()
		flowMeter.ReadFromPB(pbDoc.Meter.Flow)
		doc.Meter = flowMeter
	case zerodoc.ACL_ID:
		usageMeter := zerodoc.AcquireUsageMeter()
		usageMeter.ReadFromPB(pbDoc.Meter.Usage)
		doc.Meter = usageMeter
	case zerodoc.APP_ID:
		appMeter := zerodoc.AcquireAppMeter()
		appMeter.ReadFromPB(pbDoc.Meter.App)
		doc.Meter = appMeter
	}

	doc.Flags = DocumentFlag(pbDoc.Flags)
	return doc, nil
}

func GetDbMeterID(db, rp string) (uint8, error) {
	// vtap_flow数据库，不使用flow_second_id返回数据
	for meterID := zerodoc.FLOW_ID; meterID < zerodoc.MAX_APP_ID; meterID++ {
		if strings.HasPrefix(db, zerodoc.MeterVTAPNames[meterID]) {
			return meterID, nil
		}
	}
	return zerodoc.MAX_APP_ID, fmt.Errorf("unsupport db %s", db)
}

func DecodeTsdbRow(decoder *codec.SimpleDecoder) (*Document, error) {
	version := decoder.ReadU32()
	if version != VERSION {
		return nil, fmt.Errorf("message version incorrect, expect %d, found %d.", VERSION, version)
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
