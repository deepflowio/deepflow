package app

import (
	"errors"
	"fmt"

	"gitlab.yunshan.net/yunshan/droplet-libs/codec"
	"gitlab.yunshan.net/yunshan/droplet-libs/zerodoc"
	"gitlab.yunshan.net/yunshan/droplet-libs/zerodoc/pb"
)

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
