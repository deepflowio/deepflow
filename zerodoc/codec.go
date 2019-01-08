package zerodoc

import (
	"errors"
	"fmt"

	"gitlab.x.lan/yunshan/droplet-libs/app"
	"gitlab.x.lan/yunshan/droplet-libs/codec"
)

// send to zero
// Protocol:
//     version     uint32
//     sequence    uint32
//     timestamp   uint32
//     tag         Tag (bytes)
//     meterType   uint8
//     meter       Meter (bytes)
//     actionFlags uint32
func Encode(sequence uint32, doc *app.Document, encoder *codec.SimpleEncoder) error {
	if doc.Tag == nil || doc.Meter == nil {
		return errors.New("No tag or meter in document")
	}

	var msgType MessageType
	switch v := doc.Meter.(type) {
	case *UsageMeter:
		msgType = MSG_USAGE
	case *PerfMeter:
		msgType = MSG_PERF
	case *GeoMeter:
		msgType = MSG_GEO
	case *FlowMeter:
		msgType = MSG_FLOW
	case *ConsoleLogMeter:
		msgType = MSG_CONSOLE_LOG
	case *TypeMeter:
		msgType = MSG_TYPE
	case *FPSMeter:
		msgType = MSG_FPS
	default:
		return fmt.Errorf("Unknown supported type %T", v)
	}

	encoder.WriteU32(app.VERSION)
	encoder.WriteU32(sequence)
	encoder.WriteU32(doc.Timestamp)

	var tag *Tag
	tag, ok := doc.Tag.(*Tag)
	if !ok {
		return fmt.Errorf("Unknown supported tag type %T", doc.Tag)
	}
	tag.Encode(encoder)

	encoder.WriteU8(uint8(msgType))
	var meter app.Meter
	switch msgType {
	case MSG_USAGE:
		meter = doc.Meter.(*UsageMeter)
	case MSG_PERF:
		meter = doc.Meter.(*PerfMeter)
	case MSG_GEO:
		meter = doc.Meter.(*GeoMeter)
	case MSG_FLOW:
		meter = doc.Meter.(*FlowMeter)
	case MSG_CONSOLE_LOG:
		meter = doc.Meter.(*ConsoleLogMeter)
	case MSG_TYPE:
		meter = doc.Meter.(*TypeMeter)
	case MSG_FPS:
		meter = doc.Meter.(*FPSMeter)
	}
	meter.Encode(encoder)

	encoder.WriteU32(doc.ActionFlags)

	return nil
}

// The return Document, must call app.ReleaseDocument to release after used
func Decode(decoder *codec.SimpleDecoder) (*app.Document, error) {
	if decoder == nil {
		return nil, errors.New("No input decoder")
	}

	if version := decoder.ReadU32(); version != app.VERSION {
		return nil, errors.New(fmt.Sprintf("message version incorrect, expect %d, found %d.", app.VERSION, version))
	}
	decoder.ReadU32() // sequence

	doc := app.AcquireDocument()

	doc.Timestamp = decoder.ReadU32()

	tag := AcquireTag()
	tag.Field = AcquireField()
	tag.Decode(decoder)
	doc.Tag = tag

	msgType := decoder.ReadU8()
	switch MessageType(msgType) {
	case MSG_USAGE:
		m := AcquireUsageMeter()
		m.Decode(decoder)
		doc.Meter = m
	case MSG_PERF:
		m := AcquirePerfMeter()
		m.Decode(decoder)
		doc.Meter = m
	case MSG_GEO:
		m := AcquireGeoMeter()
		m.Decode(decoder)
		doc.Meter = m
	case MSG_FLOW:
		m := AcquireFlowMeter()
		m.Decode(decoder)
		doc.Meter = m
	case MSG_CONSOLE_LOG:
		m := AcquireConsoleLogMeter()
		m.Decode(decoder)
		doc.Meter = m
	case MSG_TYPE:
		m := AcquireTypeMeter()
		m.Decode(decoder)
		doc.Meter = m
	case MSG_FPS:
		m := AcquireFPSMeter()
		m.Decode(decoder)
		doc.Meter = m
	default:
		app.ReleaseDocument(doc)
		return nil, errors.New(fmt.Sprintf("Error meter type %v", msgType))
	}

	doc.ActionFlags = decoder.ReadU32()

	if decoder.Failed() {
		app.ReleaseDocument(doc)
		return nil, errors.New("Decode failed")
	}

	return doc, nil
}

func EncodeVTAP(doc *app.Document, encoder *codec.SimpleEncoder) error {
	if doc.Tag == nil || doc.Meter == nil {
		return errors.New("No tag or meter in document")
	}
	encoder.Reset()

	var msgType MessageType
	switch v := doc.Meter.(type) {
	case *VTAPUsageMeter:
		msgType = MSG_VTAP_USAGE
	default:
		return fmt.Errorf("Unknown supported type %T", v)
	}

	encoder.WriteU32(app.VERSION)
	encoder.WriteU32(doc.Timestamp)

	var tag *Tag
	tag, ok := doc.Tag.(*Tag)
	if !ok {
		return fmt.Errorf("Unknown supported tag type %T", doc.Tag)
	}
	tag.Encode(encoder)

	encoder.WriteU8(uint8(msgType))
	var meter app.Meter
	switch msgType {
	case MSG_VTAP_USAGE:
		meter = doc.Meter.(*VTAPUsageMeter)
	}
	meter.Encode(encoder)

	return nil
}

func DecodeVTAP(b []byte) (*app.Document, error) {
	if b == nil {
		return nil, errors.New("No input byte")
	}

	decoder := &codec.SimpleDecoder{}
	decoder.Init(b)

	if version := decoder.ReadU32(); version != app.VERSION {
		return nil, errors.New(fmt.Sprintf("message version incorrect, expect %d, found %d.", app.VERSION, version))
	}

	doc := app.AcquireDocument()

	doc.Timestamp = decoder.ReadU32()

	tag := AcquireTag()
	tag.Field = AcquireField()
	tag.Decode(decoder)
	doc.Tag = tag

	msgType := decoder.ReadU8()
	switch MessageType(msgType) {
	case MSG_VTAP_USAGE:
		m := AcquireVTAPUsageMeter()
		m.Decode(decoder)
		doc.Meter = m
	default:
		return nil, fmt.Errorf("Error meter type %v", msgType)
	}

	if decoder.Failed() {
		return nil, errors.New("Decode failed")
	}
	return doc, nil
}
