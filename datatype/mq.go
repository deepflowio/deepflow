package datatype

import (
	"fmt"

	"gitlab.yunshan.net/yunshan/droplet-libs/codec"
	"gitlab.yunshan.net/yunshan/droplet-libs/datatype/pb"
	"gitlab.yunshan.net/yunshan/droplet-libs/pool"
)

var kafkaInfoPool = pool.NewLockFreePool(func() interface{} {
	return new(KafkaInfo)
})

func AcquireKafkaInfo() *KafkaInfo {
	return kafkaInfoPool.Get().(*KafkaInfo)
}

func ReleaseKafkaInfo(d *KafkaInfo) {
	*d = KafkaInfo{}
	kafkaInfoPool.Put(d)
}

type KafkaInfo struct {
	CorrelationId uint32

	// request
	ReqMsgSize uint32
	ApiVersion uint16
	ApiKey     uint16
	ClientID   string

	// reponse
	RespMsgSize uint32
}

func (i *KafkaInfo) Encode(encoder *codec.SimpleEncoder, msgType LogMessageType, code uint16) {
	encoder.WriteU32(i.CorrelationId)

	switch msgType {
	case MSG_T_REQUEST:
		encoder.WriteU32(i.ReqMsgSize)
		encoder.WriteU16(i.ApiVersion)
		encoder.WriteU16(i.ApiKey)
		encoder.WriteString255(i.ClientID)
	case MSG_T_RESPONSE:
		encoder.WriteU32(i.RespMsgSize)
	case MSG_T_SESSION:
		encoder.WriteU32(i.ReqMsgSize)
		encoder.WriteU16(i.ApiVersion)
		encoder.WriteU16(i.ApiKey)
		encoder.WriteString255(i.ClientID)

		encoder.WriteU32(i.RespMsgSize)
	}
}

func (i *KafkaInfo) WriteToPB(p *pb.KafkaInfo, msgType LogMessageType) {

	switch msgType {
	case MSG_T_REQUEST:
		p.CorrelationId = i.CorrelationId
		p.ReqMsgSize = i.ReqMsgSize
		p.ApiVersion = uint32(i.ApiVersion)
		p.ApiKey = uint32(i.ApiKey)
		p.ClientID = i.ClientID

		p.RespMsgSize = 0
	case MSG_T_RESPONSE:
		*p = pb.KafkaInfo{}
		p.CorrelationId = i.CorrelationId
		p.RespMsgSize = i.RespMsgSize
	case MSG_T_SESSION:
		p.CorrelationId = i.CorrelationId
		p.ReqMsgSize = i.ReqMsgSize
		p.ApiVersion = uint32(i.ApiVersion)
		p.ApiKey = uint32(i.ApiKey)
		p.ClientID = i.ClientID

		p.RespMsgSize = i.RespMsgSize
	}
}

func (i *KafkaInfo) Decode(decoder *codec.SimpleDecoder, msgType LogMessageType, code uint16) {
	i.CorrelationId = decoder.ReadU32()
	switch msgType {
	case MSG_T_REQUEST:
		i.ReqMsgSize = decoder.ReadU32()
		i.ApiVersion = decoder.ReadU16()
		i.ApiKey = decoder.ReadU16()
		i.ClientID = decoder.ReadString255()
	case MSG_T_RESPONSE:
		i.RespMsgSize = decoder.ReadU32()
	case MSG_T_SESSION:
		i.ReqMsgSize = decoder.ReadU32()
		i.ApiVersion = decoder.ReadU16()
		i.ApiKey = decoder.ReadU16()
		i.ClientID = decoder.ReadString255()

		i.RespMsgSize = decoder.ReadU32()
	}
}

func (i *KafkaInfo) String() string {
	return fmt.Sprintf("%#v", i)
}

func (i *KafkaInfo) Merge(r interface{}) {
	if kafka, ok := r.(*KafkaInfo); ok {
		i.RespMsgSize = kafka.RespMsgSize
	}
}
