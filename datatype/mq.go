package datatype

import (
	"fmt"

	"gitlab.yunshan.net/yunshan/droplet-libs/codec"
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
	MessageSize   uint32
	CorrelationId uint32

	// request
	ApiVersion uint16
	ApiKey     string
	ClientID   string
}

func (i *KafkaInfo) Encode(encoder *codec.SimpleEncoder, msgType LogMessageType, code uint16) {
	encoder.WriteU32(i.MessageSize)
	encoder.WriteU32(i.CorrelationId)
	if msgType == MSG_T_SESSION || msgType == MSG_T_REQUEST {
		encoder.WriteU16(i.ApiVersion)
		encoder.WriteString255(i.ApiKey)
		encoder.WriteString255(i.ClientID)
	}
}

func (i *KafkaInfo) Decode(decoder *codec.SimpleDecoder, msgType LogMessageType, code uint16) {
	i.MessageSize = decoder.ReadU32()
	i.CorrelationId = decoder.ReadU32()
	if msgType == MSG_T_SESSION || msgType == MSG_T_REQUEST {
		i.ApiVersion = decoder.ReadU16()
		i.ApiKey = decoder.ReadString255()
		i.ClientID = decoder.ReadString255()
	}
}

func (i *KafkaInfo) String() string {
	return fmt.Sprintf("%#v", i)
}

func (h *KafkaInfo) Merge(_ interface{}) {}
