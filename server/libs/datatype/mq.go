package datatype

import (
	"fmt"

	"github.com/metaflowys/metaflow/server/libs/datatype/pb"
	"github.com/metaflowys/metaflow/server/libs/pool"
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
	ReqMsgSize int32
	ApiVersion uint16
	ApiKey     uint16
	ClientID   string

	// reponse
	RespMsgSize int32
}

func (i *KafkaInfo) WriteToPB(p *pb.KafkaInfo, msgType LogMessageType) {

	switch msgType {
	case MSG_T_REQUEST:
		p.CorrelationId = i.CorrelationId
		p.ReqMsgSize = i.ReqMsgSize
		p.ApiVersion = uint32(i.ApiVersion)
		p.ApiKey = uint32(i.ApiKey)
		p.ClientId = i.ClientID

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
		p.ClientId = i.ClientID

		p.RespMsgSize = i.RespMsgSize
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

var mqttInfoPool = pool.NewLockFreePool(func() interface{} {
	return new(MqttInfo)
})

func AcquireMqttInfo() *MqttInfo {
	return mqttInfoPool.Get().(*MqttInfo)
}

func ReleaseMqttInfo(d *MqttInfo) {
	*d = MqttInfo{}
	mqttInfoPool.Put(d)
}

type MqttInfo struct {
	MqttType string

	// request
	ReqMsgSize   int32
	ProtoVersion uint16
	ClientID     string

	// reponse
	RespMsgSize int32
}

func (i *MqttInfo) WriteToPB(p *pb.MqttInfo, msgType LogMessageType) {
	*p = pb.MqttInfo{}
	p.MqttType = i.MqttType
	switch msgType {
	case MSG_T_REQUEST:
		p.ReqMsgSize = i.ReqMsgSize
		p.ProtoVersion = uint32(i.ProtoVersion)
		p.ClientId = i.ClientID

		p.RespMsgSize = 0
	case MSG_T_RESPONSE:
		p.RespMsgSize = i.RespMsgSize
	case MSG_T_SESSION:
		p.ReqMsgSize = i.ReqMsgSize
		p.ProtoVersion = uint32(i.ProtoVersion)
		p.ClientId = i.ClientID

		p.RespMsgSize = i.RespMsgSize
	}
}

func (i *MqttInfo) String() string {
	return fmt.Sprintf("%#v", i)
}

func (i *MqttInfo) Merge(r interface{}) {
	if mqtt, ok := r.(*MqttInfo); ok {
		i.RespMsgSize = mqtt.RespMsgSize
	}
}
