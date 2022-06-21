package datatype

import (
	"fmt"

	"gitlab.yunshan.net/yunshan/droplet-libs/codec"
	"gitlab.yunshan.net/yunshan/droplet-libs/datatype/pb"
	"gitlab.yunshan.net/yunshan/droplet-libs/pool"
)

var dubboInfoPool = pool.NewLockFreePool(func() interface{} {
	return new(DubboInfo)
})

func AcquireDubboInfo() *DubboInfo {
	return dubboInfoPool.Get().(*DubboInfo)
}

func ReleaseDubboInfo(d *DubboInfo) {
	*d = DubboInfo{}
	dubboInfoPool.Put(d)
}

type DubboInfo struct {
	// header
	SerialID uint8
	Type     uint8
	ID       int64

	// req
	ReqBodyLen     int32
	DubboVersion   string
	ServiceName    string
	ServiceVersion string
	MethodName     string
	TraceId        string

	// resp
	RespBodyLen int32
}

func (i *DubboInfo) Encode(encoder *codec.SimpleEncoder, msgType LogMessageType, code uint16) {
	encoder.WriteU8(i.SerialID)
	encoder.WriteU8(i.Type)
	encoder.WriteU64(uint64(i.ID))

	switch msgType {
	case MSG_T_REQUEST:
		encoder.WriteU32(uint32(i.ReqBodyLen))
		encoder.WriteString255(i.DubboVersion)
		encoder.WriteString255(i.ServiceName)
		encoder.WriteString255(i.ServiceVersion)
		encoder.WriteString255(i.MethodName)
		encoder.WriteString255(i.TraceId)
	case MSG_T_RESPONSE:
		encoder.WriteU32(uint32(i.RespBodyLen))
	case MSG_T_SESSION:
		encoder.WriteU32(uint32(i.ReqBodyLen))
		encoder.WriteString255(i.DubboVersion)
		encoder.WriteString255(i.ServiceName)
		encoder.WriteString255(i.ServiceVersion)
		encoder.WriteString255(i.MethodName)
		encoder.WriteString255(i.TraceId)

		encoder.WriteU32(uint32(i.RespBodyLen))
	}
}

func (i *DubboInfo) WriteToPB(p *pb.DubboInfo, msgType LogMessageType) {
	p.SerialID = uint32(i.SerialID)
	p.Type = uint32(i.Type)
	p.ID = uint32(i.ID)
	switch msgType {
	case MSG_T_REQUEST:
		p.ReqBodyLen = i.ReqBodyLen
		p.DubboVersion = i.DubboVersion
		p.ServiceName = i.ServiceName
		p.ServiceVersion = i.ServiceVersion
		p.MethodName = i.MethodName
		p.TraceId = i.TraceId
		p.RespBodyLen = 0
	case MSG_T_RESPONSE:
		p.RespBodyLen = i.RespBodyLen
		p.ReqBodyLen = 0
		p.DubboVersion = ""
		p.ServiceName = ""
		p.ServiceVersion = ""
		p.MethodName = ""
		p.TraceId = ""
	case MSG_T_SESSION:
		p.ReqBodyLen = i.ReqBodyLen
		p.DubboVersion = i.DubboVersion
		p.ServiceName = i.ServiceName
		p.ServiceVersion = i.ServiceVersion
		p.MethodName = i.MethodName
		p.TraceId = i.TraceId

		p.RespBodyLen = i.RespBodyLen
	}
}

func (i *DubboInfo) Decode(decoder *codec.SimpleDecoder, msgType LogMessageType, code uint16) {
	i.SerialID = decoder.ReadU8()
	i.Type = decoder.ReadU8()
	i.ID = int64(decoder.ReadU64())

	switch msgType {
	case MSG_T_REQUEST:
		i.ReqBodyLen = int32(decoder.ReadU32())
		i.DubboVersion = decoder.ReadString255()
		i.ServiceName = decoder.ReadString255()
		i.ServiceVersion = decoder.ReadString255()
		i.MethodName = decoder.ReadString255()
		i.TraceId = decoder.ReadString255()
	case MSG_T_RESPONSE:
		i.RespBodyLen = int32(decoder.ReadU32())
	case MSG_T_SESSION:
		i.ReqBodyLen = int32(decoder.ReadU32())
		i.DubboVersion = decoder.ReadString255()
		i.ServiceName = decoder.ReadString255()
		i.ServiceVersion = decoder.ReadString255()
		i.MethodName = decoder.ReadString255()
		i.TraceId = decoder.ReadString255()

		i.RespBodyLen = int32(decoder.ReadU32())
	}
}

func (i *DubboInfo) String() string {
	return fmt.Sprintf("%#v", i)
}

func (i *DubboInfo) Merge(r interface{}) {
	if dubbo, ok := r.(*DubboInfo); ok {
		i.RespBodyLen = dubbo.RespBodyLen
	}
}
