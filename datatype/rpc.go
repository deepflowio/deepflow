package datatype

import (
	"fmt"

	"gitlab.yunshan.net/yunshan/droplet-libs/codec"
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
	BodyLen  uint32
	ID       int64

	// body
	DubboVersion   string
	ServiceName    string
	ServiceVersion string
	MethodName     string

	// Attachments
}

func (i *DubboInfo) Encode(encoder *codec.SimpleEncoder, msgType LogMessageType, code uint16) {
	encoder.WriteU8(i.SerialID)
	encoder.WriteU8(i.Type)
	encoder.WriteU32(i.BodyLen)
	encoder.WriteU64(uint64(i.ID))
	if msgType == MSG_T_SESSION || msgType == MSG_T_REQUEST {
		encoder.WriteString255(i.DubboVersion)
		encoder.WriteString255(i.ServiceName)
		encoder.WriteString255(i.ServiceVersion)
		encoder.WriteString255(i.MethodName)
	}

}

func (i *DubboInfo) Decode(decoder *codec.SimpleDecoder, msgType LogMessageType, code uint16) {
	i.SerialID = decoder.ReadU8()
	i.Type = decoder.ReadU8()
	i.BodyLen = decoder.ReadU32()
	i.ID = int64(decoder.ReadU64())
	if msgType == MSG_T_SESSION || msgType == MSG_T_REQUEST {
		i.DubboVersion = decoder.ReadString255()
		i.ServiceName = decoder.ReadString255()
		i.ServiceVersion = decoder.ReadString255()
		i.MethodName = decoder.ReadString255()
	}
}

func (i *DubboInfo) String() string {
	return fmt.Sprintf("%#v", i)
}

func (h *DubboInfo) Merge(_ interface{}) {}
