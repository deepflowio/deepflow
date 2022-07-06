package datatype

import (
	"fmt"

	"github.com/metaflowys/metaflow/server/libs/datatype/pb"
	"github.com/metaflowys/metaflow/server/libs/pool"
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

func (i *DubboInfo) WriteToPB(p *pb.DubboInfo, msgType LogMessageType) {
	p.SerialId = uint32(i.SerialID)
	p.Type = uint32(i.Type)
	p.Id = uint32(i.ID)
	switch msgType {
	case MSG_T_REQUEST:
		p.ReqBodyLen = i.ReqBodyLen
		p.Version = i.DubboVersion
		p.ServiceName = i.ServiceName
		p.ServiceVersion = i.ServiceVersion
		p.MethodName = i.MethodName
		p.TraceId = i.TraceId
		p.RespBodyLen = 0
	case MSG_T_RESPONSE:
		p.RespBodyLen = i.RespBodyLen
		p.ReqBodyLen = 0
		p.Version = ""
		p.ServiceName = ""
		p.ServiceVersion = ""
		p.MethodName = ""
		p.TraceId = ""
	case MSG_T_SESSION:
		p.ReqBodyLen = i.ReqBodyLen
		p.Version = i.DubboVersion
		p.ServiceName = i.ServiceName
		p.ServiceVersion = i.ServiceVersion
		p.MethodName = i.MethodName
		p.TraceId = i.TraceId

		p.RespBodyLen = i.RespBodyLen
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
