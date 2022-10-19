/*
 * Copyright (c) 2022 Yunshan Networks
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package datatype

import (
	"fmt"

	"github.com/deepflowys/deepflow/server/libs/datatype/pb"
	"github.com/deepflowys/deepflow/server/libs/pool"
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

func (i *DubboInfo) WriteToPB(p *pb.AppProtoLogsData, msgType LogMessageType) {
	/*
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
	*/
}

func (i *DubboInfo) String() string {
	return fmt.Sprintf("%#v", i)
}

func (i *DubboInfo) Merge(r interface{}) {
	if dubbo, ok := r.(*DubboInfo); ok {
		i.RespBodyLen = dubbo.RespBodyLen
	}
}
