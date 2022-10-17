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
	"net"
	"time"

	"github.com/deepflowys/deepflow/server/libs/codec"
	"github.com/deepflowys/deepflow/server/libs/datatype/pb"
	"github.com/deepflowys/deepflow/server/libs/pool"
	"github.com/deepflowys/deepflow/server/libs/utils"
)

type LogMessageType uint8

const (
	MSG_T_REQUEST LogMessageType = iota
	MSG_T_RESPONSE
	MSG_T_SESSION
	MSG_T_OTHER
	MSG_T_MAX
)

func (t *LogMessageType) String() string {
	formatted := ""
	switch *t {
	case MSG_T_SESSION:
		formatted = "SESSION"
	case MSG_T_REQUEST:
		formatted = "REQUEST"
	case MSG_T_RESPONSE:
		formatted = "RESPONSE"
	case MSG_T_OTHER:
		formatted = "OTHER"
	default:
		formatted = "UNKNOWN"
	}

	return formatted
}

const (
	STATUS_OK uint8 = iota
	STATUS_ERROR
	STATUS_NOT_EXIST
	STATUS_SERVER_ERROR
	STATUS_CLIENT_ERROR
)

type AppProtoHead struct {
	Proto   L7Protocol
	MsgType LogMessageType // HTTP，DNS: request/response
	Status  uint8          // 状态描述：0：正常，1：已废弃使用(先前用于表示异常)，2：不存在，3：服务端异常，4：客户端异常
	Code    uint16         // HTTP状态码: 1xx-5xx, DNS状态码: 0-7
	RRT     time.Duration  // HTTP，DNS时延: response-request

}

func (h *AppProtoHead) WriteToPB(p *pb.AppProtoHead) {
	p.Proto = uint32(h.Proto)
	p.MsgType = uint32(h.MsgType)
	p.Rrt = uint64(h.RRT)
}

type AppProtoLogsBaseInfo struct {
	StartTime time.Duration // 开始时间, packet的时间戳
	EndTime   time.Duration // 结束时间, 初始化时等于开始时间
	FlowId    uint64        // 对应flow的ID
	TapPort   TapPort
	VtapId    uint16
	TapType   uint16
	IsIPv6    bool
	TapSide   uint8
	AppProtoHead

	/* L2 */
	MacSrc uint64
	MacDst uint64
	/* L3 */
	IPSrc IPv4Int
	IPDst IPv4Int
	/* L3 IPv6 */
	IP6Src [net.IPv6len]byte
	IP6Dst [net.IPv6len]byte
	/* L3EpcID */
	L3EpcIDSrc int32
	L3EpcIDDst int32
	/* L4 */
	PortSrc uint16
	PortDst uint16
	/* First L7 TCP Seq */
	ReqTcpSeq  uint32
	RespTcpSeq uint32

	Protocol          uint8
	IsVIPInterfaceSrc bool
	IsVIPInterfaceDst bool
}

func (i *AppProtoLogsBaseInfo) String() string {
	formatted := ""
	formatted += fmt.Sprintf("StartTime: %v ", i.StartTime)
	formatted += fmt.Sprintf("EndTime: %v ", i.EndTime)
	formatted += fmt.Sprintf("FlowId: %v ", i.FlowId)
	formatted += fmt.Sprintf("VtapId: %v ", i.VtapId)
	formatted += fmt.Sprintf("TapType: %v ", i.TapType)
	formatted += fmt.Sprintf("TapPort: %s ", i.TapPort)
	formatted += fmt.Sprintf("Proto: %s ", i.Proto.String())
	formatted += fmt.Sprintf("MsgType: %s ", i.MsgType.String())
	formatted += fmt.Sprintf("Code: %v ", i.Code)
	formatted += fmt.Sprintf("Status: %v ", i.Status)
	formatted += fmt.Sprintf("RRT: %v ", i.RRT)
	formatted += fmt.Sprintf("TapSide: %d ", i.TapSide)
	formatted += fmt.Sprintf("IsVIPInterfaceSrc: %v ", i.IsVIPInterfaceSrc)
	formatted += fmt.Sprintf("IsVIPInterfaceDst: %v ", i.IsVIPInterfaceDst)
	if i.MacSrc > 0 || i.MacDst > 0 {
		formatted += fmt.Sprintf("MacSrc: %s ", utils.Uint64ToMac(i.MacSrc))
		formatted += fmt.Sprintf("MacDst: %s ", utils.Uint64ToMac(i.MacDst))
	}

	if i.IsIPv6 {
		formatted += fmt.Sprintf("IP6Src: %s ", net.IP(i.IP6Src[:]))
		formatted += fmt.Sprintf("IP6Dst: %s ", net.IP(i.IP6Dst[:]))
	} else {
		formatted += fmt.Sprintf("IPSrc: %s ", utils.IpFromUint32(i.IPSrc))
		formatted += fmt.Sprintf("IPDst: %s ", utils.IpFromUint32(i.IPDst))
	}
	formatted += fmt.Sprintf("Protocol: %v ", i.Protocol)
	formatted += fmt.Sprintf("PortSrc: %v ", i.PortSrc)
	formatted += fmt.Sprintf("PortDst: %v ", i.PortDst)
	formatted += fmt.Sprintf("L3EpcIDSrc: %v ", i.L3EpcIDSrc)
	formatted += fmt.Sprintf("L3EpcIDDst: %v ", i.L3EpcIDDst)
	formatted += fmt.Sprintf("ReqTcpSeq: %v ", i.ReqTcpSeq)
	formatted += fmt.Sprintf("RespTcpSeq: %v", i.RespTcpSeq)
	return formatted
}

type AppProtoLogsData struct {
	AppProtoLogsBaseInfo
	Detail ProtoSpecialInfo

	pool.ReferenceCount
}

var appProtoLogsDataPool = pool.NewLockFreePool(func() interface{} {
	return new(AppProtoLogsData)
})
var zeroAppProtoLogsData = AppProtoLogsData{}

func AcquireAppProtoLogsData() *AppProtoLogsData {
	d := appProtoLogsDataPool.Get().(*AppProtoLogsData)
	d.Reset()
	return d
}

func ReleaseAppProtoLogsData(d *AppProtoLogsData) {
	if d.SubReferenceCount() {
		return
	}

	*d = zeroAppProtoLogsData
	appProtoLogsDataPool.Put(d)
}

func CloneAppProtoLogsData(d *AppProtoLogsData) *AppProtoLogsData {
	newAppProtoLogsData := AcquireAppProtoLogsData()
	*newAppProtoLogsData = *d
	newAppProtoLogsData.Reset()
	return newAppProtoLogsData
}

func (l *AppProtoLogsData) String() string {
	return fmt.Sprintf("base info: %s, Detail info: %s",
		l.AppProtoLogsBaseInfo.String(), l.Detail.String())
}

func (l *AppProtoLogsData) Release() {
	ReleaseAppProtoLogsData(l)
}

func (l *AppProtoLogsBaseInfo) WriteToPB(p *pb.AppProtoLogsBaseInfo) {
	p.StartTime = uint64(l.StartTime)
	p.EndTime = uint64(l.EndTime)
	p.FlowId = l.FlowId
	p.TapPort = uint64(l.TapPort)
	p.VtapId = uint32(l.VtapId)
	p.TapType = uint32(l.TapType)
	p.IsIpv6 = utils.Bool2UInt32(l.IsIPv6)
	p.TapSide = uint32(l.TapSide)
	if p.Head == nil {
		p.Head = &pb.AppProtoHead{}
	}
	l.AppProtoHead.WriteToPB(p.Head)

	p.MacSrc = l.MacSrc
	p.MacDst = l.MacDst
	p.IpSrc = l.IPSrc
	p.IpDst = l.IPDst
	p.Ip6Src = l.IP6Src[:]
	p.Ip6Dst = l.IP6Dst[:]
	p.L3EpcIdSrc = l.L3EpcIDSrc
	p.L3EpcIdDst = l.L3EpcIDDst
	p.PortSrc = uint32(l.PortSrc)
	p.PortDst = uint32(l.PortDst)
	p.Protocol = uint32(l.Protocol)
	p.IsVipInterfaceSrc = utils.Bool2UInt32(l.IsVIPInterfaceSrc)
	p.IsVipInterfaceDst = utils.Bool2UInt32(l.IsVIPInterfaceDst)
	p.ReqTcpSeq = l.ReqTcpSeq
	p.RespTcpSeq = l.RespTcpSeq
}

func (l *AppProtoLogsData) EncodePB(encoder *codec.SimpleEncoder, i interface{}) error {
	p, ok := i.(*pb.AppProtoLogsData)
	if !ok {
		return fmt.Errorf("invalid interface type, should be *pb.AppProtoLogsData")
	}

	l.WriteToPB(p)
	encoder.WritePB(p)
	return nil
}

func (l *AppProtoLogsData) WriteToPB(p *pb.AppProtoLogsData) {
	if p.Base == nil {
		p.Base = &pb.AppProtoLogsBaseInfo{}
	}
	l.AppProtoLogsBaseInfo.WriteToPB(p.Base)
}

type ProtoSpecialInfo interface {
	String() string
	Merge(interface{})
}
