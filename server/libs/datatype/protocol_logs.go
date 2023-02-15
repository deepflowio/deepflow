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

	"github.com/deepflowio/deepflow/server/libs/codec"
	"github.com/deepflowio/deepflow/server/libs/datatype/pb"
	"github.com/deepflowio/deepflow/server/libs/pool"
	"github.com/deepflowio/deepflow/server/libs/utils"
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

var httpInfoPool = pool.NewLockFreePool(func() interface{} {
	return new(HTTPInfo)
})

func AcquireHTTPInfo() *HTTPInfo {
	return httpInfoPool.Get().(*HTTPInfo)
}

func ReleaseHTTPInfo(h *HTTPInfo) {
	*h = HTTPInfo{}
	httpInfoPool.Put(h)
}

var dnsInfoPool = pool.NewLockFreePool(func() interface{} {
	return new(DNSInfo)
})

func AcquireDNSInfo() *DNSInfo {
	return dnsInfoPool.Get().(*DNSInfo)
}

func ReleaseDNSInfo(d *DNSInfo) {
	*d = DNSInfo{}
	dnsInfoPool.Put(d)
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
	switch d.Proto {
	case L7_PROTOCOL_HTTP_2:
		fallthrough
	case L7_PROTOCOL_HTTP_1:
		ReleaseHTTPInfo(d.Detail.(*HTTPInfo))
	case L7_PROTOCOL_DNS:
		ReleaseDNSInfo(d.Detail.(*DNSInfo))
	case L7_PROTOCOL_MYSQL:
		ReleaseMYSQLInfo(d.Detail.(*MysqlInfo))
	case L7_PROTOCOL_REDIS:
		ReleaseREDISInfo(d.Detail.(*RedisInfo))
	case L7_PROTOCOL_DUBBO:
		ReleaseDubboInfo(d.Detail.(*DubboInfo))
	case L7_PROTOCOL_KAFKA:
		ReleaseKafkaInfo(d.Detail.(*KafkaInfo))
	case L7_PROTOCOL_MQTT:
		ReleaseMqttInfo(d.Detail.(*MqttInfo))
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
	if l.AppProtoLogsBaseInfo.MsgType == MSG_T_RESPONSE ||
		l.AppProtoLogsBaseInfo.MsgType == MSG_T_SESSION {
		p.Resp = &pb.L7Response{
			Status: uint32(l.AppProtoLogsBaseInfo.AppProtoHead.Status),
			Code:   int32(l.AppProtoLogsBaseInfo.AppProtoHead.Code),
		}
	}
	switch l.Proto {
	case L7_PROTOCOL_HTTP_1:
		fallthrough
	case L7_PROTOCOL_HTTP_2:
		if http, ok := l.Detail.(*HTTPInfo); ok {
			http.WriteToPB(p, l.AppProtoLogsBaseInfo.MsgType)
		}
	case L7_PROTOCOL_DNS:
		if dns, ok := l.Detail.(*DNSInfo); ok {
			dns.WriteToPB(p, l.AppProtoLogsBaseInfo.MsgType)
		}
	case L7_PROTOCOL_MYSQL:
		if mysql, ok := l.Detail.(*MysqlInfo); ok {
			mysql.WriteToPB(p, l.AppProtoLogsBaseInfo.MsgType)
		}
	case L7_PROTOCOL_REDIS:
		if redis, ok := l.Detail.(*RedisInfo); ok {
			redis.WriteToPB(p, l.AppProtoLogsBaseInfo.MsgType)
		}
	case L7_PROTOCOL_DUBBO:
		if dubbo, ok := l.Detail.(*DubboInfo); ok {
			dubbo.WriteToPB(p, l.AppProtoLogsBaseInfo.MsgType)
		}
	case L7_PROTOCOL_KAFKA:
		if kafka, ok := l.Detail.(*KafkaInfo); ok {
			kafka.WriteToPB(p, l.AppProtoLogsBaseInfo.MsgType)
		}
	case L7_PROTOCOL_MQTT:
		if mqtt, ok := l.Detail.(*MqttInfo); ok {
			mqtt.WriteToPB(p, l.AppProtoLogsBaseInfo.MsgType)
		}
	}
}

type ProtoSpecialInfo interface {
	String() string
	Merge(interface{})
}

// HTTPv2根据需要添加
type HTTPInfo struct {
	StreamID uint32 // HTTPv2
	Version  string
	TraceID  string
	SpanID   string

	Method     string
	Path       string
	Host       string
	ClientIP   string
	XRequestId string

	ReqContentLength  int64
	RespContentLength int64
}

func (h *HTTPInfo) WriteToPB(p *pb.AppProtoLogsData, msgType LogMessageType) {
	p.Version = h.Version
	p.TraceInfo = &pb.TraceInfo{
		TraceId: h.TraceID,
		SpanId:  h.SpanID,
	}

	p.ReqLen, p.RespLen = -1, -1
	if msgType == MSG_T_REQUEST || msgType == MSG_T_SESSION {
		p.Req = &pb.L7Request{
			ReqType:  h.Method,
			Domain:   h.Host,
			Resource: h.Path,
		}

		p.ExtInfo = &pb.ExtendedInfo{
			ClientIp:   h.ClientIP,
			RequestId:  h.StreamID,
			XRequestId: h.XRequestId,
		}
		p.ReqLen = int32(h.ReqContentLength)
	}

	if msgType == MSG_T_RESPONSE || msgType == MSG_T_SESSION {
		if h.XRequestId != "" {
			if p.ExtInfo == nil {
				p.ExtInfo = &pb.ExtendedInfo{}
			}
			p.ExtInfo.XRequestId = h.XRequestId
		}
		p.RespLen = int32(h.RespContentLength)
	}
}

func (h *HTTPInfo) String() string {
	return fmt.Sprintf("%#v", h)
}

func (h *HTTPInfo) Merge(r interface{}) {
	if http, ok := r.(*HTTPInfo); ok {
		h.RespContentLength = http.RespContentLength
		if h.XRequestId == "" {
			h.XRequestId = http.XRequestId
		}
		if h.TraceID == "" {
			h.TraceID = http.TraceID
		}
		if h.SpanID == "" {
			h.SpanID = http.SpanID
		}
	}
}

// | type | 查询类型 | 说明|
// | ---- | -------- | --- |
// | 1	  | A	     |由域名获得IPv4地址|
// | 2	  | NS	     |查询域名服务器|
// | 5	  | CNAME    |查询规范名称|
// | 6	  | SOA	     |开始授权|
// | 11	  | WKS	     |熟知服务|
// | 12	  | PTR	     |把IP地址转换成域名|
// | 13	  | HINFO	 |主机信息|
// | 15	  | MX	     |邮件交换|
// | 28	  | AAAA	 |由域名获得IPv6地址|
// | 252  | AXFR	 |传送整个区的请求|
// | 255  | ANY      |对所有记录的请求|
type DNSInfo struct {
	TransID   uint16
	QueryType uint16
	QueryName string
	// 根据查询类型的不同而不同，如：
	// A: ipv4/ipv6地址
	// NS: name server
	// SOA: primary name server
	Answers string
}

func (h *DNSInfo) WriteToPB(p *pb.AppProtoLogsData, msgType LogMessageType) {
	if h.TransID != 0 {
		p.ExtInfo = &pb.ExtendedInfo{
			RequestId: uint32(h.TransID),
		}
	}
	p.ReqLen, p.RespLen = -1, -1
	if msgType == MSG_T_REQUEST || msgType == MSG_T_SESSION {
		p.Req = &pb.L7Request{
			ReqType:  GetDNSQueryType(uint8(h.QueryType)),
			Resource: h.QueryName,
		}
	}

	if msgType == MSG_T_RESPONSE || msgType == MSG_T_SESSION {
		p.Resp.Result = h.Answers
		if p.Resp.Code == 0 {
			p.Resp.Code = L7PROTOCOL_LOG_RESP_CODE_NONE
		}
	}
}

func (d *DNSInfo) String() string {
	return fmt.Sprintf("%#v", d)
}

func (d *DNSInfo) Merge(r interface{}) {
	if response, ok := r.(*DNSInfo); ok {
		d.Answers = response.Answers
	}
}
