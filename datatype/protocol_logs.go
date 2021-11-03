package datatype

import (
	"fmt"
	"net"
	"time"

	"gitlab.yunshan.net/yunshan/droplet-libs/codec"
	"gitlab.yunshan.net/yunshan/droplet-libs/pool"
	"gitlab.yunshan.net/yunshan/droplet-libs/utils"
)

type LogProtoType uint8

const (
	PROTO_UNKOWN LogProtoType = iota
	PROTO_HTTP
	PROTO_DNS
	PROTO_MYSQL
	PROTO_REDIS
	PROTO_DUBBO
	PROTO_KAFKA
)

func (t *LogProtoType) String() string {
	formatted := ""
	switch *t {
	case PROTO_HTTP:
		formatted = "HTTP"
	case PROTO_DNS:
		formatted = "DNS"
	case PROTO_MYSQL:
		formatted = "MYSQL"
	case PROTO_REDIS:
		formatted = "REDIS"
	case PROTO_DUBBO:
		formatted = "DUBBO"
	case PROTO_KAFKA:
		formatted = "KAFKA"
	default:
		formatted = "UNKOWN"
	}

	return formatted
}

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
		formatted = "UNKOWN"
	}

	return formatted
}

type AppProtoHead struct {
	Proto   LogProtoType
	MsgType LogMessageType // HTTP，DNS: request/response
	Code    uint16         // HTTP状态码: 1xx-5xx, DNS状态码: 0-7
	RRT     time.Duration  // HTTP，DNS时延: response-request
}

type AppProtoLogsBaseInfo struct {
	StartTime time.Duration // 开始时间, packet的时间戳
	EndTime   time.Duration // 结束时间, 初始化时等于开始时间
	FlowId    uint64        // 对应flow的ID
	VtapId    uint16
	TapType   uint16
	TapPort   uint32
	IsIPv6    bool
	AppProtoHead

	/* L3 */
	IPSrc IPv4Int
	IPDst IPv4Int
	/* L3 IPv6 */
	IP6Src [net.IPv6len]byte
	IP6Dst [net.IPv6len]byte
	/* L4 */
	PortSrc uint16
	PortDst uint16
	/* L3EpcID */
	L3EpcIDSrc int32
	L3EpcIDDst int32
}

func (i *AppProtoLogsBaseInfo) String() string {
	formatted := ""
	formatted += fmt.Sprintf("StartTime: %v ", i.StartTime)
	formatted += fmt.Sprintf("EndTime: %v ", i.EndTime)
	formatted += fmt.Sprintf("FlowId: %v ", i.FlowId)
	formatted += fmt.Sprintf("VtapId: %v ", i.VtapId)
	formatted += fmt.Sprintf("TapType: %v ", i.TapType)
	formatted += fmt.Sprintf("TapPort: %v ", i.TapPort)
	formatted += fmt.Sprintf("Proto: %s ", i.Proto.String())
	formatted += fmt.Sprintf("MsgType: %s ", i.MsgType.String())
	formatted += fmt.Sprintf("Code: %v ", i.Code)
	formatted += fmt.Sprintf("RRT: %v ", i.RRT)

	if i.IsIPv6 {
		formatted += fmt.Sprintf("IP6Src: %s ", net.IP(i.IP6Src[:]))
		formatted += fmt.Sprintf("IP6Dst: %s ", net.IP(i.IP6Dst[:]))
	} else {
		formatted += fmt.Sprintf("IPSrc: %s ", utils.IpFromUint32(i.IPSrc))
		formatted += fmt.Sprintf("IPDst: %s ", utils.IpFromUint32(i.IPDst))
	}
	formatted += fmt.Sprintf("PortSrc: %v ", i.PortSrc)
	formatted += fmt.Sprintf("PortDst: %v ", i.PortDst)
	formatted += fmt.Sprintf("L3EpcIDSrc: %v ", i.L3EpcIDSrc)
	formatted += fmt.Sprintf("L3EpcIDDst: %v", i.L3EpcIDDst)

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

	if d.Proto == PROTO_HTTP {
		ReleaseHTTPInfo(d.Detail.(*HTTPInfo))
	} else if d.Proto == PROTO_DNS {
		ReleaseDNSInfo(d.Detail.(*DNSInfo))
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

func (l *AppProtoLogsData) Encode(encoder *codec.SimpleEncoder) error {
	encoder.WriteU64(uint64(l.StartTime))
	encoder.WriteU64(uint64(l.EndTime))
	encoder.WriteU64(l.FlowId)
	encoder.WriteU16(l.VtapId)
	encoder.WriteU16(l.TapType)
	encoder.WriteU32(l.TapPort)
	encoder.WriteU8(byte(l.Proto))
	encoder.WriteU8(byte(l.MsgType))
	encoder.WriteU16(l.Code)
	encoder.WriteU64(uint64(l.RRT))

	if l.IsIPv6 {
		encoder.WriteBool(true)
		encoder.WriteIPv6(l.IP6Src[:])
		encoder.WriteIPv6(l.IP6Dst[:])
	} else {
		encoder.WriteBool(false)
		encoder.WriteU32(uint32(l.IPSrc))
		encoder.WriteU32(uint32(l.IPDst))
	}
	encoder.WriteU16(l.PortSrc)
	encoder.WriteU16(l.PortDst)
	encoder.WriteU32(uint32(l.L3EpcIDSrc))
	encoder.WriteU32(uint32(l.L3EpcIDDst))

	l.Detail.Encode(encoder, l.MsgType, l.Code)
	return nil
}

func (l *AppProtoLogsData) Decode(decoder *codec.SimpleDecoder) error {
	l.StartTime = time.Duration(decoder.ReadU64())
	l.EndTime = time.Duration(decoder.ReadU64())
	l.FlowId = decoder.ReadU64()
	l.VtapId = decoder.ReadU16()
	l.TapType = decoder.ReadU16()
	l.TapPort = decoder.ReadU32()
	l.Proto = LogProtoType(decoder.ReadU8())
	l.MsgType = LogMessageType(decoder.ReadU8())
	l.Code = decoder.ReadU16()
	l.RRT = time.Duration(decoder.ReadU64())

	if decoder.ReadBool() {
		l.IsIPv6 = true
		decoder.ReadIPv6(l.IP6Src[:])
		decoder.ReadIPv6(l.IP6Dst[:])
	} else {
		l.IsIPv6 = false
		l.IPSrc = decoder.ReadU32()
		l.IPDst = decoder.ReadU32()
	}
	l.PortSrc = decoder.ReadU16()
	l.PortDst = decoder.ReadU16()
	l.L3EpcIDSrc = int32(decoder.ReadU32())
	l.L3EpcIDDst = int32(decoder.ReadU32())

	if l.Proto == PROTO_HTTP {
		httpInfo := AcquireHTTPInfo()
		httpInfo.Decode(decoder, l.MsgType, l.Code)
		l.Detail = httpInfo
	} else if l.Proto == PROTO_DNS {
		dnsInfo := AcquireDNSInfo()
		dnsInfo.Decode(decoder, l.MsgType, l.Code)
		l.Detail = dnsInfo
	} else if l.Proto == PROTO_MYSQL {
		mysqlInfo := AcquireMYSQLInfo()
		mysqlInfo.Decode(decoder, l.MsgType, l.Code)
		l.Detail = mysqlInfo
	} else if l.Proto == PROTO_REDIS {
		mysqlInfo := AcquireREDISInfo()
		mysqlInfo.Decode(decoder, l.MsgType, l.Code)
		l.Detail = mysqlInfo
	} else if l.Proto == PROTO_DUBBO {
		dubboInfo := AcquireDubboInfo()
		dubboInfo.Decode(decoder, l.MsgType, l.Code)
		l.Detail = dubboInfo
	} else if l.Proto == PROTO_KAFKA {
		kafkaInfo := AcquireKafkaInfo()
		kafkaInfo.Decode(decoder, l.MsgType, l.Code)
		l.Detail = kafkaInfo
	}

	return nil
}

type ProtoSpecialInfo interface {
	Encode(encoder *codec.SimpleEncoder, msgType LogMessageType, code uint16)
	Decode(decoder *codec.SimpleDecoder, msgType LogMessageType, code uint16)
	String() string
	Merge(interface{})
}

// HTTPv2根据需要添加
type HTTPInfo struct {
	StreamID      uint32 // HTTPv2
	ContentLength int64
	Version       string
	Method        string
	Path          string
	Host          string
	ClientIP      string
	TraceID       string
}

func (h *HTTPInfo) Encode(encoder *codec.SimpleEncoder, msgType LogMessageType, code uint16) {
	encoder.WriteU32(h.StreamID)
	encoder.WriteU64(uint64(h.ContentLength))
	encoder.WriteString255(h.Version)
	if msgType == MSG_T_SESSION || msgType == MSG_T_REQUEST {
		encoder.WriteString255(h.Method)
		encoder.WriteString255(h.Path)
		encoder.WriteString255(h.Host)
		encoder.WriteString255(h.ClientIP)
	}
	encoder.WriteString255(h.TraceID)
}

func (h *HTTPInfo) Decode(decoder *codec.SimpleDecoder, msgType LogMessageType, code uint16) {
	h.StreamID = decoder.ReadU32()
	h.ContentLength = int64(decoder.ReadU64())
	h.Version = decoder.ReadString255()
	if msgType == MSG_T_SESSION || msgType == MSG_T_REQUEST {
		h.Method = decoder.ReadString255()
		h.Path = decoder.ReadString255()
		h.Host = decoder.ReadString255()
		h.ClientIP = decoder.ReadString255()
	}
	h.TraceID = decoder.ReadString255()
}

func (h *HTTPInfo) String() string {
	return fmt.Sprintf("%#v", h)
}

func (h *HTTPInfo) Merge(_ interface{}) {}

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

func (d *DNSInfo) Encode(encoder *codec.SimpleEncoder, msgType LogMessageType, code uint16) {
	encoder.WriteU16(d.TransID)
	encoder.WriteU16(d.QueryType)
	if msgType == MSG_T_SESSION || msgType == MSG_T_REQUEST {
		encoder.WriteString255(d.QueryName)
	}
	if msgType == MSG_T_SESSION || msgType == MSG_T_RESPONSE {
		encoder.WriteString255(d.Answers)
	}
}

func (d *DNSInfo) Decode(decoder *codec.SimpleDecoder, msgType LogMessageType, code uint16) {
	d.TransID = decoder.ReadU16()
	d.QueryType = decoder.ReadU16()
	if msgType == MSG_T_SESSION || msgType == MSG_T_REQUEST {
		d.QueryName = decoder.ReadString255()
	}
	if msgType == MSG_T_SESSION || msgType == MSG_T_RESPONSE {
		d.Answers = decoder.ReadString255()
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
