package datatype

import (
	"fmt"
	"net"
	"time"

	"gitlab.yunshan.net/yunshan/droplet-libs/codec"
	"gitlab.yunshan.net/yunshan/droplet-libs/datatype/pb"
	"gitlab.yunshan.net/yunshan/droplet-libs/pool"
	"gitlab.yunshan.net/yunshan/droplet-libs/utils"
)

type LogProtoType uint8

const (
	PROTO_UNKNOWN LogProtoType = iota
	PROTO_HTTP
	PROTO_DNS
	PROTO_MYSQL
	PROTO_REDIS
	PROTO_DUBBO
	PROTO_KAFKA
	PROTO_OTHER
	PROTO_MAX
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
	case PROTO_OTHER:
		formatted = "OTHER"
	default:
		formatted = "UNKNOWN"
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
	Proto   LogProtoType
	MsgType LogMessageType // HTTP，DNS: request/response
	Status  uint8          // 状态描述：0：正常，1：已废弃使用(先前用于表示异常)，2：不存在，3：服务端异常，4：客户端异常
	Code    uint16         // HTTP状态码: 1xx-5xx, DNS状态码: 0-7
	RRT     time.Duration  // HTTP，DNS时延: response-request

}

func (h *AppProtoHead) WriteToPB(p *pb.AppProtoHead) {
	p.Proto = uint32(h.Proto)
	p.MsgType = uint32(h.MsgType)
	p.Status = uint32(h.Status)
	p.Code = uint32(h.Code)
	p.RRT = uint64(h.RRT)
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
	switch d.Proto {
	case PROTO_HTTP:
		ReleaseHTTPInfo(d.Detail.(*HTTPInfo))
	case PROTO_DNS:
		ReleaseDNSInfo(d.Detail.(*DNSInfo))
	case PROTO_MYSQL:
		ReleaseMYSQLInfo(d.Detail.(*MysqlInfo))
	case PROTO_REDIS:
		ReleaseREDISInfo(d.Detail.(*RedisInfo))
	case PROTO_DUBBO:
		ReleaseDubboInfo(d.Detail.(*DubboInfo))
	case PROTO_KAFKA:
		ReleaseKafkaInfo(d.Detail.(*KafkaInfo))
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
	encoder.WriteU64(uint64(l.TapPort))
	encoder.WriteU8(byte(l.Proto))
	encoder.WriteU8(byte(l.MsgType))
	encoder.WriteU8(byte(l.Status))
	encoder.WriteU16(l.Code)
	encoder.WriteU64(uint64(l.RRT))
	encoder.WriteU8(l.TapSide)
	encoder.WriteU64(l.MacSrc)
	encoder.WriteU64(l.MacDst)

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
	encoder.WriteU8(l.Protocol)
	encoder.WriteBool(l.IsVIPInterfaceSrc)
	encoder.WriteBool(l.IsVIPInterfaceDst)

	l.Detail.Encode(encoder, l.MsgType, l.Code)
	return nil
}

func (l *AppProtoLogsBaseInfo) WriteToPB(p *pb.AppProtoLogsBaseInfo) {
	p.StartTime = uint64(l.StartTime)
	p.EndTime = uint64(l.EndTime)
	p.FlowId = l.FlowId
	p.TapPort = uint64(l.TapPort)
	p.VtapId = uint32(l.VtapId)
	p.TapType = uint32(l.TapType)
	p.IsIPv6 = utils.Bool2UInt32(l.IsIPv6)
	p.TapSide = uint32(l.TapSide)
	if p.Head == nil {
		p.Head = &pb.AppProtoHead{}
	}
	l.AppProtoHead.WriteToPB(p.Head)

	p.MacSrc = l.MacSrc
	p.MacDst = l.MacDst
	p.IPSrc = l.IPSrc
	p.IPDst = l.IPDst
	p.IP6Src = l.IP6Src[:]
	p.IP6Dst = l.IP6Dst[:]
	p.L3EpcIDSrc = l.L3EpcIDSrc
	p.L3EpcIDDst = l.L3EpcIDDst
	p.PortSrc = uint32(l.PortSrc)
	p.PortDst = uint32(l.PortDst)
	p.Protocol = uint32(l.Protocol)
	p.IsVIPInterfaceSrc = utils.Bool2UInt32(l.IsVIPInterfaceSrc)
	p.IsVIPInterfaceDst = utils.Bool2UInt32(l.IsVIPInterfaceDst)
}

func (l *AppProtoLogsData) EncodePB(encoder *codec.SimpleEncoder, i interface{}) error {
	p, ok := i.(*pb.AppProtoLogsData)
	if !ok {
		return fmt.Errorf("invalid interface type, should be *pb.AppProtoLogsData")
	}

	data := *p
	l.WriteToPB(p)
	encoder.WritePB(p)
	if p.Http == nil {
		p.Http = data.Http
	}
	if p.Dns == nil {
		p.Dns = data.Dns
	}
	if p.Mysql == nil {
		p.Mysql = data.Mysql
	}
	if p.Redis == nil {
		p.Redis = data.Redis
	}
	if p.Dubbo == nil {
		p.Dubbo = data.Dubbo
	}
	if p.Kafka == nil {
		p.Kafka = data.Kafka
	}
	return nil
}

func (l *AppProtoLogsData) WriteToPB(p *pb.AppProtoLogsData) {
	if p.BaseInfo == nil {
		p.BaseInfo = &pb.AppProtoLogsBaseInfo{}
	}
	l.AppProtoLogsBaseInfo.WriteToPB(p.BaseInfo)
	switch l.Proto {
	case PROTO_HTTP:
		if http, ok := l.Detail.(*HTTPInfo); ok {
			if p.Http == nil {
				p.Http = &pb.HTTPInfo{}
			}
			http.WriteToPB(p.Http, l.AppProtoLogsBaseInfo.MsgType)
		}
		p.Dns, p.Mysql, p.Redis, p.Dubbo, p.Kafka = nil, nil, nil, nil, nil
	case PROTO_DNS:
		if dns, ok := l.Detail.(*DNSInfo); ok {
			if p.Dns == nil {
				p.Dns = &pb.DNSInfo{}
			}
			dns.WriteToPB(p.Dns, l.AppProtoLogsBaseInfo.MsgType)
		}
		p.Http, p.Mysql, p.Redis, p.Dubbo, p.Kafka = nil, nil, nil, nil, nil
	case PROTO_MYSQL:
		if mysql, ok := l.Detail.(*MysqlInfo); ok {
			if p.Mysql == nil {
				p.Mysql = &pb.MysqlInfo{}
			}
			mysql.WriteToPB(p.Mysql, l.AppProtoLogsBaseInfo.MsgType)
		}
		p.Http, p.Dns, p.Redis, p.Dubbo, p.Kafka = nil, nil, nil, nil, nil
	case PROTO_REDIS:
		if redis, ok := l.Detail.(*RedisInfo); ok {
			if p.Redis == nil {
				p.Redis = &pb.RedisInfo{}
			}
			redis.WriteToPB(p.Redis, l.AppProtoLogsBaseInfo.MsgType)
		}
		p.Http, p.Dns, p.Mysql, p.Dubbo, p.Kafka = nil, nil, nil, nil, nil
	case PROTO_DUBBO:
		if dubbo, ok := l.Detail.(*DubboInfo); ok {
			if p.Dubbo == nil {
				p.Dubbo = &pb.DubboInfo{}
			}
			dubbo.WriteToPB(p.Dubbo, l.AppProtoLogsBaseInfo.MsgType)
		}
		p.Http, p.Dns, p.Mysql, p.Redis, p.Kafka = nil, nil, nil, nil, nil
	case PROTO_KAFKA:
		if kafka, ok := l.Detail.(*KafkaInfo); ok {
			if p.Kafka == nil {
				p.Kafka = &pb.KafkaInfo{}
			}
			kafka.WriteToPB(p.Kafka, l.AppProtoLogsBaseInfo.MsgType)
		}
		p.Http, p.Dns, p.Mysql, p.Redis, p.Dubbo = nil, nil, nil, nil, nil
	}
}

func (l *AppProtoLogsData) Decode(decoder *codec.SimpleDecoder) error {
	l.StartTime = time.Duration(decoder.ReadU64())
	l.EndTime = time.Duration(decoder.ReadU64())
	l.FlowId = decoder.ReadU64()
	l.VtapId = decoder.ReadU16()
	l.TapType = decoder.ReadU16()
	l.TapPort = TapPort(decoder.ReadU64())
	l.Proto = LogProtoType(decoder.ReadU8())
	l.MsgType = LogMessageType(decoder.ReadU8())
	l.Status = decoder.ReadU8()
	l.Code = decoder.ReadU16()
	l.RRT = time.Duration(decoder.ReadU64())
	l.TapSide = decoder.ReadU8()
	l.MacSrc = decoder.ReadU64()
	l.MacDst = decoder.ReadU64()

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
	l.Protocol = decoder.ReadU8()
	l.IsVIPInterfaceSrc = decoder.ReadBool()
	l.IsVIPInterfaceDst = decoder.ReadBool()

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
	StreamID uint32 // HTTPv2
	Version  string
	TraceID  string
	SpanID   string

	Method   string
	Path     string
	Host     string
	ClientIP string

	ReqContentLength  int64
	RespContentLength int64
}

func (h *HTTPInfo) Encode(encoder *codec.SimpleEncoder, msgType LogMessageType, code uint16) {
	encoder.WriteU32(h.StreamID)
	encoder.WriteString255(h.Version)
	encoder.WriteString255(h.TraceID)
	encoder.WriteString255(h.SpanID)

	switch msgType {
	case MSG_T_REQUEST:
		encoder.WriteString255(h.Method)
		encoder.WriteString255(h.Path)
		encoder.WriteString255(h.Host)
		encoder.WriteString255(h.ClientIP)
		encoder.WriteU64(uint64(h.ReqContentLength))
	case MSG_T_RESPONSE:
		encoder.WriteU64(uint64(h.RespContentLength))
	case MSG_T_SESSION:
		encoder.WriteString255(h.Method)
		encoder.WriteString255(h.Path)
		encoder.WriteString255(h.Host)
		encoder.WriteString255(h.ClientIP)
		encoder.WriteU64(uint64(h.ReqContentLength))

		encoder.WriteU64(uint64(h.RespContentLength))
	}
}

func (h *HTTPInfo) WriteToPB(p *pb.HTTPInfo, msgType LogMessageType) {
	p.StreamID = h.StreamID
	p.Version = h.Version
	p.TraceID = h.TraceID
	p.SpanID = h.SpanID

	switch msgType {
	case MSG_T_REQUEST:
		p.Method = h.Method
		p.Path = h.Path
		p.Host = h.Host
		p.ClientIP = h.ClientIP
		p.ReqContentLength = h.ReqContentLength
		p.RespContentLength = 0
	case MSG_T_RESPONSE:
		p.RespContentLength = h.RespContentLength
		p.Method = ""
		p.Path = ""
		p.Host = ""
		p.ClientIP = ""
		p.ReqContentLength = 0
	case MSG_T_SESSION:
		p.Method = h.Method
		p.Path = h.Path
		p.Host = h.Host
		p.ClientIP = h.ClientIP
		p.ReqContentLength = h.ReqContentLength

		p.RespContentLength = h.RespContentLength
	}
}

func (h *HTTPInfo) Decode(decoder *codec.SimpleDecoder, msgType LogMessageType, code uint16) {
	h.StreamID = decoder.ReadU32()
	h.Version = decoder.ReadString255()
	h.TraceID = decoder.ReadString255()
	h.SpanID = decoder.ReadString255()

	switch msgType {
	case MSG_T_REQUEST:
		h.Method = decoder.ReadString255()
		h.Path = decoder.ReadString255()
		h.Host = decoder.ReadString255()
		h.ClientIP = decoder.ReadString255()
		h.ReqContentLength = int64(decoder.ReadU64())
	case MSG_T_RESPONSE:
		h.RespContentLength = int64(decoder.ReadU64())
	case MSG_T_SESSION:
		h.Method = decoder.ReadString255()
		h.Path = decoder.ReadString255()
		h.Host = decoder.ReadString255()
		h.ClientIP = decoder.ReadString255()
		h.ReqContentLength = int64(decoder.ReadU64())

		h.RespContentLength = int64(decoder.ReadU64())
	}
}

func (h *HTTPInfo) String() string {
	return fmt.Sprintf("%#v", h)
}

func (h *HTTPInfo) Merge(r interface{}) {
	if http, ok := r.(*HTTPInfo); ok {
		h.RespContentLength = http.RespContentLength
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

func (h *DNSInfo) WriteToPB(p *pb.DNSInfo, msgType LogMessageType) {
	p.TransID = uint32(h.TransID)
	p.QueryType = uint32(h.QueryType)

	if msgType == MSG_T_SESSION || msgType == MSG_T_REQUEST {
		p.QueryName = h.QueryName
	} else {
		p.QueryName = ""
	}
	if msgType == MSG_T_SESSION || msgType == MSG_T_RESPONSE {
		p.Answers = h.Answers
	} else {
		p.Answers = ""
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
