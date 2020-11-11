package datatype

import (
	"fmt"
	"net"
	"time"

	"github.com/google/gopacket/layers"
	"gitlab.x.lan/yunshan/droplet-libs/codec"
	"gitlab.x.lan/yunshan/droplet-libs/pool"
	"gitlab.x.lan/yunshan/droplet-libs/utils"
)

type LogProtoType uint8

const (
	PROTO_UNKOWN LogProtoType = iota
	PROTO_ICMP
	PROTO_HTTP
	PROTO_DNS
)

func (t *LogProtoType) String() string {
	formatted := ""
	switch *t {
	case PROTO_HTTP:
		formatted = "HTTP"
	case PROTO_DNS:
		formatted = "DNS"
	case PROTO_ICMP:
		formatted = "ICMP"
	default:
		formatted = "UNKOWN"
	}

	return formatted
}

type LogMessageType uint8

// 仅针对HTTP,DNS
const (
	MSG_T_REQUEST LogMessageType = iota
	MSG_T_RESPONSE
)

func (t *LogMessageType) String() string {
	formatted := ""
	if *t == MSG_T_REQUEST {
		formatted = "REQUEST"
	} else {
		formatted = "RESPONSE"
	}

	return formatted
}

type AppProtoHead struct {
	Proto   LogProtoType
	MsgType LogMessageType // HTTP,DNS: request/response, ICMP: 0-255
	Code    uint16         // HTTP状态码:1xx-5xx, DNS状态码:0-7, ICMP code:0-255
}

type AppProtoLogsBaseInfo struct {
	Timestamp time.Duration // packet时间戳
	FlowID    uint64        // 对应flow的ID
	AppProtoHead

	/* L3 */
	IPSrc IPv4Int
	IPDst IPv4Int
	/* L3 IPv6 */
	IP6Src net.IP
	IP6Dst net.IP
	/* L4 */
	PortSrc uint16
	PortDst uint16
	/* L3EpcID */
	L3EpcIDSrc int32
	L3EpcIDDst int32
}

func (i *AppProtoLogsBaseInfo) String() string {
	formatted := ""
	formatted += fmt.Sprintf("Timestamp: %v ", i.Timestamp)
	formatted += fmt.Sprintf("FlowID: %v ", i.FlowID)
	formatted += fmt.Sprintf("Proto: %s ", i.Proto.String())
	formatted += fmt.Sprintf("MsgType: %s ", i.MsgType.String())
	formatted += fmt.Sprintf("Code: %v ", i.Code)

	if len(i.IP6Src) > 0 {
		formatted += fmt.Sprintf("IP6Src: %s ", i.IP6Src)
		formatted += fmt.Sprintf("IP6Dst: %s ", i.IP6Dst)

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

// TODO String方法
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

func (l *AppProtoLogsData) Encode(encoder *codec.SimpleEncoder) error {
	encoder.WriteU64(uint64(l.Timestamp))
	encoder.WriteU64(l.FlowID)
	encoder.WriteU8(byte(l.Proto))
	encoder.WriteU8(byte(l.MsgType))
	encoder.WriteU16(l.Code)

	if len(l.IP6Src) > 0 {
		encoder.WriteBool(true) // 额外encode bool, decode时需要根据该bool, 来判断是否decode ipv6
		encoder.WriteIPv6(l.IP6Src)
		encoder.WriteIPv6(l.IP6Dst)
	} else {
		encoder.WriteBool(false)
		encoder.WriteU32(uint32(l.IPSrc))
		encoder.WriteU32(uint32(l.IPSrc))
	}
	encoder.WriteU16(l.PortSrc)
	encoder.WriteU16(l.PortDst)

	l.Detail.Encode(encoder, l.MsgType, l.Code)
	return nil
}

func (l *AppProtoLogsData) Decode(decoder *codec.SimpleDecoder) error {
	l.Timestamp = time.Duration(decoder.ReadU64())
	l.FlowID = decoder.ReadU64()
	l.Proto = LogProtoType(decoder.ReadU8())
	l.MsgType = LogMessageType(decoder.ReadU8())
	l.Code = decoder.ReadU16()

	if decoder.ReadBool() {
		decoder.ReadIPv6(l.IP6Src)
		decoder.ReadIPv6(l.IP6Dst)
	} else {
		l.IPSrc = decoder.ReadU32()
		l.IPSrc = decoder.ReadU32()
		l.IP6Src = nil
		l.IP6Dst = nil
	}
	l.PortSrc = decoder.ReadU16()
	l.PortDst = decoder.ReadU16()

	l.Detail.Decode(decoder, l.MsgType, l.Code)
	return nil
}

type ProtoSpecialInfo interface {
	Encode(encoder *codec.SimpleEncoder, msgType LogMessageType, code uint16)
	Decode(decoder *codec.SimpleDecoder, msgType LogMessageType, code uint16)
	String() string
}

// HTTPv2根据需要添加
type HTTPInfo struct {
	StreamID uint32 // HTTPv2
	Method   string
	URI      string
	Host     string
}

func (h *HTTPInfo) Encode(encoder *codec.SimpleEncoder, msgType LogMessageType, code uint16) {
	encoder.WriteU32(h.StreamID)
	if msgType == MSG_T_REQUEST {
		encoder.WriteString255(h.URI)
		encoder.WriteString255(h.Host)
	} else {
		encoder.WriteString255(h.Method)
	}
}

func (h *HTTPInfo) Decode(decoder *codec.SimpleDecoder, msgType LogMessageType, code uint16) {
	h.StreamID = decoder.ReadU32()
	if msgType == MSG_T_REQUEST {
		h.URI = decoder.ReadString255()
		h.Host = decoder.ReadString255()
	} else {
		h.Method = decoder.ReadString255()
	}
}

func (h *HTTPInfo) String() string {
	return fmt.Sprintf("%#v", h)
	// TODO
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
	if msgType == MSG_T_REQUEST {
		encoder.WriteString255(d.QueryName)
	} else {
		encoder.WriteString255(d.Answers)
	}
}

func (d *DNSInfo) Decode(decoder *codec.SimpleDecoder, msgType LogMessageType, code uint16) {
	d.TransID = decoder.ReadU16()
	d.QueryType = decoder.ReadU16()
	if msgType == MSG_T_REQUEST {
		d.QueryName = decoder.ReadString255()
	} else {
		d.Answers = decoder.ReadString255()
	}
}

func (d *DNSInfo) String() string {
	return fmt.Sprintf("%#v", d)
	// TODO
}

// 根据ICMP TYPE + CODE不同而不同
// 可能为空，如type(0) + code(0)
type ICMPInfo struct {
	Proto   layers.IPProtocol
	IPSrc   net.IP
	IPDst   net.IP
	PortSrc uint16
	PortDst uint16
}

// | 类型 | 代码  | 描述  |
// | ---  | ---   | --- |
// | 0    |0      |回显应答 |
// | 3    |0      |网络不可达 |
// |      |1      |主机不可达 |
// |      |2      |协议不可达 |
// |      |3      |端口不可达 |
// |      |4      |不可分片 |
// |      |5      |源站选路失败 |
// |      |6      |目的网络不认识 |
// |      |7      |目的主机不认识 |
// |      |8      |源主机被隔离 |
// |      |9      |目的网络被强制禁止 |
// |      |10     |目的主机被强制禁止 |
// |      |11     |服务类型TOS，网络不可达 |
// |      |12     |服务类型TOS，主机不可达 |
// |      |13     |过滤，通信被强制禁止 |
// |      |14     |主机越权 |
// |      |15     |优先权中止生效 |
// | 4    |0      |源端被关闭 |
// | 5    |0      |网络重定向 |
// |      |1      |主机重定向 |
// |      |2      |服务类型和网络重定向 |
// |      |3      |服务类型和主机重定向 |
// | 8    |0      |请求回显 |
// | 9    |0      |路由器通告 |
// | 10   |0      |路由器请求 |
// | 11   |0      |传输期间TTL为0 |
// |      |1      |数据包组装期间TTL为 0 |
// | 12   |0      |IP首部异常 |
// |      |1      |缺少必需的选项 |
// | 13   |0      |时间戳请求 |
// | 14   |0      |时间戳应答 |
// | 17   |0      |地址掩码请求 |
// | 18   |0      |地址掩码应答 |
func (i *ICMPInfo) Encode(encoder *codec.SimpleEncoder, msgType LogMessageType, code uint16) {
	notifyCode := uint16(msgType)<<16 + code
	switch notifyCode {
	// TODO
	//		case :
	}
}

func (i *ICMPInfo) Decode(decoder *codec.SimpleDecoder, msgType LogMessageType, code uint16) {
	notifyCode := uint16(msgType)<<16 + code
	switch notifyCode {
	// TODO
	//		case :
	}
}

func (i *ICMPInfo) String() string {
	return fmt.Sprintf("%#v", i)
	// TODO
}
