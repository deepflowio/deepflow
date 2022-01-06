package jsonify

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/google/gopacket/layers"
	"gitlab.yunshan.net/yunshan/droplet-libs/ckdb"
	"gitlab.yunshan.net/yunshan/droplet-libs/datatype"
	"gitlab.yunshan.net/yunshan/droplet-libs/grpc"
	"gitlab.yunshan.net/yunshan/droplet-libs/pool"
	"gitlab.yunshan.net/yunshan/droplet-libs/utils"
	"gitlab.yunshan.net/yunshan/droplet-libs/zerodoc"
	"gitlab.yunshan.net/yunshan/droplet/common"
	"gitlab.yunshan.net/yunshan/message/trident"
)

type L7Base struct {
	// 知识图谱
	KnowledgeGraph

	// 网络层
	IP40   uint32 `json:"ip4_0"`
	IP41   uint32 `json:"ip4_1"`
	IP60   net.IP `json:"ip6_0"`
	IP61   net.IP `json:"ip6_1"`
	IsIPv4 bool   `json:"is_ipv4"`

	// 传输层
	ClientPort uint16 `json:"client_port"`
	ServerPort uint16 `json:"server_port"`

	// 流信息
	FlowID    uint64 `json:"flow_id"`
	TapType   uint16 `json:"tap_type"`
	TapPort   uint32 `json:"tap_port"` // 显示为固定八个字符的16进制如'01234567'
	TapSide   string `json:"tap_side"`
	VtapID    uint16 `json:"vtap_id"`
	StartTime uint64 `json:"start_time"` // us
	EndTime   uint64 `json:"end_time"`   // us
}

func L7BaseColumns() []*ckdb.Column {
	columns := []*ckdb.Column{}
	// 知识图谱
	columns = append(columns, KnowledgeGraphColumns...)
	columns = append(columns,
		// 网络层
		ckdb.NewColumn("ip4_0", ckdb.IPv4),
		ckdb.NewColumn("ip4_1", ckdb.IPv4),
		ckdb.NewColumn("ip6_0", ckdb.IPv6),
		ckdb.NewColumn("ip6_1", ckdb.IPv6),
		ckdb.NewColumn("is_ipv4", ckdb.UInt8).SetIndex(ckdb.IndexMinmax),

		// 传输层
		ckdb.NewColumn("client_port", ckdb.UInt16).SetIndex(ckdb.IndexNone),
		ckdb.NewColumn("server_port", ckdb.UInt16).SetIndex(ckdb.IndexSet),

		// 流信息
		ckdb.NewColumn("flow_id", ckdb.UInt64).SetIndex(ckdb.IndexMinmax),
		ckdb.NewColumn("tap_type", ckdb.UInt16).SetIndex(ckdb.IndexSet),
		ckdb.NewColumn("tap_port", ckdb.UInt32).SetIndex(ckdb.IndexNone),
		ckdb.NewColumn("tap_side", ckdb.LowCardinalityString),
		ckdb.NewColumn("vtap_id", ckdb.UInt16).SetIndex(ckdb.IndexSet),
		ckdb.NewColumn("start_time", ckdb.DateTime64us).SetComment("精度: 微秒"),
		ckdb.NewColumn("end_time", ckdb.DateTime64us).SetComment("精度: 微秒"),
		ckdb.NewColumn("time", ckdb.DateTime).SetComment("精度: 秒"),
		ckdb.NewColumn("end_time_s", ckdb.DateTime).SetComment("精度: 秒"),
	)

	return columns
}

func (f *L7Base) WriteBlock(block *ckdb.Block) error {
	if err := f.KnowledgeGraph.WriteBlock(block); err != nil {
		return err
	}

	if err := block.WriteUInt32(f.IP40); err != nil {
		return err
	}
	if err := block.WriteUInt32(f.IP41); err != nil {
		return err
	}
	if len(f.IP60) == 0 {
		f.IP60 = net.IPv6zero
	}
	if err := block.WriteIP(f.IP60); err != nil {
		return err
	}
	if len(f.IP61) == 0 {
		f.IP61 = net.IPv6zero
	}
	if err := block.WriteIP(f.IP61); err != nil {
		return err
	}

	if err := block.WriteBool(f.IsIPv4); err != nil {
		return err
	}

	if err := block.WriteUInt16(f.ClientPort); err != nil {
		return err
	}
	if err := block.WriteUInt16(f.ServerPort); err != nil {
		return err
	}

	if err := block.WriteUInt64(f.FlowID); err != nil {
		return err
	}
	if err := block.WriteUInt16(f.TapType); err != nil {
		return err
	}
	if err := block.WriteUInt32(f.TapPort); err != nil {
		return err
	}
	if err := block.WriteString(f.TapSide); err != nil {
		return err
	}
	if err := block.WriteUInt16(f.VtapID); err != nil {
		return err
	}
	if err := block.WriteUInt64(f.StartTime); err != nil {
		return err
	}
	if err := block.WriteUInt64(f.EndTime); err != nil {
		return err
	}
	if err := block.WriteUInt32(uint32(f.EndTime / US_TO_S_DEVISOR)); err != nil {
		return err
	}
	if err := block.WriteUInt32(uint32(f.EndTime / US_TO_S_DEVISOR)); err != nil {
		return err
	}

	return nil
}

// http
type HTTPLogger struct {
	pool.ReferenceCount
	_id uint64

	L7Base

	// http应用层
	Type         uint8  `json:"type"` // 0: request  1: response 2: session
	Version      uint8  `json:"version"`
	Method       string `json:"method,omitempty"`
	ClientIP4    uint32 `json:"client_ip4,omitempty"`
	ClientIP6    net.IP `json:"client_ip6,omitempty"`
	ClientIsIPv4 bool   `json:"client_is_ipv4"`
	Host         string `json:"host,omitempty"`
	Path         string `json:"path,omitempty"`
	StreamID     uint32 `json:"stream_id,omitempty"`
	TraceID      string `json:"trace_id,omitempty"`
	AnswerCode   uint16 `json:"answer_code,omitempty"`

	// 指标量
	ContentLength int64  `json:"content_length"`
	Duration      uint64 `json:"duration,omitempty"` // us
}

func HTTPLoggerColumns() []*ckdb.Column {
	httpColumns := []*ckdb.Column{}
	httpColumns = append(httpColumns, ckdb.NewColumn("_id", ckdb.UInt64).SetCodec(ckdb.CodecDoubleDelta))
	httpColumns = append(httpColumns, L7BaseColumns()...)
	httpColumns = append(httpColumns,
		// 应用层HTTP
		ckdb.NewColumn("type", ckdb.UInt8).SetIndex(ckdb.IndexNone),
		ckdb.NewColumn("version", ckdb.UInt8),
		ckdb.NewColumn("method", ckdb.LowCardinalityString),
		ckdb.NewColumn("client_ip4", ckdb.IPv4),
		ckdb.NewColumn("client_ip6", ckdb.IPv6),
		ckdb.NewColumn("client_is_ipv4", ckdb.UInt8).SetIndex(ckdb.IndexNone),

		ckdb.NewColumn("host", ckdb.String),
		ckdb.NewColumn("path", ckdb.String),
		ckdb.NewColumn("stream_id", ckdb.UInt32Nullable),
		ckdb.NewColumn("trace_id", ckdb.String),
		ckdb.NewColumn("answer_code", ckdb.UInt16Nullable),

		// 指标量
		ckdb.NewColumn("content_length", ckdb.Int64Nullable),
		ckdb.NewColumn("duration", ckdb.UInt64),
	)
	return httpColumns
}

func (h *HTTPLogger) WriteBlock(block *ckdb.Block) error {
	index := 0
	err := block.WriteUInt64(h._id)
	if err != nil {
		return err
	}
	index++

	if err := h.L7Base.WriteBlock(block); err != nil {
		return nil
	}

	if err := block.WriteUInt8(h.Type); err != nil {
		return err
	}
	if err := block.WriteUInt8(h.Version); err != nil {
		return err
	}
	if err := block.WriteString(h.Method); err != nil {
		return err
	}
	if err := block.WriteUInt32(h.ClientIP4); err != nil {
		return err
	}
	if len(h.ClientIP6) == 0 {
		h.ClientIP6 = net.IPv6zero
	}
	if err := block.WriteIP(h.ClientIP6); err != nil {
		return err
	}
	if err := block.WriteBool(h.ClientIsIPv4); err != nil {
		return err
	}

	if err := block.WriteString(h.Host); err != nil {
		return err
	}
	if err := block.WriteString(h.Path); err != nil {
		return err
	}
	streamID := &(h.StreamID)
	if h.StreamID == 0 {
		streamID = nil
	}
	if err := block.WriteUInt32Nullable(streamID); err != nil {
		return err
	}
	if err := block.WriteString(h.TraceID); err != nil {
		return err
	}
	statusCode := &(h.AnswerCode)
	if h.AnswerCode == 0 {
		statusCode = nil
	}
	if err := block.WriteUInt16Nullable(statusCode); err != nil {
		return err
	}
	contentLength := &(h.ContentLength)
	if h.ContentLength == -1 { // contentLength解析失败时会赋值为-1，需要按无意义处理
		contentLength = nil
	}
	if err := block.WriteInt64Nullable(contentLength); err != nil {
		return err
	}
	if err := block.WriteUInt64(h.Duration); err != nil {
		return err
	}

	return nil
}

func parseIP(ipStr string) (uint32, net.IP, bool) {
	var ip4 uint32
	var ip6 net.IP
	isIPv4 := true

	ip := net.ParseIP(ipStr)
	if ip != nil {
		to4 := ip.To4()
		if to4 != nil {
			isIPv4 = true
			ip4 = utils.IpToUint32(to4)
		} else {
			isIPv4 = false
			ip6 = ip
		}
	}

	return ip4, ip6, isIPv4
}

func parseVersion(str string) uint8 {
	// 对于1.0,1.1 解析为 10, 11
	rmDot := strings.ReplaceAll(str, ".", "")
	v, _ := strconv.Atoi(rmDot)
	// 对于 2，需要解析为20
	if v < 10 {
		v = v * 10
	}
	return uint8(v)
}

func (h *HTTPLogger) Fill(l *datatype.AppProtoLogsData, platformData *grpc.PlatformInfoTable) {
	h.L7Base.Fill(l, platformData)
	if l.Proto == datatype.PROTO_HTTP {
		if httpInfo, ok := l.Detail.(*datatype.HTTPInfo); ok {
			h.Version = parseVersion(httpInfo.Version)
			h.Method = strings.ToUpper(httpInfo.Method)
			h.ClientIP4, h.ClientIP6, h.ClientIsIPv4 = parseIP(httpInfo.ClientIP)
			h.Host = httpInfo.Host
			h.Path = httpInfo.Path
			h.StreamID = httpInfo.StreamID
			h.TraceID = httpInfo.TraceID
			h.ContentLength = int64(httpInfo.ContentLength)
		}
	}
	h.Type = uint8(l.MsgType)
	h.AnswerCode = l.Code
	h.Duration = uint64(l.RRT / time.Microsecond)
}

func (h *HTTPLogger) Release() {
	ReleaseHTTPLogger(h)
}

func (h *HTTPLogger) EndTime() time.Duration {
	return time.Duration(h.L7Base.EndTime) * time.Microsecond
}

func (h *HTTPLogger) String() string {
	return fmt.Sprintf("HTTP: %+v\n", *h)
}

// dns
type DNSLogger struct {
	pool.ReferenceCount
	_id uint64

	L7Base

	// DNS应用层
	Type       uint8  `json:"type"` // 0: request  1: response 2: session
	ID         uint16 `json:"id"`
	DomainName string `json:"domain_name,omitempty"`
	QueryType  uint16 `json:"query_type,omitempty"`
	AnswerCode uint16 `json:"answer_code"`
	AnswerAddr string `json:"answer_addr,omitempty"`
	Protocol   uint8  `json:"protocol"`

	// 指标量
	Duration uint64 `json:"duration,omitempty"` // us
}

func DNSLoggerColumns() []*ckdb.Column {
	dnsColumns := []*ckdb.Column{}
	dnsColumns = append(dnsColumns, ckdb.NewColumn("_id", ckdb.UInt64).SetCodec(ckdb.CodecDoubleDelta))
	dnsColumns = append(dnsColumns, L7BaseColumns()...)
	dnsColumns = append(dnsColumns,
		// 应用层DNS
		ckdb.NewColumn("type", ckdb.UInt8).SetComment("0: request 1: response 2: session"),
		ckdb.NewColumn("id", ckdb.UInt16),
		ckdb.NewColumn("domain_name", ckdb.String),
		ckdb.NewColumn("query_type", ckdb.UInt16Nullable),
		ckdb.NewColumn("answer_code", ckdb.UInt16Nullable),
		ckdb.NewColumn("answer_addr", ckdb.String),
		ckdb.NewColumn("protocol", ckdb.UInt8).SetComment("0: 非IP包, 1-255: ip协议号(其中 1:icmp 6:tcp 17:udp)"),

		// 指标量
		ckdb.NewColumn("duration", ckdb.UInt64).SetComment(" 单位: 微秒"),
	)
	return dnsColumns
}

func (d *DNSLogger) WriteBlock(block *ckdb.Block) error {
	if err := block.WriteUInt64(d._id); err != nil {
		return err
	}

	if err := d.L7Base.WriteBlock(block); err != nil {
		return nil
	}

	if err := block.WriteUInt8(d.Type); err != nil {
		return err
	}
	if err := block.WriteUInt16(d.ID); err != nil {
		return err
	}
	if err := block.WriteString(d.DomainName); err != nil {
		return err
	}
	queryType := &(d.QueryType)
	if d.QueryType == 0 {
		queryType = nil
	}
	if err := block.WriteUInt16Nullable(queryType); err != nil {
		return err
	}
	answerCode := &(d.AnswerCode)
	if d.Type == 0 {
		answerCode = nil
	}
	if err := block.WriteUInt16Nullable(answerCode); err != nil {
		return err
	}
	if err := block.WriteString(d.AnswerAddr); err != nil {
		return err
	}
	if err := block.WriteUInt8(d.Protocol); err != nil {
		return err
	}

	if err := block.WriteUInt64(d.Duration); err != nil {
		return err
	}
	return nil
}

func (d *DNSLogger) Fill(l *datatype.AppProtoLogsData, platformData *grpc.PlatformInfoTable) {
	d.L7Base.Fill(l, platformData)

	// 应用层DNS信息
	if l.Proto == datatype.PROTO_DNS {
		if dnsInfo, ok := l.Detail.(*datatype.DNSInfo); ok {
			d.ID = dnsInfo.TransID
			d.DomainName = dnsInfo.QueryName
			d.QueryType = dnsInfo.QueryType
			d.AnswerAddr = dnsInfo.Answers
			d.Protocol = l.Protocol
		}
	}
	d.Type = uint8(l.MsgType)
	d.AnswerCode = l.Code

	// 指标量
	d.Duration = uint64(l.RRT / time.Microsecond)
}

func (d *DNSLogger) Release() {
	ReleaseDNSLogger(d)
}

func (d *DNSLogger) EndTime() time.Duration {
	return time.Duration(d.L7Base.EndTime) * time.Microsecond
}

func (d *DNSLogger) String() string {
	return fmt.Sprintf("DNS: %+v\n", *d)
}

func (b *L7Base) Fill(l *datatype.AppProtoLogsData, platformData *grpc.PlatformInfoTable) {
	// 网络层
	if l.IsIPv6 {
		b.IsIPv4 = false
		b.IP60 = l.IP6Src[:]
		b.IP61 = l.IP6Dst[:]
	} else {
		b.IsIPv4 = true
		b.IP40 = l.IPSrc
		b.IP41 = l.IPDst
	}

	// 传输层
	b.ClientPort = l.PortSrc
	b.ServerPort = l.PortDst

	// 知识图谱
	b.KnowledgeGraph.FillL7(l, platformData)

	// 流信息
	b.FlowID = l.FlowId
	b.TapType = l.TapType
	b.TapPort = l.TapPort
	b.TapSide = zerodoc.TAPSideEnum(l.TapSide).String()
	b.VtapID = l.VtapId
	b.StartTime = uint64(l.StartTime / time.Microsecond)
	b.EndTime = uint64(l.EndTime / time.Microsecond)
}

func (k *KnowledgeGraph) FillL7(l *datatype.AppProtoLogsData, platformData *grpc.PlatformInfoTable) {
	var info0, info1 *grpc.Info
	l3EpcID0, l3EpcID1 := l.L3EpcIDSrc, l.L3EpcIDDst

	// 对于VIP的流量，需要使用MAC来匹配
	lookupByMac0, lookupByMac1 := l.IsVIPInterfaceSrc, l.IsVIPInterfaceDst
	// 对于本地的流量，也需要使用MAC来匹配
	if l.TapSide == uint8(zerodoc.Local) {
		lookupByMac0, lookupByMac1 = true, true
	}
	mac0, mac1 := l.MacSrc, l.MacDst
	l3EpcMac0, l3EpcMac1 := mac0|uint64(l3EpcID0)<<48, mac1|uint64(l3EpcID1)<<48

	if lookupByMac0 && lookupByMac1 {
		info0, info1 = platformData.QueryMacInfosPair(l3EpcMac0, l3EpcMac1)
		if info0 == nil {
			info0 = common.RegetInfoFromIP(l.IsIPv6, l.IP6Src[:], uint32(l.IPSrc), int16(l3EpcID0), platformData)
		}
		if info1 == nil {
			info1 = common.RegetInfoFromIP(l.IsIPv6, l.IP6Dst[:], uint32(l.IPDst), int16(l3EpcID1), platformData)
		}
	} else if lookupByMac0 {
		info0 = platformData.QueryMacInfo(l3EpcMac0)
		if info0 == nil {
			info0 = common.RegetInfoFromIP(l.IsIPv6, l.IP6Src[:], uint32(l.IPSrc), int16(l3EpcID0), platformData)
		}
		if l.IsIPv6 {
			info1 = platformData.QueryIPV6Infos(int16(l3EpcID1), l.IP6Dst[:])
		} else {
			info1 = platformData.QueryIPV4Infos(int16(l3EpcID1), uint32(l.IPDst))
		}
	} else if lookupByMac1 {
		if l.IsIPv6 {
			info0 = platformData.QueryIPV6Infos(int16(l3EpcID0), l.IP6Src[:])
		} else {
			info0 = platformData.QueryIPV4Infos(int16(l3EpcID0), uint32(l.IPSrc))
		}
		info1 = platformData.QueryMacInfo(l3EpcMac1)
		if info1 == nil {
			info1 = common.RegetInfoFromIP(l.IsIPv6, l.IP6Dst[:], uint32(l.IPDst), int16(l3EpcID1), platformData)
		}
	} else if l.IsIPv6 {
		info0, info1 = platformData.QueryIPV6InfosPair(int16(l3EpcID0), net.IP(l.IP6Src[:]), int16(l3EpcID1), net.IP(l.IP6Dst[:]))

	} else {
		info0, info1 = platformData.QueryIPV4InfosPair(int16(l3EpcID0), uint32(l.IPSrc), int16(l3EpcID1), uint32(l.IPDst))
	}

	if info0 != nil {
		k.RegionID0 = uint16(info0.RegionID)
		k.AZID0 = uint16(info0.AZID)
		k.HostID0 = uint16(info0.HostID)
		k.L3DeviceType0 = uint8(info0.DeviceType)
		k.L3DeviceID0 = info0.DeviceID
		k.PodNodeID0 = info0.PodNodeID
		k.PodNSID0 = uint16(info0.PodNSID)
		k.PodGroupID0 = info0.PodGroupID
		k.PodID0 = info0.PodID
		k.PodClusterID0 = uint16(info0.PodClusterID)
		k.SubnetID0 = uint16(info0.SubnetID)
	}
	if info1 != nil {
		k.RegionID1 = uint16(info1.RegionID)
		k.AZID1 = uint16(info1.AZID)
		k.HostID1 = uint16(info1.HostID)
		k.L3DeviceType1 = uint8(info1.DeviceType)
		k.L3DeviceID1 = info1.DeviceID
		k.PodNodeID1 = info1.PodNodeID
		k.PodNSID1 = uint16(info1.PodNSID)
		k.PodGroupID1 = info1.PodGroupID
		k.PodID1 = info1.PodID
		k.PodClusterID1 = uint16(info1.PodClusterID)
		k.SubnetID1 = uint16(info1.SubnetID)
	}
	k.L3EpcID0, k.L3EpcID1 = l3EpcID0, l3EpcID1

	// DNS的协议是any，其他l7的协议都是TCP
	protocol := layers.IPProtocolTCP
	if l.Proto == datatype.PROTO_DNS {
		protocol = 0
	}

	if l.IsIPv6 {
		k.GroupIDs0, k.BusinessIDs0 = platformData.QueryIPv6GroupIDsAndBusinessIDs(int16(l3EpcID0), l.IP6Src[:])
		k.GroupIDs1, k.BusinessIDs1 = platformData.QueryIPv6GroupIDsAndBusinessIDs(int16(l3EpcID1), l.IP6Dst[:])

		// 0端如果是clusterIP或后端podIP需要匹配service_id
		if k.L3DeviceType0 == uint8(trident.DeviceType_DEVICE_TYPE_POD_SERVICE) ||
			k.PodID0 != 0 {
			_, k.ServiceID0 = platformData.QueryIPv6IsKeyServiceAndID(int16(l3EpcID0), net.IP(l.IP6Src[:]), 0, 0)
		}
		// 1端如果是NodeIP,clusterIP或后端podIP需要匹配service_id
		if k.L3DeviceType1 == uint8(trident.DeviceType_DEVICE_TYPE_POD_SERVICE) ||
			k.PodID1 != 0 ||
			k.PodNodeID1 != 0 {
			_, k.ServiceID1 = platformData.QueryIPv6IsKeyServiceAndID(int16(l3EpcID1), net.IP(l.IP6Dst[:]), protocol, l.PortDst)
		}
	} else {
		k.GroupIDs0, k.BusinessIDs0 = platformData.QueryGroupIDsAndBusinessIDs(int16(l3EpcID0), l.IPSrc)
		k.GroupIDs1, k.BusinessIDs1 = platformData.QueryGroupIDsAndBusinessIDs(int16(l3EpcID1), l.IPDst)

		// 0端如果是clusterIP或后端podIP需要匹配service_id
		if k.L3DeviceType0 == uint8(trident.DeviceType_DEVICE_TYPE_POD_SERVICE) ||
			k.PodID0 != 0 {
			_, k.ServiceID0 = platformData.QueryIsKeyServiceAndID(int16(l3EpcID0), l.IPSrc, 0, 0)
		}
		// 1端如果是NodeIP,clusterIP或后端podIP需要匹配service_id
		if k.L3DeviceType1 == uint8(trident.DeviceType_DEVICE_TYPE_POD_SERVICE) ||
			k.PodID1 != 0 ||
			k.PodNodeID1 != 0 {
			_, k.ServiceID1 = platformData.QueryIsKeyServiceAndID(int16(l3EpcID1), l.IPDst, protocol, l.PortDst)
		}
	}
}

// http
var poolHTTPLogger = pool.NewLockFreePool(func() interface{} {
	return new(HTTPLogger)
})

func AcquireHTTPLogger() *HTTPLogger {
	l := poolHTTPLogger.Get().(*HTTPLogger)
	l.ReferenceCount.Reset()
	return l
}

func ReleaseHTTPLogger(l *HTTPLogger) {
	if l == nil {
		return
	}
	if l.SubReferenceCount() {
		return
	}
	*l = HTTPLogger{}
	poolHTTPLogger.Put(l)
}

var L7HTTPCounter uint32

func ProtoLogToHTTPLogger(l *datatype.AppProtoLogsData, shardID int, platformData *grpc.PlatformInfoTable) interface{} {
	h := AcquireHTTPLogger()
	h._id = genID(uint32(l.EndTime/time.Second), &L7HTTPCounter, shardID)
	h.Fill(l, platformData)
	return h
}

// dns
var poolDNSLogger = pool.NewLockFreePool(func() interface{} {
	return new(DNSLogger)
})

func AcquireDNSLogger() *DNSLogger {
	l := poolDNSLogger.Get().(*DNSLogger)
	l.ReferenceCount.Reset()
	return l
}

func ReleaseDNSLogger(l *DNSLogger) {
	if l == nil {
		return
	}
	if l.SubReferenceCount() {
		return
	}
	*l = DNSLogger{}
	poolDNSLogger.Put(l)
}

var L7DNSCounter uint32

func ProtoLogToDNSLogger(l *datatype.AppProtoLogsData, shardID int, platformData *grpc.PlatformInfoTable) interface{} {
	h := AcquireDNSLogger()
	h._id = genID(uint32(l.EndTime/time.Second), &L7DNSCounter, shardID)
	h.Fill(l, platformData)
	return h
}
