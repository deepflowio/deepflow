package jsonify

import (
	"fmt"
	"net"
	"strconv"
	"time"

	"gitlab.x.lan/yunshan/droplet-libs/datatype"
	"gitlab.x.lan/yunshan/droplet-libs/grpc"
	"gitlab.x.lan/yunshan/droplet-libs/pool"
	pf "gitlab.x.lan/yunshan/droplet/stream/platformdata"
)

type L7Base struct {
	// 网络层
	IP0     string `json:"ip_0"` // 广域网IP为0.0.0.0或::
	IP1     string `json:"ip_1"`
	RealIP0 string `json:"real_ip_0"`
	RealIP1 string `json:"real_ip_1"`

	// 传输层
	ClientPort uint16 `json:"client_port"`
	ServerPort uint16 `json:"server_port"`

	// 知识图谱
	KnowledgeGraph

	// 流信息
	FlowIDStr   string `json:"flow_id_str"`
	TapType     uint16 `json:"tap_type"`
	TapPort     string `json:"tap_port"` // 显示为固定八个字符的16进制如'01234567'
	VtapID      uint16 `json:"vtap_id"`
	Timestamp   uint64 `json:"timestamp"`    // us
	TimestampMs uint64 `json:"timestamp_ms"` // ms, kibana不支持微秒的展示，增加毫秒字段
}

type HTTPLogger struct {
	pool.ReferenceCount
	L7Base

	// http应用层
	Type       string `json:"type"` // 0: request  1: response
	Version    string `json:"version"`
	Method     string `json:"method,omitempty"`
	ClientIP   string `json:"client_ip,omitempty"`
	Host       string `json:"host,omitempty"`
	Path       string `json:"path,omitempty"`
	StreamID   uint32 `json:"stream_id,omitempty"`
	TraceID    string `json:"trace_id,omitempty"`
	StatusCode uint16 `json:"status_code,omitempty"`

	// 指标量
	ContentLength int64  `json:"content_length"`
	Duration      uint64 `json:"duration,omitempty"` // us
}

func (h *HTTPLogger) Fill(l *datatype.AppProtoLogsData) {
	h.L7Base.Fill(l)
	if l.Proto == datatype.PROTO_HTTP {
		if httpInfo, ok := l.Detail.(*datatype.HTTPInfo); ok {
			h.Version = httpInfo.Version
			h.Method = httpInfo.Method
			h.ClientIP = httpInfo.ClientIP
			h.Host = httpInfo.Host
			h.Path = httpInfo.Path
			h.StreamID = httpInfo.StreamID
			h.TraceID = httpInfo.TraceID
			h.ContentLength = int64(httpInfo.ContentLength)
		}
	}
	h.Type = l.MsgType.String()
	h.StatusCode = l.Code
	h.Duration = uint64(l.RRT / time.Microsecond)
}

func (h *HTTPLogger) Release() {
	ReleaseHTTPLogger(h)
}

func (h *HTTPLogger) EndTime() time.Duration {
	return time.Duration(h.Timestamp) * time.Microsecond
}

func (h *HTTPLogger) String() string {
	return fmt.Sprintf("HTTP: %+v\n", *h)
}

type DNSLogger struct {
	pool.ReferenceCount
	L7Base

	// DNS应用层
	Type       string `json:"type"` // 0: request  1: response
	ID         uint16 `json:"id"`
	DomainName string `json:"domain_name,omitempty"`
	QueryType  uint16 `json:"query_type,omitempty"`
	AnswerCode uint16 `json:"answer_code"`
	AnswerAddr string `json:"answer_addr,omitempty"`

	// 指标量
	Duration uint64 `json:"duration,omitempty"` // us
}

func (d *DNSLogger) Fill(l *datatype.AppProtoLogsData) {
	d.L7Base.Fill(l)

	// 应用层DNS信息
	if l.Proto == datatype.PROTO_DNS {
		if dnsInfo, ok := l.Detail.(*datatype.DNSInfo); ok {
			d.ID = dnsInfo.TransID
			d.DomainName = dnsInfo.QueryName
			d.QueryType = dnsInfo.QueryType
			d.AnswerAddr = dnsInfo.Answers
		}
	}
	d.Type = l.MsgType.String()
	d.AnswerCode = l.Code

	// 指标量
	d.Duration = uint64(l.RRT / time.Microsecond)
}

func (d *DNSLogger) Release() {
	ReleaseDNSLogger(d)
}

func (d *DNSLogger) EndTime() time.Duration {
	return time.Duration(d.Timestamp) * time.Microsecond
}

func (d *DNSLogger) String() string {
	return fmt.Sprintf("DNS: %+v\n", *d)
}

func (b *L7Base) Fill(l *datatype.AppProtoLogsData) {
	// 网络层
	if l.IsIPv6 {
		if datatype.EPC_FROM_INTERNET == l.L3EpcIDSrc {
			b.IP0 = "::"
		} else {
			b.IP0 = net.IP(l.IP6Src[:]).String()
		}
		if datatype.EPC_FROM_INTERNET == l.L3EpcIDDst {
			b.IP1 = "::"
		} else {
			b.IP1 = net.IP(l.IP6Dst[:]).String()
		}
		b.RealIP0 = net.IP(l.IP6Src[:]).String()
		b.RealIP1 = net.IP(l.IP6Dst[:]).String()
	} else {
		if datatype.EPC_FROM_INTERNET == l.L3EpcIDSrc {
			b.IP0 = "0.0.0.0"
		} else {
			b.IP0 = IPIntToString(uint32(l.IPSrc))
		}
		if datatype.EPC_FROM_INTERNET == l.L3EpcIDDst {
			b.IP1 = "0.0.0.0"
		} else {
			b.IP1 = IPIntToString(uint32(l.IPDst))
		}
		b.RealIP0 = IPIntToString(uint32(l.IPSrc))
		b.RealIP1 = IPIntToString(uint32(l.IPDst))
	}

	// 传输层
	b.ClientPort = l.PortSrc
	b.ServerPort = l.PortDst

	// 知识图谱
	b.KnowledgeGraph.FillL7(l)

	// 流信息
	b.FlowIDStr = strconv.FormatInt(int64(l.FlowId), 10)
	b.TapType = l.TapType
	b.TapPort = fmt.Sprintf("%08x", l.TapPort)
	b.VtapID = l.VtapId
	b.Timestamp = uint64(l.Timestamp / time.Microsecond)
	b.TimestampMs = uint64(l.Timestamp / time.Millisecond)
}

func (k *KnowledgeGraph) FillL7(l *datatype.AppProtoLogsData) {
	var info0, info1 *grpc.Info
	l3EpcID0, l3EpcID1 := l.L3EpcIDSrc, l.L3EpcIDDst

	if l.IsIPv6 {
		info0, info1 = pf.PlatformData.QueryIPV6InfosPair(int16(l3EpcID0), net.IP(l.IP6Src[:]), int16(l3EpcID1), net.IP(l.IP6Dst[:]))
	} else {
		info0, info1 = pf.PlatformData.QueryIPV4InfosPair(int16(l3EpcID0), uint32(l.IPSrc), int16(l3EpcID1), uint32(l.IPDst))
	}

	if info0 != nil {
		k.RegionID0 = info0.RegionID
		k.AZID0 = info0.AZID
		k.HostID0 = info0.HostID
		k.L3DeviceType0 = info0.DeviceType
		k.L3DeviceID0 = info0.DeviceID
		k.PodNodeID0 = info0.PodNodeID
		k.PodNSID0 = info0.PodNSID
		k.PodGroupID0 = info0.PodGroupID
		k.PodID0 = info0.PodID
		k.PodClusterID0 = info0.PodClusterID
		k.SubnetID0 = info0.SubnetID
	}
	if info1 != nil {
		k.RegionID1 = info1.RegionID
		k.AZID1 = info1.AZID
		k.HostID1 = info1.HostID
		k.L3DeviceType1 = info1.DeviceType
		k.L3DeviceID1 = info1.DeviceID
		k.PodNodeID1 = info1.PodNodeID
		k.PodNSID1 = info1.PodNSID
		k.PodGroupID1 = info1.PodGroupID
		k.PodID1 = info1.PodID
		k.PodClusterID1 = info1.PodClusterID
		k.SubnetID1 = info1.SubnetID
	}
	k.L3EpcID0, k.L3EpcID1 = l3EpcID0, l3EpcID1
}

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

func ProtoLogToHTTPLogger(l *datatype.AppProtoLogsData) *HTTPLogger {
	h := AcquireHTTPLogger()
	h.Fill(l)
	return h
}

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

func ProtoLogToDNSLogger(l *datatype.AppProtoLogsData) *DNSLogger {
	h := AcquireDNSLogger()
	h.Fill(l)
	return h
}
