package jsonify

import (
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/google/gopacket/layers"
	logging "github.com/op/go-logging"
	"gitlab.yunshan.net/yunshan/droplet-libs/ckdb"
	"gitlab.yunshan.net/yunshan/droplet-libs/datatype"
	"gitlab.yunshan.net/yunshan/droplet-libs/datatype/pb"
	"gitlab.yunshan.net/yunshan/droplet-libs/grpc"
	"gitlab.yunshan.net/yunshan/droplet-libs/pool"
	"gitlab.yunshan.net/yunshan/droplet-libs/zerodoc"
)

var log = logging.MustGetLogger("stream.jsonify")

type L7Base struct {
	// 知识图谱
	KnowledgeGraph

	// 网络层
	IP40     uint32 `json:"ip4_0"`
	IP41     uint32 `json:"ip4_1"`
	IP60     net.IP `json:"ip6_0"`
	IP61     net.IP `json:"ip6_1"`
	IsIPv4   bool   `json:"is_ipv4"`
	Protocol uint8

	// 传输层
	ClientPort uint16 `json:"client_port"`
	ServerPort uint16 `json:"server_port"`

	// 流信息
	FlowID      uint64 `json:"flow_id"`
	TapType     uint8  `json:"tap_type"`
	TapPortType uint8  `json:"tap_port_type"`
	TunnelType  uint8  `json:"tunnel_type"`
	TapPort     uint32 `json:"tap_port"`
	TapSide     string `json:"tap_side"`
	VtapID      uint16 `json:"vtap_id"`
	ReqTcpSeq   uint32 `json:"req_tcp_seq"`
	RespTcpSeq  uint32 `json:"resp_tcp_seq"`
	StartTime   uint64 `json:"start_time"` // us
	EndTime     uint64 `json:"end_time"`   // us

	ProcessID0             uint32
	ProcessID1             uint32
	ProcessKName0          string
	ProcessKName1          string
	SyscallTraceIDRequest  uint64
	SyscallTraceIDResponse uint64
	SyscallThread0         uint32
	SyscallThread1         uint32
	SyscallCapSeq0         uint32
	SyscallCapSeq1         uint32
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
		ckdb.NewColumn("protocol", ckdb.UInt8).SetIndex(ckdb.IndexMinmax),

		// 传输层
		ckdb.NewColumn("client_port", ckdb.UInt16).SetIndex(ckdb.IndexNone),
		ckdb.NewColumn("server_port", ckdb.UInt16).SetIndex(ckdb.IndexSet),

		// 流信息
		ckdb.NewColumn("flow_id", ckdb.UInt64).SetIndex(ckdb.IndexMinmax),
		ckdb.NewColumn("tap_type", ckdb.UInt8).SetIndex(ckdb.IndexSet),
		ckdb.NewColumn("tap_port_type", ckdb.UInt8).SetIndex(ckdb.IndexNone),
		ckdb.NewColumn("tunnel_type", ckdb.UInt8).SetIndex(ckdb.IndexNone),
		ckdb.NewColumn("tap_port", ckdb.UInt32).SetIndex(ckdb.IndexNone),
		ckdb.NewColumn("tap_side", ckdb.LowCardinalityString),
		ckdb.NewColumn("vtap_id", ckdb.UInt16).SetIndex(ckdb.IndexSet),
		ckdb.NewColumn("req_tcp_seq", ckdb.UInt32).SetIndex(ckdb.IndexNone),
		ckdb.NewColumn("resp_tcp_seq", ckdb.UInt32).SetIndex(ckdb.IndexNone),
		ckdb.NewColumn("start_time", ckdb.DateTime64us).SetComment("精度: 微秒"),
		ckdb.NewColumn("end_time", ckdb.DateTime64us).SetComment("精度: 微秒"),
		ckdb.NewColumn("time", ckdb.DateTime).SetComment("精度: 秒"),
		ckdb.NewColumn("end_time_s", ckdb.DateTime).SetComment("精度: 秒"),

		ckdb.NewColumn("process_id_0", ckdb.Int32).SetComment("客户端进程ID"),
		ckdb.NewColumn("process_id_1", ckdb.Int32).SetComment("服务端进程ID"),
		ckdb.NewColumn("process_kname_0", ckdb.String).SetComment("客户端进程名"),
		ckdb.NewColumn("process_kname_1", ckdb.String).SetComment("服务端进程名"),
		ckdb.NewColumn("syscall_trace_id_request", ckdb.UInt64).SetComment("SyscallTraceID-请求"),
		ckdb.NewColumn("syscall_trace_id_response", ckdb.UInt64).SetComment("SyscallTraceID-响应"),
		ckdb.NewColumn("syscall_thread_0", ckdb.UInt32).SetComment("Syscall线程-请求"),
		ckdb.NewColumn("syscall_thread_1", ckdb.UInt32).SetComment("Syscall线程-响应"),
		ckdb.NewColumn("syscall_cap_seq_0", ckdb.UInt32).SetComment("Syscall序列号-请求"),
		ckdb.NewColumn("syscall_cap_seq_1", ckdb.UInt32).SetComment("Syscall序列号-响应"),
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

	if err := block.WriteUInt8(f.Protocol); err != nil {
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
	if err := block.WriteUInt8(f.TapType); err != nil {
		return err
	}
	if err := block.WriteUInt8(f.TapPortType); err != nil {
		return err
	}
	if err := block.WriteUInt8(f.TunnelType); err != nil {
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
	if err := block.WriteUInt32(f.ReqTcpSeq); err != nil {
		return err
	}
	if err := block.WriteUInt32(f.RespTcpSeq); err != nil {
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

	if err := block.WriteUInt32(f.ProcessID0); err != nil {
		return err
	}
	if err := block.WriteUInt32(f.ProcessID1); err != nil {
		return err
	}
	if err := block.WriteString(f.ProcessKName0); err != nil {
		return err
	}
	if err := block.WriteString(f.ProcessKName1); err != nil {
		return err
	}
	if err := block.WriteUInt64(f.SyscallTraceIDRequest); err != nil {
		return err
	}
	if err := block.WriteUInt64(f.SyscallTraceIDResponse); err != nil {
		return err
	}
	if err := block.WriteUInt32(f.SyscallThread0); err != nil {
		return err
	}
	if err := block.WriteUInt32(f.SyscallThread1); err != nil {
		return err
	}
	if err := block.WriteUInt32(f.SyscallCapSeq0); err != nil {
		return err
	}
	if err := block.WriteUInt32(f.SyscallCapSeq1); err != nil {
		return err
	}

	return nil
}

type L7Logger struct {
	pool.ReferenceCount
	_id uint64

	L7Base

	L7Protocol    uint8
	L7ProtocolStr string
	Version       string
	Type          uint8

	RequestType     string
	RequestDomain   string
	RequestResource string

	// 数据库nullabled类型的字段, 需使用指针传值写入。如果值无意义，应传递nil.
	RequestId *uint64
	requestId uint64

	ResponseStatus    uint8
	ResponseCode      *int16
	responseCode      int16
	ResponseException string
	ResponseResult    string

	HttpProxyClient string
	XRequestId      string
	TraceId         string
	SpanId          string
	ParentSpanId    string
	SpanKind        uint8

	ResponseDuration uint64
	RequestLength    *uint64
	requestLength    uint64
	ResponseLength   *uint64
	responseLength   uint64
	SqlAffectedRows  *uint64
	sqlAffectedRows  uint64

	TagNames  []string
	TagValues []string
}

func L7LoggerColumns() []*ckdb.Column {
	l7Columns := []*ckdb.Column{}
	l7Columns = append(l7Columns, ckdb.NewColumn("_id", ckdb.UInt64).SetCodec(ckdb.CodecDoubleDelta))
	l7Columns = append(l7Columns, L7BaseColumns()...)
	l7Columns = append(l7Columns,
		ckdb.NewColumn("l7_protocol", ckdb.UInt8).SetIndex(ckdb.IndexNone).SetComment("0:未知 1:其他, 20:http1, 21:http2, 40:dubbo, 60:mysql, 80:redis, 100:kafka, 120:dns"),
		ckdb.NewColumn("l7_protocol_str", ckdb.LowCardinalityString).SetIndex(ckdb.IndexNone).SetComment("应用协议"),
		ckdb.NewColumn("version", ckdb.LowCardinalityString).SetComment("协议版本"),
		ckdb.NewColumn("type", ckdb.UInt8).SetIndex(ckdb.IndexNone).SetComment("日志类型, 0:请求, 1:响应, 2:会话"),

		ckdb.NewColumn("request_type", ckdb.LowCardinalityString).SetComment("请求类型, HTTP请求方法、SQL命令类型、NoSQL命令类型、MQ命令类型、DNS查询类型"),
		ckdb.NewColumn("request_domain", ckdb.String).SetComment("请求域名, HTTP主机名、RPC服务名称、DNS查询域名"),
		ckdb.NewColumn("request_resource", ckdb.String).SetComment("请求资源, HTTP路径、RPC方法名称、SQL命令、NoSQL命令"),
		ckdb.NewColumn("request_id", ckdb.UInt64Nullable).SetComment("请求ID, HTTP请求ID、RPC请求ID、MQ请求ID、DNS请求ID"),

		ckdb.NewColumn("response_status", ckdb.UInt8).SetComment("响应状态 0:正常, 1:异常 ,2:不存在，3:服务端异常, 4:客户端异常"),
		ckdb.NewColumn("response_code", ckdb.Int16Nullable).SetComment("响应码, HTTP响应码、RPC响应码、SQL响应码、MQ响应码、DNS响应码"),
		ckdb.NewColumn("response_exception", ckdb.String).SetComment("响应异常"),
		ckdb.NewColumn("response_result", ckdb.String).SetComment("响应结果, DNS解析地址"),

		ckdb.NewColumn("http_proxy_client", ckdb.String).SetComment("HTTP代理客户端"),
		ckdb.NewColumn("x_request_id", ckdb.String).SetComment("XRequestID"),
		ckdb.NewColumn("trace_id", ckdb.String).SetComment("TraceID"),
		ckdb.NewColumn("span_id", ckdb.String).SetComment("SpanID"),
		ckdb.NewColumn("parent_span_id", ckdb.String).SetComment("ParentSpanID"),
		ckdb.NewColumn("span_kind", ckdb.UInt8).SetComment("SpanKind"),

		ckdb.NewColumn("response_duration", ckdb.UInt64),
		ckdb.NewColumn("request_length", ckdb.Int64Nullable).SetComment("请求长度"),
		ckdb.NewColumn("response_length", ckdb.Int64Nullable).SetComment("响应长度"),
		ckdb.NewColumn("sql_affected_rows", ckdb.UInt64Nullable).SetComment("sql影响行数"),
		ckdb.NewColumn("tag_names", ckdb.ArrayString).SetComment("额外的tag"),
		ckdb.NewColumn("tag_values", ckdb.ArrayString).SetComment("额外的tag对应的值"),
	)
	return l7Columns
}

func (h *L7Logger) WriteBlock(block *ckdb.Block) error {
	index := 0
	err := block.WriteUInt64(h._id)
	if err != nil {
		return err
	}
	index++

	if err := h.L7Base.WriteBlock(block); err != nil {
		return nil
	}

	if err := block.WriteUInt8(h.L7Protocol); err != nil {
		return err
	}
	if err := block.WriteString(h.L7ProtocolStr); err != nil {
		return err
	}
	if err := block.WriteString(h.Version); err != nil {
		return err
	}
	if err := block.WriteUInt8(h.Type); err != nil {
		return err
	}

	if err := block.WriteString(h.RequestType); err != nil {
		return err
	}
	if err := block.WriteString(h.RequestDomain); err != nil {
		return err
	}
	if err := block.WriteString(h.RequestResource); err != nil {
		return err
	}

	if err := block.WriteUInt64Nullable(h.RequestId); err != nil {
		return err
	}
	if err := block.WriteUInt8(h.ResponseStatus); err != nil {
		return err
	}
	if err := block.WriteInt16Nullable(h.ResponseCode); err != nil {
		return err
	}
	if err := block.WriteString(h.ResponseException); err != nil {
		return err
	}
	if err := block.WriteString(h.ResponseResult); err != nil {
		return err
	}

	if err := block.WriteString(h.HttpProxyClient); err != nil {
		return err
	}
	if err := block.WriteString(h.XRequestId); err != nil {
		return err
	}
	if err := block.WriteString(h.TraceId); err != nil {
		return err
	}
	if err := block.WriteString(h.SpanId); err != nil {
		return err
	}
	if err := block.WriteString(h.ParentSpanId); err != nil {
		return err
	}
	if err := block.WriteUInt8(h.SpanKind); err != nil {
		return err
	}

	if err := block.WriteUInt64(h.ResponseDuration); err != nil {
		return err
	}
	if err := block.WriteUInt64Nullable(h.RequestLength); err != nil {
		return err
	}
	if err := block.WriteUInt64Nullable(h.ResponseLength); err != nil {
		return err
	}
	if err := block.WriteUInt64Nullable(h.SqlAffectedRows); err != nil {
		return err
	}

	if err := block.WriteArray(h.TagNames); err != nil {
		return err
	}
	if err := block.WriteArray(h.TagValues); err != nil {
		return err
	}

	return nil
}

func (h *L7Logger) fillHttp(l *pb.AppProtoLogsData) {
	if l.Http == nil {
		return
	}
	info := l.Http
	h.Version = info.Version
	h.RequestType = info.Method
	h.RequestDomain = info.Host
	h.RequestResource = info.Path

	if info.StreamID != 0 {
		h.requestId = uint64(info.StreamID)
		h.RequestId = &h.requestId
	}

	h.HttpProxyClient = info.ClientIP
	h.XRequestId = info.XRequestId
	h.TraceId = info.TraceID
	h.SpanId = info.SpanID

	if h.ResponseStatus == datatype.STATUS_SERVER_ERROR ||
		h.ResponseStatus == datatype.STATUS_CLIENT_ERROR {

		h.ResponseException = GetHTTPExceptionDesc(uint16(l.BaseInfo.Head.Code))
	}

	if info.ReqContentLength != -1 && h.Type != uint8(datatype.MSG_T_RESPONSE) {
		h.requestLength = uint64(info.ReqContentLength)
		h.RequestLength = &h.requestLength
	}

	if info.RespContentLength != -1 && h.Type != uint8(datatype.MSG_T_REQUEST) {
		h.responseLength = uint64(info.RespContentLength)
		h.ResponseLength = &h.responseLength
	}
}

func (h *L7Logger) fillDns(l *pb.AppProtoLogsData) {
	if l.Dns == nil {
		return
	}
	info := l.Dns
	h.RequestType = GetDNSQueryType(uint8(info.QueryType))
	h.RequestDomain = info.QueryName

	if info.TransID != 0 {
		requestId := uint64(info.TransID)
		h.RequestId = &requestId
	}

	h.ResponseResult = info.Answers
	if h.ResponseStatus == datatype.STATUS_SERVER_ERROR ||
		h.ResponseStatus == datatype.STATUS_CLIENT_ERROR {

		h.ResponseException = GetDNSExceptionDesc(uint16(l.BaseInfo.Head.Code))
	}
}

func (h *L7Logger) fillMysql(l *pb.AppProtoLogsData) {
	if l.Mysql == nil {
		return
	}
	info := l.Mysql
	if info.ProtocolVersion != 0 {
		h.Version = strconv.Itoa(int(info.ProtocolVersion))
	}
	if h.Type != uint8(datatype.MSG_T_RESPONSE) {
		h.RequestType = MysqlCommand(info.Command).String()
	}
	h.RequestResource = info.Context

	if h.Type != uint8(datatype.MSG_T_REQUEST) {
		h.responseCode = int16(info.ErrorCode)
		h.ResponseCode = &h.responseCode
	}
	h.ResponseException = info.ErrorMessage

	if info.AffectedRows != 0 {
		h.sqlAffectedRows = info.AffectedRows
		h.SqlAffectedRows = &h.sqlAffectedRows
	}
}

func (h *L7Logger) fillRedis(l *pb.AppProtoLogsData) {
	if l.Redis == nil {
		return
	}
	info := l.Redis
	h.RequestType = info.RequestType
	h.RequestResource = info.Request

	h.ResponseException = info.Error
	h.ResponseResult = info.Response
}

func (h *L7Logger) fillDubbo(l *pb.AppProtoLogsData) {
	if l.Dubbo == nil {
		return
	}
	info := l.Dubbo
	h.Version = info.DubboVersion
	h.RequestDomain = info.ServiceName
	h.RequestResource = info.MethodName
	if info.ID != 0 {
		h.requestId = uint64(info.ID)
		h.RequestId = &h.requestId
	}

	if h.ResponseStatus == datatype.STATUS_SERVER_ERROR ||
		h.ResponseStatus == datatype.STATUS_CLIENT_ERROR {

		h.ResponseException = GetDubboExceptionDesc(uint16(l.BaseInfo.Head.Code))
	}
	h.TraceId = info.TraceId

	if info.ReqBodyLen != -1 && h.Type != uint8(datatype.MSG_T_RESPONSE) {
		h.requestLength = uint64(info.ReqBodyLen)
		h.RequestLength = &h.requestLength
	}
	if info.RespBodyLen != -1 && h.Type != uint8(datatype.MSG_T_REQUEST) {
		h.responseLength = uint64(info.RespBodyLen)
		h.ResponseLength = &h.responseLength
	}
}
func (h *L7Logger) fillKafka(l *pb.AppProtoLogsData) {
	if l.Kafka == nil {
		return
	}
	info := l.Kafka
	if h.Type != uint8(datatype.MSG_T_RESPONSE) {
		h.RequestType = KafkaCommand(info.ApiKey).String()
	}
	if info.CorrelationId != 0 {
		h.requestId = uint64(info.CorrelationId)
		h.RequestId = &h.requestId
	}
	// 除fetch命令外，其他命令响应码不存在，状态也置为不存在
	if h.responseCode == 0 && info.ApiKey != uint32(Fetch) {
		h.ResponseStatus = uint8(datatype.STATUS_NOT_EXIST)
		h.ResponseCode = nil
	}

	if h.ResponseStatus == datatype.STATUS_SERVER_ERROR ||
		h.ResponseStatus == datatype.STATUS_CLIENT_ERROR {
		h.ResponseException = GetKafkaExceptionDesc(int16(l.BaseInfo.Head.Code))
	}

	if info.ReqMsgSize != -1 && h.Type != uint8(datatype.MSG_T_RESPONSE) {
		h.requestLength = uint64(info.ReqMsgSize)
		h.RequestLength = &h.requestLength
	}
	if info.RespMsgSize != -1 && h.Type != uint8(datatype.MSG_T_REQUEST) {
		h.responseLength = uint64(info.RespMsgSize)
		h.ResponseLength = &h.responseLength
	}
}

func (h *L7Logger) Fill(l *pb.AppProtoLogsData, platformData *grpc.PlatformInfoTable) {
	h.L7Base.Fill(l, platformData)

	h.Type = uint8(l.BaseInfo.Head.MsgType)
	h.L7Protocol = uint8(l.BaseInfo.Head.Proto)
	h.L7ProtocolStr = datatype.L7Protocol(h.L7Protocol).String()

	h.ResponseStatus = uint8(datatype.STATUS_NOT_EXIST)
	if h.Type != uint8(datatype.MSG_T_REQUEST) {
		h.ResponseStatus = uint8(l.BaseInfo.Head.Status)
		h.responseCode = int16(l.BaseInfo.Head.Code)
		h.ResponseCode = &h.responseCode
	}

	h.ResponseDuration = l.BaseInfo.Head.RRT / uint64(time.Microsecond)
	switch datatype.L7Protocol(l.BaseInfo.Head.Proto) {
	case datatype.L7_PROTOCOL_HTTP_1, datatype.L7_PROTOCOL_HTTP_2:
		h.fillHttp(l)
	case datatype.L7_PROTOCOL_DNS:
		h.fillDns(l)
	case datatype.L7_PROTOCOL_MYSQL:
		// mysql 异常时有响应码
		if h.ResponseStatus != datatype.STATUS_CLIENT_ERROR &&
			h.ResponseStatus != datatype.STATUS_SERVER_ERROR {
			h.ResponseCode = nil
		}
		h.fillMysql(l)
	case datatype.L7_PROTOCOL_REDIS:
		// redis 没有响应码
		if h.responseCode == 0 {
			h.ResponseCode = nil
		}
		h.fillRedis(l)
	case datatype.L7_PROTOCOL_DUBBO:
		h.fillDubbo(l)
	case datatype.L7_PROTOCOL_KAFKA:
		// 非fetch命令没有响应码
		h.fillKafka(l)
	}
}

func (h *L7Logger) Release() {
	ReleaseL7Logger(h)
}

func (h *L7Logger) EndTime() time.Duration {
	return time.Duration(h.L7Base.EndTime) * time.Microsecond
}

func (h *L7Logger) String() string {
	return fmt.Sprintf("L7Log: %+v\n", *h)
}

func (b *L7Base) Fill(log *pb.AppProtoLogsData, platformData *grpc.PlatformInfoTable) {
	l := log.BaseInfo
	// 网络层
	if l.IsIPv6 == 1 {
		b.IsIPv4 = false
		b.IP60 = l.IP6Src[:]
		b.IP61 = l.IP6Dst[:]
	} else {
		b.IsIPv4 = true
		b.IP40 = l.IPSrc
		b.IP41 = l.IPDst
	}

	// 传输层
	b.ClientPort = uint16(l.PortSrc)
	b.ServerPort = uint16(l.PortDst)

	// 知识图谱
	b.Protocol = uint8(log.BaseInfo.Protocol)
	b.KnowledgeGraph.FillL7(l, platformData, layers.IPProtocol(b.Protocol))

	// 流信息
	b.FlowID = l.FlowId
	b.TapType = uint8(l.TapType)
	tunnelType := datatype.TunnelType(0)
	b.TapPort, b.TapPortType, tunnelType = datatype.TapPort(l.TapPort).SplitToPortTypeTunnel()
	b.TunnelType = uint8(tunnelType)
	b.TapSide = zerodoc.TAPSideEnum(l.TapSide).String()
	b.VtapID = uint16(l.VtapId)
	b.ReqTcpSeq = l.ReqTcpSeq
	b.RespTcpSeq = l.RespTcpSeq
	b.StartTime = l.StartTime / uint64(time.Microsecond)
	b.EndTime = l.EndTime / uint64(time.Microsecond)

	// FIXME 补充填充链路追踪数据
	b.ProcessID0 = l.ProcessId0
	b.ProcessID1 = l.ProcessId1
	b.ProcessKName0 = l.ProcessKname0
	b.ProcessKName1 = l.ProcessKname1
	b.SyscallTraceIDRequest = l.SyscallTraceIdRequest
	b.SyscallTraceIDResponse = l.SyscallTraceIdResponse
	b.SyscallThread0 = l.SyscallTraceIdThread0
	b.SyscallThread1 = l.SyscallTraceIdThread1
	b.SyscallCapSeq0 = l.SyscallCapSeq0
	b.SyscallCapSeq1 = l.SyscallCapSeq1
}

func (k *KnowledgeGraph) FillL7(l *pb.AppProtoLogsBaseInfo, platformData *grpc.PlatformInfoTable, protocol layers.IPProtocol) {
	k.fill(
		platformData,
		l.IsIPv6 == 1, l.IsVIPInterfaceSrc == 1, l.IsVIPInterfaceDst == 1,
		int16(l.L3EpcIDSrc), int16(l.L3EpcIDDst),
		l.IPSrc, l.IPDst,
		l.IP6Src, l.IP6Dst,
		l.MacSrc, l.MacDst,
		uint16(l.PortDst),
		l.TapSide,
		protocol,
	)
}

var poolL7Logger = pool.NewLockFreePool(func() interface{} {
	return new(L7Logger)
})

func AcquireL7Logger() *L7Logger {
	l := poolL7Logger.Get().(*L7Logger)
	l.ReferenceCount.Reset()
	return l
}

func ReleaseL7Logger(l *L7Logger) {
	if l == nil {
		return
	}
	if l.SubReferenceCount() {
		return
	}
	*l = L7Logger{}
	poolL7Logger.Put(l)
}

var L7LogCounter uint32

func ProtoLogToL7Logger(l *pb.AppProtoLogsData, shardID int, platformData *grpc.PlatformInfoTable) interface{} {
	h := AcquireL7Logger()
	h._id = genID(uint32(l.BaseInfo.EndTime/uint64(time.Second)), &L7LogCounter, shardID)
	h.Fill(l, platformData)
	return h
}
