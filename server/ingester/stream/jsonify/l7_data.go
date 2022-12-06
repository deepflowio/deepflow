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

package jsonify

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"time"

	"github.com/deepflowys/deepflow/server/ingester/flow_tag"
	"github.com/deepflowys/deepflow/server/ingester/stream/common"
	"github.com/deepflowys/deepflow/server/libs/ckdb"
	"github.com/deepflowys/deepflow/server/libs/datatype"
	"github.com/deepflowys/deepflow/server/libs/datatype/pb"
	"github.com/deepflowys/deepflow/server/libs/grpc"
	"github.com/deepflowys/deepflow/server/libs/pool"
	"github.com/deepflowys/deepflow/server/libs/zerodoc"

	"github.com/google/gopacket/layers"
	logging "github.com/op/go-logging"
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
	FlowID       uint64 `json:"flow_id"`
	TapType      uint8  `json:"tap_type"`
	TapPortType  uint8  `json:"tap_port_type"`
	SignalSource uint16 `json:"signal_source"`
	TunnelType   uint8  `json:"tunnel_type"`
	TapPort      uint32 `json:"tap_port"`
	TapSide      string `json:"tap_side"`
	VtapID       uint16 `json:"vtap_id"`
	ReqTcpSeq    uint32 `json:"req_tcp_seq"`
	RespTcpSeq   uint32 `json:"resp_tcp_seq"`
	StartTime    int64  `json:"start_time"` // us
	EndTime      int64  `json:"end_time"`   // us

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
		ckdb.NewColumn("signal_source", ckdb.UInt16).SetIndex(ckdb.IndexNone),
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

	if err := block.WriteIPv4(f.IP40); err != nil {
		return err
	}
	if err := block.WriteIPv4(f.IP41); err != nil {
		return err
	}
	if len(f.IP60) == 0 {
		f.IP60 = net.IPv6zero
	}
	if err := block.WriteIPv6(f.IP60); err != nil {
		return err
	}
	if len(f.IP61) == 0 {
		f.IP61 = net.IPv6zero
	}
	if err := block.WriteIPv6(f.IP61); err != nil {
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
	if err := block.WriteUInt16(f.SignalSource); err != nil {
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
	if err := block.WriteInt64(f.StartTime); err != nil {
		return err
	}
	if err := block.WriteInt64(f.EndTime); err != nil {
		return err
	}
	if err := block.WriteDateTime(uint32(f.EndTime / US_TO_S_DEVISOR)); err != nil {
		return err
	}
	if err := block.WriteDateTime(uint32(f.EndTime / US_TO_S_DEVISOR)); err != nil {
		return err
	}

	if err := block.WriteInt32(int32(f.ProcessID0)); err != nil {
		return err
	}
	if err := block.WriteInt32(int32(f.ProcessID1)); err != nil {
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

type L7FlowLog struct {
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
	Endpoint        string

	// 数据库nullabled类型的字段, 需使用指针传值写入。如果值无意义，应传递nil.
	RequestId *uint64
	requestId uint64

	ResponseStatus    uint8
	ResponseCode      *int32
	responseCode      int32
	ResponseException string
	ResponseResult    string

	HttpProxyClient   string
	XRequestId        string
	TraceId           string
	SpanId            string
	ParentSpanId      string
	SpanKind          uint8
	spanKind          *uint8
	ServiceName       string
	ServiceInstanceId string

	ResponseDuration uint64
	RequestLength    *int64
	requestLength    int64
	ResponseLength   *int64
	responseLength   int64
	SqlAffectedRows  *uint64
	sqlAffectedRows  uint64

	AttributeNames  []string
	AttributeValues []string

	MetricsNames  []string
	MetricsValues []float64
}

func L7FlowLogColumns() []*ckdb.Column {
	l7Columns := []*ckdb.Column{}
	l7Columns = append(l7Columns, ckdb.NewColumn("_id", ckdb.UInt64).SetCodec(ckdb.CodecDoubleDelta))
	l7Columns = append(l7Columns, L7BaseColumns()...)
	l7Columns = append(l7Columns,
		ckdb.NewColumn("l7_protocol", ckdb.UInt8).SetIndex(ckdb.IndexNone).SetComment("0:未知 1:其他, 20:http1, 21:http2, 40:dubbo, 60:mysql, 80:redis, 100:kafka, 101:mqtt, 120:dns"),
		ckdb.NewColumn("l7_protocol_str", ckdb.LowCardinalityString).SetIndex(ckdb.IndexNone).SetComment("应用协议"),
		ckdb.NewColumn("version", ckdb.LowCardinalityString).SetComment("协议版本"),
		ckdb.NewColumn("type", ckdb.UInt8).SetIndex(ckdb.IndexNone).SetComment("日志类型, 0:请求, 1:响应, 2:会话"),

		ckdb.NewColumn("request_type", ckdb.LowCardinalityString).SetComment("请求类型, HTTP请求方法、SQL命令类型、NoSQL命令类型、MQ命令类型、DNS查询类型"),
		ckdb.NewColumn("request_domain", ckdb.String).SetComment("请求域名, HTTP主机名、RPC服务名称、DNS查询域名"),
		ckdb.NewColumn("request_resource", ckdb.String).SetComment("请求资源, HTTP路径、RPC方法名称、SQL命令、NoSQL命令"),
		ckdb.NewColumn("endpoint", ckdb.String).SetComment("端点"),
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
		ckdb.NewColumn("span_kind", ckdb.UInt8Nullable).SetComment("SpanKind"),
		ckdb.NewColumn("service_name", ckdb.LowCardinalityString).SetComment("service name"),
		ckdb.NewColumn("service_instance_id", ckdb.String).SetComment("service instance id"),

		ckdb.NewColumn("response_duration", ckdb.UInt64),
		ckdb.NewColumn("request_length", ckdb.Int64Nullable).SetComment("请求长度"),
		ckdb.NewColumn("response_length", ckdb.Int64Nullable).SetComment("响应长度"),
		ckdb.NewColumn("sql_affected_rows", ckdb.UInt64Nullable).SetComment("sql影响行数"),
		ckdb.NewColumn("attribute_names", ckdb.ArrayString).SetComment("额外的属性"),
		ckdb.NewColumn("attribute_values", ckdb.ArrayString).SetComment("额外的属性对应的值"),
		ckdb.NewColumn("metrics_names", ckdb.ArrayString).SetComment("额外的指标"),
		ckdb.NewColumn("metrics_values", ckdb.ArrayFloat64).SetComment("额外的指标对应的值"),
	)
	return l7Columns
}

func (h *L7FlowLog) WriteBlock(block *ckdb.Block) error {
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
	if err := block.WriteString(h.Endpoint); err != nil {
		return err
	}

	if err := block.WriteUInt64Nullable(h.RequestId); err != nil {
		return err
	}
	if err := block.WriteUInt8(h.ResponseStatus); err != nil {
		return err
	}
	if err := block.WriteInt32Nullable(h.ResponseCode); err != nil {
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
	if err := block.WriteUInt8Nullable(h.spanKind); err != nil {
		return err
	}
	if err := block.WriteString(h.ServiceName); err != nil {
		return err
	}
	if err := block.WriteString(h.ServiceInstanceId); err != nil {
		return err
	}

	if err := block.WriteUInt64(h.ResponseDuration); err != nil {
		return err
	}
	if err := block.WriteInt64Nullable(h.RequestLength); err != nil {
		return err
	}
	if err := block.WriteInt64Nullable(h.ResponseLength); err != nil {
		return err
	}
	if err := block.WriteUInt64Nullable(h.SqlAffectedRows); err != nil {
		return err
	}

	if err := block.WriteArrayString(h.AttributeNames); err != nil {
		return err
	}
	if err := block.WriteArrayString(h.AttributeValues); err != nil {
		return err
	}
	if err := block.WriteArrayString(h.MetricsNames); err != nil {
		return err
	}
	if err := block.WriteArrayFloat64(h.MetricsValues); err != nil {
		return err
	}

	return nil
}

func base64ToHexString(str string) string {
	if len(str) < 2 || str[len(str)-1] != '=' {
		return str
	}
	bytes, err := base64.StdEncoding.DecodeString(str)
	if err == nil {
		return hex.EncodeToString(bytes)
	}
	return str
}

func (h *L7FlowLog) Fill(l *pb.AppProtoLogsData, platformData *grpc.PlatformInfoTable) {
	h.L7Base.Fill(l, platformData)

	h.Type = uint8(l.Base.Head.MsgType)
	h.L7Protocol = uint8(l.Base.Head.Proto)
	h.L7ProtocolStr = datatype.L7Protocol(h.L7Protocol).String()

	h.ResponseStatus = datatype.STATUS_NOT_EXIST
	h.ResponseDuration = l.Base.Head.Rrt / uint64(time.Microsecond)
	// 协议结构统一, 不再为每个协议定义单独结构
	h.fillL7FlowLog(l)
}

// requestLength,responseLength 等于 -1 会认为是没有值. responseCode=-32768 会认为没有值
func (h *L7FlowLog) fillL7FlowLog(l *pb.AppProtoLogsData) {
	h.Version = l.Version
	h.requestLength = int64(l.ReqLen)
	h.responseLength = int64(l.RespLen)
	h.sqlAffectedRows = uint64(l.RowEffect)
	if h.sqlAffectedRows != 0 {
		h.SqlAffectedRows = &h.sqlAffectedRows
	}

	if l.Req != nil {
		h.RequestDomain = l.Req.Domain
		h.RequestResource = l.Req.Resource
		h.RequestType = l.Req.ReqType
		if h.requestLength != -1 && h.Type != uint8(datatype.MSG_T_RESPONSE) {
			h.RequestLength = &h.requestLength
		}
		h.Endpoint = l.Req.Endpoint
	}

	if l.Resp != nil && h.Type != uint8(datatype.MSG_T_REQUEST) {
		h.ResponseResult = l.Resp.Result
		h.responseCode = l.Resp.Code
		h.ResponseStatus = uint8(l.Resp.Status)
		h.fillExceptionDesc(l)

		if h.responseCode != datatype.L7PROTOCOL_LOG_RESP_CODE_NONE {
			h.ResponseCode = &h.responseCode
		}
		if h.responseLength != -1 {
			h.ResponseLength = &h.responseLength
		}
	}

	if l.ExtInfo != nil {
		h.requestId = uint64(l.ExtInfo.RequestId)
		if h.requestId != 0 {
			h.RequestId = &h.requestId
		}
		h.ServiceName = l.ExtInfo.ServiceName
		h.XRequestId = l.ExtInfo.XRequestId
		h.HttpProxyClient = l.ExtInfo.ClientIp
		if l.ExtInfo.HttpUserAgent != "" {
			h.AttributeNames = append(h.AttributeNames, "http_user_agent")
			h.AttributeValues = append(h.AttributeValues, l.ExtInfo.HttpUserAgent)
		}
		if l.ExtInfo.HttpReferer != "" {
			h.AttributeNames = append(h.AttributeNames, "http_referer")
			h.AttributeValues = append(h.AttributeValues, l.ExtInfo.HttpReferer)
		}
		if l.ExtInfo.RpcService != "" {
			h.AttributeNames = append(h.AttributeNames, "rpc_service")
			h.AttributeValues = append(h.AttributeValues, l.ExtInfo.RpcService)
		}
		h.AttributeNames = append(h.AttributeNames, l.ExtInfo.AttributeNames...)
		h.AttributeValues = append(h.AttributeValues, l.ExtInfo.AttributeValues...)
	}
	if l.TraceInfo != nil {
		h.SpanId = l.TraceInfo.SpanId
		h.TraceId = l.TraceInfo.TraceId
		h.ParentSpanId = l.TraceInfo.ParentSpanId
	}

	// 处理内置协议特殊情况
	switch datatype.L7Protocol(h.L7Protocol) {
	case datatype.L7_PROTOCOL_KAFKA:
		if l.Req != nil {
			if h.responseCode == 0 && l.Req.ReqType != datatype.KafkaCommandString[datatype.Fetch] {
				h.ResponseStatus = datatype.STATUS_NOT_EXIST
				h.ResponseCode = nil
			}
			h.RequestId = &h.requestId
		}
	case datatype.L7_PROTOCOL_PROTOBUF_RPC:
		// assume protobuf rpc Always have request_id and maybe equal to 0
		h.RequestId = &h.requestId
	}
}

func (h *L7FlowLog) fillExceptionDesc(l *pb.AppProtoLogsData) {
	if h.ResponseStatus != datatype.STATUS_SERVER_ERROR && h.ResponseStatus != datatype.STATUS_CLIENT_ERROR {
		return
	}
	code := l.Resp.Code
	switch datatype.L7Protocol(h.L7Protocol) {
	case datatype.L7_PROTOCOL_HTTP_1, datatype.L7_PROTOCOL_HTTP_2,
		datatype.L7_PROTOCOL_HTTP_1_TLS, datatype.L7_PROTOCOL_HTTP_2_TLS:
		h.ResponseException = GetHTTPExceptionDesc(uint16(code))
	case datatype.L7_PROTOCOL_DNS:
		h.ResponseException = GetDNSExceptionDesc(uint16(code))
	case datatype.L7_PROTOCOL_DUBBO:
		h.ResponseException = GetDubboExceptionDesc(uint16(code))
	case datatype.L7_PROTOCOL_KAFKA:
		h.ResponseException = GetKafkaExceptionDesc(int16(code))
	case datatype.L7_PROTOCOL_MQTT:
		if l.Version != "5" {
			h.ResponseException = GetMQTTV3ExceptionDesc(uint16(code))
		} else {
			h.ResponseException = GetMQTTV5ExceptionDesc(uint16(code))
		}
	case datatype.L7_PROTOCOL_MYSQL, datatype.L7_PROTOCOL_REDIS:
		fallthrough
	default:
		h.ResponseException = l.Resp.Exception
	}
}

func (h *L7FlowLog) Release() {
	ReleaseL7FlowLog(h)
}

func (h *L7FlowLog) EndTime() time.Duration {
	return time.Duration(h.L7Base.EndTime) * time.Microsecond
}

func (h *L7FlowLog) String() string {
	return fmt.Sprintf("L7FlowLog: %+v\n", *h)
}

func (b *L7Base) Fill(log *pb.AppProtoLogsData, platformData *grpc.PlatformInfoTable) {
	l := log.Base
	// 网络层
	if l.IsIpv6 == 1 {
		b.IsIPv4 = false
		if len(b.IP60) > 0 {
			b.IP60 = b.IP60[:0]
		}
		b.IP60 = append(b.IP60, l.Ip6Src...)
		if len(b.IP61) > 0 {
			b.IP61 = b.IP61[:0]
		}
		b.IP61 = append(b.IP61, l.Ip6Dst...)
	} else {
		b.IsIPv4 = true
		b.IP40 = l.IpSrc
		b.IP41 = l.IpDst
	}

	// 传输层
	b.ClientPort = uint16(l.PortSrc)
	b.ServerPort = uint16(l.PortDst)

	// 知识图谱
	b.Protocol = uint8(log.Base.Protocol)
	b.KnowledgeGraph.FillL7(l, platformData, layers.IPProtocol(b.Protocol))

	// 流信息
	b.FlowID = l.FlowId
	b.TapType = uint8(l.TapType)
	tunnelType := datatype.TunnelType(0)
	b.TapPort, b.TapPortType, tunnelType = datatype.TapPort(l.TapPort).SplitToPortTypeTunnel()
	b.SignalSource = uint16(datatype.SIGNAL_SOURCE_PACKET)
	if b.TapPortType == datatype.TAPPORT_FROM_OTEL {
		b.SignalSource = uint16(datatype.SIGNAL_SOURCE_OTEL)
	} else if b.TapPortType == datatype.TAPPORT_FROM_EBPF {
		b.SignalSource = uint16(datatype.SIGNAL_SOURCE_EBPF)
	}
	b.TunnelType = uint8(tunnelType)
	b.TapSide = zerodoc.TAPSideEnum(l.TapSide).String()
	b.VtapID = uint16(l.VtapId)
	b.ReqTcpSeq = l.ReqTcpSeq
	b.RespTcpSeq = l.RespTcpSeq
	b.StartTime = int64(l.StartTime) / int64(time.Microsecond)
	b.EndTime = int64(l.EndTime) / int64(time.Microsecond)

	// FIXME 补充填充链路追踪数据
	b.ProcessID0 = l.ProcessId_0
	b.ProcessID1 = l.ProcessId_1
	b.ProcessKName0 = l.ProcessKname_0
	b.ProcessKName1 = l.ProcessKname_1
	b.SyscallTraceIDRequest = l.SyscallTraceIdRequest
	b.SyscallTraceIDResponse = l.SyscallTraceIdResponse
	b.SyscallThread0 = l.SyscallTraceIdThread_0
	b.SyscallThread1 = l.SyscallTraceIdThread_1
	b.SyscallCapSeq0 = l.SyscallCapSeq_0
	b.SyscallCapSeq1 = l.SyscallCapSeq_1
}

func (k *KnowledgeGraph) FillL7(l *pb.AppProtoLogsBaseInfo, platformData *grpc.PlatformInfoTable, protocol layers.IPProtocol) {
	k.fill(
		platformData,
		l.IsIpv6 == 1, l.IsVipInterfaceSrc == 1, l.IsVipInterfaceDst == 1,
		l.L3EpcIdSrc, l.L3EpcIdDst,
		l.IpSrc, l.IpDst,
		l.Ip6Src, l.Ip6Dst,
		l.MacSrc, l.MacDst,
		uint16(l.PortDst),
		l.TapSide,
		protocol,
	)
}

var poolL7FlowLog = pool.NewLockFreePool(func() interface{} {
	return new(L7FlowLog)
})

func AcquireL7FlowLog() *L7FlowLog {
	l := poolL7FlowLog.Get().(*L7FlowLog)
	l.ReferenceCount.Reset()
	return l
}

func ReleaseL7FlowLog(l *L7FlowLog) {
	if l == nil {
		return
	}
	if l.SubReferenceCount() {
		return
	}
	*l = L7FlowLog{}
	poolL7FlowLog.Put(l)
}

var L7FlowLogCounter uint32

func ProtoLogToL7FlowLog(l *pb.AppProtoLogsData, platformData *grpc.PlatformInfoTable) *L7FlowLog {
	h := AcquireL7FlowLog()
	h._id = genID(uint32(l.Base.EndTime/uint64(time.Second)), &L7FlowLogCounter, uint16(l.Base.VtapId))
	h.Fill(l, platformData)
	return h
}

func L7FlowLogToFlowTagInterfaces(l *L7FlowLog, fields, fieldValues *[]interface{}) ([]interface{}, []interface{}) {
	time := uint32(l.L7Base.EndTime / US_TO_S_DEVISOR)
	db, table := common.FLOW_LOG_DB, common.L7_FLOW_ID.String()

	extraFieldNames := []string{"service_name", "endpoint", "service_instance_id"}
	extraFieldValues := []string{l.ServiceName, l.Endpoint, l.ServiceInstanceId}

	L3EpcIDs := []int32{l.L3EpcID0, l.L3EpcID1}
	PodNSIDs := []uint16{l.PodNSID0, l.PodNSID1}
	if l.L3EpcID0 == l.L3EpcID1 && l.PodNSID0 == l.PodNSID1 {
		L3EpcIDs = L3EpcIDs[:1]
		PodNSIDs = PodNSIDs[:1]
	}

	for i, L3EpcID := range L3EpcIDs {
		PodNSID := PodNSIDs[i]
		for i, name := range extraFieldNames {
			if extraFieldValues[i] == "" {
				continue
			}
			*fieldValues = append(*fieldValues, flow_tag.NewTagFieldValue(time, db, table, L3EpcID, PodNSID, flow_tag.FieldTag, name, extraFieldValues[i]))
		}

		for i, name := range l.AttributeNames {
			*fields = append(*fields, flow_tag.NewTagField(time, db, table, L3EpcID, PodNSID, flow_tag.FieldTag, name))
			if l.AttributeValues[i] != "" {
				*fieldValues = append(*fieldValues, flow_tag.NewTagFieldValue(time, db, table, L3EpcID, PodNSID, flow_tag.FieldTag, name, l.AttributeValues[i]))
			}
		}
		for _, name := range l.MetricsNames {
			*fields = append(*fields, flow_tag.NewTagField(time, db, table, L3EpcID, PodNSID, flow_tag.FieldMetrics, name))
		}
	}

	return *fields, *fieldValues
}
