package exporter

import (
	"encoding/binary"
	"strconv"
	"strings"

	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/ptrace"
	"go.opentelemetry.io/collector/pdata/ptrace/ptraceotlp"
	_ "go.opentelemetry.io/proto/otlp/common/v1"

	"github.com/deepflowio/deepflow/server/ingester/flow_log/log_data"
	"github.com/deepflowio/deepflow/server/libs/datatype"
	"github.com/deepflowio/deepflow/server/libs/utils"
	"github.com/google/gopacket/layers"
)

func putStrWithoutEmpty(attrs pcommon.Map, key, value string) {
	if value != "" {
		attrs.PutStr(key, value)
	}
}

func putIntWithoutZero(attrs pcommon.Map, key string, value int64) {
	if value != 0 {
		attrs.PutInt(key, value)
	}
}

func putUniversalTags(attrs pcommon.Map, tags0, tags1 *UniversalTags) {
	putStrWithoutEmpty(attrs, "df.universal_tag.region_0", tags0.Region)
	putStrWithoutEmpty(attrs, "df.universal_tag.region_1", tags1.Region)
	putStrWithoutEmpty(attrs, "df.universal_tag.az_0", tags0.AZ)
	putStrWithoutEmpty(attrs, "df.universal_tag.az_1", tags1.AZ)
	putStrWithoutEmpty(attrs, "df.universal_tag.host_0", tags0.Host)
	putStrWithoutEmpty(attrs, "df.universal_tag.host_1", tags1.Host)
	putStrWithoutEmpty(attrs, "df.universal_tag.epc_0", tags0.L3Epc)
	putStrWithoutEmpty(attrs, "df.universal_tag.epc_1", tags1.L3Epc)
	putStrWithoutEmpty(attrs, "df.universal_tag.pod_cluster_0", tags0.PodCluster)
	putStrWithoutEmpty(attrs, "df.universal_tag.pod_cluster_1", tags1.PodCluster)
	putStrWithoutEmpty(attrs, "df.universal_tag.pod_ns_0", tags0.PodNS)
	putStrWithoutEmpty(attrs, "df.universal_tag.pod_ns_1", tags1.PodNS)
	putStrWithoutEmpty(attrs, "df.universal_tag.pod_node_0", tags0.PodNode)
	putStrWithoutEmpty(attrs, "df.universal_tag.pod_node_1", tags1.PodNode)
	putStrWithoutEmpty(attrs, "df.universal_tag.pod_group_0", tags0.PodGroup)
	putStrWithoutEmpty(attrs, "df.universal_tag.pod_group_1", tags1.PodGroup)
	putStrWithoutEmpty(attrs, "df.universal_tag.pod_0", tags0.Pod)
	putStrWithoutEmpty(attrs, "df.universal_tag.pod_1", tags1.Pod)
	putStrWithoutEmpty(attrs, "df.universal_tag.service_0", tags0.Service)
	putStrWithoutEmpty(attrs, "df.universal_tag.service_1", tags1.Service)
}

func L7FlowLogToExportRequest(l7 *log_data.L7FlowLog, universalTagsManager *UniversalTagsManager) ptraceotlp.ExportRequest {
	tags0, tags1 := universalTagsManager.QueryUniversalTags(l7)
	td := ptrace.NewTraces()

	resSpan := td.ResourceSpans().AppendEmpty()
	resAttrs := resSpan.Resource().Attributes()
	putUniversalTags(resAttrs, tags0, tags1)

	span := resSpan.ScopeSpans().AppendEmpty().Spans().AppendEmpty()
	spanAttrs := span.Attributes()
	for i := range l7.AttributeNames {
		putStrWithoutEmpty(spanAttrs, l7.AttributeNames[i], l7.AttributeValues[i])
	}
	putStrWithoutEmpty(spanAttrs, "df.span.x_request_id", l7.XRequestId)
	putIntWithoutZero(spanAttrs, "df.span.syscall_trace_id_request", int64(l7.SyscallTraceIDRequest))
	putIntWithoutZero(spanAttrs, "df.span.syscall_trace_id_response", int64(l7.SyscallTraceIDResponse))
	putIntWithoutZero(spanAttrs, "df.span.syscall_thread_0", int64(l7.SyscallThread0))
	putIntWithoutZero(spanAttrs, "df.span.syscall_thread_1", int64(l7.SyscallThread1))
	putIntWithoutZero(spanAttrs, "df.span.syscall_cap_seq_0", int64(l7.SyscallCapSeq0))
	putIntWithoutZero(spanAttrs, "df.span.syscall_cap_seq_1", int64(l7.SyscallCapSeq1))
	putIntWithoutZero(spanAttrs, "df.span.req_tcp_seq", int64(l7.ReqTcpSeq))
	putIntWithoutZero(spanAttrs, "df.span.resp_tcp_seq", int64(l7.RespTcpSeq))
	msgType := datatype.LogMessageType(l7.Type)
	putStrWithoutEmpty(spanAttrs, "df.span.type", strings.ToLower(msgType.String()))

	putStrWithoutEmpty(spanAttrs, "df.span.app_service", l7.AppService)
	putStrWithoutEmpty(spanAttrs, "df.span.app_instance", l7.AppInstance)
	putStrWithoutEmpty(spanAttrs, "df.span.endpoint", l7.Endpoint)
	putIntWithoutZero(spanAttrs, "df.span.process_id_0", int64(l7.ProcessID0))
	putIntWithoutZero(spanAttrs, "df.span.process_id_1", int64(l7.ProcessID1))
	putStrWithoutEmpty(spanAttrs, "df.span.process_kname_0", l7.ProcessKName0)
	putStrWithoutEmpty(spanAttrs, "df.span.process_kname_1", l7.ProcessKName1)

	putIntWithoutZero(resAttrs, "df.flow_info.id", int64(l7.ID()))
	putIntWithoutZero(resAttrs, "df.flow_info.time", int64(l7.EndTime()))
	putIntWithoutZero(resAttrs, "df.flow_info.flow_id", int64(l7.FlowID))

	span.SetStartTimestamp(pcommon.Timestamp(l7.StartTime()))
	span.SetEndTimestamp(pcommon.Timestamp(l7.EndTime()))
	span.Status().SetCode(responseStatusToSpanStatus(l7.ResponseStatus))
	span.SetSpanID(uint64ToSpanID(l7.ID()))
	span.SetTraceID(genTraceID(int(l7.ID())))
	span.SetParentSpanID(pcommon.NewSpanIDEmpty())
	span.SetKind(tapSideToSpanKind(l7.TapSide))

	putStrWithoutEmpty(resAttrs, "df.capture_info.signal_source", datatype.SignalSource(l7.SignalSource).String())
	putStrWithoutEmpty(resAttrs, "df.capture_info.nat_source", datatype.NATSource(l7.NatSource).String())
	putStrWithoutEmpty(resAttrs, "df.capture_info.tap_port", datatype.TapPort(l7.TapPort).String())
	putStrWithoutEmpty(resAttrs, "df.capture_info.tap_port_type", tapPortTypeToString(l7.TapPortType))
	putStrWithoutEmpty(resAttrs, "df.capture_info.tap_side", l7.TapSide)
	putStrWithoutEmpty(resAttrs, "df.capture_info.vtap", tags0.Vtap)

	resAttrs.PutBool("df.network.is_ipv4", l7.IsIPv4)
	resAttrs.PutBool("df.network.is_internet_0", l7.L3EpcID0 == datatype.EPC_FROM_INTERNET)
	resAttrs.PutBool("df.network.is_internet_1", l7.L3EpcID1 == datatype.EPC_FROM_INTERNET)
	if l7.IsIPv4 {
		resAttrs.PutStr("df.network.ip_0", utils.IpFromUint32(l7.IP40).String())
		resAttrs.PutStr("df.network.ip_1", utils.IpFromUint32(l7.IP41).String())
	} else {
		resAttrs.PutStr("df.network.ip_0", l7.IP60.String())
		resAttrs.PutStr("df.network.ip_1", l7.IP61.String())
	}
	resAttrs.PutStr("df.network.protocol", layers.IPProtocol(l7.Protocol).String())

	putIntWithoutZero(resAttrs, "df.transport.client_port", int64(l7.ClientPort))
	putIntWithoutZero(resAttrs, "df.transport.server_port", int64(l7.ServerPort))

	putStrWithoutEmpty(resAttrs, "df.application.l7_protocol", datatype.L7Protocol(l7.L7Protocol).String())

	switch datatype.L7Protocol(l7.L7Protocol) {
	case datatype.L7_PROTOCOL_DNS:
		setDNS(&span, spanAttrs, l7)
	case datatype.L7_PROTOCOL_HTTP_1, datatype.L7_PROTOCOL_HTTP_2, datatype.L7_PROTOCOL_HTTP_1_TLS, datatype.L7_PROTOCOL_HTTP_2_TLS:
		setHTTP(&span, spanAttrs, l7)
	case datatype.L7_PROTOCOL_DUBBO:
		setDubbo(&span, spanAttrs, resAttrs, l7)
	case datatype.L7_PROTOCOL_GRPC:
		setGRPC(&span, spanAttrs, l7)
	case datatype.L7_PROTOCOL_KAFKA:
		setKafka(&span, spanAttrs, l7)
	case datatype.L7_PROTOCOL_MQTT:
		setMQTT(&span, spanAttrs, l7)
	case datatype.L7_PROTOCOL_MYSQL:
		setMySQL(&span, spanAttrs, l7)
	case datatype.L7_PROTOCOL_REDIS:
		setRedis(&span, spanAttrs, l7)
	}

	return ptraceotlp.NewExportRequestFromTraces(td)
}

func setDNS(span *ptrace.Span, spanAttrs pcommon.Map, l7 *log_data.L7FlowLog) {
	putStrWithoutEmpty(spanAttrs, "df.dns.request_type", l7.RequestType)
	putStrWithoutEmpty(spanAttrs, "df.dns.request_resource", l7.RequestResource)
	if l7.RequestId != nil {
		spanAttrs.PutInt("df.global.request_id", int64(*l7.RequestId))
	}
	spanAttrs.PutInt("df.dns.response_status", int64(l7.ResponseStatus))
	if l7.ResponseCode != nil {
		spanAttrs.PutInt("df.dns.response_code", int64(*l7.ResponseCode))
	}
	if l7.ResponseException != "" {
		span.Events().AppendEmpty().SetName(l7.ResponseException)
	}
	if l7.ResponseResult != "" {
		spanAttrs.PutStr("df.dns.response_result", l7.ResponseResult)
	}
}

func setHTTP(span *ptrace.Span, spanAttrs pcommon.Map, l7 *log_data.L7FlowLog) {
	putStrWithoutEmpty(spanAttrs, "http.flavor", l7.Version)
	putStrWithoutEmpty(spanAttrs, "http.method", l7.RequestType)
	putStrWithoutEmpty(spanAttrs, "net.peer.name", l7.RequestDomain)
	putStrWithoutEmpty(spanAttrs, "df.http.path", l7.RequestResource)
	if l7.RequestId != nil {
		spanAttrs.PutInt("df.global.request_id", int64(*l7.RequestId))
	}
	// ResponseStatus
	if l7.ResponseCode != nil {
		spanAttrs.PutInt("http.status_code", int64(*l7.ResponseCode))
	}
	if l7.ResponseException != "" {
		span.Events().AppendEmpty().SetName(l7.ResponseException)
	}
	putStrWithoutEmpty(spanAttrs, "df.http.proxy_client", l7.HttpProxyClient)
}

func setDubbo(span *ptrace.Span, spanAttrs, resAttrs pcommon.Map, l7 *log_data.L7FlowLog) {
	putStrWithoutEmpty(spanAttrs, "df.dubbo.version", l7.Version)
	putStrWithoutEmpty(spanAttrs, "df.dubbo.request_type", l7.RequestType)
	putStrWithoutEmpty(spanAttrs, "df.dubbo.request_resource", l7.RequestResource)
	if l7.RequestId != nil {
		spanAttrs.PutInt("df.global.request_id", int64(*l7.RequestId))
	}
	spanAttrs.PutInt("df.dubbo.response_status", int64(l7.ResponseStatus))
	if l7.ResponseCode != nil {
		spanAttrs.PutInt("df.dubbo.response_code", int64(*l7.ResponseCode))
	}
	if l7.ResponseException != "" {
		span.Events().AppendEmpty().SetName(l7.ResponseException)
	}
	if l7.Endpoint != "" {
		resAttrs.PutStr("service.name", l7.Endpoint)
		span.SetName(l7.Endpoint)
	}
}

func setGRPC(span *ptrace.Span, spanAttrs pcommon.Map, l7 *log_data.L7FlowLog) {
	setHTTP(span, spanAttrs, l7)
	if l7.Endpoint != "" {
		spanAttrs.PutStr("df.grpc.endpoint", l7.Endpoint)
	}
}

func setKafka(span *ptrace.Span, spanAttrs pcommon.Map, l7 *log_data.L7FlowLog) {
	putStrWithoutEmpty(spanAttrs, "df.kafka.request_type", l7.RequestType)
	if l7.RequestId != nil {
		spanAttrs.PutInt("df.global.request_id", int64(*l7.RequestId))
	}
	spanAttrs.PutInt("df.kafka.response_status", int64(l7.ResponseStatus))
	if l7.ResponseCode != nil {
		spanAttrs.PutInt("df.kafka.response_code", int64(*l7.ResponseCode))
	}
	if l7.ResponseException != "" {
		span.Events().AppendEmpty().SetName(l7.ResponseException)
	}
}

func setMQTT(span *ptrace.Span, spanAttrs pcommon.Map, l7 *log_data.L7FlowLog) {
	putStrWithoutEmpty(spanAttrs, "df.mqtt.request_type", l7.RequestType)
	putStrWithoutEmpty(spanAttrs, "df.mqtt.request_resource", l7.RequestResource)
	putStrWithoutEmpty(spanAttrs, "df.mqtt.request_domain", l7.RequestDomain)
	if l7.RequestId != nil {
		spanAttrs.PutInt("df.global.request_id", int64(*l7.RequestId))
	}
	spanAttrs.PutInt("df.mqtt.response_status", int64(l7.ResponseStatus))
	if l7.ResponseCode != nil {
		spanAttrs.PutInt("http.status_code", int64(*l7.ResponseCode))
	}
}

func setMySQL(span *ptrace.Span, spanAttrs pcommon.Map, l7 *log_data.L7FlowLog) {
	putStrWithoutEmpty(spanAttrs, "df.mysql.request_type", l7.RequestType)
	putStrWithoutEmpty(spanAttrs, "df.mysql.request_resource", l7.RequestResource)
	spanAttrs.PutInt("df.mysql.response_status", int64(l7.ResponseStatus))
	if l7.ResponseCode != nil {
		spanAttrs.PutInt("df.mysql.response_code", int64(*l7.ResponseCode))
	}
	if l7.ResponseException != "" {
		span.Events().AppendEmpty().SetName(l7.ResponseException)
	}
}

func setPostgreSQL(span *ptrace.Span, spanAttrs pcommon.Map, l7 *log_data.L7FlowLog) {
	putStrWithoutEmpty(spanAttrs, "df.pg.request_type", l7.RequestType)
	putStrWithoutEmpty(spanAttrs, "df.pg.request_resource", l7.RequestResource)
	spanAttrs.PutInt("df.pg.response_status", int64(l7.ResponseStatus))
	if l7.ResponseCode != nil {
		spanAttrs.PutInt("df.pg.response_code", int64(*l7.ResponseCode))
	}
	if l7.ResponseException != "" {
		span.Events().AppendEmpty().SetName(l7.ResponseException)
	}
}

func setRedis(span *ptrace.Span, spanAttrs pcommon.Map, l7 *log_data.L7FlowLog) {
	putStrWithoutEmpty(spanAttrs, "df.redis.request_type", l7.RequestType)
	putStrWithoutEmpty(spanAttrs, "df.redis.request_resource", l7.RequestResource)
	spanAttrs.PutInt("df.redis.response_status", int64(l7.ResponseStatus))
	if l7.ResponseException != "" {
		span.Events().AppendEmpty().SetName(l7.ResponseException)
	}
}

func responseStatusToSpanStatus(status uint8) ptrace.StatusCode {
	switch status {
	case datatype.STATUS_OK:
		return ptrace.StatusCodeOk
	case datatype.STATUS_CLIENT_ERROR, datatype.STATUS_SERVER_ERROR, datatype.STATUS_ERROR:
		return ptrace.StatusCodeError
	default:
		return ptrace.StatusCodeUnset
	}
}

func tapSideToSpanKind(tapSide string) ptrace.SpanKind {
	if strings.HasPrefix(tapSide, "c") {
		return ptrace.SpanKindClient
	} else if strings.HasPrefix(tapSide, "s") {
		return ptrace.SpanKindServer
	}
	return ptrace.SpanKindUnspecified
}

func uint64ToSpanID(id uint64) pcommon.SpanID {
	b := [8]byte{0}
	binary.BigEndian.PutUint64(b[:], uint64(id))
	return pcommon.SpanID(b)
}

func genTraceID(id int) pcommon.TraceID {
	b := [16]byte{0}
	binary.BigEndian.PutUint64(b[:], uint64(id))
	return pcommon.TraceID(b)
}

func tapPortTypeToString(tapPortType uint8) string {
	switch tapPortType {
	case 0:
		return "Local NIC"
	case 1:
		return "NFV Gateway NIC"
	case 2:
		return "ERSPAN"
	case 3:
		return "ERSPAN (IPv6)"
	case 4:
		return "Traffic Mirror"
	case 5:
		return "NetFlow"
	case 6:
		return "sFlow"
	case 7:
		return "eBPF"
	case 8:
		return "OTel"
	}
	return strconv.Itoa(int(tapPortType))
}
