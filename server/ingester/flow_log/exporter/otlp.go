package exporter

import (
	"encoding/binary"
	"encoding/hex"
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

func putUniversalTags(attrs pcommon.Map, tags0, tags1 *UniversalTags, dataTypeBits uint32) {
	if dataTypeBits&CLIENT_UNIVERSAL_TAG != 0 {
		putStrWithoutEmpty(attrs, "df.universal_tag.region_0", tags0.Region)
		putStrWithoutEmpty(attrs, "df.universal_tag.az_0", tags0.AZ)
		putStrWithoutEmpty(attrs, "df.universal_tag.host_0", tags0.Host)
		putStrWithoutEmpty(attrs, "df.universal_tag.epc_0", tags0.L3Epc)
		putStrWithoutEmpty(attrs, "df.universal_tag.pod_cluster_0", tags0.PodCluster)
		putStrWithoutEmpty(attrs, "df.universal_tag.pod_ns_0", tags0.PodNS)
		putStrWithoutEmpty(attrs, "df.universal_tag.pod_node_0", tags0.PodNode)
		putStrWithoutEmpty(attrs, "df.universal_tag.pod_group_0", tags0.PodGroup)
		putStrWithoutEmpty(attrs, "df.universal_tag.pod_0", tags0.Pod)
		putStrWithoutEmpty(attrs, "df.universal_tag.service_0", tags0.Service)
		putStrWithoutEmpty(attrs, "df.universal_tag.chost_0", tags0.CHost)
		putStrWithoutEmpty(attrs, "df.universal_tag.router_0", tags0.Router)
		putStrWithoutEmpty(attrs, "df.universal_tag.dhcpgw_0", tags0.DhcpGW)
		putStrWithoutEmpty(attrs, "df.universal_tag.pod_service_0", tags0.PodService)
		putStrWithoutEmpty(attrs, "df.universal_tag.redis_0", tags0.Redis)
		putStrWithoutEmpty(attrs, "df.universal_tag.rds_0", tags0.RDS)
		putStrWithoutEmpty(attrs, "df.universal_tag.lb_0", tags0.LB)
		putStrWithoutEmpty(attrs, "df.universal_tag.natgw_0", tags0.NatGW)
	}
	if dataTypeBits&SERVER_UNIVERSAL_TAG != 0 {
		putStrWithoutEmpty(attrs, "df.universal_tag.region_1", tags1.Region)
		putStrWithoutEmpty(attrs, "df.universal_tag.az_1", tags1.AZ)
		putStrWithoutEmpty(attrs, "df.universal_tag.host_1", tags1.Host)
		putStrWithoutEmpty(attrs, "df.universal_tag.epc_1", tags1.L3Epc)
		putStrWithoutEmpty(attrs, "df.universal_tag.pod_cluster_1", tags1.PodCluster)
		putStrWithoutEmpty(attrs, "df.universal_tag.pod_ns_1", tags1.PodNS)
		putStrWithoutEmpty(attrs, "df.universal_tag.pod_node_1", tags1.PodNode)
		putStrWithoutEmpty(attrs, "df.universal_tag.pod_group_1", tags1.PodGroup)
		putStrWithoutEmpty(attrs, "df.universal_tag.pod_1", tags1.Pod)
		putStrWithoutEmpty(attrs, "df.universal_tag.service_1", tags1.Service)
		putStrWithoutEmpty(attrs, "df.universal_tag.chost_1", tags1.CHost)
		putStrWithoutEmpty(attrs, "df.universal_tag.router_1", tags1.Router)
		putStrWithoutEmpty(attrs, "df.universal_tag.dhcpgw_1", tags1.DhcpGW)
		putStrWithoutEmpty(attrs, "df.universal_tag.pod_service_1", tags1.PodService)
		putStrWithoutEmpty(attrs, "df.universal_tag.redis_1", tags1.Redis)
		putStrWithoutEmpty(attrs, "df.universal_tag.rds_1", tags1.RDS)
		putStrWithoutEmpty(attrs, "df.universal_tag.lb_1", tags1.LB)
		putStrWithoutEmpty(attrs, "df.universal_tag.natgw_1", tags1.NatGW)
	}
}

func L7FlowLogToExportRequest(l7 *log_data.L7FlowLog, universalTagsManager *UniversalTagsManager, dataTypeBits uint32) ptraceotlp.ExportRequest {
	tags0, tags1 := universalTagsManager.QueryUniversalTags(l7)
	td := ptrace.NewTraces()

	resSpan := td.ResourceSpans().AppendEmpty()
	resAttrs := resSpan.Resource().Attributes()
	putUniversalTags(resAttrs, tags0, tags1, dataTypeBits)

	span := resSpan.ScopeSpans().AppendEmpty().Spans().AppendEmpty()
	spanAttrs := span.Attributes()

	if dataTypeBits&NATIVE_TAG != 0 {
		for i := range l7.AttributeNames {
			putStrWithoutEmpty(spanAttrs, l7.AttributeNames[i], l7.AttributeValues[i])
		}
	}

	if dataTypeBits&TRACING_INFO != 0 {
		putIntWithoutZero(spanAttrs, "df.span.req_tcp_seq", int64(l7.ReqTcpSeq))
		putIntWithoutZero(spanAttrs, "df.span.resp_tcp_seq", int64(l7.RespTcpSeq))
		putStrWithoutEmpty(spanAttrs, "df.span.x_request_id", l7.XRequestId)
		putStrWithoutEmpty(spanAttrs, "df.span.http_proxy_client", l7.HttpProxyClient)
		putIntWithoutZero(spanAttrs, "df.span.syscall_trace_id_request", int64(l7.SyscallTraceIDRequest))
		putIntWithoutZero(spanAttrs, "df.span.syscall_trace_id_response", int64(l7.SyscallTraceIDResponse))
		putIntWithoutZero(spanAttrs, "df.span.syscall_thread_0", int64(l7.SyscallThread0))
		putIntWithoutZero(spanAttrs, "df.span.syscall_thread_1", int64(l7.SyscallThread1))
		putIntWithoutZero(spanAttrs, "df.span.syscall_cap_seq_0", int64(l7.SyscallCapSeq0))
		putIntWithoutZero(spanAttrs, "df.span.syscall_cap_seq_1", int64(l7.SyscallCapSeq1))

		if l7.SignalSource == uint16(datatype.SIGNAL_SOURCE_OTEL) {
			if spanId, err := hex.DecodeString(l7.SpanId); err != nil {
				id := [8]byte{}
				copy(id[:], spanId)
				span.SetSpanID(pcommon.SpanID(id))
			}
			if traceId, err := hex.DecodeString(l7.TraceId); err != nil {
				id := [16]byte{}
				copy(id[:], traceId)
				span.SetTraceID(pcommon.TraceID(id))
			}
			if parentSpanId, err := hex.DecodeString(l7.ParentSpanId); err != nil {
				id := [8]byte{}
				copy(id[:], parentSpanId)
				span.SetSpanID(pcommon.SpanID(id))
			}
			span.SetKind(ptrace.SpanKind(l7.SpanKind))
		} else {
			span.SetSpanID(uint64ToSpanID(l7.ID()))
			span.SetTraceID(genTraceID(int(l7.ID())))
			span.SetParentSpanID(pcommon.NewSpanIDEmpty())
			span.SetKind(tapSideToSpanKind(l7.TapSide))
		}
	}

	msgType := datatype.LogMessageType(l7.Type)
	putStrWithoutEmpty(spanAttrs, "df.span.type", strings.ToLower(msgType.String()))
	putStrWithoutEmpty(spanAttrs, "df.span.app_service", l7.AppService)
	putStrWithoutEmpty(spanAttrs, "df.span.app_instance", l7.AppInstance)
	putStrWithoutEmpty(spanAttrs, "df.span.endpoint", l7.Endpoint)

	if dataTypeBits&SERVICE_INFO != 0 {
		putIntWithoutZero(spanAttrs, "df.span.process_id_0", int64(l7.ProcessID0))
		putIntWithoutZero(spanAttrs, "df.span.process_id_1", int64(l7.ProcessID1))
		putStrWithoutEmpty(spanAttrs, "df.span.process_kname_0", l7.ProcessKName0)
		putStrWithoutEmpty(spanAttrs, "df.span.process_kname_1", l7.ProcessKName1)
	}

	if dataTypeBits&FLOW_INFO != 0 {
		putIntWithoutZero(resAttrs, "df.flow_info.id", int64(l7.ID()))
		putIntWithoutZero(resAttrs, "df.flow_info.time", int64(l7.EndTime()))
		putIntWithoutZero(resAttrs, "df.flow_info.flow_id", int64(l7.FlowID))
	}

	span.SetStartTimestamp(pcommon.Timestamp(l7.StartTime()))
	span.SetEndTimestamp(pcommon.Timestamp(l7.EndTime()))
	span.Status().SetCode(responseStatusToSpanStatus(l7.ResponseStatus))

	if dataTypeBits&CAPTURE_INFO != 0 {
		putStrWithoutEmpty(resAttrs, "df.capture_info.signal_source", datatype.SignalSource(l7.SignalSource).String())
		putStrWithoutEmpty(resAttrs, "df.capture_info.nat_source", datatype.NATSource(l7.NatSource).String())
		putStrWithoutEmpty(resAttrs, "df.capture_info.tap_port", datatype.TapPort(l7.TapPort).String())
		putStrWithoutEmpty(resAttrs, "df.capture_info.tap_port_type", tapPortTypeToString(l7.TapPortType))
		putStrWithoutEmpty(resAttrs, "df.capture_info.tap_port_name", tags0.TapPortName)
		putStrWithoutEmpty(resAttrs, "df.capture_info.tap_side", tapSideToName(l7.TapSide))
		putStrWithoutEmpty(resAttrs, "df.capture_info.vtap", tags0.Vtap)
	}

	if dataTypeBits&NETWORK_LAYER != 0 {
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
	}

	if dataTypeBits&TUNNEL_INFO != 0 {
		if l7.TunnelType != uint8(datatype.TUNNEL_TYPE_NONE) {
			putStrWithoutEmpty(resAttrs, "df.tunnel.tunnel_type", datatype.TunnelType(l7.TunnelType).String())
		}
	}

	if dataTypeBits&TRANSPORT_LAYER != 0 {
		putIntWithoutZero(resAttrs, "df.transport.client_port", int64(l7.ClientPort))
		putIntWithoutZero(resAttrs, "df.transport.server_port", int64(l7.ServerPort))
	}

	if dataTypeBits&APPLICATION_LAYER != 0 {
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
		case datatype.L7_PROTOCOL_POSTGRE:
			setPostgreSQL(&span, spanAttrs, l7)
		}
	}
	if dataTypeBits&METRICS != 0 {
		if l7.RequestLength != nil {
			spanAttrs.PutInt("df.metrics.request_length", *l7.RequestLength)
		}
		if l7.ResponseLength != nil {
			spanAttrs.PutInt("df.metrics.response_length", *l7.ResponseLength)
		}
		if l7.SqlAffectedRows != nil {
			spanAttrs.PutInt("df.metrics.sql_affected_rows", int64(*l7.SqlAffectedRows))
		}
		putIntWithoutZero(spanAttrs, "df.metrics.response_duration_us", int64(l7.ResponseDuration))
		putIntWithoutZero(spanAttrs, "df.metrics.direction_score", int64(l7.DirectionScore))
		for i := range l7.MetricsNames {
			spanAttrs.PutDouble(l7.MetricsNames[i], l7.MetricsValues[i])
		}
	}

	return ptraceotlp.NewExportRequestFromTraces(td)
}

func setDNS(span *ptrace.Span, spanAttrs pcommon.Map, l7 *log_data.L7FlowLog) {
	putStrWithoutEmpty(spanAttrs, "df.dns.request_type", l7.RequestType)
	putStrWithoutEmpty(spanAttrs, "df.dns.request_resource", l7.RequestResource)
	if l7.RequestId != nil {
		spanAttrs.PutInt("df.global.request_id", int64(*l7.RequestId))
	}
	spanAttrs.PutStr("df.dns.response_status", datatype.LogMessageStatus(l7.ResponseStatus).String())
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
	spanAttrs.PutStr("df.dubbo.response_status", datatype.LogMessageStatus(l7.ResponseStatus).String())
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
	spanAttrs.PutStr("df.kafka.response_status", datatype.LogMessageStatus(l7.ResponseStatus).String())
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
	spanAttrs.PutStr("df.mqtt.response_status", datatype.LogMessageStatus(l7.ResponseStatus).String())
	if l7.ResponseCode != nil {
		spanAttrs.PutInt("df.mqtt.response_code", int64(*l7.ResponseCode))
	}
}

func setMySQL(span *ptrace.Span, spanAttrs pcommon.Map, l7 *log_data.L7FlowLog) {
	putStrWithoutEmpty(spanAttrs, "df.mysql.request_type", l7.RequestType)
	putStrWithoutEmpty(spanAttrs, "df.mysql.request_resource", l7.RequestResource)
	spanAttrs.PutStr("df.mysql.response_status", datatype.LogMessageStatus(l7.ResponseStatus).String())
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
	spanAttrs.PutStr("df.pg.response_status", datatype.LogMessageStatus(l7.ResponseStatus).String())
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
	spanAttrs.PutStr("df.redis.response_status", datatype.LogMessageStatus(l7.ResponseStatus).String())
	if l7.ResponseException != "" {
		span.Events().AppendEmpty().SetName(l7.ResponseException)
	}
}

func responseStatusToSpanStatus(status uint8) ptrace.StatusCode {
	switch datatype.LogMessageStatus(status) {
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

func tapSideToName(tapSide string) string {
	switch tapSide {
	case "c":
		return "Client NIC"
	case "c-nd":
		return "Client K8s Node"
	case "c-hv":
		return "Client VM Hypervisor"
	case "c-gw-hv":
		return "Client-side Gateway Hypervisor"
	case "c-gw":
		return "Client-side Gateway"
	case "local":
		return "Local NIC"
	case "rest":
		return "Other NIC"
	case "s-gw":
		return "Server-side Gateway"
	case "s-gw-hv":
		return "Server-side Gateway Hypervisor"
	case "s-hv":
		return "Server VM Hypervisor"
	case "s-nd":
		return "Server K8s Node"
	case "s":
		return "Server NIC"
	case "c-p":
		return "Client Process"
	case "s-p":
		return "Server Process"
	case "c-app":
		return "Client Application"
	case "s-app":
		return "Server Application"
	case "app":
		return "Application"

	}
	return tapSide
}
