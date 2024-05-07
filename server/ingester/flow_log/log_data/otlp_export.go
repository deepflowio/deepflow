/*
 * Copyright (c) 2024 Yunshan Networks
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

package log_data

import (
	crand "crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"math/rand"
	"net"
	"strconv"
	"strings"

	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/ptrace"
	_ "go.opentelemetry.io/proto/otlp/common/v1"

	"github.com/google/gopacket/layers"

	"github.com/deepflowio/deepflow/server/ingester/common"
	"github.com/deepflowio/deepflow/server/ingester/exporters/config"
	utag "github.com/deepflowio/deepflow/server/ingester/exporters/universal_tag"
	"github.com/deepflowio/deepflow/server/libs/datatype"
	"github.com/deepflowio/deepflow/server/libs/utils"
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

func putUniversalTags(attrs pcommon.Map, tags0, tags1 *utag.UniversalTags, dataTypeBits uint64) {
	if dataTypeBits&config.UNIVERSAL_TAG != 0 {
		putStrWithoutEmpty(attrs, "df.universal_tag.region_0", tags0[utag.Region])
		putStrWithoutEmpty(attrs, "df.universal_tag.az_0", tags0[utag.AZ])
		putStrWithoutEmpty(attrs, "df.universal_tag.host_0", tags0[utag.Host])
		putStrWithoutEmpty(attrs, "df.universal_tag.vpc_0", tags0[utag.L3Epc])
		putStrWithoutEmpty(attrs, "df.universal_tag.subnet_0", tags0[utag.Subnet])
		putStrWithoutEmpty(attrs, "df.universal_tag.pod_cluster_0", tags0[utag.PodCluster])
		putStrWithoutEmpty(attrs, "df.universal_tag.pod_ns_0", tags0[utag.PodNS])
		putStrWithoutEmpty(attrs, "df.universal_tag.pod_node_0", tags0[utag.PodNode])
		putStrWithoutEmpty(attrs, "df.universal_tag.pod_group_0", tags0[utag.PodGroup])
		putStrWithoutEmpty(attrs, "df.universal_tag.pod_0", tags0[utag.Pod])
		putStrWithoutEmpty(attrs, "df.universal_tag.service_0", tags0[utag.Service])

		putStrWithoutEmpty(attrs, "df.universal_tag.chost_0", tags0[utag.CHost])
		putStrWithoutEmpty(attrs, "df.universal_tag.router_0", tags0[utag.Router])
		putStrWithoutEmpty(attrs, "df.universal_tag.dhcpgw_0", tags0[utag.DhcpGW])
		putStrWithoutEmpty(attrs, "df.universal_tag.pod_service_0", tags0[utag.PodService])
		putStrWithoutEmpty(attrs, "df.universal_tag.redis_0", tags0[utag.Redis])
		putStrWithoutEmpty(attrs, "df.universal_tag.rds_0", tags0[utag.RDS])
		putStrWithoutEmpty(attrs, "df.universal_tag.lb_0", tags0[utag.LB])

		putStrWithoutEmpty(attrs, "df.universal_tag.natgw_0", tags0[utag.NatGW])
		putStrWithoutEmpty(attrs, "df.universal_tag.auto_instance_type_0", tags0[utag.AutoInstanceType])
		putStrWithoutEmpty(attrs, "df.universal_tag.auto_instance_0", tags0[utag.AutoInstance])
		putStrWithoutEmpty(attrs, "df.universal_tag.auto_service_type_0", tags0[utag.AutoServiceType])
		putStrWithoutEmpty(attrs, "df.universal_tag.auto_service_0", tags0[utag.AutoService])

		putStrWithoutEmpty(attrs, "df.universal_tag.region_1", tags1[utag.Region])
		putStrWithoutEmpty(attrs, "df.universal_tag.az_1", tags1[utag.AZ])
		putStrWithoutEmpty(attrs, "df.universal_tag.host_1", tags1[utag.Host])
		putStrWithoutEmpty(attrs, "df.universal_tag.vpc_1", tags1[utag.L3Epc])
		putStrWithoutEmpty(attrs, "df.universal_tag.subnet_1", tags1[utag.Subnet])
		putStrWithoutEmpty(attrs, "df.universal_tag.pod_cluster_1", tags1[utag.PodCluster])
		putStrWithoutEmpty(attrs, "df.universal_tag.pod_ns_1", tags1[utag.PodNS])
		putStrWithoutEmpty(attrs, "df.universal_tag.pod_node_1", tags1[utag.PodNode])
		putStrWithoutEmpty(attrs, "df.universal_tag.pod_group_1", tags1[utag.PodGroup])
		putStrWithoutEmpty(attrs, "df.universal_tag.pod_1", tags1[utag.Pod])
		putStrWithoutEmpty(attrs, "df.universal_tag.service_1", tags1[utag.Service])
		putStrWithoutEmpty(attrs, "df.universal_tag.chost_1", tags1[utag.CHost])
		putStrWithoutEmpty(attrs, "df.universal_tag.router_1", tags1[utag.Router])
		putStrWithoutEmpty(attrs, "df.universal_tag.dhcpgw_1", tags1[utag.DhcpGW])
		putStrWithoutEmpty(attrs, "df.universal_tag.pod_service_1", tags1[utag.PodService])
		putStrWithoutEmpty(attrs, "df.universal_tag.redis_1", tags1[utag.Redis])
		putStrWithoutEmpty(attrs, "df.universal_tag.rds_1", tags1[utag.RDS])
		putStrWithoutEmpty(attrs, "df.universal_tag.lb_1", tags1[utag.LB])
		putStrWithoutEmpty(attrs, "df.universal_tag.natgw_1", tags1[utag.NatGW])
		putStrWithoutEmpty(attrs, "df.universal_tag.auto_instance_type_1", tags1[utag.AutoInstanceType])
		putStrWithoutEmpty(attrs, "df.universal_tag.auto_instance_1", tags1[utag.AutoInstance])
		putStrWithoutEmpty(attrs, "df.universal_tag.auto_service_type_1", tags1[utag.AutoServiceType])
		putStrWithoutEmpty(attrs, "df.universal_tag.auto_service_1", tags1[utag.AutoService])
	}
}

func newAttrName(prefix, name, suffix string) string {
	var sb strings.Builder
	sb.WriteString(prefix)
	sb.WriteString(name)
	sb.WriteString(suffix)
	return sb.String()
}

func putK8sLabels(attrs pcommon.Map, podID uint32, universalTagsManager *utag.UniversalTagsManager, suffix string) {
	labels := universalTagsManager.QueryCustomK8sLabels(podID)
	if labels != nil {
		for name, value := range labels {
			putStrWithoutEmpty(attrs, newAttrName("df.custom_tag.k8s.labels.", name, suffix), value)
		}
	}
}

func (l7 *L7FlowLog) EncodeToOtlp(utags *utag.UniversalTagsManager, dataTypeBits uint64) interface{} {
	spanSlice := ptrace.NewResourceSpansSlice()
	resSpan := spanSlice.AppendEmpty()
	tags0, tags1 := l7.QueryUniversalTags(utags)
	resAttrs := resSpan.Resource().Attributes()
	putUniversalTags(resAttrs, tags0, tags1, dataTypeBits)
	if dataTypeBits&config.K8S_LABEL != 0 && l7.PodID0 != 0 {
		putK8sLabels(resAttrs, l7.PodID0, utags, "_0")
	}
	if dataTypeBits&config.K8S_LABEL != 0 && l7.PodID1 != 0 {
		putK8sLabels(resAttrs, l7.PodID1, utags, "_1")
	}

	span := resSpan.ScopeSpans().AppendEmpty().Spans().AppendEmpty()
	spanAttrs := span.Attributes()

	if dataTypeBits&config.NATIVE_TAG != 0 {
		for i := range l7.AttributeNames {
			putStrWithoutEmpty(spanAttrs, l7.AttributeNames[i], l7.AttributeValues[i])
		}
	}

	spanKind := tapSideToSpanKind(l7.TapSide)
	if dataTypeBits&config.TRACING_INFO != 0 {
		putStrWithoutEmpty(spanAttrs, "df.span.x_request_id_0", l7.XRequestId0)
		putStrWithoutEmpty(spanAttrs, "df.span.x_request_id_1", l7.XRequestId1)
		putIntWithoutZero(spanAttrs, "df.span.syscall_trace_id_request", int64(l7.SyscallTraceIDRequest))
		putIntWithoutZero(spanAttrs, "df.span.syscall_trace_id_response", int64(l7.SyscallTraceIDResponse))
		putIntWithoutZero(spanAttrs, "df.span.syscall_thread_0", int64(l7.SyscallThread0))
		putIntWithoutZero(spanAttrs, "df.span.syscall_thread_1", int64(l7.SyscallThread1))
		putIntWithoutZero(spanAttrs, "df.span.syscall_cap_seq_0", int64(l7.SyscallCapSeq0))
		putIntWithoutZero(spanAttrs, "df.span.syscall_cap_seq_1", int64(l7.SyscallCapSeq1))
		putStrWithoutEmpty(spanAttrs, "df.span.native.trace_id", l7.TraceId)
		putStrWithoutEmpty(spanAttrs, "df.span.native.span_id", l7.SpanId)

		span.SetTraceID(getTraceID(l7.TraceId, l7.ID()))
		if l7.SignalSource == uint16(datatype.SIGNAL_SOURCE_OTEL) {
			span.SetSpanID(getSpanID(l7.SpanId, l7.ID()))
			if l7.ParentSpanId == "" {
				span.SetParentSpanID(pcommon.NewSpanIDEmpty())
			} else {
				span.SetParentSpanID(getSpanID(l7.ParentSpanId, l7.ID()))
			}
		} else {
			span.SetParentSpanID(getSpanID(l7.SpanId, l7.ID()))
			span.SetSpanID(uint64ToSpanID(l7.ID()))
		}

		if l7.SpanKind != uint8(ptrace.SpanKindUnspecified) {
			span.SetKind(ptrace.SpanKind(l7.SpanKind))
		} else {
			span.SetKind(spanKind)
		}
	}

	msgType := datatype.LogMessageType(l7.Type)
	putStrWithoutEmpty(spanAttrs, "df.span.type", strings.ToLower(msgType.String()))
	putStrWithoutEmpty(spanAttrs, "df.span.endpoint", l7.Endpoint)

	if dataTypeBits&config.SERVICE_INFO != 0 {
		if isClientSide(l7.TapSide) {
			putStrWithoutEmpty(resAttrs, "service.name", tags0[utag.AutoService])
			putStrWithoutEmpty(resAttrs, "service.instance.id", tags0[utag.AutoInstance])
		} else {
			putStrWithoutEmpty(resAttrs, "service.name", tags1[utag.AutoService])
			putStrWithoutEmpty(resAttrs, "service.instance.id", tags1[utag.AutoInstance])
		}
		// if l7.AppService/l7.AppInstance is not empty, overwrite the value
		putStrWithoutEmpty(resAttrs, "service.name", l7.AppService)
		putStrWithoutEmpty(resAttrs, "service.instance.id", l7.AppInstance)

		putIntWithoutZero(resAttrs, "process.pid_0", int64(l7.ProcessID0))
		putIntWithoutZero(resAttrs, "process.pid_1", int64(l7.ProcessID1))
		putStrWithoutEmpty(resAttrs, "thread.name_0", l7.ProcessKName0)
		putStrWithoutEmpty(resAttrs, "thread.name_1", l7.ProcessKName1)
	}

	if dataTypeBits&config.FLOW_INFO != 0 {
		putIntWithoutZero(resAttrs, "df.flow_info.id", int64(l7.ID()))
		putIntWithoutZero(resAttrs, "df.flow_info.time", int64(l7.EndTime()))
		putIntWithoutZero(resAttrs, "df.flow_info.flow_id", int64(l7.FlowID))
		span.SetStartTimestamp(pcommon.Timestamp(l7.StartTime()))
		span.SetEndTimestamp(pcommon.Timestamp(l7.EndTime()))
	}

	if dataTypeBits&config.CAPTURE_INFO != 0 {
		putStrWithoutEmpty(resAttrs, "df.capture_info.signal_source", datatype.SignalSource(l7.SignalSource).String())
		putStrWithoutEmpty(resAttrs, "df.capture_info.nat_source", datatype.NATSource(l7.NatSource).String())
		putStrWithoutEmpty(resAttrs, "df.capture_info.capture_nic", datatype.TapPortValueToString(l7.TapPort, l7.TapPortType, datatype.TunnelType(l7.TunnelType)))
		putStrWithoutEmpty(resAttrs, "df.capture_info.capture_nic_type", tapPortTypeToString(l7.TapPortType))
		// todo suport TapPortName
		// putStrWithoutEmpty(resAttrs, "df.capture_info.capture_nic_name", tags0.TapPortName)
		putStrWithoutEmpty(resAttrs, "df.capture_info.observation_point", tapSideToName(l7.TapSide))
		putStrWithoutEmpty(resAttrs, "df.capture_info.agent", tags0[utag.Vtap])
	}

	if dataTypeBits&config.NETWORK_LAYER != 0 {
		resAttrs.PutBool("df.network.is_ipv4", l7.IsIPv4)
		resAttrs.PutBool("df.network.is_internet_0", l7.L3EpcID0 == datatype.EPC_FROM_INTERNET)
		resAttrs.PutBool("df.network.is_internet_1", l7.L3EpcID1 == datatype.EPC_FROM_INTERNET)
		if l7.IsIPv4 {
			// resAttrs.PutStr("df.network.ip_0", utils.IpFromUint32(l7.IP40).String())
			resAttrs.PutStr("df.network.ip_0", utils.IpFromUint32(l7.IP40).String())
			resAttrs.PutStr("df.network.ip_1", utils.IpFromUint32(l7.IP41).String())
		} else {
			resAttrs.PutStr("df.network.ip_0", l7.IP60.String())
			resAttrs.PutStr("df.network.ip_1", l7.IP61.String())
		}
		resAttrs.PutStr("df.network.protocol", layers.IPProtocol(l7.Protocol).String())
	}

	if dataTypeBits&config.TUNNEL_INFO != 0 {
		if l7.TunnelType != uint8(datatype.TUNNEL_TYPE_NONE) {
			putStrWithoutEmpty(resAttrs, "df.tunnel.tunnel_type", datatype.TunnelType(l7.TunnelType).String())
		}
	}

	if dataTypeBits&config.TRANSPORT_LAYER != 0 {
		putIntWithoutZero(resAttrs, "df.transport.client_port", int64(l7.ClientPort))
		putIntWithoutZero(resAttrs, "df.transport.server_port", int64(l7.ServerPort))
		putIntWithoutZero(resAttrs, "df.transport.req_tcp_seq", int64(l7.ReqTcpSeq))
		putIntWithoutZero(resAttrs, "df.transport.resp_tcp_seq", int64(l7.RespTcpSeq))
	}

	if dataTypeBits&config.APPLICATION_LAYER != 0 {
		putStrWithoutEmpty(resAttrs, "df.application.l7_protocol", datatype.L7Protocol(l7.L7Protocol).String(l7.IsTLS == 1))
		putStrWithoutEmpty(resAttrs, "telemetry.sdk.name", "deepflow")
		putStrWithoutEmpty(resAttrs, "telemetry.sdk.version", common.CK_VERSION)
		span.Status().SetCode(responseStatusToSpanStatus(l7.ResponseStatus))

		switch datatype.L7Protocol(l7.L7Protocol) {
		case datatype.L7_PROTOCOL_DNS:
			setDNS(&span, spanAttrs, l7)
		case datatype.L7_PROTOCOL_HTTP_1, datatype.L7_PROTOCOL_HTTP_2:
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

		// the priority of the value of 'net.peer.name' is CHost > PodNode > RequestDomain(set in HTTPBase)
		// if 'net.peer.name' is set multiple times, the value set later will overwrite the value set before
		if spanKind == ptrace.SpanKindServer {
			setServerSpanKindHostAndPeer(spanAttrs, l7, tags0, tags1)
		} else {
			setOtherSpanKindHostAndPeer(spanAttrs, l7, tags0, tags1)
		}
	}
	if dataTypeBits&config.METRICS != 0 {
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
	return spanSlice
}

func getTraceID(traceID string, id uint64) pcommon.TraceID {
	if traceID == "" {
		return genTraceID(int(id))
	}

	if traceId, err := hex.DecodeString(traceID); err == nil {
		id := [16]byte{}
		copy(id[:], traceId)
		return pcommon.TraceID(id)
	}

	return swTraceIDToTraceID(traceID)
}

func getSpanID(spanID string, id uint64) pcommon.SpanID {
	if spanID == "" {
		return uint64ToSpanID(id)
	}

	if spanId, err := hex.DecodeString(spanID); err == nil {
		id := [8]byte{}
		copy(id[:], spanId)
		return pcommon.SpanID(id)
	}
	return pcommon.NewSpanIDEmpty()
}

func newSpanId() pcommon.SpanID {
	var rngSeed int64
	_ = binary.Read(crand.Reader, binary.LittleEndian, &rngSeed)
	var randSource = rand.New(rand.NewSource(rngSeed))

	sid := pcommon.SpanID{}
	randSource.Read(sid[:])
	return sid
}

// use server info (_1) to fill in 'host' information, use client info (_0) to fill in 'peer' information
func setServerSpanKindHostAndPeer(spanAttrs pcommon.Map, l7 *L7FlowLog, tags0, tags1 *utag.UniversalTags) {
	if tags1[utag.CHost] != "" {
		putStrWithoutEmpty(spanAttrs, "net.host.name", tags1[utag.CHost])
	} else {
		putStrWithoutEmpty(spanAttrs, "net.host.name", tags1[utag.PodNode])
	}
	putIntWithoutZero(spanAttrs, "net.host.port", int64(l7.ServerPort))
	if l7.IsIPv4 {
		if l7.IP41 != 0 {
			spanAttrs.PutStr("net.sock.host.addr", utils.IpFromUint32(l7.IP41).String())
		}
	} else {
		if !l7.IP61.Equal(net.IPv6zero) {
			spanAttrs.PutStr("net.sock.host.addr", l7.IP61.String())
		}
	}

	if tags0[utag.CHost] != "" {
		putStrWithoutEmpty(spanAttrs, "net.peer.name", tags0[utag.CHost])
	} else {
		putStrWithoutEmpty(spanAttrs, "net.peer.name", tags0[utag.PodNode])
	}
	putIntWithoutZero(spanAttrs, "net.peer.port", int64(l7.ClientPort))
	if l7.IsIPv4 {
		if l7.IP40 != 0 {
			spanAttrs.PutStr("net.sock.peer.addr", utils.IpFromUint32(l7.IP40).String())
		}
	} else {
		if !l7.IP60.Equal(net.IPv6zero) {
			spanAttrs.PutStr("net.sock.peer.addr", l7.IP60.String())
		}
	}
}

// use client info (_0) to fill in 'host' information, use server info (_1) to fill in 'peer' information
func setOtherSpanKindHostAndPeer(spanAttrs pcommon.Map, l7 *L7FlowLog, tags0, tags1 *utag.UniversalTags) {
	if tags0[utag.CHost] != "" {
		putStrWithoutEmpty(spanAttrs, "net.host.name", tags0[utag.CHost])
	} else {
		putStrWithoutEmpty(spanAttrs, "net.host.name", tags0[utag.PodNode])
	}
	putIntWithoutZero(spanAttrs, "net.host.port", int64(l7.ClientPort))
	if l7.IsIPv4 {
		if l7.IP40 != 0 {
			spanAttrs.PutStr("net.sock.host.addr", utils.IpFromUint32(l7.IP40).String())
		}
	} else {
		if !l7.IP60.Equal(net.IPv6zero) {
			spanAttrs.PutStr("net.sock.host.addr", l7.IP60.String())
		}
	}

	if tags1[utag.CHost] != "" {
		putStrWithoutEmpty(spanAttrs, "net.peer.name", tags1[utag.CHost])
	} else {
		putStrWithoutEmpty(spanAttrs, "net.peer.name", tags1[utag.PodNode])
	}
	putIntWithoutZero(spanAttrs, "net.peer.port", int64(l7.ServerPort))
	if l7.IsIPv4 {
		if l7.IP41 != 0 {
			spanAttrs.PutStr("net.sock.peer.addr", utils.IpFromUint32(l7.IP41).String())
		}
	} else {
		if !l7.IP61.Equal(net.IPv6zero) {
			spanAttrs.PutStr("net.sock.peer.addr", l7.IP61.String())
		}
	}
}

func setDNS(span *ptrace.Span, spanAttrs pcommon.Map, l7 *L7FlowLog) {
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

func setHTTP(span *ptrace.Span, spanAttrs pcommon.Map, l7 *L7FlowLog) {
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
	span.SetName(strings.Join([]string{l7.RequestType, l7.RequestResource}, " "))
}

func setDubbo(span *ptrace.Span, spanAttrs, resAttrs pcommon.Map, l7 *L7FlowLog) {
	spanAttrs.PutStr("rpc.system", "apache_dubbo")
	putStrWithoutEmpty(spanAttrs, "rpc.service", l7.RequestResource)
	putStrWithoutEmpty(spanAttrs, "rpc.method", l7.RequestType)
	span.SetName(strings.Join([]string{l7.RequestResource, l7.RequestType}, "/"))

	if l7.ResponseException != "" {
		span.Events().AppendEmpty().SetName(l7.ResponseException)
	}
	putStrWithoutEmpty(spanAttrs, "df.request_domain", l7.RequestDomain)
	putStrWithoutEmpty(spanAttrs, "df.dubbo.version", l7.Version)
	if l7.RequestId != nil {
		spanAttrs.PutInt("df.global.request_id", int64(*l7.RequestId))
	}
	if l7.ResponseCode != nil {
		spanAttrs.PutInt("df.response_code", int64(*l7.ResponseCode))
	}
}

func setGRPC(span *ptrace.Span, spanAttrs pcommon.Map, l7 *L7FlowLog) {
	spanAttrs.PutStr("rpc.system", "grpc")
	putStrWithoutEmpty(spanAttrs, "rpc.service", l7.RequestResource)
	putStrWithoutEmpty(spanAttrs, "rpc.method", l7.RequestType)
	span.SetName(strings.Join([]string{l7.RequestResource, l7.RequestType}, "/"))

	if l7.ResponseException != "" {
		span.Events().AppendEmpty().SetName(l7.ResponseException)
	}
	putStrWithoutEmpty(spanAttrs, "http.flavor", l7.Version)
	putStrWithoutEmpty(spanAttrs, "df.request_domain", l7.RequestDomain)
	if l7.RequestId != nil {
		spanAttrs.PutInt("df.global.request_id", int64(*l7.RequestId))
	}
}

func setKafka(span *ptrace.Span, spanAttrs pcommon.Map, l7 *L7FlowLog) {
	spanAttrs.PutStr("messaging.system", "kafka")
	span.SetName(l7.RequestResource)

	putStrWithoutEmpty(spanAttrs, "df.kafka.request_type", l7.RequestType)
	if l7.RequestId != nil {
		spanAttrs.PutInt("df.global.request_id", int64(*l7.RequestId))
	}
	putStrWithoutEmpty(spanAttrs, "df.global.request_resource", l7.RequestResource)
	putStrWithoutEmpty(spanAttrs, "df.kafka.request_domain", l7.RequestDomain)
	if l7.ResponseCode != nil {
		spanAttrs.PutInt("df.kafka.response_code", int64(*l7.ResponseCode))
	}
	if l7.ResponseException != "" {
		span.Events().AppendEmpty().SetName(l7.ResponseException)
	}
}

func setMQTT(span *ptrace.Span, spanAttrs pcommon.Map, l7 *L7FlowLog) {
	spanAttrs.PutStr("messaging.system", "mqtt")
	span.SetName(l7.RequestResource)

	putStrWithoutEmpty(spanAttrs, "df.mqtt.request_type", l7.RequestType)
	putStrWithoutEmpty(spanAttrs, "df.mqtt.request_resource", l7.RequestResource)
	putStrWithoutEmpty(spanAttrs, "df.mqtt.request_domain", l7.RequestDomain)
	if l7.ResponseCode != nil {
		spanAttrs.PutInt("df.mqtt.response_code", int64(*l7.ResponseCode))
	}
	if l7.ResponseException != "" {
		span.Events().AppendEmpty().SetName(l7.ResponseException)
	}
}

func setMySQL(span *ptrace.Span, spanAttrs pcommon.Map, l7 *L7FlowLog) {
	spanName, operation := getSQLSpanNameAndOperation(l7.RequestResource)
	putStrWithoutEmpty(spanAttrs, "db.system", "mysql")
	putStrWithoutEmpty(spanAttrs, "db.operation", operation)
	putStrWithoutEmpty(spanAttrs, "db.statement", l7.RequestResource)

	putStrWithoutEmpty(spanAttrs, "df.mysql.request_type", l7.RequestType)
	if l7.ResponseException != "" {
		span.Events().AppendEmpty().SetName(l7.ResponseException)
	}
	span.SetName(spanName)
}

func setPostgreSQL(span *ptrace.Span, spanAttrs pcommon.Map, l7 *L7FlowLog) {
	spanName, operation := getSQLSpanNameAndOperation(l7.RequestResource)
	putStrWithoutEmpty(spanAttrs, "db.system", "postgresql")
	putStrWithoutEmpty(spanAttrs, "db.operation", operation)
	putStrWithoutEmpty(spanAttrs, "db.statement", l7.RequestResource)
	putStrWithoutEmpty(spanAttrs, "df.postgresql.request_type", l7.RequestType)
	if l7.ResponseException != "" {
		span.Events().AppendEmpty().SetName(l7.ResponseException)
	}
	span.SetName(spanName)
}

func setRedis(span *ptrace.Span, spanAttrs pcommon.Map, l7 *L7FlowLog) {
	putStrWithoutEmpty(spanAttrs, "db.system", "redis")
	putStrWithoutEmpty(spanAttrs, "db.operation", l7.RequestType)
	putStrWithoutEmpty(spanAttrs, "db.statement", l7.RequestResource)
	if l7.ResponseException != "" {
		span.Events().AppendEmpty().SetName(l7.ResponseException)
	}
	span.SetName(l7.RequestType)
}

// Return the first part after 'key' from the 'parts' array.
// Returns an empty string if 'key' does not exist or has no next part.
func getFirstPartAfterKey(key string, parts []string) string {
	for i := range parts {
		if strings.ToUpper(parts[i]) == key && len(parts) > i+1 {
			return parts[i+1]
		}
	}
	return ""
}

// Extract the database, table, and command from the SQL statement to form SpanName("${comman} ${db}.${table}")
// Returns "unknown","" if it cannot be fetched.
func getSQLSpanNameAndOperation(sql string) (string, string) {
	sql = strings.TrimSpace(sql)
	if sql == "" {
		return "unknow", ""
	}
	parts := strings.Split(sql, " ")
	if len(parts) <= 2 {
		return parts[0], parts[0]
	}

	var command, dbTable string
	command = parts[0]
	parts = parts[1:]
	switch strings.ToUpper(command) {
	case "SELECT", "DELETE":
		dbTable = getFirstPartAfterKey("FROM", parts)
	case "INSERT":
		dbTable = getFirstPartAfterKey("INTO", parts)
	case "UPDATE":
		dbTable = parts[0]
	case "CREATE", "DROP":
		createType := strings.ToUpper(parts[0])
		if createType == "DATABASE" || createType == "TABLE" {
			// ignore 'if not exists' or 'if exists'
			if strings.ToUpper(parts[1]) == "IF" {
				dbTable = getFirstPartAfterKey("EXISTS", parts)
			} else {
				dbTable = parts[1]
			}
		}
	case "ALTER":
		dbTable = getFirstPartAfterKey("TABLE", parts)
	}

	if dbTable == "" {
		return command, command
	}
	if i := strings.Index(dbTable, "("); i > 0 {
		dbTable = dbTable[:i]
	} else {
		dbTable = strings.TrimRight(dbTable, ";")
	}
	return strings.Join([]string{command, dbTable}, " "), command
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

func isClientSide(tapSide string) bool {
	return strings.HasPrefix(tapSide, "c")
}

func isServerSide(tapSide string) bool {
	return strings.HasPrefix(tapSide, "s")
}

func tapSideToSpanKind(tapSide string) ptrace.SpanKind {
	if isClientSide(tapSide) {
		return ptrace.SpanKindClient
	} else if isServerSide(tapSide) {
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
