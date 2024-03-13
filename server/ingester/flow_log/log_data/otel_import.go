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
	"encoding/hex"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/deepflowio/deepflow/server/ingester/common"
	flowlogCfg "github.com/deepflowio/deepflow/server/ingester/flow_log/config"
	"github.com/deepflowio/deepflow/server/libs/datatype"
	flow_metrics "github.com/deepflowio/deepflow/server/libs/flow-metrics"
	"github.com/deepflowio/deepflow/server/libs/grpc"
	"github.com/deepflowio/deepflow/server/libs/utils"

	json "github.com/goccy/go-json"
	"github.com/google/gopacket/layers"
	v11 "go.opentelemetry.io/proto/otlp/common/v1"
	v1 "go.opentelemetry.io/proto/otlp/trace/v1"
)

func OTelTracesDataToL7FlowLogs(vtapID uint16, l *v1.TracesData, platformData *grpc.PlatformInfoTable, cfg *flowlogCfg.Config) []*L7FlowLog {
	ret := []*L7FlowLog{}
	for _, resourceSpan := range l.GetResourceSpans() {
		var resAttributes []*v11.KeyValue
		resource := resourceSpan.GetResource()
		if resource != nil {
			resAttributes = resource.Attributes
		}
		for _, scopeSpan := range resourceSpan.GetScopeSpans() {
			for _, span := range scopeSpan.GetSpans() {
				ret = append(ret, spanToL7FlowLog(vtapID, span, resAttributes, platformData, cfg))
			}
		}
	}
	return ret
}

func spanToL7FlowLog(vtapID uint16, span *v1.Span, resAttributes []*v11.KeyValue, platformData *grpc.PlatformInfoTable, cfg *flowlogCfg.Config) *L7FlowLog {
	h := AcquireL7FlowLog()
	h._id = genID(uint32(span.EndTimeUnixNano/uint64(time.Second)), &L7FlowLogCounter, platformData.QueryAnalyzerID())
	h.VtapID = vtapID
	h.FillOTel(span, resAttributes, platformData, cfg)
	return h
}

func spanKindToTapSide(spanKind v1.Span_SpanKind) string {
	switch spanKind {
	case v1.Span_SPAN_KIND_PRODUCER, v1.Span_SPAN_KIND_CLIENT:
		return "c-app"
	case v1.Span_SPAN_KIND_CONSUMER, v1.Span_SPAN_KIND_SERVER:
		return "s-app"
	default:
		return "app"
	}
}

func spanStatusToResponseStatus(status *v1.Status) datatype.LogMessageStatus {
	if status == nil {
		return datatype.STATUS_NOT_EXIST
	}
	switch status.Code {
	case v1.Status_STATUS_CODE_OK:
		return datatype.STATUS_OK
	case v1.Status_STATUS_CODE_ERROR:
		return datatype.STATUS_SERVER_ERROR
	case v1.Status_STATUS_CODE_UNSET:
		return datatype.STATUS_NOT_EXIST
	}
	return datatype.STATUS_NOT_EXIST
}

func httpCodeToResponseStatus(code int32) datatype.LogMessageStatus {
	if code >= 400 && code <= 499 {
		return datatype.STATUS_CLIENT_ERROR
	} else if code >= 500 && code <= 600 {
		return datatype.STATUS_SERVER_ERROR
	} else {
		return datatype.STATUS_OK
	}
}

func getValueString(value *v11.AnyValue) string {
	valueString := value.GetStringValue()
	if valueString != "" {
		return valueString
	} else {
		valueString = value.String()
		// 获取:后边的内容(:前边的是数据类型)
		index := strings.Index(valueString, ":")
		if index > -1 && len(valueString) > index+1 {
			return valueString[index+1:]
		} else {
			return valueString
		}
	}
}

func skywalkingGetParentSpanIdFromLinks(links []*v1.Span_Link) string {
	for _, link := range links {
		refTypeValid := false
		parentSpanId := ""
		parentSegmentId := ""
		for _, attr := range link.GetAttributes() {
			key := attr.GetKey()
			value := attr.GetValue()
			if value == nil {
				continue
			}

			switch key {
			case "refType":
				valueStr := getValueString(value)
				if valueStr == "CrossProcess" || valueStr == "CrossThread" {
					refTypeValid = true
				}
			case "sw8.parent_span_id":
				parentSpanId = getValueString(value)
			case "sw8.parent_segment_id":
				parentSegmentId = getValueString(value)
			}
		}
		if refTypeValid && parentSpanId != "" && parentSegmentId != "" {
			return parentSegmentId + "-" + parentSpanId
		}
	}
	return ""
}

func (h *L7FlowLog) fillAttributes(spanAttributes, resAttributes []*v11.KeyValue, links []*v1.Span_Link) {
	h.IsIPv4 = true
	sw8SegmentId := ""
	attributeNames, attributeValues := []string{}, []string{}
	metricsNames, metricsValues := []string{}, []float64{}
	for i, attr := range append(spanAttributes, resAttributes...) {
		key := attr.GetKey()
		value := attr.GetValue()
		if value == nil {
			continue
		}
		is_metrics := false

		if i >= len(spanAttributes) {
			switch key {
			case "service.name":
				h.AppService = getValueString(value)
			case "service.instance.id":
				h.AppInstance = getValueString(value)
			// 通过一个[k8sattributesprocessor插件](https://pkg.go.dev/github.com/open-telemetry/opentelemetry-collector-contrib/processor/k8sattributesprocessor#section-readme)
			// 获取当前应用(otel-agent)对应上一级（即Span的来源）的IP地址，例如：Span为POD产生，则获取POD的IP；Span为部署在虚拟机上的进程产生，则获取虚拟机的IP
			//   - 限制：因为获取的为当前应用的上一级IP，因此如果Span所在的应用发送数据给otel-agent是通过LB过来，则获取的为LB的IP
			// ===
			// Through a [k8sattributesprocessor plugin](https://pkg.go.dev/github.com/open-telemetry/opentelemetry-collector-contrib/processor/k8sattributesprocessor#section-readme)
			// Get the current application (otel-agent ) The IP address of the upper level (that is, the source of the span), for example: the span is generated by the POD, and the IP of the POD is obtained; the span is generated by the deployment on the virtual machine, then the IP of the virtual machine is obtained
			// - Restriction: because the obtained It is the upper-level IP of the current application, so if the application where the Span is located sends data to the otel-agent through the LB, the obtained IP is the LB's IP
			case "app.host.ip":
				ip := net.ParseIP(value.GetStringValue())
				if ip == nil {
					continue
				}
				if ip4 := ip.To4(); ip4 != nil {
					if h.TapSide == "c-app" {
						h.IP40 = utils.IpToUint32(ip4)
					} else {
						h.IP41 = utils.IpToUint32(ip4)
					}
				} else {
					h.IsIPv4 = false
					if h.TapSide == "c-app" {
						h.IP60 = ip
					} else {
						h.IP61 = ip
					}
				}
			case "sw8.trace_id":
				h.TraceId = getValueString(value)
			}

		} else {
			switch key {
			case "net.transport":
				protocol := value.GetStringValue()
				if strings.Contains(protocol, "tcp") {
					h.Protocol = uint8(layers.IPProtocolTCP)
				} else if strings.Contains(protocol, "udp") {
					h.Protocol = uint8(layers.IPProtocolUDP)
				}
			// https://github.com/open-telemetry/opentelemetry-go/blob/db7fd1bb51ce6ed1171cac15eeecb6871dbbb80a/semconv/internal/http.go#L79
			case "net.peer.ip":
				ip := net.ParseIP(value.GetStringValue())
				if ip == nil {
					continue
				}
				if ip4 := ip.To4(); ip4 != nil {
					if h.TapSide == "c-app" {
						h.IP41 = utils.IpToUint32(ip4)
					} else {
						h.IP40 = utils.IpToUint32(ip4)
					}
				} else {
					h.IsIPv4 = false
					if h.TapSide == "c-app" {
						h.IP61 = ip
					} else {
						h.IP60 = ip
					}
				}
			case "http.scheme", "db.system", "rpc.system", "messaging.system", "messaging.protocol":
				h.L7ProtocolStr = value.GetStringValue()
			case "http.flavor":
				h.Version = value.GetStringValue()
			case "http.status_code":
				v, _ := strconv.Atoi(getValueString(value))
				h.responseCode = int32(v)
				h.ResponseCode = &h.responseCode
			case "http.host", "db.connection_string":
				h.RequestDomain = value.GetStringValue()
			case "http.method", "db.operation", "rpc.method":
				h.RequestType = value.GetStringValue()
			case "http.target", "db.statement", "messaging.url", "rpc.service":
				h.RequestResource = value.GetStringValue()
			case "sw8.span_id":
				h.SpanId = getValueString(value)
			case "sw8.parent_span_id":
				h.ParentSpanId = getValueString(value)
			case "sw8.segment_id":
				sw8SegmentId = getValueString(value)
			case "http.request_content_length":
				h.requestLength = value.GetIntValue()
				h.RequestLength = &h.requestLength
				is_metrics = true
			case "http.response_content_length":
				h.responseLength = value.GetIntValue()
				h.ResponseLength = &h.responseLength
				is_metrics = true
			case "db.cassandra.page_size":
				h.sqlAffectedRows = uint64(value.GetIntValue())
				h.SqlAffectedRows = &h.sqlAffectedRows
				is_metrics = true
			case "message.uncompressed_size", "messaging.message_payload_size_bytes", "messaging.message_payload_compressed_size_bytes":
				is_metrics = true
			default:
				// nothing
			}
		}

		if is_metrics {
			metricsNames = append(metricsNames, key)
			v, _ := strconv.ParseFloat(getValueString(value), 64)
			metricsValues = append(metricsValues, v)
		} else {
			// FIXME 不同类型都按string存储，后续不同类型存储应分开, 参考: https://github.com/open-telemetry/opentelemetry-proto/blob/main/opentelemetry/proto/common/v1/common.proto#L31
			attributeNames = append(attributeNames, key)
			attributeValues = append(attributeValues, getValueString(value))
		}

	}
	if sw8SegmentId != "" {
		h.SpanId = sw8SegmentId + "-" + h.SpanId
		if h.ParentSpanId != "" {
			h.ParentSpanId = sw8SegmentId + "-" + h.ParentSpanId
		} else {
			h.ParentSpanId = skywalkingGetParentSpanIdFromLinks(links)
		}
	}

	if len(h.L7ProtocolStr) > 0 {
		l7ProtocolStrLower := strings.ToLower(h.L7ProtocolStr)
		if strings.Contains(l7ProtocolStrLower, "https") {
			h.IsTLS = 1
		}
		for l7ProtocolStr, l7Protocol := range datatype.L7ProtocolStringMap {
			if strings.Contains(l7ProtocolStr, l7ProtocolStrLower) {
				h.L7Protocol = uint8(l7Protocol)
				break
			}
		}
		// If the protocol name is 'http', it may be randomly matched to 'http1' or 'http2' and needs to be corrected.
		if h.L7Protocol == uint8(datatype.L7_PROTOCOL_HTTP_1) || h.L7Protocol == uint8(datatype.L7_PROTOCOL_HTTP_2) {
			if strings.HasPrefix(h.Version, "2") {
				h.L7Protocol = uint8(datatype.L7_PROTOCOL_HTTP_2)
			} else {
				h.L7Protocol = uint8(datatype.L7_PROTOCOL_HTTP_1)
			}
		}
	}

	h.AttributeNames = attributeNames
	h.AttributeValues = attributeValues
	h.MetricsNames = metricsNames
	h.MetricsValues = metricsValues
}

func (h *L7FlowLog) FillOTel(l *v1.Span, resAttributes []*v11.KeyValue, platformData *grpc.PlatformInfoTable, cfg *flowlogCfg.Config) {
	// OTel data net protocol always set to TCP
	h.Protocol = uint8(layers.IPProtocolTCP)
	h.TapType = uint8(datatype.TAP_CLOUD)
	h.Type = uint8(datatype.MSG_T_SESSION)
	h.TapPortType = datatype.TAPPORT_FROM_OTEL
	h.SignalSource = uint16(datatype.SIGNAL_SOURCE_OTEL)
	h.TraceId = hex.EncodeToString(l.TraceId)
	h.TraceIdIndex = parseTraceIdIndex(h.TraceId, &cfg.Base.TraceIdWithIndex)
	h.SpanId = hex.EncodeToString(l.SpanId)
	h.ParentSpanId = hex.EncodeToString(l.ParentSpanId)
	h.TapSide = spanKindToTapSide(l.Kind)
	h.Endpoint = l.Name
	h.SpanKind = uint8(l.Kind)
	h.spanKind = &h.SpanKind
	h.L7Base.StartTime = int64(l.StartTimeUnixNano) / int64(time.Microsecond)
	h.L7Base.EndTime = int64(l.EndTimeUnixNano) / int64(time.Microsecond)
	if h.L7Base.EndTime > h.L7Base.StartTime {
		h.ResponseDuration = uint64(h.L7Base.EndTime - h.L7Base.StartTime)
	}

	if eventsJSON, err := json.Marshal(l.Events); err == nil {
		h.Events = string(eventsJSON)
	}

	h.fillAttributes(l.GetAttributes(), resAttributes, l.GetLinks())
	// 优先匹配http的响应码
	if h.responseCode != 0 {
		h.ResponseStatus = uint8(httpCodeToResponseStatus(h.responseCode))
		if h.ResponseStatus == uint8(datatype.STATUS_CLIENT_ERROR) ||
			h.ResponseStatus == uint8(datatype.STATUS_SERVER_ERROR) {
			h.ResponseException = GetHTTPExceptionDesc(uint16(h.responseCode))
		}
	} else {
		// 若没有http的响应码，则使用span的响应码
		h.ResponseStatus = uint8(spanStatusToResponseStatus(l.Status))
		if l.Status != nil {
			if l.Status.Code == v1.Status_STATUS_CODE_ERROR {
				h.ResponseException = l.Status.Message
			}
			if l.Status.Code != v1.Status_STATUS_CODE_UNSET {
				h.responseCode = int32(l.Status.Code)
				h.ResponseCode = &h.responseCode
			}
		}
	}
	h.L7Base.KnowledgeGraph.FillOTel(h, platformData)
	// only show data for services as 'server side'
	if h.TapSide == flow_metrics.ServerApp.String() && h.ServerPort == 0 {
		h.ServerPort = 65535
	}
}

func (k *KnowledgeGraph) FillOTel(l *L7FlowLog, platformData *grpc.PlatformInfoTable) {
	switch l.TapSide {
	case "c-app":
		// fill Epc0 with the Epc the Vtap belongs to
		k.L3EpcID0 = platformData.QueryVtapEpc0(uint32(l.VtapID))
		// fill in Epc1 with other rules, see function description for details
		k.L3EpcID1 = platformData.QueryVtapEpc1(uint32(l.VtapID), l.IsIPv4, l.IP41, l.IP61)
	case "s-app":
		// fill Epc1 with the Epc the Vtap belongs to
		k.L3EpcID1 = platformData.QueryVtapEpc0(uint32(l.VtapID))
		// fill in Epc0 with other rules, see function description for details
		k.L3EpcID0 = platformData.QueryVtapEpc1(uint32(l.VtapID), l.IsIPv4, l.IP40, l.IP60)
	default: // "app" or others
		// fill Epc0 and Epc1 with the Epc the Vtap belongs to
		k.L3EpcID0 = platformData.QueryVtapEpc0(uint32(l.VtapID))
		k.L3EpcID1 = k.L3EpcID0
	}
	k.fill(
		platformData,
		!l.IsIPv4, false, false,
		k.L3EpcID0, k.L3EpcID1,
		l.IP40, l.IP41,
		l.IP60, l.IP61,
		0, 0,
		l.GPID0, l.GPID1,
		0, 0, 0,
		uint16(l.ServerPort),
		flow_metrics.Rest,
		layers.IPProtocol(l.Protocol),
	)

	// OTel data always not from INTERNET
	if k.L3EpcID0 == datatype.EPC_FROM_INTERNET {
		k.L3EpcID0 = datatype.EPC_UNKNOWN
	}
	if k.L3EpcID1 == datatype.EPC_FROM_INTERNET {
		k.L3EpcID1 = datatype.EPC_UNKNOWN
	}
	if k.AutoServiceType0 == common.InternetIpType {
		k.AutoServiceType0 = common.IpType
	}
	if k.AutoServiceType1 == common.InternetIpType {
		k.AutoServiceType1 = common.IpType
	}
	if k.AutoInstanceType0 == common.InternetIpType {
		k.AutoInstanceType0 = common.IpType
	}
	if k.AutoInstanceType1 == common.InternetIpType {
		k.AutoInstanceType1 = common.IpType
	}

}
