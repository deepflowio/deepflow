package jsonify

import (
	"encoding/base64"
	"encoding/hex"
	"net"
	"strings"
	"time"

	"github.com/google/gopacket/layers"
	"gitlab.yunshan.net/yunshan/droplet-libs/datatype"
	"gitlab.yunshan.net/yunshan/droplet-libs/grpc"
	"gitlab.yunshan.net/yunshan/droplet-libs/utils"
	"gitlab.yunshan.net/yunshan/droplet-libs/zerodoc"
	v11 "go.opentelemetry.io/proto/otlp/common/v1"
	v1 "go.opentelemetry.io/proto/otlp/trace/v1"
)

func OTelTracesDataToL7Loggers(vtapID uint16, l *v1.TracesData, shardID int, platformData *grpc.PlatformInfoTable) []interface{} {
	ret := []interface{}{}
	for _, resourceSpan := range l.GetResourceSpans() {
		for _, scopeSpan := range resourceSpan.GetScopeSpans() {
			for _, span := range scopeSpan.GetSpans() {
				ret = append(ret, spanToL7Logger(vtapID, span, shardID, platformData))
			}
		}
	}
	return ret
}

func spanToL7Logger(vtapID uint16, span *v1.Span, shardID int, platformData *grpc.PlatformInfoTable) interface{} {
	h := AcquireL7Logger()
	h._id = genID(uint32(span.EndTimeUnixNano/uint64(time.Second)), &L7LogCounter, shardID)
	h.VtapID = vtapID
	h.FillOTel(span, platformData)
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

func spanStatusToResponseStatus(status *v1.Status) uint8 {
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

func httpCodeToResponseStatus(code int16) uint8 {
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

func (h *L7Logger) fillAttributes(attributes []*v11.KeyValue) {
	h.IsIPv4 = true
	tagNames, tagValues := []string{}, []string{}
	for _, attr := range attributes {
		key := attr.GetKey()
		value := attr.GetValue()
		if value == nil {
			continue
		}

		// FIXME 不同类型都按string存储，后续不同类型存储应分开, 参考: https://github.com/open-telemetry/opentelemetry-proto/blob/main/opentelemetry/proto/common/v1/common.proto#L31
		tagNames = append(tagNames, key)
		tagValues = append(tagValues, getValueString(value))

		switch key {
		case "net.transport":
			protocol := value.GetStringValue()
			if strings.Contains(protocol, "tcp") {
				h.Protocol = uint8(layers.IPProtocolTCP)
			} else if strings.Contains(protocol, "udp") {
				h.Protocol = uint8(layers.IPProtocolUDP)
			}
		case "net.host.ip":
			ip := net.ParseIP(value.GetStringValue())
			if ip == nil {
				continue
			}
			if ip4 := ip.To4(); ip4 != nil {
				h.IP40 = utils.IpToUint32(ip4)
			} else {
				h.IsIPv4 = false
				h.IP60 = ip
			}
		case "net.host.port":
			h.ClientPort = uint16(value.GetIntValue())
		case "net.peer.ip":
			ip := net.ParseIP(value.GetStringValue())
			if ip == nil {
				continue
			}
			if ip4 := ip.To4(); ip4 != nil {
				h.IP41 = utils.IpToUint32(ip4)
			} else {
				h.IsIPv4 = false
				h.IP61 = ip
			}
		case "net.peer.port":
			h.ServerPort = uint16(value.GetIntValue())
		case "http.scheme", "db.system", "rpc.system", "messaging.system", "messaging.protocol":
			h.L7ProtocolStr = value.GetStringValue()
		case "http.flavor":
			h.Version = value.GetStringValue()
		case "http.status_code":
			h.responseCode = int16(value.GetIntValue())
			h.ResponseCode = &h.responseCode
		case "http.host", "db.connection_string":
			h.RequestDomain = value.GetStringValue()
		case "http.method", "db.operation", "rpc.method":
			h.RequestType = value.GetStringValue()
		case "http.target", "db.statement", "messaging.url", "rpc.service":
			h.RequestResource = value.GetStringValue()
		case "http.request_content_length":
			h.requestLength = uint64(value.GetIntValue())
			h.RequestLength = &h.requestLength
		case "http.response_content_length":
			h.responseLength = uint64(value.GetIntValue())
			h.ResponseLength = &h.responseLength
		default:
			// nothing
		}
	}
	if len(h.L7ProtocolStr) > 0 {
		if strings.Contains(strings.ToLower(h.L7ProtocolStr), "http") {
			if strings.HasPrefix(h.Version, "2") {
				h.L7Protocol = uint8(datatype.L7_PROTOCOL_HTTP_2)
			} else {
				h.L7Protocol = uint8(datatype.L7_PROTOCOL_HTTP_1)
			}
		} else {
			for l7ProtocolStr, l7Protocol := range datatype.L7ProtocolStringMap {
				if strings.Contains(l7ProtocolStr, strings.ToLower(h.L7ProtocolStr)) {
					h.L7Protocol = uint8(l7Protocol)
					break
				}
			}
		}
	}

	h.TagNames = tagNames
	h.TagValues = tagValues
}

func (h *L7Logger) FillOTel(l *v1.Span, platformData *grpc.PlatformInfoTable) {
	h.Type = uint8(datatype.MSG_T_SESSION)
	h.TapPortType = datatype.TAPPORT_FROM_OTEL
	h.TraceId = hex.EncodeToString(l.TraceId)
	h.SpanId = hex.EncodeToString(l.SpanId)
	h.ParentSpanId = base64.StdEncoding.EncodeToString(l.ParentSpanId)
	h.TapSide = spanKindToTapSide(l.Kind)
	h.SpanKind = uint8(l.Kind)
	h.StartTime = l.StartTimeUnixNano / uint64(time.Microsecond)
	h.L7Base.EndTime = l.EndTimeUnixNano / uint64(time.Microsecond)
	if h.L7Base.EndTime > h.StartTime {
		h.ResponseDuration = h.L7Base.EndTime - h.StartTime
	}

	h.fillAttributes(l.GetAttributes())
	// 优先匹配http的响应码
	if h.responseCode != 0 {
		h.ResponseStatus = httpCodeToResponseStatus(h.responseCode)
		if h.ResponseStatus == datatype.STATUS_CLIENT_ERROR ||
			h.ResponseStatus == datatype.STATUS_SERVER_ERROR {
			h.ResponseException = GetHTTPExceptionDesc(uint16(h.responseCode))
		}
	} else {
		// 若没有http的响应码，则使用span的响应码
		h.ResponseStatus = spanStatusToResponseStatus(l.Status)
		if l.Status != nil {
			if l.Status.Code == v1.Status_STATUS_CODE_ERROR {
				h.ResponseException = l.Status.Message
			}
			if l.Status.Code != v1.Status_STATUS_CODE_UNSET {
				h.responseCode = int16(l.Status.Code)
				h.ResponseCode = &h.responseCode
			}
		}
	}
	h.L7Base.KnowledgeGraph.FillOTel(h, platformData)
}

func (k *KnowledgeGraph) FillOTel(l *L7Logger, platformData *grpc.PlatformInfoTable) {
	k.L3EpcID0 = platformData.QueryVtapEpc0(uint32(l.VtapID))
	k.L3EpcID1 = platformData.QueryVtapEpc1(uint32(l.VtapID), l.IsIPv4, l.IP41, l.IP61)
	k.fill(
		platformData,
		!l.IsIPv4, false, false,
		int16(k.L3EpcID0), int16(k.L3EpcID1),
		l.IP40, l.IP41,
		l.IP60, l.IP61,
		0, 0,
		uint16(l.ServerPort),
		zerodoc.Rest,
		layers.IPProtocol(l.Protocol),
	)
}
