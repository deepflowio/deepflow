package common

import (
	"github.com/deepflowio/deepflow/server/libs/datatype"
	"github.com/op/go-logging"
)

const (
	UNKNOWN_DATA  = 0
	CBPF_NET_SPAN = uint32(1 << datatype.SIGNAL_SOURCE_PACKET)
	EBPF_SYS_SPAN = uint32(1 << datatype.SIGNAL_SOURCE_EBPF)
	OTEL_APP_SPAN = uint32(1 << datatype.SIGNAL_SOURCE_OTEL)
)

var exportedDataStringMap = map[string]uint32{
	"cbpf-net-span": CBPF_NET_SPAN,
	"ebpf-sys-span": EBPF_SYS_SPAN,
	"otel-app-span": OTEL_APP_SPAN,
}

var log = logging.MustGetLogger("exporter.common")

func bitsToString(bits uint32, strMap map[string]uint32) string {
	ret := ""
	for k, v := range strMap {
		if bits&v != 0 {
			if len(ret) == 0 {
				ret = k
			} else {
				ret = ret + "," + k
			}
		}
	}
	return ret
}

func ExportedDataBitsToString(bits uint32) string {
	return bitsToString(bits, exportedDataStringMap)
}

func StringToExportedData(str string) uint32 {
	t, ok := exportedDataStringMap[str]
	if !ok {
		log.Warningf("unknown exporter data: %s", str)
		return UNKNOWN_DATA
	}
	return t
}

const (
	UNKNOWN_DATA_TYPE = 0

	SERVICE_INFO uint32 = 1 << iota
	TRACING_INFO
	NETWORK_LAYER
	FLOW_INFO
	CLIENT_UNIVERSAL_TAG
	SERVER_UNIVERSAL_TAG
	TUNNEL_INFO
	TRANSPORT_LAYER
	APPLICATION_LAYER
	CAPTURE_INFO
	CLIENT_CUSTOM_TAG
	SERVER_CUSTOM_TAG
	NATIVE_TAG
	METRICS
	K8S_LABEL
)

var exportedDataTypeStringMap = map[string]uint32{
	"service_info":         SERVICE_INFO,
	"tracing_info":         TRACING_INFO,
	"network_layer":        NETWORK_LAYER,
	"flow_info":            FLOW_INFO,
	"client_universal_tag": CLIENT_UNIVERSAL_TAG,
	"server_universal_tag": SERVER_UNIVERSAL_TAG,
	"tunnel_info":          TUNNEL_INFO,
	"transport_layer":      TRANSPORT_LAYER,
	"application_layer":    APPLICATION_LAYER,
	"capture_info":         CAPTURE_INFO,
	"client_custom_tag":    CLIENT_CUSTOM_TAG,
	"server_custom_tag":    SERVER_CUSTOM_TAG,
	"native_tag":           NATIVE_TAG,
	"metrics":              METRICS,
	"k8s_label":            K8S_LABEL,
}

func StringToExportedDataType(str string) uint32 {
	t, ok := exportedDataTypeStringMap[str]
	if !ok {
		log.Warningf("unknown exporter data type: %s", str)
		return UNKNOWN_DATA_TYPE
	}
	return t
}

func ExportedDataTypeBitsToString(bits uint32) string {
	return bitsToString(bits, exportedDataTypeStringMap)
}
