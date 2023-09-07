package config

import (
	logging "github.com/op/go-logging"

	"github.com/deepflowio/deepflow/server/libs/datatype"
)

var log = logging.MustGetLogger("exporters_config")

type OverridableCfg struct {
	ExportDatas                 []string `yaml:"export-datas"`
	ExportDataBits              uint32   // generate from 'ExportDatas'
	ExportDataTypes             []string `yaml:"export-data-types"`
	ExportDataTypeBits          uint32   // generate from 'ExportDataTypes'
	ExportCustomK8sLabelsRegexp string   `yaml:"export-custom-k8s-labels-regexp"`
	ExportOnlyWithTraceID       *bool    `yaml:"export-only-with-traceid"`
}

// ExporterCfg holds configs of different exporters.
type ExportersCfg struct {
	Enabled bool `yaml:"enabled"`

	// global config, could be overridden by same fields under each exporter.
	OverridableCfg `yaml:",inline"`

	// OtlpExporter config for OTLP exporters
	OtlpExporterCfgs []OtlpExporterConfig `yaml:"otlp-exporters"`

	// other exporter configs ...
}

func (ec *ExportersCfg) Validate() error {
	for i := range ec.OtlpExporterCfgs {
		if err := ec.OtlpExporterCfgs[i].Validate(ec.OverridableCfg); err != nil {
			return err
		}
	}
	return nil
}

var DefaultOtlpExportDatas = []string{"cbpf-net-span", "ebpf-sys-span"}
var DefaultOtlpExportDataTypes = []string{"service_info", "tracing_info", "network_layer", "flow_info", "transport_layer", "application_layer", "metrics"}

func NewDefaultExportersCfg() ExportersCfg {
	return ExportersCfg{
		Enabled: false,
		OverridableCfg: OverridableCfg{
			ExportDatas:     DefaultOtlpExportDatas,
			ExportDataTypes: DefaultOtlpExportDataTypes,
		},
		OtlpExporterCfgs: []OtlpExporterConfig{NewOtlpDefaultConfig()},
	}
}

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
