package otlp_exporter

type OtlpExporterConfig struct {
	Enabled                     bool              `yaml:"enabled"`
	Addr                        string            `yaml:"addr"`
	QueueCount                  int               `yaml:"queue-count"`
	QueueSize                   int               `yaml:"queue-size"`
	ExportDatas                 []string          `yaml:"export-datas"`
	ExportDataTypes             []string          `yaml:"export-data-types"`
	ExportCustomK8sLabelsRegexp string            `yaml:"export-custom-k8s-labels-regexp"`
	ExportOnlyWithTraceID       bool              `yaml:"export-only-with-traceid"`
	ExportBatchCount            int               `yaml:"export-batch-count"`
	GrpcHeaders                 map[string]string `yaml:"grpc-headers"`
}

const (
	DefaultOtlpExportBatchCount = 32
)

var DefaultOtlpExportDatas = []string{"cbpf-net-span", "ebpf-sys-span"}
var DefaultOtlpExportDataTypes = []string{"service_info", "tracing_info", "network_layer", "flow_info", "transport_layer", "application_layer", "metrics"}

func Validate(cfg OtlpExporterConfig) error {
	if len(cfg.ExportDatas) == 0 {
		cfg.ExportDatas = DefaultOtlpExportDatas
	}

	if len(cfg.ExportDataTypes) == 0 {
		cfg.ExportDataTypes = DefaultOtlpExportDataTypes
	}
	if cfg.ExportBatchCount == 0 {
		cfg.ExportBatchCount = DefaultOtlpExportBatchCount
	}

	return nil
}

func NewDefaultConfig() OtlpExporterConfig {
	return OtlpExporterConfig{
		Enabled:                     false,
		Addr:                        "127.0.0.1:4317",
		QueueCount:                  4,
		QueueSize:                   100000,
		ExportDatas:                 DefaultOtlpExportDatas,
		ExportDataTypes:             DefaultOtlpExportDataTypes,
		ExportCustomK8sLabelsRegexp: "",
		ExportOnlyWithTraceID:       false,
		ExportBatchCount:            DefaultOtlpExportBatchCount,
		GrpcHeaders:                 nil,
	}
}
