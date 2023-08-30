package exporter

import (
	"fmt"

	otlp_exporter "github.com/deepflowio/deepflow/server/ingester/flow_log/exporter/otlp_exporter"
)

// ExporterCfg holds configs of different exporters.
type ExporterCfg struct {
	Name string       `yaml:"name"`
	Type ExporterType `yaml:"exporter_type"`

	// OtlpExporter config for OTLP exporter
	OtlpExporter otlp_exporter.OtlpExporterConfig `yaml:"otlp-exporter"`
}

type ExporterType string

const (
	OtlpExporter ExporterType = "otlp-exporter"
)

func (ec ExporterCfg) Validate() error {
	switch ec.Type {
	case OtlpExporter:
		return otlp_exporter.Validate(ec.OtlpExporter)
	default:
		return fmt.Errorf("unknown exporter type %s", ec.Type)
	}
}

func GetDefaultExporterCfg() []ExporterCfg {
	return []ExporterCfg{
		{
			Name:         "Default OTLP Exporter",
			Type:         OtlpExporter,
			OtlpExporter: otlp_exporter.NewDefaultConfig(),
		},
	}
}
