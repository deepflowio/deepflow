package exporter

import (
	"github.com/op/go-logging"

	"github.com/deepflowio/deepflow/server/ingester/config"
	"github.com/deepflowio/deepflow/server/ingester/flow_log/exporter/otlp_exporter"
)

var log = logging.MustGetLogger("exporter")

type Exporter interface {
	// Start starts an exporter worker
	Start()

	// Put sends data to the exporter worker. Worker could decide what to do next. e.g.:
	// - send it out synchronously.
	// - store it in a queue and handle it later.
	Put(items ...interface{})

	// IsExportData tell the decoder if data need to be sended to specific exporter.
	IsExportData(items interface{}) bool
}

func NewExporters(exportersCfg []ExporterCfg, baseCfg *config.Config) []Exporter {
	log.Infof("Init Exporters: %v", exportersCfg)
	exporters := make([]Exporter, 0, len(exportersCfg))
	for i := range exportersCfg {
		switch exportersCfg[i].Type {
		case OtlpExporter:
			if otlpExporter := otlp_exporter.NewOtlpExporter(&exportersCfg[i].OtlpExporter, baseCfg); otlpExporter != nil {
				exporters = append(exporters, otlpExporter)
			}
		default:

		}
	}

	return exporters
}
