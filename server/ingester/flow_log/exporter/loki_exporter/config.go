package loki_exporter

import "errors"

type LokiExporterConfig struct {
	URL                   string            `yaml:"url"`
	TenantID              string            `yaml:"tenant-id"`
	MaxMessageWait        int64             `yaml:"max-message-wait"`
	MaxMessageBytes       int64             `yaml:"max-message-bytes"`
	MaxRetries            int64             `yaml:"max-retries"`
	ExportDatas           []string          `yaml:"export-datas"`
	ExportDataTypes       []string          `yaml:"export-data-types"`
	ExportOnlyWithTraceID bool              `yaml:"export-only-with-traceid"`
	DynamicLabels         []string          `yaml:"dynamic-labels"`
	StaticLabels          map[string]string `yaml:"static-labels"`
}

func Validate(cfg LokiExporterConfig) error {
	if cfg.URL == "" {
		return errors.New("url is nil")
	}
	if cfg.MaxMessageBytes <= 0 {
		return errors.New("batch size is required > 0")
	}
	if len(cfg.StaticLabels) == 0 && len(cfg.DynamicLabels) == 0 {
		return errors.New("at least one label should be set")
	}
	return nil
}
