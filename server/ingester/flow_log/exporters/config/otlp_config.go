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

package config

// Preserved for backward compatibility ONLY
type OtlpExporterConfigDeprecated struct {
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

func NewOtlpDefaultConfigDeprecated() OtlpExporterConfigDeprecated {
	return OtlpExporterConfigDeprecated{
		Enabled:          false,
		Addr:             "127.0.0.1:4317",
		QueueCount:       DefaultOtlpExportQueueCount,
		QueueSize:        DefaultOtlpExportQueueSize,
		ExportDatas:      DefaultOtlpExportDatas,
		ExportDataTypes:  DefaultOtlpExportDataTypes,
		ExportBatchCount: DefaultOtlpExportBatchCount,
		GrpcHeaders:      nil,
	}
}

type OtlpExporterConfig struct {
	Enabled          bool              `yaml:"enabled"`
	Addr             string            `yaml:"addr"`
	QueueCount       int               `yaml:"queue-count"`
	QueueSize        int               `yaml:"queue-size"`
	ExportBatchCount int               `yaml:"export-batch-count"`
	GrpcHeaders      map[string]string `yaml:"grpc-headers"`

	OverridableCfg `yaml:",inline"`
}

const (
	DefaultOtlpExportBatchCount = 32
	DefaultOtlpExportQueueCount = 4
	DefaultOtlpExportQueueSize  = 100000
)

func (cfg *OtlpExporterConfig) Validate(overridableCfg OverridableCfg) error {
	if !cfg.Enabled {
		return nil
	}

	cfg.calcDataBits()

	if cfg.ExportBatchCount == 0 {
		cfg.ExportBatchCount = DefaultOtlpExportBatchCount
	}

	if cfg.QueueCount == 0 {
		cfg.QueueCount = DefaultOtlpExportQueueCount
	}
	if cfg.QueueSize == 0 {
		cfg.QueueSize = DefaultOtlpExportQueueSize
	}

	// overwritten params
	if cfg.ExportCustomK8sLabelsRegexp == "" {
		cfg.ExportCustomK8sLabelsRegexp = overridableCfg.ExportCustomK8sLabelsRegexp
	}

	if len(cfg.ExportDatas) == 0 {
		cfg.ExportDatas = overridableCfg.ExportDatas
	}

	if len(cfg.ExportDataTypes) == 0 {
		cfg.ExportDataTypes = overridableCfg.ExportDataTypes
	}

	if cfg.ExportOnlyWithTraceID == nil {
		cfg.ExportOnlyWithTraceID = overridableCfg.ExportOnlyWithTraceID
	}
	return nil
}

func (cfg *OtlpExporterConfig) calcDataBits() {
	for _, v := range cfg.ExportDatas {
		cfg.ExportDataBits |= uint32(StringToExportedData(v))
	}
	log.Infof("export data bits: %08b, string: %s", cfg.ExportDataBits, ExportedDataBitsToString(cfg.ExportDataBits))

	for _, v := range cfg.ExportDataTypes {
		cfg.ExportDataTypeBits |= uint32(StringToExportedDataType(v))
	}
	if cfg.ExportCustomK8sLabelsRegexp != "" {
		cfg.ExportDataTypeBits |= K8S_LABEL
	}
	log.Infof("export data type bits: %08b, string: %s", cfg.ExportDataTypeBits, ExportedDataTypeBitsToString(cfg.ExportDataTypeBits))
}

func NewOtlpDefaultConfig() OtlpExporterConfig {
	return OtlpExporterConfig{
		Enabled:          false,
		Addr:             "127.0.0.1:4317",
		QueueCount:       DefaultOtlpExportQueueCount,
		QueueSize:        DefaultOtlpExportQueueSize,
		ExportBatchCount: DefaultOtlpExportBatchCount,
		GrpcHeaders:      nil,
	}
}
