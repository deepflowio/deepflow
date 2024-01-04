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

package exporters

import (
	logging "github.com/op/go-logging"

	"github.com/deepflowio/deepflow/server/ingester/flow_log/config"
	exporters_cfg "github.com/deepflowio/deepflow/server/ingester/flow_log/exporters/config"
	"github.com/deepflowio/deepflow/server/ingester/flow_log/exporters/otlp_exporter"
	"github.com/deepflowio/deepflow/server/ingester/flow_log/exporters/universal_tag"
	"github.com/deepflowio/deepflow/server/ingester/flow_log/log_data"
)

var log = logging.MustGetLogger("exporters")

const (
	PUT_BATCH_SIZE = 1024
)

type Exporter interface {
	// Starts an exporter worker
	Start()
	// Close an exporter worker
	Close()

	// Put sends data to the exporter worker. Worker could decide what to do next. e.g.:
	// - send it out synchronously.
	// - store it in a queue and handle it later.
	Put(items ...interface{})

	// IsExportData tell the decoder if data need to be sended to specific exporter.
	IsExportData(l *log_data.L7FlowLog) bool
}

type ExportersCache [][]interface{}

type Exporters struct {
	config               *exporters_cfg.ExportersCfg
	universalTagsManager *universal_tag.UniversalTagsManager
	exporters            []Exporter
	putCaches            []ExportersCache // cache for batch put to exporter, multi flowlog decoders call Put(), and put to multi exporters
}

func NewExporters(flowlogCfg *config.Config) *Exporters {
	exportersCfg := &flowlogCfg.ExportersCfg
	if !exportersCfg.Enabled {
		log.Infof("exporters disabled")
		return nil
	}
	log.Infof("init exporters: %v", flowlogCfg.ExportersCfg)
	exporters := make([]Exporter, 0)
	putCaches := make([]ExportersCache, flowlogCfg.DecoderQueueCount)

	universalTagManager := universal_tag.NewUniversalTagsManager(exportersCfg.ExportCustomK8sLabelsRegexp, flowlogCfg.Base)

	for i := range exportersCfg.OtlpExporterCfgs {
		if exportersCfg.OtlpExporterCfgs[i].Enabled {
			otlpExporter := otlp_exporter.NewOtlpExporter(i, exportersCfg, universalTagManager)
			exporters = append(exporters, otlpExporter)
		}
	}

	// todo add other exporters....

	// init caches
	for i := range putCaches {
		putCaches[i] = make(ExportersCache, len(exporters))
		for j := range exporters {
			putCaches[i][j] = make([]interface{}, 0, PUT_BATCH_SIZE)
		}
	}

	return &Exporters{
		config:               exportersCfg,
		universalTagsManager: universalTagManager,
		exporters:            exporters,
		putCaches:            putCaches,
	}
}

func (es *Exporters) Start() {
	es.universalTagsManager.Start()
	for _, e := range es.exporters {
		e.Start()
	}
}

func (es *Exporters) Close() {
	es.universalTagsManager.Close()
	for _, e := range es.exporters {
		e.Close()
	}
}

// parallel put
func (es *Exporters) Put(l *log_data.L7FlowLog, decoderIndex int) {
	if l == nil {
		es.Flush(decoderIndex)
		return
	}

	exportersCache := es.putCaches[decoderIndex]
	for i, e := range es.exporters {
		if e.IsExportData(l) {
			l.AddReferenceCount()
			exportersCache[i] = append(exportersCache[i], l)
			if len(exportersCache[i]) >= PUT_BATCH_SIZE {
				e.Put(exportersCache[i]...)
				exportersCache[i] = exportersCache[i][:0]
			}
		}
	}
}

func (es *Exporters) Flush(decoderIndex int) {
	exportersCache := es.putCaches[decoderIndex]
	for i := range exportersCache {
		if len(exportersCache[i]) > 0 {
			es.exporters[i].Put(exportersCache[i]...)
			exportersCache[i] = exportersCache[i][:0]
		}
	}
}
