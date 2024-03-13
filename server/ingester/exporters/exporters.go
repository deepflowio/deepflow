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
	"strings"

	logging "github.com/op/go-logging"

	"github.com/deepflowio/deepflow/server/ingester/exporters/common"
	"github.com/deepflowio/deepflow/server/ingester/exporters/config"
	"github.com/deepflowio/deepflow/server/ingester/exporters/otlp_exporter"
	"github.com/deepflowio/deepflow/server/ingester/exporters/universal_tag"
	"github.com/deepflowio/deepflow/server/libs/queue"
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
}

type ExportersCache []interface{}

type Exporters struct {
	config                  *config.Config
	universalTagsManagerMap map[string]*universal_tag.UniversalTagsManager
	exporters               []Exporter
	dataSourceExporters     [][]Exporter
	dataSourceExporterCfgs  [][]config.ExporterCfg
	putCaches               []ExportersCache // cache for batch put to exporter, multi flowlog decoders call Put(), and put to multi exporters
}

func NewExporters(cfg *config.Config) *Exporters {
	if len(cfg.Exporters) == 0 {
		log.Infof("exporters is empty")
		return nil
	}
	log.Infof("init exporters: %v", cfg.Exporters)

	putCaches := make([]ExportersCache, config.MAX_DATASOURCE_ID*queue.MAX_QUEUE_COUNT)

	exporters := make([]Exporter, 0)
	dataSourceExporters := [][]Exporter{}
	dataSourceExporterCfgs := [][]config.ExporterCfg{}
	var exporter Exporter
	var universalTagManager *universal_tag.UniversalTagsManager
	uTagManagerMap := make(map[string]*universal_tag.UniversalTagsManager)
	for i, exporterCfg := range cfg.Exporters {
		// If the ExportFieldK8s are the same, you can use the same universalTagManager
		universalTagManager = uTagManagerMap[strings.Join(exporterCfg.ExportFieldK8s, "-")]
		if universalTagManager == nil {
			universalTagManager = universal_tag.NewUniversalTagsManager(exporterCfg.ExportFieldK8s, cfg.Base)
			uTagManagerMap[strings.Join(exporterCfg.ExportFieldK8s, "-")] = universalTagManager
		}
		switch exporterCfg.ExportProtocol {
		case config.PROTOCOL_OTLP:
			exporter = otlp_exporter.NewOtlpExporter(i, &exporterCfg, universalTagManager)
		case config.PROTOCOL_PROMETHEUS:
		case config.PROTOCOL_KAFKA:
		default:
			exporter = nil
			log.Warningf("unsupport export protocol %s", exporterCfg.Protocol)
		}
		if exporter == nil {
			continue
		}
		exporters = append(exporters, exporter)
		for _, dataSource := range exporterCfg.DataSources {
			dataSourceId := config.DataSourceStringMap[dataSource]
			dataSourceExporters[dataSourceId] = append(dataSourceExporters[dataSourceId], exporter)
			dataSourceExporterCfgs[dataSourceId] = append(dataSourceExporterCfgs[dataSourceId], exporterCfg)
		}
	}

	return &Exporters{
		config:                  cfg,
		universalTagsManagerMap: uTagManagerMap,
		exporters:               exporters,
		putCaches:               putCaches,
		dataSourceExporters:     dataSourceExporters,
		dataSourceExporterCfgs:  dataSourceExporterCfgs,
	}
}

func (es *Exporters) Start() {
	for _, v := range es.universalTagsManagerMap {
		v.Start()
	}
	for _, e := range es.exporters {
		e.Start()
	}
}

func (es *Exporters) Close() {
	for _, v := range es.universalTagsManagerMap {
		v.Close()
	}
	for _, e := range es.exporters {
		e.Close()
	}
}

func isMatchTagFilter(value interface{}, tagFilter *config.TagFilter) bool {
	var float64Value float64
	var isFloat64 bool
	strValue, isStr := value.(string)
	if !isStr {
		float64Value, isFloat64 = common.ConvertToFloat64(value)
	}

	// 读取config时，已经过滤了非这2中数据的类型了
	if !isStr && !isFloat64 {
		// not filter
		return true
	}

	if isStr {
		switch tagFilter.OperatorID {
		case config.EQ:
			for _, v := range tagFilter.ValueStrings {
				if v != strValue {
					return false
				}
			}
		case config.NEQ:
			for _, v := range tagFilter.ValueStrings {
				if v == strValue {
					return false
				}
			}
		}

	} else if isFloat64 {
		switch tagFilter.OperatorID {
		case config.EQ:
			for _, v := range tagFilter.ValueFloat64 {
				if v != float64Value {
					return false
				}
			}
		case config.NEQ:
			for _, v := range tagFilter.ValueFloat64 {
				if v == float64Value {
					return false
				}
			}
		case config.IN:
			for _, v := range tagFilter.ValueFloat64 {
				if v != float64Value {
					return false
				}
			}
		case config.NOT_IN:
			for _, v := range tagFilter.ValueFloat64 {
				if v != float64Value {
					return false
				}
			}
		}
	}
	return true
}

func initStructTags(item interface{}, dataSourceId int, exporterCfg *config.ExporterCfg) {
	if len(exporterCfg.TagFilters) > 0 && len(exporterCfg.TagFieltertStructTags[dataSourceId]) == 0 {

	}
}

func (es *Exporters) IsExportItem(dataSourceId int, item common.ExportItem, exporterCfg *config.ExporterCfg) bool {
	for _, structTag := range exporterCfg.TagFieltertStructTags[dataSourceId] {
		value := common.GetFieldValueByOffsetAndKind(item, structTag.Offset, structTag.DataType)
		for _, tagFilter := range structTag.TagFilters {
			if !isMatchTagFilter(value, &tagFilter) {
				// todo add counter
				return false
			}
		}
	}

	return true
}

// parallel put
func (es *Exporters) Put(dataSourceId, decoderIndex int, item common.ExportItem) {
	if dataSourceId >= len(es.dataSourceExporters) ||
		es.dataSourceExporters[dataSourceId] == nil {
		return
	}
	if item == nil {
		es.Flush(dataSourceId, decoderIndex)
		return
	}
	exporters := es.dataSourceExporters[dataSourceId]
	exportersCount := len(exporters)
	if exportersCount == 0 {
		return
	}
	exporterCfgs := es.dataSourceExporterCfgs[dataSourceId]
	exportersCache := &es.putCaches[dataSourceId*queue.MAX_QUEUE_COUNT+decoderIndex]
	item.AddReferenceCountN(exportersCount)
	*exportersCache = append(*exportersCache, item)
	for i, e := range exporters {
		if es.IsExportItem(dataSourceId, item, &exporterCfgs[i]) {
			item.Release()
			continue
		}
		if len(*exportersCache) >= PUT_BATCH_SIZE {
			e.Put(*exportersCache...)
		}
	}
	*exportersCache = (*exportersCache)[:0]
}

func (es *Exporters) Flush(dataSourceId, decoderIndex int) {
	exportersCache := &es.putCaches[dataSourceId*queue.MAX_QUEUE_COUNT+decoderIndex]

	exporters := es.dataSourceExporters[dataSourceId]
	exportersCount := len(exporters)
	if exportersCount == 0 {
		return
	}
	for _, e := range exporters {
		if len(*exportersCache) >= 0 {
			e.Put(*exportersCache...)
		}
	}
	*exportersCache = (*exportersCache)[:0]
}
