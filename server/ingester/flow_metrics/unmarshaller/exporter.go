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

package unmarshaller

import (
	"fmt"
	"reflect"
	"strings"
	"time"
	"unsafe"

	exportercommon "github.com/deepflowio/deepflow/server/ingester/exporters/common"
	"github.com/deepflowio/deepflow/server/ingester/exporters/config"
	utag "github.com/deepflowio/deepflow/server/ingester/exporters/universal_tag"
	"github.com/deepflowio/deepflow/server/libs/app"
	flow_metrics "github.com/deepflowio/deepflow/server/libs/flow-metrics"
	"github.com/deepflowio/deepflow/server/libs/utils"
	"github.com/prometheus/prometheus/prompb"
)

type ExportDocumentFlow app.DocumentFlow
type ExportDocumentApp app.DocumentApp
type ExportDocumentUsage app.DocumentUsage

func (e *ExportDocumentFlow) TimestampUs() int64 {
	return int64(time.Duration(e.Timestamp) * time.Second / time.Microsecond)
}

func (e *ExportDocumentFlow) GetFieldValueByOffsetAndKind(offset uintptr, kind reflect.Kind, dataType utils.DataType) interface{} {
	return utils.GetValueByOffsetAndKind(uintptr(unsafe.Pointer(e)), offset, kind, dataType)
}

func (e *ExportDocumentFlow) Meter() flow_metrics.Meter {
	return e.Meter()
}

func (e *ExportDocumentFlow) EncodeTo(protocol config.ExportProtocol, utags *utag.UniversalTagsManager, cfg *config.ExporterCfg) (interface{}, error) {
	return EncodeTo(e, protocol, utags, cfg)
}

func (e *ExportDocumentApp) GetFieldValueByOffsetAndKind(offset uintptr, kind reflect.Kind, dataType utils.DataType) interface{} {
	return utils.GetValueByOffsetAndKind(uintptr(unsafe.Pointer(e)), offset, kind, dataType)
}

func (e *ExportDocumentApp) Meter() flow_metrics.Meter {
	return e.Meter()
}

func (e *ExportDocumentApp) EncodeTo(protocol config.ExportProtocol, utags *utag.UniversalTagsManager, cfg *config.ExporterCfg) (interface{}, error) {
	return EncodeTo(e, protocol, utags, cfg)
}

func (e *ExportDocumentUsage) GetFieldValueByOffsetAndKind(offset uintptr, kind reflect.Kind, dataType utils.DataType) interface{} {
	return utils.GetValueByOffsetAndKind(uintptr(unsafe.Pointer(e)), offset, kind, dataType)
}

func (e *ExportDocumentUsage) Meter() flow_metrics.Meter {
	return e.Meter()
}

func (e *ExportDocumentUsage) EncodeTo(protocol config.ExportProtocol, utags *utag.UniversalTagsManager, cfg *config.ExporterCfg) (interface{}, error) {
	return EncodeTo(e, protocol, utags, cfg)
}

func EncodeTo(e app.Document, protocol config.ExportProtocol, utags *utag.UniversalTagsManager, cfg *config.ExporterCfg) (interface{}, error) {
	switch protocol {
	case config.PROTOCOL_KAFKA:
		tags0, tags1 := QueryUniversalTags0(e, utags), QueryUniversalTags1(e, utags)
		k8sLabels0, k8sLabels1 := utags.QueryCustomK8sLabels(e.Tags().PodID), utags.QueryCustomK8sLabels(e.Tags().PodID1)
		return exportercommon.EncodeToJson(e, int(e.DataSource()), cfg, tags0, tags1, k8sLabels0, k8sLabels1), nil
	case config.PROTOCOL_PROMETHEUS:
		return EncodeToPrometheus(e, utags, cfg)
	default:
		return nil, fmt.Errorf("doc unsupport export to %s", protocol)
	}
}

func QueryUniversalTags0(e app.Document, utags *utag.UniversalTagsManager) *utag.UniversalTags {
	t := e.Tags()
	return utags.QueryUniversalTags(
		t.RegionID, t.AZID, t.HostID, t.PodNSID, t.PodClusterID, t.SubnetID, t.VTAPID,
		uint8(t.L3DeviceType), t.AutoServiceType, t.AutoInstanceType,
		t.L3DeviceID, t.AutoServiceID, t.AutoInstanceID, t.PodNodeID, t.PodGroupID, t.PodID, uint32(t.L3EpcID), t.GPID, t.ServiceID,
		t.IsIPv4 == 1, t.IP, t.IP6,
	)
}

func QueryUniversalTags1(e app.Document, utags *utag.UniversalTagsManager) *utag.UniversalTags {
	t := e.Tags()
	return utags.QueryUniversalTags(
		t.RegionID1, t.AZID1, t.HostID1, t.PodNSID1, t.PodClusterID1, t.SubnetID1, t.VTAPID,
		uint8(t.L3DeviceType1), t.AutoServiceType1, t.AutoInstanceType1,
		t.L3DeviceID1, t.AutoServiceID1, t.AutoInstanceID1, t.PodNodeID1, t.PodGroupID1, t.PodID1, uint32(t.L3EpcID1), t.GPID1, t.ServiceID1,
		t.IsIPv4 == 1, t.IP1, t.IP61,
	)
}

func getPrometheusLabels(e app.Document, uTags0, uTags1 *utag.UniversalTags, cfg *config.ExporterCfg) []prompb.Label {
	dataSourceId := config.DataSourceID(e.DataSource())
	labels := make([]prompb.Label, 0, 16)
	labels = append(labels, prompb.Label{
		Name:  "datasource",
		Value: dataSourceId.String(),
	})
	isMapItem := dataSourceId.IsMap()
	var name, valueStr string
	for _, structTags := range cfg.ExportFieldStructTags[dataSourceId] {
		if structTags.CategoryBit&config.TAG == 0 {
			continue
		}

		value := e.GetFieldValueByOffsetAndKind(structTags.Offset, structTags.DataKind, structTags.DataType)
		if utils.IsNil(value) {
			log.Debug("is nil ", structTags.FieldName)
			continue
		}

		if v, ok := value.(string); ok {
			valueStr = v
		} else {
			valueStr = fmt.Sprintf("%v", value)
		}

		if structTags.ToStringFuncName != "" {
			ret := structTags.ToStringFunc.Call([]reflect.Value{reflect.ValueOf(value)})
			valueStr = ret[0].String()
		} else if structTags.UniversalTagMapID > 0 && !cfg.UniversalTagTranslateToNameDisabled {
			if strings.HasSuffix(structTags.Name, "_1") {
				valueStr = uTags1.GetTagValue(structTags.UniversalTagMapID)
			} else {
				valueStr = uTags0.GetTagValue(structTags.UniversalTagMapID)
			}
		} else if structTags.EnumFile != "" && !cfg.EnumTranslateToNameDisabled {
			valueStr = structTags.EnumStringMap[valueStr]
		}

		if !cfg.ExportEmptyTag && valueStr == "" {
			continue
		}

		if isMapItem && structTags.MapName != "" {
			name = structTags.MapName
		} else {
			name = structTags.Name
		}

		labels = append(labels, prompb.Label{
			Name:  name,
			Value: valueStr,
		})
	}
	return labels
}

func EncodeToPrometheus(e app.Document, utags *utag.UniversalTagsManager, cfg *config.ExporterCfg) (interface{}, error) {
	dataSourceId := e.DataSource()
	uTags0, uTags1 := QueryUniversalTags0(e, utags), QueryUniversalTags1(e, utags)
	timeSeries := []prompb.TimeSeries{}

	labels := getPrometheusLabels(e, uTags0, uTags1, cfg)
	for _, structTags := range cfg.ExportFieldStructTags[dataSourceId] {
		if structTags.CategoryBit&config.METRICS == 0 {
			continue
		}
		isFloat64 := false
		value := e.GetFieldValueByOffsetAndKind(structTags.Offset, structTags.DataKind, structTags.DataType)
		if utils.IsNil(value) {
			log.Debugf("is nil ", structTags.FieldName)
			continue
		}

		valueFloat64, isFloat64 := utils.ConvertToFloat64(value)
		if !isFloat64 {
			continue
		}

		if cfg.ExportEmptyMetricsDisabled && valueFloat64 == 0 {
			continue
		}

		ts := prompb.TimeSeries{}
		ts.Labels = make([]prompb.Label, 0, len(labels)+1)
		ts.Labels = append(ts.Labels, labels...)
		ts.Labels = append(ts.Labels, prompb.Label{
			Name:  "__name__",
			Value: structTags.Name,
		})
		ts.Samples = make([]prompb.Sample, 1)
		ts.Samples[0].Value = valueFloat64
		ts.Samples[0].Timestamp = int64(e.Time()) * 1000 // convert to  ms
		timeSeries = append(timeSeries, ts)
	}

	return timeSeries, nil
}
