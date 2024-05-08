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

package common

import (
	"fmt"
	"net"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/deepflowio/deepflow/server/ingester/exporters/config"
	utag "github.com/deepflowio/deepflow/server/ingester/exporters/universal_tag"
	"github.com/deepflowio/deepflow/server/libs/utils"
	logging "github.com/op/go-logging"
)

var log = logging.MustGetLogger("exporters.interface")

type ExportItem interface {
	DataSource() uint32
	GetFieldValueByOffsetAndKind(offset uintptr, kind reflect.Kind, dataType utils.DataType) interface{}
	EncodeTo(p config.ExportProtocol, utags *utag.UniversalTagsManager, cfg *config.ExporterCfg) (interface{}, error)
	TimestampUs() int64 // us
	Release()
	AddReferenceCount()
}

type EncodeItem interface {
	GetFieldValueByOffsetAndKind(offset uintptr, kind reflect.Kind, dataType utils.DataType) interface{}
	TimestampUs() int64 // us
}

var funcMaps = map[string]interface{}{
	"IPv4String": IPv4String,
	"IPv6String": IPv6String,
	"MacString":  MacString,
}

func IPv4String(ip4 uint32) string {
	ip := make(net.IP, 4)
	ip[0] = byte(ip4 >> 24)
	ip[1] = byte(ip4 >> 16)
	ip[2] = byte(ip4 >> 8)
	ip[3] = byte(ip4)
	return ip.String()
}

func IPv6String(ip6 net.IP) string {
	str := ip6.String()
	if str == "<nil>" {
		return ""
	}
	return str
}

func MacString(mac uint64) string {
	return utils.Uint64ToMac(mac).String()
}

func GetFunc(funcName string) interface{} {
	return funcMaps[funcName]
}

func writeK8sLabels(sb *strings.Builder, keyName, valueName string, k8sLabels utag.Labels) {
	if len(k8sLabels) == 0 {
		return
	}
	valuesBuilder := &strings.Builder{}
	sb.WriteString(`,"`)
	sb.WriteString(keyName)
	sb.WriteString(`":[`)

	valuesBuilder.WriteString(`,"`)
	valuesBuilder.WriteString(valueName)
	valuesBuilder.WriteString(`":[`)

	isFirst := true
	for key, value := range k8sLabels {
		if !isFirst {
			sb.WriteString(`,`)
			valuesBuilder.WriteString(`,`)
		}
		isFirst = false
		sb.WriteString(`"`)
		sb.WriteString(key)
		sb.WriteString(`"`)

		valuesBuilder.WriteString(`"`)
		valuesBuilder.WriteString(value)
		valuesBuilder.WriteString(`"`)

	}
	sb.WriteString(`]`)
	valuesBuilder.WriteString(`]`)

	sb.WriteString(valuesBuilder.String())
}

func EncodeToJson(item EncodeItem, dataSourceId int, exporterCfg *config.ExporterCfg, uTags0, uTags1 *utag.UniversalTags, k8sLabels0, k8sLabels1 utag.Labels) string {
	var sb = &strings.Builder{}
	sb.WriteString("{\"datasource\":\"")
	sb.WriteString(config.DataSourceID(dataSourceId).String())
	sb.WriteString(`"`)

	if dataSourceId >= int(config.MAX_DATASOURCE_ID) {
		log.Errorf("export datasource wrong: datasourceid %d ", dataSourceId)
		return ""
	}

	isMapItem := config.DataSourceID(dataSourceId).IsMap()
	var isString, isFloat64, isStringSlice, isFloat64Slice bool
	var keyStr, valueStr string
	var valueFloat64 float64
	var stringSlice []string
	var float64Slice []float64
	for _, structTags := range exporterCfg.ExportFieldStructTags[dataSourceId] {
		isString, isFloat64, isStringSlice, isFloat64Slice = false, false, false, false
		value := item.GetFieldValueByOffsetAndKind(structTags.Offset, structTags.DataKind, structTags.DataType)
		if utils.IsNil(value) {
			log.Debugf("%s value is nil", structTags.FieldName)
			continue
		}
		if isMapItem && structTags.MapName != "" {
			keyStr = structTags.MapName
		} else {
			keyStr = structTags.Name
		}
		if v, ok := value.(string); ok {
			isString = true
			valueStr = v
		} else if v, ok := value.([]string); ok {
			isStringSlice = true
			stringSlice = v
		} else if v, ok := value.([]float64); ok {
			isFloat64Slice = true
			float64Slice = v
		} else if v, vStr, ok := utils.ConvertToFloat64(value); ok {
			isFloat64 = true
			valueFloat64 = v
			valueStr = vStr
		} else {
			isString = true
			valueStr = fmt.Sprintf("%v", value)
		}

		if structTags.ToStringFuncName != "" {
			ret := structTags.ToStringFunc.Call([]reflect.Value{reflect.ValueOf(value)})
			valueStr = ret[0].String()
			isString = true
		} else if structTags.UniversalTagMapID > 0 && !exporterCfg.UniversalTagTranslateToNameDisabled {
			// skip '_id'
			if pos := strings.Index(keyStr, "_id"); pos != -1 {
				keyStr = (keyStr[:pos]) + keyStr[pos+3:] // 3 is  length of '_id'
			}
			if strings.HasSuffix(structTags.Name, "_1") {
				valueStr = uTags1.GetTagValue(structTags.UniversalTagMapID)
			} else {
				valueStr = uTags0.GetTagValue(structTags.UniversalTagMapID)
			}
			isString = true
		} else if structTags.EnumFile != "" && !exporterCfg.EnumTranslateToNameDisabled {
			if isString {
				valueStr = structTags.EnumStringMap[valueStr]
			} else if isFloat64 {
				valueStr = structTags.EnumIntMap[int(valueFloat64)]
			}
			isString = true
		}

		// not export empty tags
		if !exporterCfg.ExportEmptyTag &&
			(structTags.CategoryBit&config.TAG) != 0 &&
			((isString && valueStr == "") ||
				(isStringSlice && len(stringSlice) == 0)) {
			continue
		}

		// not export empty metrics
		if exporterCfg.ExportEmptyMetricsDisabled &&
			(structTags.CategoryBit&config.METRICS) != 0 &&
			((isString && valueStr == "") || (isFloat64 && valueFloat64 == 0) ||
				(isFloat64Slice && len(float64Slice) == 0)) {
			continue
		}

		sb.WriteString(`,"`)
		sb.WriteString(keyStr)
		sb.WriteString(`":`)
		if isString {
			sb.WriteString(`"`)
			sb.WriteString(valueStr)
			sb.WriteString(`"`)
		} else if isStringSlice {
			sb.WriteString("[")
			for i, v := range stringSlice {
				if i != 0 {
					sb.WriteString(`,`)
				}
				sb.WriteString(`"`)
				sb.WriteString(v)
				sb.WriteString(`"`)
			}
			sb.WriteString("]")
		} else if isFloat64Slice {
			sb.WriteString("[")
			for i, v := range float64Slice {
				if i != 0 {
					sb.WriteString(`,`)
				}
				sb.WriteString(strconv.FormatFloat(v, 'f', -1, 64))
			}
			sb.WriteString("]")
		} else if isFloat64 {
			sb.WriteString(valueStr)
		} else {
			log.Warningf("unreachable")
		}
	}

	if isMapItem {
		writeK8sLabels(sb, "k8s_label_names_0", "k8s_label_values_0", k8sLabels0)
		writeK8sLabels(sb, "k8s_label_names_1", "k8s_label_values_1", k8sLabels1)
	} else {
		writeK8sLabels(sb, "k8s_label_names", "k8s_label_values", k8sLabels0)
	}

	sb.WriteString(`,"time_str":"`)
	sb.WriteString(time.UnixMicro(item.TimestampUs()).String())
	sb.WriteString(`"`)

	sb.WriteString("}")
	return sb.String()
}
