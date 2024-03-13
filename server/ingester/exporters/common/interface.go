package common

import (
	"fmt"
	"reflect"
	"strings"
	"unsafe"

	"github.com/deepflowio/deepflow/server/ingester/exporters/config"
	utag "github.com/deepflowio/deepflow/server/ingester/exporters/universal_tag"
)

type ExportItem interface {
	DataSource() uint8
	IsExportItem(cfg *config.ExporterCfg) bool // Tag Filter
	EncodeTo(p config.ExportProtocol, utags *utag.UniversalTagsManager, cfg *config.ExporterCfg) (interface{}, error)
	Release()
	AddReferenceCountN(c int)
}

// func GetValueByOffset(value interface{}, offset uintptr, dataType reflect.Kind) interface{} {
//	reflect.NewAt(reflect.TypeOf(dataType), unsafe.Pointer(value))
//	return nil
//}
func GetFieldValueByOffsetAndKind(data interface{}, offset uintptr, kind reflect.Kind) interface{} {
	var ptr uintptr
	switch v := data.(type) {
	case *int:
		ptr = uintptr(unsafe.Pointer(v))
	default:
		return nil // 如果类型不匹配，返回nil
	}

	fieldAddr := unsafe.Pointer(ptr + offset)

	switch kind {
	case reflect.Int:
		return *(*int)(fieldAddr)
	case reflect.String:
		return *(*string)(fieldAddr)
	default:
		return nil
	}
}

func EncodeToJson(item interface{}, dataSourceId int, exporterCfg *config.ExporterCfg, uTags0, uTags1 utag.UniversalTags) string {
	var sb strings.Builder
	sb.WriteString("{")

	var valueStr string
	var valueFloat64 float64
	first := true
	values := reflect.ValueOf(item)
	for _, structTags := range exporterCfg.ExportFieldStructTags[dataSourceId] {
		isString := false
		isFloat64 := false
		value := values.Field(structTags.Index).Interface()
		if structTags.UniversalTagID > 0 {
			if strings.HasSuffix(structTags.Name, "_1") {
				valueStr = uTags1.GetTagValue(structTags.UniversalTagID)
			} else {
				valueStr = uTags0.GetTagValue(structTags.UniversalTagID)
			}
			isString = true
		} else if v, ok := value.(string); ok {
			valueStr = v
			isString = true
		} else {
			valueFloat64, isFloat64 = ConvertToFloat64(value)
		}

		if structTags.Omitempty && ((isString && valueStr == "") ||
			(isFloat64 && valueFloat64 == 0)) {
			continue
		}

		if structTags.Translate {
			if isString {
				// valueStr = TranslateStr(structTags.Name, valueStr)
			} else if isFloat64 {
				// valueStr = TranslateIDToString(structTags.Name, valueFloat64)
				isString = true
			}
		}

		if !first {
			sb.WriteString(",")
			first = false
		}
		sb.WriteString(`"`)
		sb.WriteString(structTags.Name)
		sb.WriteString(`":`)
		if isString {
			sb.WriteString(`"`)
			sb.WriteString(valueStr)
			sb.WriteString(`"`)
		} else {
			sb.WriteString(fmt.Sprintf("%v", value))
		}
	}
	sb.WriteString("}")
	return sb.String()
}

func ConvertToFloat64(data interface{}) (float64, bool) {
	switch v := data.(type) {
	case uint:
		return float64(v), true
	case uint8:
		return float64(v), true
	case uint16:
		return float64(v), true
	case uint32:
		return float64(v), true
	case uint64:
		return float64(v), true
	case uintptr:
		return float64(v), true
	case int:
		return float64(v), true
	case int8:
		return float64(v), true
	case int16:
		return float64(v), true
	case int32:
		return float64(v), true
	case int64:
		return float64(v), true
	case float64:
		return v, true
	default:
		return 0, false
	}
}
