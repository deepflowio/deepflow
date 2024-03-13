package log_data

import (
	"fmt"
	"reflect"

	"github.com/deepflowio/deepflow/server/ingester/exporters/common"
	. "github.com/deepflowio/deepflow/server/ingester/exporters/config"
	config "github.com/deepflowio/deepflow/server/ingester/exporters/config"
	utag "github.com/deepflowio/deepflow/server/ingester/exporters/universal_tag"
)

func init() {

}

func (h *L7FlowLog) EncodeTo(protocol config.ExportProtocol, utags *utag.UniversalTagsManager, cfg *config.ExporterCfg) (interface{}, error) {
	switch protocol {
	case config.PROTOCOL_OTLP:
		return h.EncodeToOtlp(utags, 65535), nil
	case config.PROTOCOL_KAFKA:
		tags0, tags1 := h.QueryUniversalTags(utags)
		return common.EncodeToJson(h, int(config.L7_FLOW_LOG), cfg, tags0, tags1), nil
	case config.PROTOCOL_PROMETHEUS:
		return nil, fmt.Errorf("unsupport export to %s", config.PROTOCOL_PROMETHEUS)
	}
	return nil, nil
}

var allExportFields = []StructTags{}
var allTagFilter = []StructTags{}

func (l7 *L7FlowLog) GetExportFileds(cfg *config.ExporterCfg) {
	// 获取结构体类型
	t := reflect.TypeOf(*l7)
	size := t.NumField()
	all := make([]StructTags, size)
	// 遍历结构体的字段
	for i := 0; i < size; i++ {
		field := t.Field(i)
		category := field.Tag.Get("category")
		subCategory := field.Tag.Get("sub")

		categoryID := config.StringsToCategoryBits([]string{category})
		subCategoryID := config.StringsToCategoryBits([]string{subCategory})
		all[i] = StructTags{
			Name:        field.Tag.Get("json"),
			Category:    categoryID,
			SubCategory: subCategoryID,
			Offset:      field.Offset,
			DataType:    field.Type.Kind(),
		}
	}

	for _, v := range all {
		if cfg.ExportFieldCategoryBits&(v.Category|v.SubCategory) != 0 {
			allExportFields = append(allExportFields, v)
			continue
		}
		// if v.Name in cfg.ExportFieldStrs
		// allExportFields = append(allExportFields, v)
	}
	for _, v := range all {
		if len(cfg.TagFilters) == 0 {
			break
		}
		// if v.Name in cfg.TagFilters
		allTagFilter = append(allTagFilter, v)
	}
}

func (l7 *L7FlowLog) DataSource() int {
	return 1
}
