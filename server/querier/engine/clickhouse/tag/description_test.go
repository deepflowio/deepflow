package tag

import (
	"testing"

	"github.com/deepflowio/deepflow/server/querier/common"
	"github.com/deepflowio/deepflow/server/querier/config"
)

func resetTagDescriptionGlobals() {
	TAG_DESCRIPTION_KEYS = nil
	TAG_DESCRIPTIONS = map[TagDescriptionKey]*TagDescription{}
	TAG_ENUMS = map[string][]*TagEnum{}
	TAG_INT_ENUMS = map[string][]*TagEnum{}
	TAG_STRING_ENUMS = map[string][]*TagEnum{}
	AUTO_CUSTOM_TAG_NAMES = nil
	AUTO_CUSTOM_TAG_MAP = map[string][]string{}
	AUTO_CUSTOM_TAG_CHECK_MAP = map[string][]string{}
}

func loadTagDescriptionsForTest(t *testing.T) {
	t.Helper()
	resetTagDescriptionGlobals()
	config.Cfg = &config.QuerierConfig{Language: "en"}
	dir := "../../../db_descriptions"
	dbDescriptions, err := common.LoadDbDescriptions(dir)
	if err != nil {
		t.Fatalf("load db descriptions failed: %v", err)
	}
	dbData, ok := dbDescriptions["clickhouse"]
	if !ok {
		t.Fatalf("clickhouse not in dbDescription")
	}
	tagData, ok := dbData.(map[string]interface{})["tag"]
	if !ok {
		t.Fatalf("clickhouse not has tag descriptions")
	}
	if err := LoadTagDescriptions(tagData.(map[string]interface{})); err != nil {
		t.Fatalf("LoadTagDescriptions failed: %v", err)
	}
}

func TestLoadTagDescriptionsForNewAiAgentTables(t *testing.T) {
	loadTagDescriptionsForTest(t)
}

func TestGProcessBizTypeTagDescriptions(t *testing.T) {
	loadTagDescriptionsForTest(t)

	tests := []struct {
		db       string
		table    string
		tagName  string
		tagType  string
		enumFile string
	}{
		{"flow_metrics", "application", "gprocess.biz_type", "int_enum", "biz_type"},
		{"flow_metrics", "application_map", "gprocess.biz_type", "int_enum", "biz_type"},
		{"flow_log", "l7_flow_log", "gprocess.biz_type", "int_enum", "biz_type"},
		{"event", "file_event", "gprocess.biz_type", "int_enum", "biz_type"},
		{"event", "file_agg_event", "gprocess.biz_type", "int_enum", "biz_type"},
		{"event", "file_mgmt_event", "gprocess.biz_type", "int_enum", "biz_type"},
		{"event", "proc_perm_event", "gprocess.biz_type", "int_enum", "biz_type"},
		{"event", "proc_ops_event", "gprocess.biz_type", "int_enum", "biz_type"},
	}

	for _, tc := range tests {
		tagDescription, ok := TAG_DESCRIPTIONS[TagDescriptionKey{
			DB: tc.db, Table: tc.table, TagName: tc.tagName,
		}]
		if !ok {
			t.Fatalf("missing tag description for %s.%s %s", tc.db, tc.table, tc.tagName)
		}
		if tagDescription.Type != tc.tagType {
			t.Fatalf("unexpected type for %s.%s %s: got %s want %s", tc.db, tc.table, tc.tagName, tagDescription.Type, tc.tagType)
		}
		if tagDescription.EnumFile != tc.enumFile {
			t.Fatalf("unexpected enum file for %s.%s %s: got %s want %s", tc.db, tc.table, tc.tagName, tagDescription.EnumFile, tc.enumFile)
		}
	}
}

func TestBizTypeTagDescriptionsUseRawInt(t *testing.T) {
	loadTagDescriptionsForTest(t)

	tests := []struct {
		db      string
		table   string
		tagName string
	}{
		{"flow_metrics", "application", "biz_type"},
		{"flow_metrics", "application_map", "biz_type"},
		{"flow_log", "l7_flow_log", "biz_type"},
	}

	for _, tc := range tests {
		tagDescription, ok := TAG_DESCRIPTIONS[TagDescriptionKey{
			DB: tc.db, Table: tc.table, TagName: tc.tagName,
		}]
		if !ok {
			t.Fatalf("missing tag description for %s.%s %s", tc.db, tc.table, tc.tagName)
		}
		if tagDescription.Type != "int" {
			t.Fatalf("unexpected type for %s.%s %s: got %s want int", tc.db, tc.table, tc.tagName, tagDescription.Type)
		}
		if tagDescription.EnumFile != "" {
			t.Fatalf("unexpected enum file for %s.%s %s: got %s want empty", tc.db, tc.table, tc.tagName, tagDescription.EnumFile)
		}
	}
}
