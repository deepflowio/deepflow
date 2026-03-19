package tag

import (
	"testing"

	"github.com/deepflowio/deepflow/server/querier/common"
	"github.com/deepflowio/deepflow/server/querier/config"
)

func TestLoadTagDescriptionsForNewAiAgentTables(t *testing.T) {
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
