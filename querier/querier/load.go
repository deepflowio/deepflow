package querier

import (
	"metaflow/querier/common"
	"metaflow/querier/engine/clickhouse"
)

/*
	DB_DESCRIPTIONS = map[string]interface{}{
		"clickhouse": map[string]interface{}{
			"metric": map[string]interface{}{
				"flow_log": map[string]interface{}{
					"l4_flow_log": [][]string
				}
			},
			"tag": map[string]interface{}{
				"flow_log": map[string]interface{}{
					"l4_flow_log": [][]string
				},
				"enum": map[string]interface{}{
					"protocol": [][]string
				},
			}
		}
	}
*/

// 加载文件中的metrics及tags等内容
func Load() error {
	dir := "/etc/db_descriptions"
	dbDescriptions, err := common.LoadDbDescriptions(dir)
	if err != nil {
		return err
	}
	err = clickhouse.LoadDbDescriptions(dbDescriptions)
	if err != nil {
		return err
	}
	return nil
}
