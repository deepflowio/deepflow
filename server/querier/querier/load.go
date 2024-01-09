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

package querier

import (
	"github.com/deepflowio/deepflow/server/querier/common"
	"github.com/deepflowio/deepflow/server/querier/engine/clickhouse"
	"github.com/deepflowio/deepflow/server/querier/engine/clickhouse/metrics"
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
	metrics.DB_DESCRIPTIONS = dbDescriptions
	return nil
}
