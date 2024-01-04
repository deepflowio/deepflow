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

package clickhouse

import (
	"sync"

	"github.com/deepflowio/deepflow/server/libs/lru"
	"github.com/deepflowio/deepflow/server/querier/common"
	"github.com/deepflowio/deepflow/server/querier/config"
)

var (
	prometheusSubqueryCacheOnce sync.Once
	prometheusSubqueryCacheIns  *PrometheusSubqueryCache
)

type PrometheusSubqueryCache struct {
	PrometheusSubqueryCache *lru.Cache[string, common.EntryValue]
}

func GetPrometheusSubqueryCache() *PrometheusSubqueryCache {
	prometheusSubqueryCacheOnce.Do(func() {
		prometheusSubqueryCacheIns = &PrometheusSubqueryCache{
			PrometheusSubqueryCache: lru.NewCache[string, common.EntryValue](config.Cfg.MaxPrometheusIdSubqueryLruEntry),
		}
	})
	return prometheusSubqueryCacheIns
}
