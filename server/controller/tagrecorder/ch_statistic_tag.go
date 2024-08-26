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

package tagrecorder

import (
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	mysqlmodel "github.com/deepflowio/deepflow/server/controller/db/mysql/model"
)

type ChStatisticTag struct {
	UpdaterComponent[mysqlmodel.ChStatisticTag, StatisticTagKey]
}

func NewChStatisticTag() *ChStatisticTag {
	updater := &ChStatisticTag{
		newUpdaterComponent[mysqlmodel.ChStatisticTag, StatisticTagKey](
			RESOURCE_TYPE_STATISTIC_TAG,
		),
	}
	updater.updaterDG = updater
	return updater
}

func (r *ChStatisticTag) generateNewData(db *mysql.DB) (map[StatisticTagKey]mysqlmodel.ChStatisticTag, bool) {

	return nil, false
}

func (r *ChStatisticTag) generateKey(dbItem mysqlmodel.ChStatisticTag) StatisticTagKey {
	return StatisticTagKey{Db: dbItem.Db, Table: dbItem.Table, Type: dbItem.Type, Name: dbItem.Name}
}

func (r *ChStatisticTag) generateUpdateInfo(oldItem, newItem mysqlmodel.ChStatisticTag) (map[string]interface{}, bool) {

	return nil, false
}
