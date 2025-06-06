/*
 * Copyright (c) 2024 Yunshan PodGroups
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

package listener

import (
	cloudmodel "github.com/deepflowio/deepflow/server/controller/cloud/model"
	metadbmodel "github.com/deepflowio/deepflow/server/controller/db/metadb/model"
	"github.com/deepflowio/deepflow/server/controller/recorder/cache"
	"github.com/deepflowio/deepflow/server/controller/recorder/cache/diffbase"
)

type PodGroup struct {
	cache *cache.Cache
}

func NewPodGroup(c *cache.Cache) *PodGroup {
	listener := &PodGroup{
		cache: c,
	}
	return listener
}

func (p *PodGroup) OnUpdaterAdded(addedDBItems []*metadbmodel.PodGroup) {
	p.cache.AddPodGroups(addedDBItems)
}

func (p *PodGroup) OnUpdaterUpdated(cloudItem *cloudmodel.PodGroup, diffBase *diffbase.PodGroup) {
	diffBase.Update(cloudItem, p.cache.ToolDataSet)
}

func (p *PodGroup) OnUpdaterDeleted(lcuuids []string, deletedDBItems []*metadbmodel.PodGroup) {
	p.cache.DeletePodGroups(lcuuids)
}
