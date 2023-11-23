/*
 * Copyright (c) 2023 Yunshan PodClusters
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
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	"github.com/deepflowio/deepflow/server/controller/recorder/cache"
	"github.com/deepflowio/deepflow/server/controller/recorder/cache/diffbase"
)

type PodCluster struct {
	cache *cache.Cache
}

func NewPodCluster(c *cache.Cache) *PodCluster {
	listener := &PodCluster{
		cache: c,
	}
	return listener
}

func (c *PodCluster) OnUpdaterAdded(addedDBItems []*mysql.PodCluster) {
	c.cache.AddPodClusters(addedDBItems)
}

func (c *PodCluster) OnUpdaterUpdated(cloudItem *cloudmodel.PodCluster, diffBase *diffbase.PodCluster) {
	diffBase.Update(cloudItem)
}

func (c *PodCluster) OnUpdaterDeleted(lcuuids []string) {
	c.cache.DeletePodClusters(lcuuids)
}
