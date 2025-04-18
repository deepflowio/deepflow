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

package listener

import (
	cloudmodel "github.com/deepflowio/deepflow/server/controller/cloud/model"
	metadbmodel "github.com/deepflowio/deepflow/server/controller/db/metadb/model"
	"github.com/deepflowio/deepflow/server/controller/recorder/cache"
	"github.com/deepflowio/deepflow/server/controller/recorder/cache/diffbase"
)

// SubDomain is used to listen to the changes of the SubDomain resource itself
type SubDomain struct {
	cache *cache.Cache
}

func NewSubDomain(c *cache.Cache) *SubDomain {
	return &SubDomain{
		cache: c,
	}
}

func (sd *SubDomain) OnUpdaterAdded(addedDBItems []*metadbmodel.SubDomain) {
	sd.cache.AddSubDomains(addedDBItems)
}

func (sd *SubDomain) OnUpdaterUpdated(cloudItem *cloudmodel.SubDomain, diffBase *diffbase.SubDomain) {
	diffBase.Update(cloudItem)
}

func (sd *SubDomain) OnUpdaterDeleted(lcuuids []string, deletedDBItems []*metadbmodel.SubDomain) {
	sd.cache.DeleteSubDomains(lcuuids)
}
