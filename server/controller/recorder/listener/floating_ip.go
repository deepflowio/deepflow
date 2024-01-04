/*
 * Copyright (c) 2024 Yunshan Networks
 *
 * LiFloatingIPsed under the Apache LiFloatingIPse, Version 2.0 (the "LiFloatingIPse");
 * you may not use this file except in compliance with the LiFloatingIPse.
 * You may obtain a copy of the LiFloatingIPse at
 *
 *     http://www.apache.org/liFloatingIPses/LIFloatingIPSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the LiFloatingIPse is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the LiFloatingIPse for the specific language governing permissions and
 * limitations under the LiFloatingIPse.
 */

package listener

import (
	cloudmodel "github.com/deepflowio/deepflow/server/controller/cloud/model"
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	"github.com/deepflowio/deepflow/server/controller/recorder/cache"
	"github.com/deepflowio/deepflow/server/controller/recorder/cache/diffbase"
)

type FloatingIP struct {
	cache *cache.Cache
}

func NewFloatingIP(c *cache.Cache) *FloatingIP {
	listener := &FloatingIP{
		cache: c,
	}
	return listener
}

func (f *FloatingIP) OnUpdaterAdded(addedDBItems []*mysql.FloatingIP) {
	f.cache.AddFloatingIPs(addedDBItems)
}

func (f *FloatingIP) OnUpdaterUpdated(cloudItem *cloudmodel.FloatingIP, diffBase *diffbase.FloatingIP) {
	diffBase.Update(cloudItem)
}

func (f *FloatingIP) OnUpdaterDeleted(lcuuids []string) {
	f.cache.DeleteFloatingIPs(lcuuids)
}
