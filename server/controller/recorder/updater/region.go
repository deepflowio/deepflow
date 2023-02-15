/*
 * Copyright (c) 2022 Yunshan Networks
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

package updater

import (
	cloudmodel "github.com/deepflowio/deepflow/server/controller/cloud/model"
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	"github.com/deepflowio/deepflow/server/controller/recorder/cache"
	"github.com/deepflowio/deepflow/server/controller/recorder/db"
)

type Region struct {
	UpdaterBase[cloudmodel.Region, mysql.Region, *cache.Region]
}

func NewRegion(wholeCache *cache.Cache, cloudData []cloudmodel.Region) *Region {
	updater := &Region{
		UpdaterBase[cloudmodel.Region, mysql.Region, *cache.Region]{
			cache:        wholeCache,
			dbOperator:   db.NewRegion(),
			diffBaseData: wholeCache.Regions,
			cloudData:    cloudData,
		},
	}
	updater.dataGenerator = updater
	updater.cacheHandler = updater
	return updater
}

func (r *Region) getDiffBaseByCloudItem(cloudItem *cloudmodel.Region) (diffBase *cache.Region, exists bool) {
	diffBase, exists = r.diffBaseData[cloudItem.Lcuuid]
	return
}

func (r *Region) generateDBItemToAdd(cloudItem *cloudmodel.Region) (*mysql.Region, bool) {
	dbItem := &mysql.Region{
		Name:  cloudItem.Name,
		Label: cloudItem.Label,
	}
	dbItem.Lcuuid = cloudItem.Lcuuid
	return dbItem, true
}

func (r *Region) generateUpdateInfo(diffBase *cache.Region, cloudItem *cloudmodel.Region) (map[string]interface{}, bool) {
	updateInfo := make(map[string]interface{})
	if diffBase.Name != cloudItem.Name {
		updateInfo["name"] = cloudItem.Name
	}
	if diffBase.Label != cloudItem.Label {
		updateInfo["label"] = cloudItem.Label
	}
	if len(updateInfo) > 0 {
		return updateInfo, true
	}
	return nil, false
}

func (r *Region) addCache(dbItems []*mysql.Region) {
	r.cache.AddRegions(dbItems)
}

func (r *Region) updateCache(cloudItem *cloudmodel.Region, diffBase *cache.Region) {
	diffBase.Update(cloudItem)
}

func (r *Region) deleteCache(lcuuids []string) {
	r.cache.DeleteRegions(lcuuids)
}
