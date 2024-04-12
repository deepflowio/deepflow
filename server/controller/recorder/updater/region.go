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

package updater

import (
	cloudmodel "github.com/deepflowio/deepflow/server/controller/cloud/model"
	ctrlrcommon "github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	"github.com/deepflowio/deepflow/server/controller/recorder/cache"
	"github.com/deepflowio/deepflow/server/controller/recorder/cache/diffbase"
	"github.com/deepflowio/deepflow/server/controller/recorder/db"
	"github.com/deepflowio/deepflow/server/controller/recorder/pubsub/message"
)

type Region struct {
	UpdaterBase[
		cloudmodel.Region,
		mysql.Region,
		*diffbase.Region,
		*message.RegionAdd,
		message.RegionAdd,
		*message.RegionUpdate,
		message.RegionUpdate,
		*message.RegionFieldsUpdate,
		message.RegionFieldsUpdate,
		*message.RegionDelete,
		message.RegionDelete]
}

func NewRegion(wholeCache *cache.Cache, cloudData []cloudmodel.Region) *Region {
	updater := &Region{
		newUpdaterBase[
			cloudmodel.Region,
			mysql.Region,
			*diffbase.Region,
			*message.RegionAdd,
			message.RegionAdd,
			*message.RegionUpdate,
			message.RegionUpdate,
			*message.RegionFieldsUpdate,
			message.RegionFieldsUpdate,
			*message.RegionDelete,
		](
			ctrlrcommon.RESOURCE_TYPE_REGION_EN,
			wholeCache,
			db.NewRegion().SetMetadata(wholeCache.GetMetadata()),
			wholeCache.DiffBaseDataSet.Regions,
			cloudData,
		),
	}
	updater.dataGenerator = updater
	return updater
}

func (r *Region) getDiffBaseByCloudItem(cloudItem *cloudmodel.Region) (diffBase *diffbase.Region, exists bool) {
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

func (r *Region) generateUpdateInfo(diffBase *diffbase.Region, cloudItem *cloudmodel.Region) (*message.RegionFieldsUpdate, map[string]interface{}, bool) {
	structInfo := new(message.RegionFieldsUpdate)
	mapInfo := make(map[string]interface{})
	if diffBase.Name != cloudItem.Name {
		mapInfo["name"] = cloudItem.Name
		structInfo.Name.Set(diffBase.Name, cloudItem.Name)
	}
	if diffBase.Label != cloudItem.Label {
		mapInfo["label"] = cloudItem.Label
		structInfo.Label.Set(diffBase.Label, cloudItem.Label)
	}

	return structInfo, mapInfo, len(mapInfo) > 0
}
