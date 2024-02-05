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

type AZ struct {
	UpdaterBase[
		cloudmodel.AZ,
		mysql.AZ,
		*diffbase.AZ, *message.AZAdd, message.AZAdd, *message.AZUpdate, message.AZUpdate, *message.AZFieldsUpdate, message.AZFieldsUpdate, *message.AZDelete, message.AZDelete]
}

func NewAZ(wholeCache *cache.Cache, cloudData []cloudmodel.AZ) *AZ {
	updater := &AZ{
		newUpdaterBase[
			cloudmodel.AZ,
			mysql.AZ,
			*diffbase.AZ, *message.AZAdd, message.AZAdd, *message.AZUpdate, message.AZUpdate, *message.AZFieldsUpdate, message.AZFieldsUpdate, *message.AZDelete,
		](
			ctrlrcommon.RESOURCE_TYPE_AZ_EN,
			wholeCache,
			db.NewAZ(),
			wholeCache.DiffBaseDataSet.AZs,
			cloudData,
		),
	}
	updater.dataGenerator = updater
	return updater
}

func (z *AZ) getDiffBaseByCloudItem(cloudItem *cloudmodel.AZ) (diffBase *diffbase.AZ, exists bool) {
	diffBase, exists = z.diffBaseData[cloudItem.Lcuuid]
	return
}

func (z *AZ) generateDBItemToAdd(cloudItem *cloudmodel.AZ) (*mysql.AZ, bool) {
	dbItem := &mysql.AZ{
		Name:   cloudItem.Name,
		Label:  cloudItem.Label,
		Region: cloudItem.RegionLcuuid,
		Domain: z.cache.DomainLcuuid,
	}
	dbItem.Lcuuid = cloudItem.Lcuuid
	return dbItem, true
}

func (z *AZ) generateUpdateInfo(diffBase *diffbase.AZ, cloudItem *cloudmodel.AZ) (*message.AZFieldsUpdate, map[string]interface{}, bool) {
	structInfo := new(message.AZFieldsUpdate)
	mapInfo := make(map[string]interface{})
	if diffBase.Name != cloudItem.Name {
		mapInfo["name"] = cloudItem.Name
		structInfo.Name.Set(diffBase.Name, cloudItem.Name)
	}
	if diffBase.Label != cloudItem.Label {
		mapInfo["label"] = cloudItem.Label
		structInfo.Label.Set(diffBase.Label, cloudItem.Label)
	}
	if diffBase.RegionLcuuid != cloudItem.RegionLcuuid {
		mapInfo["region"] = cloudItem.RegionLcuuid
		structInfo.RegionLcuuid.Set(diffBase.RegionLcuuid, cloudItem.RegionLcuuid)
	}

	return structInfo, mapInfo, len(mapInfo) > 0
}
