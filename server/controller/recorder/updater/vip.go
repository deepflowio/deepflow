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

type VIP struct {
	UpdaterBase[
		cloudmodel.VIP,
		mysql.VIP,
		*diffbase.VIP, *message.VIPAdd, message.VIPAdd, *message.VIPUpdate, message.VIPUpdate, *message.VIPFieldsUpdate, message.VIPFieldsUpdate, *message.VIPDelete, message.VIPDelete]
}

func NewVIP(wholeCache *cache.Cache, cloudData []cloudmodel.VIP) *VIP {
	updater := &VIP{
		newUpdaterBase[
			cloudmodel.VIP,
			mysql.VIP,
			*diffbase.VIP, *message.VIPAdd, message.VIPAdd, *message.VIPUpdate, message.VIPUpdate, *message.VIPFieldsUpdate, message.VIPFieldsUpdate, *message.VIPDelete,
		](
			ctrlrcommon.RESOURCE_TYPE_VIP_EN,
			wholeCache,
			db.NewVIP(),
			wholeCache.DiffBaseDataSet.VIP,
			cloudData,
		),
	}
	updater.dataGenerator = updater
	return updater
}

func (p *VIP) getDiffBaseByCloudItem(cloudItem *cloudmodel.VIP) (diffBase *diffbase.VIP, exits bool) {
	diffBase, exits = p.diffBaseData[cloudItem.Lcuuid]
	return
}

func (p *VIP) generateDBItemToAdd(cloudItem *cloudmodel.VIP) (*mysql.VIP, bool) {
	dbItem := &mysql.VIP{
		IP:     cloudItem.IP,
		VTapID: cloudItem.VTapID,
		Domain: p.cache.DomainLcuuid,
	}
	dbItem.Lcuuid = cloudItem.Lcuuid

	return dbItem, true
}

func (p *VIP) generateUpdateInfo(diffBase *diffbase.VIP, cloudItem *cloudmodel.VIP) (*message.VIPFieldsUpdate, map[string]interface{}, bool) {
	structInfo := new(message.VIPFieldsUpdate)
	mapInfo := make(map[string]interface{})
	if diffBase.IP != cloudItem.IP {
		mapInfo["ip"] = cloudItem.IP
		structInfo.IP.Set(diffBase.IP, cloudItem.IP)
	}
	if diffBase.VTapID != cloudItem.VTapID {
		mapInfo["vtap_id"] = cloudItem.VTapID
		structInfo.VTapID.Set(diffBase.VTapID, cloudItem.VTapID)
	}

	return structInfo, mapInfo, len(mapInfo) > 0
}
