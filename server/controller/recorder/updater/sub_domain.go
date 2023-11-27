/*
 * Copyright (c) 2023 Yunshan Networks
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

type SubDomain struct {
	UpdaterBase[
		cloudmodel.SubDomain,
		mysql.SubDomain,
		*diffbase.SubDomain,
		*message.SubDomainAdd,
		message.SubDomainAdd,
		*message.SubDomainUpdate,
		message.SubDomainUpdate,
		*message.SubDomainFieldsUpdate,
		message.SubDomainFieldsUpdate,
		*message.SubDomainDelete,
		message.SubDomainDelete]
}

func NewSubDomain(wholeCache *cache.Cache, cloudData []cloudmodel.SubDomain) *SubDomain {
	updater := &SubDomain{
		newUpdaterBase[
			cloudmodel.SubDomain,
			mysql.SubDomain,
			*diffbase.SubDomain,
			*message.SubDomainAdd,
			message.SubDomainAdd,
			*message.SubDomainUpdate,
			message.SubDomainUpdate,
			*message.SubDomainFieldsUpdate,
			message.SubDomainFieldsUpdate,
			*message.SubDomainDelete,
		](
			ctrlrcommon.RESOURCE_TYPE_SUB_DOMAIN_EN,
			wholeCache,
			db.NewSubDomain(),
			wholeCache.DiffBaseDataSet.SubDomains,
			cloudData,
		),
	}
	updater.dataGenerator = updater
	return updater
}

func (d *SubDomain) getDiffBaseByCloudItem(cloudItem *cloudmodel.SubDomain) (diffBase *diffbase.SubDomain, exists bool) {
	diffBase, exists = d.diffBaseData[cloudItem.Lcuuid]
	return
}

func (d *SubDomain) generateDBItemToAdd(cloudItem *cloudmodel.SubDomain) (*mysql.SubDomain, bool) {
	dbItem := &mysql.SubDomain{
		Name:        cloudItem.Name,
		DisplayName: cloudItem.DisplayName,
		ClusterID:   cloudItem.ClusterID,
		Config:      cloudItem.Config,
		Domain:      d.cache.DomainLcuuid,
	}
	dbItem.Lcuuid = cloudItem.Lcuuid
	return dbItem, true
}

func (d *SubDomain) generateUpdateInfo(diffBase *diffbase.SubDomain, cloudItem *cloudmodel.SubDomain) (*message.SubDomainFieldsUpdate, map[string]interface{}, bool) {
	structInfo := new(message.SubDomainFieldsUpdate)
	mapInfo := make(map[string]interface{})
	if diffBase.Name != cloudItem.Name {
		mapInfo["name"] = cloudItem.Name
		structInfo.Name.Set(diffBase.Name, cloudItem.Name)
	}
	return structInfo, mapInfo, len(mapInfo) > 0
}
