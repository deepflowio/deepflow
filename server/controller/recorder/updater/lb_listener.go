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
)

type LBListener struct {
	UpdaterBase[cloudmodel.LBListener, mysql.LBListener, *diffbase.LBListener]
}

func NewLBListener(wholeCache *cache.Cache, cloudData []cloudmodel.LBListener) *LBListener {
	updater := &LBListener{
		UpdaterBase[cloudmodel.LBListener, mysql.LBListener, *diffbase.LBListener]{
			resourceType: ctrlrcommon.RESOURCE_TYPE_LB_LISTENER_EN,
			cache:        wholeCache,
			dbOperator:   db.NewLBListener(),
			diffBaseData: wholeCache.DiffBaseDataSet.LBListeners,
			cloudData:    cloudData,
		},
	}
	updater.dataGenerator = updater
	return updater
}

func (l *LBListener) getDiffBaseByCloudItem(cloudItem *cloudmodel.LBListener) (diffBase *diffbase.LBListener, exists bool) {
	diffBase, exists = l.diffBaseData[cloudItem.Lcuuid]
	return
}

func (l *LBListener) generateDBItemToAdd(cloudItem *cloudmodel.LBListener) (*mysql.LBListener, bool) {
	lbID, exists := l.cache.ToolDataSet.GetLBIDByLcuuid(cloudItem.LBLcuuid)
	if !exists {
		log.Errorf(resourceAForResourceBNotFound(
			ctrlrcommon.RESOURCE_TYPE_LB_EN, cloudItem.LBLcuuid,
			ctrlrcommon.RESOURCE_TYPE_LB_LISTENER_EN, cloudItem.Lcuuid,
		))
		return nil, false
	}

	dbItem := &mysql.LBListener{
		Name:     cloudItem.Name,
		LBID:     lbID,
		IPs:      cloudItem.IPs,
		SNATIPs:  cloudItem.SNATIPs,
		Label:    cloudItem.Label,
		Port:     cloudItem.Port,
		Protocol: cloudItem.Protocol,
		Domain:   l.cache.DomainLcuuid,
	}
	dbItem.Lcuuid = cloudItem.Lcuuid
	return dbItem, true
}

func (l *LBListener) generateUpdateInfo(diffBase *diffbase.LBListener, cloudItem *cloudmodel.LBListener) (map[string]interface{}, bool) {
	updateInfo := make(map[string]interface{})
	if diffBase.Name != cloudItem.Name {
		updateInfo["name"] = cloudItem.Name
	}
	if diffBase.IPs != cloudItem.IPs {
		updateInfo["ips"] = cloudItem.IPs
	}
	if diffBase.SNATIPs != cloudItem.SNATIPs {
		updateInfo["snat_ips"] = cloudItem.SNATIPs
	}
	if diffBase.Port != cloudItem.Port {
		updateInfo["port"] = cloudItem.Port
	}
	if diffBase.Protocol != cloudItem.Protocol {
		updateInfo["protocol"] = cloudItem.Protocol
	}

	if len(updateInfo) > 0 {
		return updateInfo, true
	}
	return nil, false
}
