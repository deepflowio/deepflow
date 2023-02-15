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
	"github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	"github.com/deepflowio/deepflow/server/controller/recorder/cache"
	"github.com/deepflowio/deepflow/server/controller/recorder/db"
)

type Host struct {
	UpdaterBase[cloudmodel.Host, mysql.Host, *cache.Host]
}

func NewHost(wholeCache *cache.Cache, cloudData []cloudmodel.Host) *Host {
	updater := &Host{
		UpdaterBase[cloudmodel.Host, mysql.Host, *cache.Host]{
			cache:        wholeCache,
			dbOperator:   db.NewHost(),
			diffBaseData: wholeCache.Hosts,
			cloudData:    cloudData,
		},
	}
	updater.dataGenerator = updater
	updater.cacheHandler = updater
	return updater
}

func (h *Host) getDiffBaseByCloudItem(cloudItem *cloudmodel.Host) (diffBase *cache.Host, exists bool) {
	diffBase, exists = h.diffBaseData[cloudItem.Lcuuid]
	return
}

func (h *Host) generateDBItemToAdd(cloudItem *cloudmodel.Host) (*mysql.Host, bool) {
	dbItem := &mysql.Host{
		Name:       cloudItem.Name,
		IP:         cloudItem.IP,
		Type:       cloudItem.Type,
		HType:      cloudItem.HType,
		VCPUNum:    cloudItem.VCPUNum,
		MemTotal:   cloudItem.MemTotal,
		ExtraInfo:  cloudItem.ExtraInfo,
		UserName:   "root",
		UserPasswd: "deepflow",
		State:      common.HOST_STATE_COMPLETE,
		AZ:         cloudItem.AZLcuuid,
		Region:     cloudItem.RegionLcuuid,
		Domain:     h.cache.DomainLcuuid,
	}
	dbItem.Lcuuid = cloudItem.Lcuuid
	return dbItem, true
}

func (h *Host) generateUpdateInfo(diffBase *cache.Host, cloudItem *cloudmodel.Host) (map[string]interface{}, bool) {
	updateInfo := make(map[string]interface{})
	if diffBase.Name != cloudItem.Name {
		updateInfo["name"] = cloudItem.Name
	}
	if diffBase.IP != cloudItem.IP {
		updateInfo["ip"] = cloudItem.IP
	}
	if diffBase.HType != cloudItem.HType {
		updateInfo["htype"] = cloudItem.HType
	}
	if diffBase.VCPUNum != cloudItem.VCPUNum {
		updateInfo["vcpu_num"] = cloudItem.VCPUNum
	}
	if diffBase.MemTotal != cloudItem.MemTotal {
		updateInfo["mem_total"] = cloudItem.MemTotal
	}
	if diffBase.ExtraInfo != cloudItem.ExtraInfo {
		updateInfo["extra_info"] = cloudItem.ExtraInfo
	}
	if diffBase.RegionLcuuid != cloudItem.RegionLcuuid {
		updateInfo["region"] = cloudItem.RegionLcuuid
	}
	if diffBase.AZLcuuid != cloudItem.AZLcuuid {
		updateInfo["az"] = cloudItem.AZLcuuid
	}

	if len(updateInfo) > 0 {
		return updateInfo, true
	}
	return nil, false
}

func (h *Host) addCache(dbItems []*mysql.Host) {
	h.cache.AddHosts(dbItems)
}

func (h *Host) updateCache(cloudItem *cloudmodel.Host, diffBase *cache.Host) {
	diffBase.Update(cloudItem)
	h.cache.UpdateHost(cloudItem)
}

func (h *Host) deleteCache(lcuuids []string) {
	h.cache.DeleteHosts(lcuuids)
}
