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
	"github.com/deepflowio/deepflow/server/controller/recorder/cache"
	"github.com/deepflowio/deepflow/server/controller/recorder/cache/tool"
)

type IP struct {
	cache        *cache.Cache
	cloudData    []cloudmodel.IP
	wanIPUpdater *WANIP
	lanIPUpdater *LANIP
}

func NewIP(cache *cache.Cache, cloudData []cloudmodel.IP, domainToolDataSet *tool.DataSet) *IP {
	return &IP{
		cache:        cache,
		cloudData:    cloudData,
		wanIPUpdater: NewWANIP(cache, domainToolDataSet),
		lanIPUpdater: NewLANIP(cache, domainToolDataSet),
	}
}

func (i *IP) GetWANIP() *WANIP {
	return i.wanIPUpdater
}

func (i *IP) GetLANIP() *LANIP {
	return i.lanIPUpdater
}

func (i *IP) HandleAddAndUpdate() {
	// Because the cloud IP data is mixed with wan and lan, and the split is based on vinterface data which has been handled addition and update,
	// so cloudData is not setted when wanIPUpdater or lanIPUpdater was initialized, but is setted now.
	wanCloudData, lanCloudData := i.splitToWANAndLAN(i.cloudData)
	i.wanIPUpdater.SetCloudData(wanCloudData)
	i.lanIPUpdater.SetCloudData(lanCloudData)
	i.wanIPUpdater.HandleAddAndUpdate()
	i.lanIPUpdater.HandleAddAndUpdate()
}

func (i *IP) HandleDelete() {
	i.wanIPUpdater.HandleDelete()
	i.lanIPUpdater.HandleDelete()
}

func (i *IP) GetChanged() bool {
	return i.wanIPUpdater.Changed || i.lanIPUpdater.Changed
}

func (i *IP) GetResourceType() string {
	return ctrlrcommon.RESOURCE_TYPE_IP_EN
}

func (i *IP) GetMySQLModelString() []string {
	return []string{i.wanIPUpdater.GetMySQLModelString()[0], i.lanIPUpdater.GetMySQLModelString()[0]}
}

func (i *IP) splitToWANAndLAN(cloudData []cloudmodel.IP) ([]cloudmodel.IP, []cloudmodel.IP) {
	wanCloudData := []cloudmodel.IP{}
	lanCloudData := []cloudmodel.IP{}
	for _, cloudItem := range cloudData {
		vt, exists := i.cache.ToolDataSet.GetVInterfaceTypeByLcuuid(cloudItem.VInterfaceLcuuid)
		if !exists {
			log.Error(resourceAForResourceBNotFound(
				ctrlrcommon.RESOURCE_TYPE_VINTERFACE_EN, cloudItem.VInterfaceLcuuid,
				"cloud ip", cloudItem.Lcuuid,
			))
			continue
		}
		if vt == ctrlrcommon.VIF_TYPE_WAN {
			wanCloudData = append(wanCloudData, cloudItem)
		} else {
			lanCloudData = append(lanCloudData, cloudItem)
		}
	}
	return wanCloudData, lanCloudData
}
