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

type Process struct {
	UpdaterBase[cloudmodel.Process, mysql.Process, *cache.Process]
}

func NewProcess(wholeCache *cache.Cache, cloudData []cloudmodel.Process) *Process {
	updater := &Process{
		UpdaterBase[cloudmodel.Process, mysql.Process, *cache.Process]{
			cache:        wholeCache,
			dbOperator:   db.NewProcess(),
			diffBaseData: wholeCache.Process,
			cloudData:    cloudData,
		},
	}
	updater.dataGenerator = updater
	updater.cacheHandler = updater
	return updater
}

func (p *Process) getDiffBaseByCloudItem(cloudItem *cloudmodel.Process) (diffBase *cache.Process, exits bool) {
	diffBase, exits = p.diffBaseData[cloudItem.Lcuuid]
	return
}

func (p *Process) generateDBItemToAdd(cloudItem *cloudmodel.Process) (*mysql.Process, bool) {
	dbItem := &mysql.Process{
		Name:        cloudItem.Name,
		VTapID:      cloudItem.VTapID,
		PID:         cloudItem.PID,
		ProcessName: cloudItem.ProcessName,
		CommandLine: cloudItem.CommandLine,
		UserName:    cloudItem.UserName,
		OSAPPTags:   cloudItem.OSAPPTags,
		Domain:      p.cache.DomainLcuuid,
		SubDomain:   cloudItem.SubDomainLcuuid,
	}
	dbItem.Lcuuid = cloudItem.Lcuuid

	return dbItem, true
}

func (p *Process) generateUpdateInfo(diffBase *cache.Process, cloudItem *cloudmodel.Process) (map[string]interface{}, bool) {
	updateInfo := make(map[string]interface{})
	if diffBase.Name != cloudItem.Name {
		updateInfo["name"] = cloudItem.Name
	}
	if diffBase.OSAPPTags != cloudItem.OSAPPTags {
		updateInfo["os_app_tags"] = cloudItem.OSAPPTags
	}

	if len(updateInfo) > 0 {
		return updateInfo, true
	}
	return nil, false
}

func (p *Process) addCache(dbItems []*mysql.Process) {
	p.cache.AddProcesses(dbItems)
}

func (p *Process) updateCache(cloudItem *cloudmodel.Process, diffBase *cache.Process) {
	diffBase.Update(cloudItem)
}

func (p *Process) deleteCache(lcuuids []string) {
	p.cache.DeleteProcesses(lcuuids)
}
