/**
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

package diffbase

import (
	cloudmodel "github.com/deepflowio/deepflow/server/controller/cloud/model"
	ctrlrcommon "github.com/deepflowio/deepflow/server/controller/common"
	metadbmodel "github.com/deepflowio/deepflow/server/controller/db/metadb/model"
)

func (b *DataSet) AddConfigMap(dbItem *metadbmodel.ConfigMap, seq int) {
	b.ConfigMaps[dbItem.Lcuuid] = &ConfigMap{
		DiffBase: DiffBase{
			Sequence: seq,
			Lcuuid:   dbItem.Lcuuid,
		},
		Name:     dbItem.Name,
		Data:     dbItem.Data,
		DataHash: dbItem.DataHash,
	}
	b.GetLogFunc()(addDiffBase(ctrlrcommon.RESOURCE_TYPE_CONFIG_MAP_EN, b.ConfigMaps[dbItem.Lcuuid]), b.metadata.LogPrefixes)
}

func (b *DataSet) DeleteConfigMap(lcuuid string) {
	delete(b.ConfigMaps, lcuuid)
	log.Info(deleteDiffBase(ctrlrcommon.RESOURCE_TYPE_CONFIG_MAP_EN, lcuuid), b.metadata.LogPrefixes)
}

type ConfigMap struct {
	DiffBase
	Name     string `json:"name"`
	Data     string `json:"data"`
	DataHash string `json:"data_hash"`
}

func (v *ConfigMap) Update(cloudItem *cloudmodel.ConfigMap) {
	v.Name = cloudItem.Name
	v.Data = cloudItem.Data
	v.DataHash = cloudItem.DataHash
	log.Info(updateDiffBase(ctrlrcommon.RESOURCE_TYPE_CONFIG_MAP_EN, v))
}
