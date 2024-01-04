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

package filereader

import (
	"github.com/deepflowio/deepflow/server/controller/cloud/model"
	"github.com/deepflowio/deepflow/server/controller/common"
)

func (f *FileReader) getRegions(fileInfo *FileInfo) ([]model.Region, error) {
	var retRegions []model.Region

	f.regionNameToLcuuid = make(map[string]string)

	if f.RegionUuid == "" {
		for _, region := range fileInfo.Regions {
			lcuuid := common.GenerateUUID(f.UuidGenerate + "_region_" + region.Name)
			f.regionNameToLcuuid[region.Name] = lcuuid
			retRegions = append(retRegions, model.Region{
				Lcuuid: common.GenerateUUID(f.UuidGenerate + "_region_" + region.Name),
				Name:   region.Name,
			})
		}
	}
	return retRegions, nil
}
