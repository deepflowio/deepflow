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
	"errors"
	"fmt"

	"github.com/deepflowio/deepflow/server/controller/cloud/model"
	"github.com/deepflowio/deepflow/server/controller/common"
)

func (f *FileReader) getHosts(fileInfo *FileInfo) ([]model.Host, error) {
	var retHosts []model.Host

	for _, host := range fileInfo.Hosts {
		regionLcuuid, err := f.getRegionLcuuid(host.Region)
		if err != nil {
			return nil, err
		}
		azLcuuid, ok := f.azNameToLcuuid[host.AZ]
		if !ok {
			err := errors.New(fmt.Sprintf("az (%s) not in file", host.AZ))
			log.Error(err)
			return nil, err
		}

		lcuuid := common.GenerateUUIDByOrgID(f.orgID, f.UuidGenerate+"_host_"+host.IP)
		retHosts = append(retHosts, model.Host{
			Lcuuid:       lcuuid,
			Name:         host.IP,
			IP:           host.IP,
			Type:         0,
			HType:        0,
			VCPUNum:      host.VCPUs,
			MemTotal:     host.MemoryMb,
			AZLcuuid:     azLcuuid,
			RegionLcuuid: regionLcuuid,
		})
	}
	return retHosts, nil
}
