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

func (f *FileReader) getNetworks(fileInfo *FileInfo) ([]model.Network, error) {
	var retNetworks []model.Network

	for _, network := range fileInfo.Networks {
		regionLcuuid, err := f.getRegionLcuuid(network.Region)
		if err != nil {
			return nil, err
		}
		azLcuuid, ok := f.azNameToLcuuid[network.AZ]
		if !ok {
			err := errors.New(fmt.Sprintf("az (%s) not in file", network.AZ))
			log.Error(err)
			return nil, err
		}
		vpcLcuuid, ok := f.vpcNameToLcuuid[network.VPC]
		if !ok {
			err := errors.New(fmt.Sprintf("vpc (%s) not in file", network.VPC))
			log.Error(err)
			return nil, err
		}

		netType := 3
		if network.NetType != "wan" {
			netType = 4
		}

		lcuuid := common.GenerateUUID(f.UuidGenerate + "_network_" + network.Name)
		network := model.Network{
			Lcuuid:         lcuuid,
			Name:           network.Name,
			Label:          network.Name,
			SegmentationID: network.SegmentationID,
			Shared:         network.Shared,
			External:       network.External,
			NetType:        netType,
			VPCLcuuid:      vpcLcuuid,
			AZLcuuid:       azLcuuid,
			RegionLcuuid:   regionLcuuid,
		}
		f.networkNameToLcuuid[network.Name] = lcuuid
		f.networkLcuuidToNetType[lcuuid] = netType
		f.networkLcuuidToVPCLcuuid[lcuuid] = vpcLcuuid
		retNetworks = append(retNetworks, network)
	}
	return retNetworks, nil
}
