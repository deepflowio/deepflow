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

func (f *FileReader) getSubnets(fileInfo *FileInfo) ([]model.Subnet, error) {
	var retSubnets []model.Subnet

	for _, subnet := range fileInfo.Subnets {
		networkLcuuid, ok := f.networkNameToLcuuid[subnet.Network]
		if !ok {
			err := errors.New(fmt.Sprintf("network (%s) not in file", subnet.Network))
			log.Error(err)
			return nil, err
		}
		vpcLcuuid, ok := f.networkLcuuidToVPCLcuuid[networkLcuuid]
		if !ok {
			err := errors.New(fmt.Sprintf("network (%s) not in file", subnet.Network))
			log.Error(err)
			return nil, err
		}

		lcuuid := common.GenerateUUID(f.UuidGenerate + "_subnet_" + subnet.Name)
		f.subnetNameToNetworkLcuuid[subnet.Name] = networkLcuuid
		f.subnetNameToLcuuid[subnet.Name] = lcuuid
		retSubnets = append(retSubnets, model.Subnet{
			Lcuuid:        lcuuid,
			Name:          subnet.Name,
			Label:         subnet.Name,
			CIDR:          subnet.CIDR,
			GatewayIP:     subnet.GatewayIP,
			NetworkLcuuid: networkLcuuid,
			VPCLcuuid:     vpcLcuuid,
		})
	}
	return retSubnets, nil
}
