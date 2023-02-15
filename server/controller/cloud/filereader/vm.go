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

package filereader

import (
	"errors"
	"fmt"

	"github.com/deepflowio/deepflow/server/controller/cloud/model"
	"github.com/deepflowio/deepflow/server/controller/common"
)

func (f *FileReader) getVMs(fileInfo *FileInfo) ([]model.VM, []model.VInterface, []model.IP, error) {
	var retVMs []model.VM
	var retVInterfaces []model.VInterface
	var retIPs []model.IP

	for _, vm := range fileInfo.VMs {
		regionLcuuid, err := f.getRegionLcuuid(vm.Region)
		if err != nil {
			return nil, nil, nil, err
		}
		azLcuuid, ok := f.azNameToLcuuid[vm.AZ]
		if !ok {
			err := errors.New(fmt.Sprintf("az (%s) not in file", vm.AZ))
			log.Error(err)
			return nil, nil, nil, err
		}
		vpcLcuuid, ok := f.vpcNameToLcuuid[vm.VPC]
		if !ok {
			err := errors.New(fmt.Sprintf("vpc (%s) not in file", vm.VPC))
			log.Error(err)
			return nil, nil, nil, err
		}

		lcuuid := common.GenerateUUID(f.UuidGenerate + "_vm_" + vm.Name)
		retVMs = append(retVMs, model.VM{
			Lcuuid:       lcuuid,
			Name:         vm.Name,
			Label:        vm.Name,
			HType:        common.VM_HTYPE_VM_C,
			State:        4,
			LaunchServer: vm.LaunchServer,
			VPCLcuuid:    vpcLcuuid,
			AZLcuuid:     azLcuuid,
			RegionLcuuid: regionLcuuid,
		})

		for _, port := range vm.Ports {
			networkLcuuid, ok := f.subnetNameToNetworkLcuuid[port.Subnet]
			if !ok {
				err := errors.New(fmt.Sprintf("subnet (%s) not in file", port.Subnet))
				log.Error(err)
				return nil, nil, nil, err
			}
			netType, ok := f.networkLcuuidToNetType[networkLcuuid]
			if !ok {
				err := errors.New(fmt.Sprintf("subnet (%s) network not in file", port.Subnet))
				log.Error(err)
				return nil, nil, nil, err
			}

			vinterfaceLcuuid := common.GenerateUUID(f.UuidGenerate + port.Mac)
			retVInterfaces = append(retVInterfaces, model.VInterface{
				Lcuuid:        vinterfaceLcuuid,
				Type:          netType,
				Mac:           port.Mac,
				DeviceLcuuid:  lcuuid,
				DeviceType:    1,
				NetworkLcuuid: networkLcuuid,
				VPCLcuuid:     vpcLcuuid,
				RegionLcuuid:  regionLcuuid,
			})

			subnetLcuuid, ok := f.subnetNameToLcuuid[port.Subnet]
			if !ok {
				err := errors.New(fmt.Sprintf("subnet (%s) not in file", port.Subnet))
				log.Error(err)
				return nil, nil, nil, err
			}
			retIPs = append(retIPs, model.IP{
				Lcuuid:           common.GenerateUUID(port.IP + port.Mac),
				VInterfaceLcuuid: vinterfaceLcuuid,
				IP:               port.IP,
				SubnetLcuuid:     subnetLcuuid,
				RegionLcuuid:     regionLcuuid,
			})
		}
	}
	return retVMs, retVInterfaces, retIPs, nil
}
