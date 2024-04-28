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

func (f *FileReader) getRouters(fileInfo *FileInfo) ([]model.VRouter, []model.VInterface, []model.IP, error) {
	var retVRouters []model.VRouter
	var retVInterfaces []model.VInterface
	var retIPs []model.IP

	for _, router := range fileInfo.Routers {
		regionLcuuid, err := f.getRegionLcuuid(router.Region)
		if err != nil {
			return nil, nil, nil, err
		}
		vpcLcuuid, ok := f.vpcNameToLcuuid[router.VPC]
		if !ok {
			err := errors.New(fmt.Sprintf("vpc (%s) not in file", router.VPC))
			log.Error(err)
			return nil, nil, nil, err
		}

		lcuuid := common.GenerateUUIDByOrgID(f.orgID, f.UuidGenerate+"_router_"+router.Name)
		retVRouters = append(retVRouters, model.VRouter{
			Lcuuid:         lcuuid,
			Name:           router.Name,
			Label:          router.Name,
			GWLaunchServer: router.GWLaunchServer,
			VPCLcuuid:      vpcLcuuid,
			RegionLcuuid:   regionLcuuid,
		})

		for _, port := range router.Ports {
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

			vinterfaceLcuuid := common.GenerateUUIDByOrgID(f.orgID, f.UuidGenerate+port.Mac)
			retVInterfaces = append(retVInterfaces, model.VInterface{
				Lcuuid:        vinterfaceLcuuid,
				Type:          netType,
				Mac:           port.Mac,
				DeviceLcuuid:  lcuuid,
				DeviceType:    5,
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
				Lcuuid:           common.GenerateUUIDByOrgID(f.orgID, port.IP+port.Mac),
				VInterfaceLcuuid: vinterfaceLcuuid,
				IP:               port.IP,
				SubnetLcuuid:     subnetLcuuid,
				RegionLcuuid:     regionLcuuid,
			})
		}
	}
	return retVRouters, retVInterfaces, retIPs, nil
}
