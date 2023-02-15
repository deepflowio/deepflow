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

package genesis

import (
	"github.com/deepflowio/deepflow/server/controller/cloud/model"
	"github.com/deepflowio/deepflow/server/controller/common"

	uuid "github.com/satori/go.uuid"
)

func (g *Genesis) getVMs() ([]model.VM, error) {
	log.Debug("get vms starting")
	vms := []model.VM{}
	vmsData := g.genesisData.VMs

	g.cloudStatsd.APICost["vms"] = []int{0}
	g.cloudStatsd.APICount["vms"] = []int{len(vmsData)}

	for _, v := range vmsData {
		vpcLcuuid := v.VPCLcuuid
		if vpcLcuuid == "" {
			vpcLcuuid = common.GetUUID(g.defaultVpcName, uuid.Nil)
			g.defaultVpc = true
		}
		launchServer := v.LaunchServer
		if launchServer == "127.0.0.1" {
			launchServer = ""
		}
		vm := model.VM{
			Lcuuid:       v.Lcuuid,
			Name:         v.Name,
			Label:        v.Label,
			HType:        common.VM_HTYPE_VM_C,
			VPCLcuuid:    vpcLcuuid,
			State:        int(v.State),
			LaunchServer: launchServer,
			CreatedAt:    v.CreatedAt,
			AZLcuuid:     g.azLcuuid,
			RegionLcuuid: g.regionUuid,
		}
		vms = append(vms, vm)
	}
	log.Debug("get vms complete")
	return vms, nil
}
