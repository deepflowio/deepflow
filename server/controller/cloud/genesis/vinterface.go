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

func (g *Genesis) getVinterfaces() ([]model.VInterface, error) {
	log.Debug("get vinterfaces starting")
	vinterfaces := []model.VInterface{}
	vinterfacesData := g.genesisData.Ports

	g.cloudStatsd.APICost["vinterfaces"] = []int{0}
	g.cloudStatsd.APICount["vinterfaces"] = []int{len(vinterfacesData)}

	for _, v := range vinterfacesData {
		if v.DeviceLcuuid == "" || v.NetworkLcuuid == "" {
			log.Debug("device lcuuid or network lcuuid not found")
			continue
		}
		vpcLcuuid := v.VPCLcuuid
		if vpcLcuuid == "" {
			vpcLcuuid = common.GetUUID(g.defaultVpcName, uuid.Nil)
			g.defaultVpc = true
		}
		vinterface := model.VInterface{
			Lcuuid:        v.Lcuuid,
			Type:          int(v.Type),
			Mac:           v.Mac,
			VPCLcuuid:     vpcLcuuid,
			RegionLcuuid:  g.regionUuid,
			DeviceType:    int(v.DeviceType),
			DeviceLcuuid:  v.DeviceLcuuid,
			NetworkLcuuid: v.NetworkLcuuid,
		}
		vinterfaces = append(vinterfaces, vinterface)
	}
	log.Debug("get vinterfaces complete")
	return vinterfaces, nil
}
