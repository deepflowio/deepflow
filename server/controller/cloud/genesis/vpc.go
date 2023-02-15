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

func (g *Genesis) getVPCs() ([]model.VPC, error) {
	log.Debug("get vpcs starting")
	vpcs := []model.VPC{}
	vpcsData := g.genesisData.VPCs

	g.cloudStatsd.APICost["vpcs"] = []int{0}
	g.cloudStatsd.APICount["vpcs"] = []int{len(vpcsData)}

	for _, v := range vpcsData {
		vpcLcuuid := v.Lcuuid
		if vpcLcuuid == "" {
			vpcLcuuid = common.GetUUID(v.Name, uuid.Nil)
		}
		vpc := model.VPC{
			Lcuuid:       vpcLcuuid,
			Name:         v.Name,
			RegionLcuuid: g.regionUuid,
		}
		vpcs = append(vpcs, vpc)
	}
	log.Debug("get vpcs complete")
	return vpcs, nil
}
