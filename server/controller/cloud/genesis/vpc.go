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

package genesis

import (
	"time"

	"github.com/deepflowio/deepflow/server/controller/cloud/model"
	"github.com/deepflowio/deepflow/server/libs/logger"
)

func (g *Genesis) getVPCs() ([]model.VPC, error) {
	log.Debug("get vpcs starting", logger.NewORGPrefix(g.orgID))
	vpcs := []model.VPC{}
	vpcsData := g.genesisData.VPCs

	g.cloudStatsd.RefreshAPIMoniter("vpcs", len(vpcsData), time.Time{})

	for _, v := range vpcsData {
		vpc := model.VPC{
			Lcuuid:       v.Lcuuid,
			Name:         v.Name,
			RegionLcuuid: g.regionLcuuid,
		}
		vpcs = append(vpcs, vpc)
	}
	log.Debug("get vpcs complete", logger.NewORGPrefix(g.orgID))
	return vpcs, nil
}
