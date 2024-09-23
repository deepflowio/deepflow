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
	"github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/libs/logger"
)

func (g *Genesis) getIPs() ([]model.IP, error) {
	log.Debug("get ips starting", logger.NewORGPrefix(g.orgID))
	ips := []model.IP{}

	g.cloudStatsd.RefreshAPIMoniter("ips", len(g.ips), time.Time{})

	for _, i := range g.ips {
		if i.VInterfaceLcuuid == "" || i.SubnetLcuuid == "" {
			log.Debug("vinterface lcuuid or subnet lcuuid not found", logger.NewORGPrefix(g.orgID))
			continue
		}
		lcuuid := i.Lcuuid
		if lcuuid == "" {
			lcuuid = common.GetUUIDByOrgID(g.orgID, i.VInterfaceLcuuid+i.IP)
		}
		ip := model.IP{
			Lcuuid:           lcuuid,
			VInterfaceLcuuid: i.VInterfaceLcuuid,
			IP:               i.IP,
			SubnetLcuuid:     i.SubnetLcuuid,
			RegionLcuuid:     g.regionLcuuid,
		}
		ips = append(ips, ip)
	}
	log.Debug("get ips complete", logger.NewORGPrefix(g.orgID))
	return ips, nil
}
