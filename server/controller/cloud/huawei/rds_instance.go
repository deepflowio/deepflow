/**
 * Copyright (c) 2023 Yunshan Networks
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

package huawei

import (
	"fmt"

	mapset "github.com/deckarep/golang-set/v2"

	cloudcommon "github.com/deepflowio/deepflow/server/controller/cloud/common"
	"github.com/deepflowio/deepflow/server/controller/cloud/model"
	"github.com/deepflowio/deepflow/server/controller/common"
)

func (h *HuaWei) getRDSInstances() ([]model.RDSInstance, []model.VInterface, []model.IP, error) {
	typeStrToInt := map[string]int{
		"MySQL":      common.RDS_TYPE_MYSQL,
		"SQLServer":  common.RDS_TYPE_SQL_SERVER,
		"PostgreSQL": common.RDS_TYPE_PSQL,
		"MariaDB":    common.RDS_TYPE_MARIADB,
	}

	stateStrToInt := map[string]int{
		"ACTIVE":    common.RDS_STATE_RUNNING,
		"RESTORING": common.RDS_STATE_RESTORING,
	}

	seriesStrToInt := map[string]int{
		"Single": common.RDS_SERIES_BASIC,
		"Ha":     common.RDS_SERIES_HA,
	}

	var rs []model.RDSInstance
	var vifs []model.VInterface
	var ips []model.IP
	for project, token := range h.projectTokenMap {
		jRDSs, err := h.getRawData(newRawDataGetContext(
			fmt.Sprintf("https://rds.%s.%s/v3/%s/instances", project.name, h.config.Domain, project.id), token.token, "instances", pageQueryMethodOffset,
		))
		if err != nil {
			return nil, nil, nil, err
		}

		regionLcuuid := h.projectNameToRegionLcuuid(project.name)
		for i := range jRDSs {
			jRDS := jRDSs[i]
			if !cloudcommon.CheckJsonAttributes(jRDS, []string{"id", "name", "status", "type", "nodes", "datastore", "vpc_id", "subnet_id"}) {
				continue
			}
			id := jRDS.Get("id").MustString()
			name := jRDS.Get("name").MustString()
			state, ok := stateStrToInt[jRDS.Get("status").MustString()]
			if !ok {
				log.Infof("exclude rds_instance: %s, state: %s", id, jRDS.Get("status").MustString())
				continue
			}

			azNames := mapset.NewSet[string]()
			for j := range jRDS.Get("nodes").MustArray() {
				azNames.Add(jRDS.Get("nodes").GetIndex(j).Get("availability_zone").MustString())
			}
			var azLcuuid string
			if azNames.Cardinality() == 1 && azNames.ToSlice()[0] != "" {
				azLcuuid, ok = h.toolDataSet.azNameToAZLcuuid[azNames.ToSlice()[0]]
				if !ok {
					log.Infof("exclude rds_instance: %s, az: %s not found", id, azNames.ToSlice()[0])
					continue
				}
			}

			networkLcuuid := jRDS.Get("subnet_id").MustString()
			if networkLcuuid == "" {
				log.Infof("exclude rds_instance: %s, no subnet_id", id)
				continue
			}

			rds := model.RDSInstance{
				Lcuuid:       id,
				Name:         name,
				Label:        id,
				State:        state,
				Type:         typeStrToInt[jRDS.Get("datastore").Get("type").MustString()],
				Version:      jRDS.Get("datastore").Get("version").MustString(),
				Series:       seriesStrToInt[jRDS.Get("type").MustString()],
				Model:        common.RDS_MODEL_PRIMARY,
				VPCLcuuid:    jRDS.Get("vpc_id").MustString(),
				AZLcuuid:     azLcuuid,
				RegionLcuuid: regionLcuuid,
			}
			rs = append(rs, rds)
			h.toolDataSet.azLcuuidToResourceNum[azLcuuid]++
			h.toolDataSet.regionLcuuidToResourceNum[regionLcuuid]++

			for _, ip := range jRDS.Get("private_ips").MustStringArray() {
				vif := model.VInterface{
					Lcuuid:        common.GenerateUUID(rds.Lcuuid + ip),
					Type:          common.VIF_TYPE_LAN,
					Mac:           common.VIF_DEFAULT_MAC,
					DeviceLcuuid:  rds.Lcuuid,
					DeviceType:    common.VIF_DEVICE_TYPE_RDS_INSTANCE,
					NetworkLcuuid: networkLcuuid,
					VPCLcuuid:     rds.VPCLcuuid,
					RegionLcuuid:  regionLcuuid,
				}
				vifs = append(vifs, vif)

				var subnetLcuuid string
				for _, subnet := range h.toolDataSet.networkLcuuidToSubnets[networkLcuuid] {
					if cloudcommon.IsIPInCIDR(ip, subnet.CIDR) {
						subnetLcuuid = subnet.Lcuuid
						break
					}
				}
				ip := model.IP{
					Lcuuid:           common.GenerateUUID(vif.Lcuuid + ip),
					VInterfaceLcuuid: vif.Lcuuid,
					IP:               ip,
					SubnetLcuuid:     subnetLcuuid,
					RegionLcuuid:     regionLcuuid,
				}
				ips = append(ips, ip)
			}

			for _, ip := range jRDS.Get("public_ips").MustStringArray() {
				vif := model.VInterface{
					Lcuuid:        common.GenerateUUID(rds.Lcuuid + ip),
					Type:          common.VIF_TYPE_WAN,
					Mac:           common.VIF_DEFAULT_MAC,
					DeviceLcuuid:  rds.Lcuuid,
					DeviceType:    common.VIF_DEVICE_TYPE_RDS_INSTANCE,
					NetworkLcuuid: common.NETWORK_ISP_LCUUID,
					VPCLcuuid:     rds.VPCLcuuid,
					RegionLcuuid:  regionLcuuid,
				}
				vifs = append(vifs, vif)

				ip := model.IP{
					Lcuuid:           common.GenerateUUID(vif.Lcuuid + ip),
					VInterfaceLcuuid: vif.Lcuuid,
					IP:               ip,
					RegionLcuuid:     regionLcuuid,
				}
				ips = append(ips, ip)
			}
		}
	}
	return rs, vifs, ips, nil
}
