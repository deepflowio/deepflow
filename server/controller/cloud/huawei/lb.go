/*
 * Copyright (c) 2023 Yunshan NATGateways
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
	"strings"

	cloudcommon "github.com/deepflowio/deepflow/server/controller/cloud/common"
	"github.com/deepflowio/deepflow/server/controller/cloud/model"
	"github.com/deepflowio/deepflow/server/controller/common"
)

func (h *HuaWei) getLBs() (
	lbs []model.LB, lbListeners []model.LBListener, lbTargetSevers []model.LBTargetServer, vifs []model.VInterface, ips []model.IP, err error,
) {
	requiredAttrs := []string{"id", "name", "vip_port_id", "vip_subnet_id", "vip_address"}
	for project, token := range h.projectTokenMap {
		jLBs, err := h.getRawData(newRawDataGetContext(
			fmt.Sprintf("https://vpc.%s.%s/v2.0/lbaas/loadbalancers", project.name, h.config.Domain), token.token, "loadbalancers", pageQueryMethodMarker,
		))
		if err != nil {
			return nil, nil, nil, nil, nil, err
		}

		regionLcuuid := h.projectNameToRegionLcuuid(project.name)
		for i := range jLBs {
			jLB := jLBs[i]
			name := jLB.Get("name").MustString()
			if !cloudcommon.CheckJsonAttributes(jLB, requiredAttrs) {
				log.Infof("exclude lb: %s, missing attr", name)
				continue
			}
			network, ok := h.toolDataSet.neutronSubnetIDToNetwork[jLB.Get("vip_subnet_id").MustString()]
			if !ok {
				log.Infof("exclude lb: %s, missing network info", name)
				continue
			}
			id := jLB.Get("id").MustString()
			var lbModel int
			var vifType int
			var networkLcuuid string
			var ip string
			publicIP, ok := h.toolDataSet.vinterfaceLcuuidToPublicIP[jLB.Get("vip_port_id").MustString()]
			if ok {
				lbModel = cloudcommon.LB_MODEL_EXTERNAL
				vifType = common.VIF_TYPE_WAN
				networkLcuuid = common.NETWORK_ISP_LCUUID
				ip = publicIP
			} else {
				lbModel = cloudcommon.LB_MODEL_INTERNAL
				vifType = common.VIF_TYPE_LAN
				networkLcuuid = network.Lcuuid
				ip = jLB.Get("vip_address").MustString()
			}
			lb := model.LB{
				Lcuuid:       id,
				Name:         name,
				Model:        lbModel,
				VPCLcuuid:    network.VPCLcuuid,
				RegionLcuuid: regionLcuuid,
			}
			lbs = append(lbs, lb)
			h.toolDataSet.regionLcuuidToResourceNum[regionLcuuid]++

			vifLcuuid := common.GenerateUUID(id)
			vifs = append(
				vifs,
				model.VInterface{
					Lcuuid:        vifLcuuid,
					Type:          vifType,
					Mac:           common.VIF_DEFAULT_MAC,
					DeviceType:    common.VIF_DEVICE_TYPE_LB,
					DeviceLcuuid:  id,
					NetworkLcuuid: networkLcuuid,
					VPCLcuuid:     lb.VPCLcuuid,
					RegionLcuuid:  lb.RegionLcuuid,
				},
			)
			var subnetLcuuid string
			for _, subnet := range h.toolDataSet.networkLcuuidToSubnets[networkLcuuid] {
				if cloudcommon.IsIPInCIDR(ip, subnet.CIDR) {
					subnetLcuuid = subnet.Lcuuid
					break
				}
			}
			ips = append(
				ips,
				model.IP{
					Lcuuid:           common.GenerateUUID(vifLcuuid + ip),
					VInterfaceLcuuid: vifLcuuid,
					IP:               ip,
					SubnetLcuuid:     subnetLcuuid,
					RegionLcuuid:     lb.RegionLcuuid,
				},
			)
			h.toolDataSet.lbLcuuidToVPCLcuuid[id] = lb.VPCLcuuid
			h.toolDataSet.lbLcuuidToIP[id] = ip
		}

		lls, ltss, err := h.formatListenersAndTargetServers(project.name, token.token)
		if err == nil {
			lbListeners = append(lbListeners, lls...)
			lbTargetSevers = append(lbTargetSevers, ltss...)
		} else {
			return nil, nil, nil, nil, nil, err
		}
	}
	return
}

func (h *HuaWei) formatListenersAndTargetServers(projectName, token string) (lbListeners []model.LBListener, lbTargetSevers []model.LBTargetServer, err error) {
	jLs, err := h.getRawData(newRawDataGetContext(
		fmt.Sprintf("https://vpc.%s.%s/v2.0/lbaas/listeners", projectName, h.config.Domain), token, "listeners", pageQueryMethodMarker,
	))
	if err != nil {
		return nil, nil, err
	}

	listenerRequiredAttrs := []string{"id", "name", "loadbalancers", "protocol_port", "protocol"}
	tsRequiredAttrs := []string{"id", "protocol_port", "subnet_id", "address"}

	for i := range jLs {
		jL := jLs[i]
		name := jL.Get("name").MustString()
		if !cloudcommon.CheckJsonAttributes(jL, listenerRequiredAttrs) {
			log.Infof("exclude lb_listener: %s, missing attr", name)
			continue
		}

		var lbLcuuid string
		jLBs := jL.Get("loadbalancers")
		for i := range jLBs.MustArray() {
			jLB := jLBs.GetIndex(i)
			id, ok := jLB.CheckGet("id")
			if ok {
				lbLcuuid = id.MustString()
			} else {
				log.Infof("pass, missing id")
			}
		}
		if lbLcuuid == "" {
			log.Infof("exclude lb_listener: %s, missing lb info", name)
			continue
		}
		listenerID := jL.Get("id").MustString()
		protocol := jL.Get("protocol").MustString()
		if strings.Contains(protocol, "HTTPS") {
			protocol = "HTTPS"
		}

		lbListeners = append(
			lbListeners,
			model.LBListener{
				Lcuuid:   listenerID,
				Name:     name,
				LBLcuuid: lbLcuuid,
				Port:     jL.Get("protocol_port").MustInt(),
				Protocol: protocol,
				IPs:      h.toolDataSet.lbLcuuidToIP[lbLcuuid],
			},
		)

		poolID, ok := jL.CheckGet("default_pool_id")
		if ok && poolID.MustString() != "" {
			jTSs, err := h.getRawData(newRawDataGetContext(
				fmt.Sprintf("https://vpc.%s.%s/v2.0/lbaas/pools/%s/members", projectName, h.config.Domain, poolID.MustString()), token, "members", pageQueryMethodMarker,
			))
			if err != nil {
				return nil, nil, err
			}
			for i := range jTSs {
				jTS := jTSs[i]
				tsID := jTS.Get("id").MustString()
				if !cloudcommon.CheckJsonAttributes(jTS, tsRequiredAttrs) {
					log.Infof("exclude lb_target_server: %s, missing attr", tsID)
					continue
				}
				subnetID := jTS.Get("subnet_id").MustString()
				ip := jTS.Get("address").MustString()
				vmLcuuid, ok := h.toolDataSet.keyToVMLcuuid[SubnetIPKey{subnetID, ip}]
				if !ok {
					log.Infof("exclude lb_target_server: %s, missing vm info", tsID)
					continue
				}
				lbTargetSevers = append(
					lbTargetSevers,
					model.LBTargetServer{
						Lcuuid:           tsID,
						LBLcuuid:         lbLcuuid,
						LBListenerLcuuid: listenerID,
						Type:             common.LB_SERVER_TYPE_VM,
						VMLcuuid:         vmLcuuid,
						VPCLcuuid:        h.toolDataSet.lbLcuuidToVPCLcuuid[lbLcuuid],
						IP:               ip,
						Port:             jTS.Get("protocol_port").MustInt(),
						Protocol:         protocol,
					},
				)
			}
		}
	}
	return
}
