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

package tencent

import (
	"strconv"
	"strings"

	"github.com/deepflowio/deepflow/server/controller/cloud/model"
	"github.com/deepflowio/deepflow/server/controller/common"
	uuid "github.com/satori/go.uuid"
)

func (t *Tencent) getLoadBalances(region tencentRegion) ([]model.LB, []model.LBListener, []model.LBTargetServer, []model.VInterface, []model.IP, error) {
	log.Debug("get load balances starting")
	var lbs []model.LB
	var lbListeners []model.LBListener
	var lbTargetServers []model.LBTargetServer
	var lbVinterfaces []model.VInterface
	var lbIPs []model.IP

	lbAttrs := []string{"LoadBalancerId", "LoadBalancerName", "LoadBalancerVips", "VpcId", "Forward", "LoadBalancerType"}
	lbListenerAttrs := []string{"ListenerId", "Protocol", "ListenerName"}
	lbTargetServerAttrs := []string{"InstanceId"}

	listenerIDToProtocol := map[string]string{}

	lbResp, err := t.getResponse("clb", "2018-03-17", "DescribeLoadBalancers", region.name, "LoadBalancerSet", true, map[string]interface{}{})
	if err != nil {
		log.Errorf("load balance request tencent api error: (%s)", err.Error())
		return []model.LB{}, []model.LBListener{}, []model.LBTargetServer{}, []model.VInterface{}, []model.IP{}, err
	}
	for _, lbData := range lbResp {
		if !t.checkRequiredAttributes(lbData, lbAttrs) {
			continue
		}
		vpcID := lbData.Get("VpcId").MustString()
		vpcLcuuid := common.GetUUID(vpcID, uuid.Nil)
		lbName := lbData.Get("LoadBalancerName").MustString()
		if vpcID == "" {
			log.Warningf("load balance (%s) vpc not found", lbName)
			continue
		}
		lbType := lbData.Get("LoadBalancerType").MustString()
		lbModel := common.LB_MODEL_INTERNAL
		if lbType == "OPEN" {
			lbModel = common.LB_MODEL_EXTERNAL
		}
		lbID := lbData.Get("LoadBalancerId").MustString()
		lbIPStrings := []string{}
		for i := range lbData.Get("LoadBalancerVips").MustArray() {
			lbIPStrings = append(lbIPStrings, lbData.Get("LoadBalancerVips").GetIndex(i).MustString())
		}
		lbLcuuid := common.GetUUID(lbID, uuid.Nil)
		lbs = append(lbs, model.LB{
			Lcuuid:       lbLcuuid,
			Name:         lbName,
			Label:        lbID,
			Model:        lbModel,
			VPCLcuuid:    vpcLcuuid,
			RegionLcuuid: t.getRegionLcuuid(region.lcuuid),
		})

		lbForward := lbData.Get("Forward").MustInt()
		params := map[string]interface{}{
			"LoadBalancerId": lbID,
		}
		if lbForward == 1 {
			// Application load balance
			lbListenerResp, err := t.getResponse("clb", "2018-03-17", "DescribeListeners", region.name, "Listeners", false, params)
			if err != nil {
				log.Errorf("application load balance listener request tencent api error: (%s)", err.Error())
				return []model.LB{}, []model.LBListener{}, []model.LBTargetServer{}, []model.VInterface{}, []model.IP{}, err
			}

			listenerTargetServers := []tencentTargetServer{}
			for _, lbListenerData := range lbListenerResp {
				if !t.checkRequiredAttributes(lbListenerData, lbListenerAttrs) {
					continue
				}
				listenerID := lbListenerData.Get("ListenerId").MustString()
				listenerName := lbListenerData.Get("ListenerName").MustString()
				listenerProtocol := lbListenerData.Get("Protocol").MustString()
				listenerPort := lbListenerData.Get("Port").MustInt()
				lbListeners = append(lbListeners, model.LBListener{
					Lcuuid:   common.GetUUID(listenerID, uuid.Nil),
					LBLcuuid: lbLcuuid,
					Name:     listenerName,
					Label:    listenerID,
					Port:     listenerPort,
					IPs:      strings.Join(lbIPStrings, ","),
					Protocol: strings.ToUpper(listenerProtocol),
				})

				listenerIDToProtocol[listenerID] = listenerProtocol
			}

			lbTargetServerResp, err := t.getResponse("clb", "2018-03-17", "DescribeTargets", region.name, "Listeners", false, params)
			if err != nil {
				log.Errorf("application load balance target request tencent api error: (%s)", err.Error())
				return []model.LB{}, []model.LBListener{}, []model.LBTargetServer{}, []model.VInterface{}, []model.IP{}, err
			}
			for _, lbTargetServerData := range lbTargetServerResp {
				targetServerID := lbTargetServerData.Get("ListenerId").MustString()
				for rIndex := range lbTargetServerData.Get("Rules").MustArray() {
					ruleData := lbTargetServerData.Get("Rules").GetIndex(rIndex)
					for tIndex := range ruleData.Get("Targets").MustArray() {
						targetData := ruleData.Get("Targets").GetIndex(tIndex)
						if !t.checkRequiredAttributes(targetData, lbTargetServerAttrs) {
							continue
						}
						listenerTargetServers = append(listenerTargetServers, tencentTargetServer{
							lcuuid: targetServerID,
							server: targetData,
						})
					}
				}

				for i := range lbTargetServerData.Get("Targets").MustArray() {
					tServerData := lbTargetServerData.Get("Targets").GetIndex(i)
					if !t.checkRequiredAttributes(tServerData, lbTargetServerAttrs) {
						continue
					}
					listenerTargetServers = append(listenerTargetServers, tencentTargetServer{
						lcuuid: targetServerID,
						server: tServerData,
					})
				}
			}
			for _, s := range listenerTargetServers {
				instanceID := s.server.Get("InstanceId").MustString()
				aPrivateIPs, ok := s.server.CheckGet("PrivateIpAddresses")
				if !ok || len(aPrivateIPs.MustArray()) == 0 {
					log.Infof("application lb target server (%s) ip not found", instanceID)
					continue
				}
				aPIPSlice := []string{}
				for ap := range aPrivateIPs.MustArray() {
					aPIPSlice = append(aPIPSlice, aPrivateIPs.GetIndex(ap).MustString())
				}

				listenerLcuuid := common.GetUUID(s.lcuuid, uuid.Nil)
				sPort := s.server.Get("Port").MustInt()
				key := instanceID + listenerLcuuid + strconv.Itoa(sPort)
				lbTargetServers = append(lbTargetServers, model.LBTargetServer{
					Lcuuid:           common.GetUUID(key, uuid.Nil),
					LBLcuuid:         lbLcuuid,
					LBListenerLcuuid: listenerLcuuid,
					Type:             common.LB_SERVER_TYPE_VM,
					VMLcuuid:         common.GetUUID(instanceID, uuid.Nil),
					Port:             sPort,
					IP:               aPIPSlice[0],
					VPCLcuuid:        vpcLcuuid,
					Protocol:         listenerIDToProtocol[s.lcuuid],
				})
			}
		} else if lbForward == 0 {
			// Classic load balance
			clbListenerResp, err := t.getResponse("clb", "2018-03-17", "DescribeClassicalLBListeners", region.name, "Listeners", false, params)
			if err != nil {
				log.Errorf("classic load balance listener request tencent api error: (%s)", err.Error())
				return []model.LB{}, []model.LBListener{}, []model.LBTargetServer{}, []model.VInterface{}, []model.IP{}, err
			}
			for _, clbListenerData := range clbListenerResp {
				if !t.checkRequiredAttributes(clbListenerData, lbListenerAttrs) {
					continue
				}
				listenerID := clbListenerData.Get("ListenerId").MustString()
				listenerProtocol := clbListenerData.Get("Protocol").MustString()
				listenerLcuuid := common.GetUUID(listenerID, uuid.Nil)
				lbListeners = append(lbListeners, model.LBListener{
					Lcuuid:   listenerLcuuid,
					LBLcuuid: lbLcuuid,
					Label:    listenerID,
					IPs:      strings.Join(lbIPStrings, ","),
					Name:     clbListenerData.Get("ListenerName").MustString(),
					Port:     clbListenerData.Get("ListenerPort").MustInt(),
					Protocol: listenerProtocol,
				})

				clbTargetServerResp, err := t.getResponse("clb", "2018-03-17", "DescribeClassicalLBTargets", region.name, "Targets", false, params)
				if err != nil {
					log.Errorf("classic load balance classic target request tencent api error: (%s)", err.Error())
					return []model.LB{}, []model.LBListener{}, []model.LBTargetServer{}, []model.VInterface{}, []model.IP{}, err
				}
				for _, clbTargetServerData := range clbTargetServerResp {
					if !t.checkRequiredAttributes(clbTargetServerData, lbTargetServerAttrs) {
						continue
					}
					clbTargetServerInstanceID := clbTargetServerData.Get("InstanceId").MustString()
					cPrivateIPs, ok := clbTargetServerData.CheckGet("PrivateIpAddresses")
					if !ok || len(cPrivateIPs.MustArray()) == 0 {
						log.Infof("classic lb target server (%s) ip not found", clbTargetServerInstanceID)
						continue
					}
					cPIPSlice := []string{}
					for cp := range cPrivateIPs.MustArray() {
						cPIPSlice = append(cPIPSlice, cPrivateIPs.GetIndex(cp).MustString())
					}

					lbTargetServers = append(lbTargetServers, model.LBTargetServer{
						Lcuuid:           common.GetUUID(clbTargetServerInstanceID+listenerLcuuid, uuid.Nil),
						LBLcuuid:         lbLcuuid,
						LBListenerLcuuid: listenerLcuuid,
						Type:             common.LB_SERVER_TYPE_VM,
						VMLcuuid:         common.GetUUID(clbTargetServerInstanceID, uuid.Nil),
						IP:               cPIPSlice[0],
						Port:             clbListenerData.Get("InstancePort").MustInt(),
						VPCLcuuid:        vpcLcuuid,
						Protocol:         listenerProtocol,
					})
				}
			}
		}

		vinterfaceLcuuid := common.GetUUID(lbLcuuid, uuid.Nil)
		vType := common.VIF_TYPE_WAN
		networkLcuuid := common.NETWORK_ISP_LCUUID
		if lbModel == common.LB_MODEL_INTERNAL {
			vType = common.VIF_TYPE_LAN
			networkLcuuid = common.GetUUID(lbData.Get("SubnetId").MustString(), uuid.Nil)
		}
		lbVinterfaces = append(lbVinterfaces, model.VInterface{
			Lcuuid:        vinterfaceLcuuid,
			Type:          vType,
			Mac:           common.VIF_DEFAULT_MAC,
			DeviceLcuuid:  lbLcuuid,
			DeviceType:    common.VIF_DEVICE_TYPE_LB,
			NetworkLcuuid: networkLcuuid,
			VPCLcuuid:     vpcLcuuid,
			RegionLcuuid:  t.getRegionLcuuid(region.lcuuid),
		})
		lbVIPs := lbData.Get("LoadBalancerVips")
		for v := range lbVIPs.MustArray() {
			lbVIP := lbVIPs.GetIndex(v).MustString()
			lbIPs = append(lbIPs, model.IP{
				Lcuuid:           common.GetUUID(vinterfaceLcuuid+lbVIP, uuid.Nil),
				VInterfaceLcuuid: vinterfaceLcuuid,
				IP:               lbVIP,
				SubnetLcuuid:     common.GetUUID(networkLcuuid, uuid.Nil),
				RegionLcuuid:     t.getRegionLcuuid(region.lcuuid),
			})
		}
	}
	log.Debug("get load balances complete")
	return lbs, lbListeners, lbTargetServers, lbVinterfaces, lbIPs, nil
}
