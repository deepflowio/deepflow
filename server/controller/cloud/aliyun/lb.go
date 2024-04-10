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

package aliyun

import (
	"strconv"
	"strings"

	slb "github.com/aliyun/alibaba-cloud-sdk-go/services/slb"
	"github.com/deepflowio/deepflow/server/controller/cloud/model"
	"github.com/deepflowio/deepflow/server/controller/common"
)

func (a *Aliyun) getLoadBalances(region model.Region, vmLcuuidToVPCLcuuid map[string]string) (
	[]model.LB, []model.LBListener, []model.LBTargetServer, []model.VInterface, []model.IP, error,
) {
	var retLBs []model.LB
	var retLBListeners []model.LBListener
	var retLBTargetServers []model.LBTargetServer
	var retVInterfaces []model.VInterface
	var retIPs []model.IP

	if region.Label == "cn-wulanchabu" || region.Label == "cn-nanjing" {
		return retLBs, retLBListeners, retLBTargetServers, retVInterfaces, retIPs, nil
	}

	log.Debug("get lbs starting")
	request := slb.CreateDescribeLoadBalancersRequest()
	response, err := a.getLBResponse(region.Label, request)
	if err != nil {
		log.Error(err)
		return retLBs, retLBListeners, retLBTargetServers, retVInterfaces, retIPs, err
	}

	for _, r := range response {
		lbs, _ := r.Get("LoadBalancer").Array()
		for i := range lbs {
			lb := r.Get("LoadBalancer").GetIndex(i)

			err := a.checkRequiredAttributes(
				lb,
				[]string{"LoadBalancerId", "LoadBalancerName", "Address", "AddressType"},
			)
			if err != nil {
				log.Info(err)
				continue
			}

			lbId := lb.Get("LoadBalancerId").MustString()
			lbName := lb.Get("LoadBalancerName").MustString()
			if lbName == "" {
				lbName = lbId
			}
			lbModel := common.LB_MODEL_EXTERNAL
			if lb.Get("AddressType").MustString() != "internet" {
				lbModel = common.LB_MODEL_INTERNAL
			}
			vpcId := lb.Get("VpcId").MustString()

			lbLcuuid := common.GenerateUUIDByOrgID(a.orgID, lbId)
			vpcLcuuid := ""
			if vpcId != "" {
				vpcLcuuid = common.GenerateUUIDByOrgID(a.orgID, vpcId)
			}

			// 获取后端server信息并补充vpcLcuuid
			tmpLBTargetServers, tmpVPCLcuuid, err := a.getLBTargetServers(region, lbId, vmLcuuidToVPCLcuuid)
			if err != nil {
				return []model.LB{}, []model.LBListener{}, []model.LBTargetServer{}, []model.VInterface{}, []model.IP{}, err
			}
			// lb API本身没有返回vpc信息且后端主机无法补充时，跳过该lb
			if vpcLcuuid == "" {
				if tmpVPCLcuuid == "" {
					log.Infof("get lb (%s) vpc info failed", lbId)
					continue
				}
				vpcLcuuid = tmpVPCLcuuid
			}
			retLBTargetServers = append(retLBTargetServers, tmpLBTargetServers...)

			retLB := model.LB{
				Lcuuid:       lbLcuuid,
				Name:         lbName,
				Label:        lbId,
				Model:        lbModel,
				VPCLcuuid:    vpcLcuuid,
				RegionLcuuid: a.getRegionLcuuid(region.Lcuuid),
			}
			retLBs = append(retLBs, retLB)
			a.regionLcuuidToResourceNum[retLB.RegionLcuuid]++

			// 监听器信息
			tmpLBListeners, err := a.getLBListeners(region, lbId, lb.Get("Address").MustString())
			if err != nil {
				return []model.LB{}, []model.LBListener{}, []model.LBTargetServer{}, []model.VInterface{}, []model.IP{}, err
			}
			retLBListeners = append(retLBListeners, tmpLBListeners...)

			// 接口信息
			portLcuuid := common.GenerateUUIDByOrgID(a.orgID, lbLcuuid)
			portType := common.VIF_TYPE_WAN
			networkLcuuid := common.NETWORK_ISP_LCUUID
			if lbModel == common.LB_MODEL_INTERNAL {
				portType = common.VIF_TYPE_LAN
				networkLcuuid = common.GenerateUUIDByOrgID(a.orgID, lb.Get("VSwitchId").MustString())
			}
			retVInterface := model.VInterface{
				Lcuuid:        portLcuuid,
				Type:          portType,
				Mac:           common.VIF_DEFAULT_MAC,
				DeviceLcuuid:  lbLcuuid,
				DeviceType:    common.VIF_DEVICE_TYPE_LB,
				NetworkLcuuid: networkLcuuid,
				VPCLcuuid:     vpcLcuuid,
				RegionLcuuid:  a.getRegionLcuuid(region.Lcuuid),
			}
			retVInterfaces = append(retVInterfaces, retVInterface)

			// IP信息
			retIP := model.IP{
				Lcuuid:           common.GenerateUUIDByOrgID(a.orgID, portLcuuid+lb.Get("Address").MustString()),
				VInterfaceLcuuid: portLcuuid,
				IP:               lb.Get("Address").MustString(),
				SubnetLcuuid:     common.GenerateUUIDByOrgID(a.orgID, networkLcuuid),
				RegionLcuuid:     a.getRegionLcuuid(region.Lcuuid),
			}
			retIPs = append(retIPs, retIP)
		}
	}
	log.Debug("get lbs complete")
	return retLBs, retLBListeners, retLBTargetServers, retVInterfaces, retIPs, nil
}

func (a *Aliyun) getLBListeners(region model.Region, lbId, lbIP string) ([]model.LBListener, error) {
	var retLBListeners []model.LBListener

	request := slb.CreateDescribeLoadBalancerAttributeRequest()
	request.LoadBalancerId = lbId
	response, err := a.getLBListenerResponse(region.Label, request)
	if err != nil {
		log.Error(err)
		return []model.LBListener{}, err
	}

	lbLcuuid := common.GenerateUUIDByOrgID(a.orgID, lbId)
	for _, rAttr := range response {
		// ListenerPortAndProtocal属于阿里云API本身的拼写错误
		for i := range rAttr.Get("ListenerPortAndProtocal").MustArray() {
			attr := rAttr.Get("ListenerPortAndProtocal").GetIndex(i)

			protocol := attr.Get("ListenerProtocal").MustString()
			if protocol == "" {
				log.Debug("no ListenerProtocal in %v", attr)
				continue
			}
			listenerPort := attr.Get("ListenerPort").MustInt()
			if listenerPort == 0 {
				log.Debug("no ListenerPort in %v", attr)
				continue
			}
			key := protocol + ":" + strconv.Itoa(listenerPort)
			name := attr.Get("Description").MustString()
			if name == "" {
				name = key
			}
			retLBListener := model.LBListener{
				Lcuuid:   common.GenerateUUIDByOrgID(a.orgID, lbId+key),
				LBLcuuid: lbLcuuid,
				IPs:      lbIP,
				Name:     name,
				Port:     listenerPort,
				Protocol: strings.ToUpper(protocol),
			}
			retLBListeners = append(retLBListeners, retLBListener)
		}
	}
	return retLBListeners, nil
}

func (a *Aliyun) getLBTargetServers(region model.Region, lbId string, vmLcuuidToVPCLcuuid map[string]string) ([]model.LBTargetServer, string, error) {
	var retLBTargetServers []model.LBTargetServer

	request := slb.CreateDescribeHealthStatusRequest()
	request.LoadBalancerId = lbId
	response, err := a.getLBTargetServerResponse(region.Label, request)
	if err != nil {
		log.Error(err)
		return []model.LBTargetServer{}, "", err
	}

	lbLcuuid := common.GenerateUUIDByOrgID(a.orgID, lbId)
	vpcLcuuid := ""
	for _, rServer := range response {
		for i := range rServer.Get("BackendServer").MustArray() {
			server := rServer.Get("BackendServer").GetIndex(i)

			err := a.checkRequiredAttributes(
				server,
				[]string{"ServerId", "Port", "Protocol", "ListenerPort", "ServerIp"},
			)
			if err != nil {
				log.Info(err)
				continue
			}

			// 获取server对应的vpcLcuuid
			serverId := server.Get("ServerId").MustString()
			protocol := server.Get("Protocol").MustString()
			port := server.Get("Port").MustInt()
			listenerPort := server.Get("ListenerPort").MustInt()

			vmLcuuid := common.GenerateUUIDByOrgID(a.orgID, serverId)
			serverVPCLcuuid, ok := vmLcuuidToVPCLcuuid[vmLcuuid]
			if !ok {
				continue
			}
			vpcLcuuid = serverVPCLcuuid
			key := serverId + strconv.Itoa(port) + protocol
			listenerId := protocol + ":" + strconv.Itoa(listenerPort)
			retLBTargetServer := model.LBTargetServer{
				Lcuuid:           common.GenerateUUIDByOrgID(a.orgID, lbId+listenerId+key),
				LBLcuuid:         lbLcuuid,
				LBListenerLcuuid: common.GenerateUUIDByOrgID(a.orgID, lbId+listenerId),
				Type:             common.LB_SERVER_TYPE_VM,
				IP:               server.Get("ServerIp").MustString(),
				VMLcuuid:         vmLcuuid,
				VPCLcuuid:        serverVPCLcuuid,
				Protocol:         strings.ToUpper(protocol),
				Port:             port,
			}
			retLBTargetServers = append(retLBTargetServers, retLBTargetServer)
		}
	}
	return retLBTargetServers, vpcLcuuid, nil
}
