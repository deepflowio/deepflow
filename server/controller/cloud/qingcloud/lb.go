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

package qingcloud

import (
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/deepflowio/deepflow/server/controller/cloud/model"
	"github.com/deepflowio/deepflow/server/controller/common"
)

func (q *QingCloud) GetLoadBalances() (
	[]model.LB, []model.LBListener, []model.LBTargetServer, []model.VInterface,
	[]model.IP, []model.LBVMConnection, error,
) {
	var retLBs []model.LB
	var retLBListeners []model.LBListener
	var retLBTargetServers []model.LBTargetServer
	var retVInterfaces []model.VInterface
	var retIPs []model.IP
	var retLBVMConnections []model.LBVMConnection

	log.Info("get lbs starting")

	lbIdToVPCLcuuid := make(map[string]string)
	lbIdToIP := make(map[string]string)
	for regionId, regionLcuuid := range q.RegionIdToLcuuid {
		regionVPCLcuuid, ok := q.regionIdToDefaultVPCLcuuid[regionId]
		if !ok {
			err := errors.New(fmt.Sprintf("(%s) default vpc not found", regionId))
			log.Error(err)
			return nil, nil, nil, nil, nil, nil, err
		}

		kwargs := []*Param{
			{"zone", regionId},
			{"status.1", "active"},
			{"status.2", "stopped"},
		}
		response, err := q.GetResponse("DescribeLoadBalancers", "loadbalancer_set", kwargs)
		if err != nil {
			log.Error(err)
			return nil, nil, nil, nil, nil, nil, err
		}

		for _, r := range response {
			for i := range r.MustArray() {
				lb := r.GetIndex(i)
				err := q.CheckRequiredAttributes(lb, []string{
					"loadbalancer_id", "loadbalancer_name", "vxnet_id",
				})
				if err != nil {
					continue
				}

				lbId := lb.Get("loadbalancer_id").MustString()
				lbLcuuid := common.GenerateUUID(lbId)
				lbName := lb.Get("loadbalancer_name").MustString()
				if lbName == "" {
					lbName = lbId
				}
				vxnetId := lb.Get("vxnet_id").MustString()
				vpcLcuuid, ok := q.VxnetIdToVPCLcuuid[vxnetId]
				if !ok {
					log.Debugf("lb (%s) vxnetId (%s) vpc not found", lbId, vxnetId)
					vpcLcuuid = regionVPCLcuuid
				}
				subnetLcuuid, ok := q.VxnetIdToSubnetLcuuid[vxnetId]
				if !ok {
					log.Debugf("lb (%s) vxnetId (%s) subnet not found", lbId, vxnetId)
					subnetLcuuid = ""
				}

				// 获取VIP
				vip := lb.Get("vxnet").Get("private_ip").MustString()
				// 获取外网IP
				eips := []string{}
				for j := range lb.Get("cluster").MustArray() {
					cluster := lb.Get("cluster").GetIndex(j)
					eip := cluster.Get("eip_addr").MustString()
					if eip == "" {
						continue
					}
					eips = append(eips, eip)
					// 确定lb与载体虚拟机的关联关系
					for k := range cluster.Get("instances").MustArray() {
						instance := cluster.Get("instances").GetIndex(k)
						instanceId := instance.Get("instance_id").MustString()
						if instanceId == "" {
							continue
						}
						if _, ok := q.vmIdToVPCLcuuid[instanceId]; !ok {
							continue
						}
						retLBVMConnections = append(retLBVMConnections, model.LBVMConnection{
							Lcuuid:   common.GenerateUUID(lbLcuuid + instanceId),
							LBLcuuid: lbLcuuid,
							VMLcuuid: common.GenerateUUID(instanceId),
						})
					}
				}

				lbModel := common.LB_MODEL_INTERNAL
				if len(eips) > 0 {
					lbModel = common.LB_MODEL_EXTERNAL
				}
				retLBs = append(retLBs, model.LB{
					Lcuuid:       lbLcuuid,
					Name:         lbName,
					Label:        lbId,
					Model:        lbModel,
					VIP:          vip,
					VPCLcuuid:    vpcLcuuid,
					RegionLcuuid: regionLcuuid,
				})
				q.regionLcuuidToResourceNum[regionLcuuid]++

				// 添加VIP接口
				if vip != "" && subnetLcuuid != "" {
					vinterfaceLcuuid := common.GenerateUUID(lbLcuuid + vip)
					networkLcuuid := common.GenerateUUID(vxnetId)
					retVInterfaces = append(retVInterfaces, model.VInterface{
						Lcuuid:        vinterfaceLcuuid,
						Type:          common.VIF_TYPE_LAN,
						Mac:           common.VIF_DEFAULT_MAC,
						DeviceType:    common.VIF_DEVICE_TYPE_LB,
						DeviceLcuuid:  lbLcuuid,
						NetworkLcuuid: networkLcuuid,
						VPCLcuuid:     vpcLcuuid,
						RegionLcuuid:  regionLcuuid,
					})
					retIPs = append(retIPs, model.IP{
						Lcuuid:           common.GenerateUUID(vinterfaceLcuuid + vip),
						VInterfaceLcuuid: vinterfaceLcuuid,
						IP:               vip,
						SubnetLcuuid:     subnetLcuuid,
						RegionLcuuid:     regionLcuuid,
					})
				}
				// 添加外网IP及接口
				if len(eips) > 0 {
					vinterfaceLcuuid := common.GenerateUUID(lbLcuuid)
					retVInterfaces = append(retVInterfaces, model.VInterface{
						Lcuuid:        vinterfaceLcuuid,
						Type:          common.VIF_TYPE_WAN,
						Mac:           common.VIF_DEFAULT_MAC,
						DeviceType:    common.VIF_DEVICE_TYPE_LB,
						DeviceLcuuid:  lbLcuuid,
						NetworkLcuuid: common.NETWORK_ISP_LCUUID,
						VPCLcuuid:     vpcLcuuid,
						RegionLcuuid:  regionLcuuid,
					})
					for _, eip := range eips {
						retIPs = append(retIPs, model.IP{
							Lcuuid:           common.GenerateUUID(vinterfaceLcuuid + eip),
							VInterfaceLcuuid: vinterfaceLcuuid,
							IP:               eip,
							RegionLcuuid:     regionLcuuid,
						})
					}
					// 确定监听器的listen ip
					lbIdToIP[lbId] = strings.Join(eips, ",")
				} else {
					lbIdToIP[lbId] = vip
				}
				lbIdToVPCLcuuid[lbId] = vpcLcuuid
			}
		}
	}
	// 监听器及后端主机
	retLBListeners, retLBTargetServers, err := q.getLBListenerAndTargetServers(
		lbIdToVPCLcuuid, lbIdToIP,
	)
	if err != nil {
		return nil, nil, nil, nil, nil, nil, err
	}
	log.Info("get lbs complete")
	return retLBs, retLBListeners, retLBTargetServers, retVInterfaces, retIPs, retLBVMConnections, nil

}

func (q *QingCloud) getLBListenerAndTargetServers(
	lbIdToVPCLcuuid map[string]string, lbIdToIP map[string]string,
) ([]model.LBListener, []model.LBTargetServer, error) {
	var retLBListeners []model.LBListener
	var retLBTargetServers []model.LBTargetServer

	if q.DisableSyncLBListener {
		log.Infof("config disable sync lb listener is (%t)", q.DisableSyncLBListener)
		return retLBListeners, retLBTargetServers, nil
	}

	log.Info("get lb listener and target_servers starting")

	for regionId := range q.RegionIdToLcuuid {
		kwargs := []*Param{
			{"zone", regionId},
			{"status.1", "active"},
			{"status.2", "stopped"},
		}
		// 监听器
		response, err := q.GetResponse(
			"DescribeLoadBalancerListeners", "loadbalancer_listener_set", kwargs,
		)
		if err != nil {
			log.Error(err)
			return nil, nil, err
		}

		for _, r := range response {
			for i := range r.MustArray() {
				listener := r.GetIndex(i)
				err := q.CheckRequiredAttributes(listener, []string{
					"loadbalancer_listener_id", "loadbalancer_listener_name",
					"loadbalancer_id", "listener_protocol", "listener_port",
				})
				if err != nil {
					continue
				}

				lbId := listener.Get("loadbalancer_id").MustString()
				listenerId := listener.Get("loadbalancer_listener_id").MustString()
				listenerName := listener.Get("loadbalancer_listener_name").MustString()
				if listenerName == "" {
					listenerName = listenerId
				}
				vpcLcuuid, ok := lbIdToVPCLcuuid[lbId]
				if !ok {
					log.Debugf("lb_listener (%s) lb (%s) not found", listenerId, lbId)
					continue
				}
				lbIP, ok := lbIdToIP[lbId]
				if !ok {
					log.Debugf("lb_listener (%s) lb (%s) no ip", listenerId, lbId)
					continue
				}

				listenerLcuuid := common.GenerateUUID(listenerId)
				listenerProtocol := strings.ToUpper(listener.Get("listener_protocol").MustString())
				retLBListeners = append(retLBListeners, model.LBListener{
					Lcuuid:   listenerLcuuid,
					LBLcuuid: common.GenerateUUID(lbId),
					IPs:      lbIP,
					Name:     listenerName,
					Label:    listenerId,
					Port:     listener.Get("listener_port").MustInt(),
					Protocol: listenerProtocol,
				})

				// 后端主机
				kwargs = []*Param{
					{"zone", regionId},
					{"loadbalancer_listener", listenerId},
				}
				serverResponse, err := q.GetResponse(
					"DescribeLoadBalancerBackends", "loadbalancer_backend_set", kwargs,
				)
				if err != nil {
					log.Error(err)
					return nil, nil, err
				}

				for _, s := range serverResponse {
					for j := range s.MustArray() {
						server := s.GetIndex(j)
						err := q.CheckRequiredAttributes(server, []string{
							"loadbalancer_backend_id", "port", "private_ip", "resource_id",
						})
						if err != nil {
							continue
						}

						resourceId := server.Get("resource_id").MustString()
						serverType := common.LB_SERVER_TYPE_IP
						ip := resourceId
						vmLcuuid := ""
						address := net.ParseIP(resourceId)
						if address == nil {
							if _, ok := q.vmIdToVPCLcuuid[resourceId]; !ok {
								log.Debugf(
									"lb (%s) listener (%s) target_server (%s) not found",
									lbId, listenerId, resourceId,
								)
								continue
							}
							serverType = common.LB_SERVER_TYPE_VM
							vmLcuuid = common.GenerateUUID(resourceId)
							ip = server.Get("private_ip").MustString()
						}
						retLBTargetServers = append(retLBTargetServers, model.LBTargetServer{
							Lcuuid: common.GenerateUUID(
								server.Get("loadbalancer_backend_id").MustString(),
							),
							LBLcuuid:         common.GenerateUUID(lbId),
							LBListenerLcuuid: listenerLcuuid,
							Type:             serverType,
							VMLcuuid:         vmLcuuid,
							IP:               ip,
							Port:             server.Get("port").MustInt(),
							VPCLcuuid:        vpcLcuuid,
							Protocol:         listenerProtocol,
						})
					}
				}
			}
		}
	}
	log.Info("get lb listener and target_servers complete")
	return retLBListeners, retLBTargetServers, nil
}
