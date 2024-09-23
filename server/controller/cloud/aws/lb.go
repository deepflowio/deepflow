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

package aws

import (
	"context"
	"strconv"

	"inet.af/netaddr"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/elasticloadbalancing"
	"github.com/aws/aws-sdk-go-v2/service/elasticloadbalancing/types"
	"github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
	v2types "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2/types"
	"github.com/deepflowio/deepflow/server/controller/cloud/model"
	"github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/libs/logger"
)

func (a *Aws) getLoadBalances(region string) ([]model.LB, []model.LBListener, []model.LBTargetServer, error) {
	log.Debug("get load balances starting", logger.NewORGPrefix(a.orgID))
	var lbs []model.LB
	var lbListeners []model.LBListener
	var lbTargetServers []model.LBTargetServer

	v2ClientConfig, err := config.LoadDefaultConfig(context.TODO(), a.credential, config.WithRegion(region), config.WithHTTPClient(a.httpClient))
	if err != nil {
		log.Error(err.Error(), logger.NewORGPrefix(a.orgID))
		return []model.LB{}, []model.LBListener{}, []model.LBTargetServer{}, err
	}

	var retLBs []types.LoadBalancerDescription
	var marker string
	var pageSize int32 = 100
	for {
		var input *elasticloadbalancing.DescribeLoadBalancersInput
		if marker == "" {
			input = &elasticloadbalancing.DescribeLoadBalancersInput{PageSize: &pageSize}
		} else {
			input = &elasticloadbalancing.DescribeLoadBalancersInput{PageSize: &pageSize, Marker: &marker}
		}
		result, err := elasticloadbalancing.NewFromConfig(v2ClientConfig).DescribeLoadBalancers(context.TODO(), input)
		if err != nil {
			log.Errorf("load balance request aws api error: (%s)", err.Error(), logger.NewORGPrefix(a.orgID))
			return []model.LB{}, []model.LBListener{}, []model.LBTargetServer{}, err
		}
		retLBs = append(retLBs, result.LoadBalancerDescriptions...)
		if result.NextMarker == nil {
			break
		}
		marker = *result.NextMarker
	}

	for _, lData := range retLBs {
		lbModel := common.LB_MODEL_EXTERNAL
		if a.getStringPointerValue(lData.Scheme) == "internal" {
			lbModel = common.LB_MODEL_INTERNAL
		}
		lbDNSName := a.getStringPointerValue(lData.DNSName)
		lbLcuuid := common.GetUUIDByOrgID(a.orgID, lbDNSName)
		vpcLcuuid := common.GetUUIDByOrgID(a.orgID, a.getStringPointerValue(lData.VPCId))
		lbs = append(lbs, model.LB{
			Lcuuid:       lbLcuuid,
			Name:         a.getStringPointerValue(lData.LoadBalancerName),
			Model:        lbModel,
			VPCLcuuid:    vpcLcuuid,
			RegionLcuuid: a.regionLcuuid,
		})

		for _, listener := range lData.ListenerDescriptions {
			if listener.Listener == nil {
				log.Debug("listener is nil", logger.NewORGPrefix(a.orgID))
				continue
			}
			protocol := a.getStringPointerValue(listener.Listener.Protocol)
			lbPort := listener.Listener.LoadBalancerPort
			key := protocol + " : " + strconv.Itoa(int(lbPort))
			listenerLcuuid := common.GetUUIDByOrgID(a.orgID, lbDNSName+key)
			lbListeners = append(lbListeners, model.LBListener{
				Lcuuid:   listenerLcuuid,
				LBLcuuid: lbLcuuid,
				IPs:      lbDNSName,
				Name:     key,
				Port:     int(lbPort),
				Protocol: protocol,
			})

			for _, server := range lData.Instances {
				serverInstanceID := a.getStringPointerValue(server.InstanceId)
				ip, ok := a.vmIDToPrivateIP[serverInstanceID]
				if !ok {
					log.Info("lb target server (%s) ip not found", serverInstanceID, logger.NewORGPrefix(a.orgID))
					continue
				}
				lbTargetServers = append(lbTargetServers, model.LBTargetServer{
					Lcuuid:           common.GetUUIDByOrgID(a.orgID, listenerLcuuid+serverInstanceID),
					LBLcuuid:         lbLcuuid,
					LBListenerLcuuid: listenerLcuuid,
					Type:             common.LB_SERVER_TYPE_VM,
					VMLcuuid:         common.GetUUIDByOrgID(a.orgID, serverInstanceID),
					Port:             int(listener.Listener.InstancePort),
					VPCLcuuid:        vpcLcuuid,
					IP:               ip,
					Protocol:         a.getStringPointerValue(listener.Listener.InstanceProtocol),
				})
			}
		}
	}

	v2Client := elasticloadbalancingv2.NewFromConfig(v2ClientConfig)
	var v2RetLBs []v2types.LoadBalancer
	var v2Marker string
	var v2PageSize int32 = 100
	for {
		var input *elasticloadbalancingv2.DescribeLoadBalancersInput
		if v2Marker == "" {
			input = &elasticloadbalancingv2.DescribeLoadBalancersInput{PageSize: &v2PageSize}
		} else {
			input = &elasticloadbalancingv2.DescribeLoadBalancersInput{PageSize: &v2PageSize, Marker: &v2Marker}
		}
		result, err := v2Client.DescribeLoadBalancers(context.TODO(), input)
		if err != nil {
			log.Errorf("load balance v2 request aws api error: (%s)", err.Error(), logger.NewORGPrefix(a.orgID))
			return []model.LB{}, []model.LBListener{}, []model.LBTargetServer{}, err
		}
		v2RetLBs = append(v2RetLBs, result.LoadBalancers...)
		if result.NextMarker == nil {
			break
		}
		v2Marker = *result.NextMarker
	}

	for _, v2LData := range v2RetLBs {
		v2LBModel := common.LB_MODEL_EXTERNAL
		if v2LData.Scheme == "internal" {
			v2LBModel = common.LB_MODEL_INTERNAL
		}
		v2LBName := a.getStringPointerValue(v2LData.LoadBalancerName)
		v2LBArn := a.getStringPointerValue(v2LData.LoadBalancerArn)
		if v2LBArn == "" {
			log.Infof("load balance v2 lb (%s) LoadBalancerArn not found", v2LBName, logger.NewORGPrefix(a.orgID))
			continue
		}
		v2LBLcuuid := common.GetUUIDByOrgID(a.orgID, v2LBArn)
		v2VPCLcuuid := common.GetUUIDByOrgID(a.orgID, a.getStringPointerValue(v2LData.VpcId))
		lbs = append(lbs, model.LB{
			Lcuuid:       v2LBLcuuid,
			Name:         v2LBName,
			Model:        v2LBModel,
			VPCLcuuid:    v2VPCLcuuid,
			RegionLcuuid: a.regionLcuuid,
		})

		v2RetListeners, err := v2Client.DescribeListeners(context.TODO(), &elasticloadbalancingv2.DescribeListenersInput{LoadBalancerArn: v2LData.LoadBalancerArn})
		if err != nil {
			log.Errorf("load balance listener v2 request aws api error: (%s)", err.Error(), logger.NewORGPrefix(a.orgID))
			return []model.LB{}, []model.LBListener{}, []model.LBTargetServer{}, err
		}
		for _, v2Listener := range v2RetListeners.Listeners {
			v2ListenerArn := a.getStringPointerValue(v2Listener.ListenerArn)
			v2ListenerPort := a.getInt32PointerValue(v2Listener.Port)
			v2ListenerPotocol := v2Listener.Protocol
			v2ListenerLcuuid := common.GetUUIDByOrgID(a.orgID, v2ListenerArn)
			lbListeners = append(lbListeners, model.LBListener{
				Lcuuid:   v2ListenerLcuuid,
				LBLcuuid: v2LBLcuuid,
				IPs:      a.getStringPointerValue(v2LData.DNSName),
				Name:     string(v2ListenerPotocol) + " : " + strconv.Itoa(int(v2ListenerPort)),
				Port:     int(v2ListenerPort),
				Protocol: string(v2ListenerPotocol),
			})

			for _, targetGrop := range v2Listener.DefaultActions {
				if a.getStringPointerValue(targetGrop.TargetGroupArn) == "" {
					continue
				}
				v2RetServers, err := v2Client.DescribeTargetHealth(context.TODO(), &elasticloadbalancingv2.DescribeTargetHealthInput{TargetGroupArn: targetGrop.TargetGroupArn})
				if err != nil {
					log.Errorf("load balance target server v2 request aws api error: (%s)", err.Error(), logger.NewORGPrefix(a.orgID))
					return []model.LB{}, []model.LBListener{}, []model.LBTargetServer{}, err
				}
				for _, v2TargetServer := range v2RetServers.TargetHealthDescriptions {
					var v2TargetIP string
					var v2TargetVMLcuuid string
					var v2TargetType int
					if v2TargetServer.Target == nil {
						log.Debug("target is nil", logger.NewORGPrefix(a.orgID))
						continue
					}
					v2TargetID := a.getStringPointerValue(v2TargetServer.Target.Id)
					v2TargetPort := a.getInt32PointerValue(v2TargetServer.Target.Port)
					netTargetIP, err := netaddr.ParseIP(v2TargetID)
					if err == nil && netTargetIP.Is4() {
						v2TargetIP = v2TargetID
						v2TargetType = common.LB_SERVER_TYPE_IP
					} else {
						v2TargetIP = a.vmIDToPrivateIP[v2TargetID]
						if v2TargetIP == "" {
							log.Info("lb target server v2 (%s) ip not found", v2TargetID, logger.NewORGPrefix(a.orgID))
							continue
						}
						v2TargetType = common.LB_SERVER_TYPE_VM
						v2TargetVMLcuuid = common.GetUUIDByOrgID(a.orgID, v2TargetID)
					}
					lbTargetServers = append(lbTargetServers, model.LBTargetServer{
						Lcuuid:           common.GetUUIDByOrgID(a.orgID, v2ListenerArn+v2TargetID+strconv.Itoa(int(v2TargetPort))),
						LBLcuuid:         v2LBLcuuid,
						LBListenerLcuuid: v2ListenerLcuuid,
						Port:             int(v2TargetPort),
						VPCLcuuid:        v2VPCLcuuid,
						Protocol:         string(v2ListenerPotocol),
						Type:             v2TargetType,
						IP:               v2TargetIP,
						VMLcuuid:         v2TargetVMLcuuid,
					})
				}
			}
		}
	}
	log.Debug("get load balances complete", logger.NewORGPrefix(a.orgID))
	return lbs, lbListeners, lbTargetServers, nil
}
