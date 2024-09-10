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

package baidubce

import (
	"time"

	"github.com/baidubce/bce-sdk-go/services/appblb"
	"github.com/baidubce/bce-sdk-go/services/blb"

	"github.com/deepflowio/deepflow/server/controller/cloud/model"
	"github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/libs/logger"
)

func (b *BaiduBce) getLoadBalances(vpcIdToLcuuid map[string]string, networkIdToLcuuid map[string]string) (
	[]model.LB, []model.VInterface, []model.IP, error,
) {
	var retLBs []model.LB
	var retVInterfaces []model.VInterface
	var retIPs []model.IP

	log.Debug("get lbs starting", logger.NewORGPrefix(b.orgID))

	// 普通型负载均衡器
	tmpLBs, tmpVInterfaces, tmpIPs, err := b.getBLoadBalances(vpcIdToLcuuid, networkIdToLcuuid)
	if err != nil {
		return nil, nil, nil, err
	}
	retLBs = append(retLBs, tmpLBs...)
	retVInterfaces = append(retVInterfaces, tmpVInterfaces...)
	retIPs = append(retIPs, tmpIPs...)

	// 应用型负载均衡器
	tmpLBs, tmpVInterfaces, tmpIPs, err = b.getAppBLoadBalances(vpcIdToLcuuid, networkIdToLcuuid)
	if err != nil {
		return nil, nil, nil, err
	}
	retLBs = append(retLBs, tmpLBs...)
	retVInterfaces = append(retVInterfaces, tmpVInterfaces...)
	retIPs = append(retIPs, tmpIPs...)

	log.Debug("get lbs complete", logger.NewORGPrefix(b.orgID))
	return retLBs, retVInterfaces, retIPs, nil
}

func (b *BaiduBce) getBLoadBalances(vpcIdToLcuuid map[string]string, networkIdToLcuuid map[string]string) (
	[]model.LB, []model.VInterface, []model.IP, error,
) {
	var retLBs []model.LB
	var retVInterfaces []model.VInterface
	var retIPs []model.IP

	log.Debug("get blbs starting", logger.NewORGPrefix(b.orgID))

	blbClient, _ := blb.NewClient(b.secretID, b.secretKey, "blb."+b.endpoint)
	blbClient.Config.ConnectionTimeoutInMillis = b.httpTimeout * 1000
	marker := ""
	args := &blb.DescribeLoadBalancersArgs{}
	results := make([]*blb.DescribeLoadBalancersResult, 0)
	for {
		args.Marker = marker
		startTime := time.Now()
		result, err := blbClient.DescribeLoadBalancers(args)
		if err != nil {
			log.Error(err, logger.NewORGPrefix(b.orgID))
			return nil, nil, nil, err
		}
		b.cloudStatsd.RefreshAPIMoniter("blbDescribeLoadBalancers", len(result.BlbList), startTime)
		results = append(results, result)
		if !result.IsTruncated {
			break
		}
		marker = result.NextMarker
	}

	b.debugger.WriteJson("blbDescribeLoadBalancers", " ", structToJson(results))
	for _, r := range results {
		for _, lb := range r.BlbList {
			vpcLcuuid, ok := vpcIdToLcuuid[lb.VpcId]
			if !ok {
				log.Debugf("lb (%s) vpc (%s) not found", lb.BlbId, lb.VpcId, logger.NewORGPrefix(b.orgID))
				continue
			}
			networkLcuuid, ok := networkIdToLcuuid[lb.SubnetId]
			if !ok {
				log.Debugf("lb (%s) network (%s) not found", lb.BlbId, lb.SubnetId, logger.NewORGPrefix(b.orgID))
				continue
			}
			lbLcuuid := common.GenerateUUIDByOrgID(b.orgID, lb.BlbId)
			retLB := model.LB{
				Lcuuid:       lbLcuuid,
				Name:         lb.Name,
				Label:        lb.BlbId,
				Model:        common.LB_MODEL_INTERNAL,
				VPCLcuuid:    vpcLcuuid,
				RegionLcuuid: b.regionLcuuid,
			}
			retLBs = append(retLBs, retLB)

			tmpVInterfaces, tmpIPs := b.getLBVInterfaceAndIPs(
				vpcLcuuid, networkLcuuid, lbLcuuid, lb.Address, lb.PublicIp,
			)
			retVInterfaces = append(retVInterfaces, tmpVInterfaces...)
			retIPs = append(retIPs, tmpIPs...)
		}
	}
	log.Debug("get blbs complete", logger.NewORGPrefix(b.orgID))
	return retLBs, retVInterfaces, retIPs, nil
}

func (b *BaiduBce) getAppBLoadBalances(vpcIdToLcuuid map[string]string, networkIdToLcuuid map[string]string) (
	[]model.LB, []model.VInterface, []model.IP, error) {
	var retLBs []model.LB
	var retVInterfaces []model.VInterface
	var retIPs []model.IP

	log.Debug("get app_blbs starting", logger.NewORGPrefix(b.orgID))

	appblbClient, _ := appblb.NewClient(b.secretID, b.secretKey, "blb."+b.endpoint)
	appblbClient.Config.ConnectionTimeoutInMillis = b.httpTimeout * 1000
	marker := ""
	args := &appblb.DescribeLoadBalancersArgs{}
	results := make([]*appblb.DescribeLoadBalancersResult, 0)
	for {
		args.Marker = marker
		startTime := time.Now()
		result, err := appblbClient.DescribeLoadBalancers(args)
		if err != nil {
			log.Error(err, logger.NewORGPrefix(b.orgID))
			return nil, nil, nil, err
		}
		b.cloudStatsd.RefreshAPIMoniter("appblbDescribeLoadBalancers", len(result.BlbList), startTime)
		results = append(results, result)
		if !result.IsTruncated {
			break
		}
		marker = result.NextMarker
	}

	b.debugger.WriteJson("appblbDescribeLoadBalancers", " ", structToJson(results))
	for _, r := range results {
		for _, lb := range r.BlbList {
			vpcLcuuid, ok := vpcIdToLcuuid[lb.VpcId]
			if !ok {
				log.Debugf("lb (%s) vpc (%s) not found", lb.BlbId, lb.VpcId, logger.NewORGPrefix(b.orgID))
				continue
			}
			networkLcuuid, ok := networkIdToLcuuid[lb.SubnetId]
			if !ok {
				log.Debugf("lb (%s) network (%s) not found", lb.BlbId, lb.SubnetId, logger.NewORGPrefix(b.orgID))
				continue
			}
			lbLcuuid := common.GenerateUUIDByOrgID(b.orgID, lb.BlbId)
			retLB := model.LB{
				Lcuuid:       lbLcuuid,
				Name:         lb.Name,
				Label:        lb.BlbId,
				Model:        common.LB_MODEL_INTERNAL,
				VPCLcuuid:    vpcLcuuid,
				RegionLcuuid: b.regionLcuuid,
			}
			retLBs = append(retLBs, retLB)

			tmpVInterfaces, tmpIPs := b.getLBVInterfaceAndIPs(
				vpcLcuuid, networkLcuuid, lbLcuuid, lb.Address, lb.PublicIp,
			)
			retVInterfaces = append(retVInterfaces, tmpVInterfaces...)
			retIPs = append(retIPs, tmpIPs...)
		}
	}
	log.Debug("get app_blbs complete", logger.NewORGPrefix(b.orgID))
	return retLBs, retVInterfaces, retIPs, nil
}

func (b *BaiduBce) getLBVInterfaceAndIPs(vpcLcuuid, networkLcuuid, lbLcuuid, ip, publicIP string) ([]model.VInterface, []model.IP) {

	var retVInterfaces []model.VInterface
	var retIPs []model.IP

	// 内网接口+IP
	if ip != "" {
		vinterfaceLcuuid := common.GenerateUUIDByOrgID(b.orgID, lbLcuuid+ip)
		retVInterfaces = append(retVInterfaces, model.VInterface{
			Lcuuid:        vinterfaceLcuuid,
			Type:          common.VIF_TYPE_LAN,
			Mac:           common.VIF_DEFAULT_MAC,
			DeviceLcuuid:  lbLcuuid,
			DeviceType:    common.VIF_DEVICE_TYPE_LB,
			NetworkLcuuid: networkLcuuid,
			VPCLcuuid:     vpcLcuuid,
			RegionLcuuid:  b.regionLcuuid,
		})
		retIPs = append(retIPs, model.IP{
			Lcuuid:           common.GenerateUUIDByOrgID(b.orgID, vinterfaceLcuuid+ip),
			VInterfaceLcuuid: vinterfaceLcuuid,
			IP:               ip,
			SubnetLcuuid:     common.GenerateUUIDByOrgID(b.orgID, networkLcuuid),
			RegionLcuuid:     b.regionLcuuid,
		})
	}

	// 公网接口+IP
	if publicIP != "" {
		vinterfaceLcuuid := common.GenerateUUIDByOrgID(b.orgID, lbLcuuid+publicIP)
		retVInterfaces = append(retVInterfaces, model.VInterface{
			Lcuuid:        vinterfaceLcuuid,
			Type:          common.VIF_TYPE_WAN,
			Mac:           common.VIF_DEFAULT_MAC,
			DeviceLcuuid:  lbLcuuid,
			DeviceType:    common.VIF_DEVICE_TYPE_LB,
			NetworkLcuuid: common.NETWORK_ISP_LCUUID,
			VPCLcuuid:     vpcLcuuid,
			RegionLcuuid:  b.regionLcuuid,
		})
		retIPs = append(retIPs, model.IP{
			Lcuuid:           common.GenerateUUIDByOrgID(b.orgID, vinterfaceLcuuid+publicIP),
			VInterfaceLcuuid: vinterfaceLcuuid,
			IP:               publicIP,
			RegionLcuuid:     b.regionLcuuid,
		})
	}
	return retVInterfaces, retIPs
}
