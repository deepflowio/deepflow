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

	"github.com/baidubce/bce-sdk-go/services/rds"

	"github.com/deepflowio/deepflow/server/controller/cloud/model"
	"github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/libs/logger"
)

func (b *BaiduBce) getRDSInstances(vpcIdToLcuuid, networkIdToLcuuid, zoneNameToAZLcuuid map[string]string) ([]model.RDSInstance, []model.VInterface, []model.IP, error) {
	var retRDSInstances []model.RDSInstance
	var retVInterfaces []model.VInterface
	var retIPs []model.IP

	typeMap := map[string]int{
		"MySQL":      common.RDS_TYPE_MYSQL,
		"SQLServer":  common.RDS_TYPE_SQL_SERVER,
		"PostgreSQL": common.RDS_TYPE_PSQL,
	}

	seriesMap := map[string]int{
		"Singleton": common.RDS_SERIES_BASIC,
		"Basic":     common.RDS_SERIES_BASIC,
		"Standard":  common.RDS_SERIES_HA,
	}

	log.Debug("get rds_instances starting", logger.NewORGPrefix(b.orgID))

	rdsClient, _ := rds.NewClient(b.secretID, b.secretKey, "rds."+b.endpoint)
	rdsClient.Config.ConnectionTimeoutInMillis = b.httpTimeout * 1000
	marker := ""
	args := &rds.ListRdsArgs{}
	results := make([]*rds.ListRdsResult, 0)
	for {
		args.Marker = marker
		startTime := time.Now()
		result, err := rdsClient.ListRds(args)
		if err != nil {
			log.Error(err, logger.NewORGPrefix(b.orgID))
			return nil, nil, nil, err
		}
		b.cloudStatsd.RefreshAPIMoniter("ListRds", len(result.Instances), startTime)
		results = append(results, result)
		if !result.IsTruncated {
			break
		}
		marker = result.NextMarker
	}

	b.debugger.WriteJson("ListRds", " ", structToJson(results))
	for _, r := range results {
		for _, instance := range r.Instances {
			rds, err := rdsClient.GetDetail(instance.InstanceId)
			if err != nil {
				log.Error(err, logger.NewORGPrefix(b.orgID))
				return nil, nil, nil, err
			}
			vpcLcuuid, ok := vpcIdToLcuuid[rds.VpcId]
			if !ok {
				//log.Debugf("rds (%s) vpc (%s) not found", rds.InstanceId, rds.VpcId, logger.NewORGPrefix(b.orgID))
				continue
			}
			if len(rds.ZoneNames) == 0 {
				log.Debugf("rds (%s) with no zones", rds.InstanceId, logger.NewORGPrefix(b.orgID))
				continue
			}
			azLcuuid, ok := zoneNameToAZLcuuid[rds.ZoneNames[0]]
			if !ok {
				log.Debugf("rds (%s) zone (%s) not found", rds.InstanceId, rds.ZoneNames[0], logger.NewORGPrefix(b.orgID))
				continue
			}

			// 获取name
			rdsName := rds.InstanceName
			if rdsName == "" {
				rdsName = rds.InstanceId
			}
			// 获取series
			rdsSeries, ok := seriesMap[rds.Category]
			if !ok {
				rdsSeries = common.RDS_UNKNOWN
			}
			// 获取engine
			rdsEngine, ok := typeMap[rds.Engine]
			if !ok {
				rdsEngine = common.RDS_UNKNOWN
			}

			rdsLcuuid := common.GenerateUUIDByOrgID(b.orgID, rds.InstanceId)
			retRDSInstances = append(retRDSInstances, model.RDSInstance{
				Lcuuid:       rdsLcuuid,
				Name:         rdsName,
				Label:        rds.InstanceId,
				State:        common.RDS_STATE_RUNNING,
				Type:         rdsEngine,
				Series:       rdsSeries,
				Version:      rds.Engine + " " + rds.EngineVersion,
				Model:        common.RDS_MODEL_PRIMARY,
				VPCLcuuid:    vpcLcuuid,
				AZLcuuid:     azLcuuid,
				RegionLcuuid: b.regionLcuuid,
			})
			b.azLcuuidToResourceNum[azLcuuid]++

			if len(rds.Subnets) == 0 {
				log.Debugf("rds (%s) with no subnets", rds.InstanceId, logger.NewORGPrefix(b.orgID))
				continue
			}
			networkLcuuid, ok := networkIdToLcuuid[rds.Subnets[0].SubnetId]
			if !ok {
				log.Debugf("rds (%s) network (%s) not found", rds.InstanceId, rds.Subnets[0].SubnetId, logger.NewORGPrefix(b.orgID))
				continue
			}

			// 内网接口 + IP
			if rds.Endpoint.VnetIp != "" {
				vinterfaceLcuuid := common.GenerateUUIDByOrgID(b.orgID, rdsLcuuid+rds.Endpoint.VnetIp)
				retVInterfaces = append(retVInterfaces, model.VInterface{
					Lcuuid:        vinterfaceLcuuid,
					Type:          common.VIF_TYPE_LAN,
					Mac:           common.VIF_DEFAULT_MAC,
					DeviceLcuuid:  rdsLcuuid,
					DeviceType:    common.VIF_DEVICE_TYPE_RDS_INSTANCE,
					NetworkLcuuid: networkLcuuid,
					VPCLcuuid:     vpcLcuuid,
					RegionLcuuid:  b.regionLcuuid,
				})
				retIPs = append(retIPs, model.IP{
					Lcuuid:           common.GenerateUUIDByOrgID(b.orgID, vinterfaceLcuuid+rds.Endpoint.VnetIp),
					VInterfaceLcuuid: vinterfaceLcuuid,
					IP:               rds.Endpoint.VnetIp,
					SubnetLcuuid:     common.GenerateUUIDByOrgID(b.orgID, networkLcuuid),
					RegionLcuuid:     b.regionLcuuid,
				})
			}

			// 公网接口 + IP
			if rds.Endpoint.InetIp != "" {
				vinterfaceLcuuid := common.GenerateUUIDByOrgID(b.orgID, rdsLcuuid+rds.Endpoint.InetIp)
				retVInterfaces = append(retVInterfaces, model.VInterface{
					Lcuuid:        vinterfaceLcuuid,
					Type:          common.VIF_TYPE_WAN,
					Mac:           common.VIF_DEFAULT_MAC,
					DeviceLcuuid:  rdsLcuuid,
					DeviceType:    common.VIF_DEVICE_TYPE_RDS_INSTANCE,
					NetworkLcuuid: common.NETWORK_ISP_LCUUID,
					VPCLcuuid:     vpcLcuuid,
					RegionLcuuid:  b.regionLcuuid,
				})
				retIPs = append(retIPs, model.IP{
					Lcuuid:           common.GenerateUUIDByOrgID(b.orgID, vinterfaceLcuuid+rds.Endpoint.InetIp),
					VInterfaceLcuuid: vinterfaceLcuuid,
					IP:               rds.Endpoint.InetIp,
					RegionLcuuid:     b.regionLcuuid,
				})
			}
		}
	}
	log.Debug("get rds_instances complete", logger.NewORGPrefix(b.orgID))
	return retRDSInstances, retVInterfaces, retIPs, nil
}
