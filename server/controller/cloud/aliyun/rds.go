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
	rds "github.com/aliyun/alibaba-cloud-sdk-go/services/rds"
	"github.com/deepflowio/deepflow/server/controller/cloud/model"
	"github.com/deepflowio/deepflow/server/controller/common"
)

func (a *Aliyun) getRDSInstances(region model.Region) (
	[]model.RDSInstance, []model.VInterface, []model.IP, error,
) {
	var retRDSInstances []model.RDSInstance
	var retVInterfaces []model.VInterface
	var retIPs []model.IP

	typeMap := map[string]int{
		"MySQL":      common.RDS_TYPE_MYSQL,
		"SQLServer":  common.RDS_TYPE_SQL_SERVER,
		"PPAS":       common.RDS_TYPE_PPAS,
		"PostgreSQL": common.RDS_TYPE_PSQL,
		"MariaDB":    common.RDS_TYPE_MARIADB,
	}

	stateMap := map[string]int{
		"Running":   common.RDS_STATE_RUNNING,
		"Restoring": common.RDS_STATE_RESTORING,
	}

	seriesMap := map[string]int{
		"Basic":            common.RDS_SERIES_BASIC,
		"HighAvailability": common.RDS_SERIES_HA,
	}

	modelMap := map[string]int{
		"Primary":  common.RDS_MODEL_PRIMARY,
		"Readonly": common.RDS_MODEL_READONLY,
		"Temp":     common.RDS_MODEL_TEMPORARY,
		"Guard":    common.RDS_MODEL_GUARD,
		"Share":    common.RDS_MODEL_SHARE,
	}

	log.Debug("get rds_instances starting")
	request := rds.CreateDescribeDBInstancesRequest()
	response, err := a.getRDSResponse(region.Label, request)
	if err != nil {
		log.Error(err)
		return retRDSInstances, retVInterfaces, retIPs, err
	}

	for _, r := range response {
		instances, _ := r.Get("DBInstance").Array()
		for i := range instances {
			dbRds := r.Get("DBInstance").GetIndex(i)

			err := a.checkRequiredAttributes(
				dbRds,
				[]string{
					"DBInstanceId", "DBInstanceStatus", "DBInstanceType", "Engine",
					"EngineVersion", "VpcId", "ZoneId",
				},
			)
			if err != nil {
				continue
			}

			rdsId := dbRds.Get("DBInstanceId").MustString()
			rdsName := dbRds.Get("DBInstanceDescription").MustString()
			if rdsName == "" {
				rdsName = rdsId
			}
			state := dbRds.Get("DBInstanceStatus").MustString()
			rdsState, ok := stateMap[state]
			if !ok {
				rdsState = common.RDS_UNKNOWN
			}
			dbType := dbRds.Get("DBInstanceType").MustString()
			rdsModel, ok := modelMap[dbType]
			if !ok {
				rdsModel = common.RDS_UNKNOWN
			}
			engine := dbRds.Get("Engine").MustString()
			rdsEngine, ok := typeMap[engine]
			if !ok {
				rdsEngine = common.RDS_UNKNOWN
			}
			vpcId := dbRds.Get("VpcId").MustString()
			zoneId := dbRds.Get("ZoneId").MustString()

			// 获取额外属性信息
			attrRequest := rds.CreateDescribeDBInstanceAttributeRequest()
			attrRequest.DBInstanceId = rdsId
			attrResponse, err := a.getRDSAttributeResponse(region.Label, attrRequest)
			if err != nil {
				log.Error(err)
				return []model.RDSInstance{}, []model.VInterface{}, []model.IP{}, err
			}

			rdsSeries := common.RDS_UNKNOWN
			for _, rAttr := range attrResponse {
				for j := range rAttr.Get("DBInstanceAttribute").MustArray() {
					attr := rAttr.Get("DBInstanceAttribute").GetIndex(j)
					series := attr.Get("Category").MustString()
					rdsSeries, ok = seriesMap[series]
					if !ok {
						rdsSeries = common.RDS_UNKNOWN
					}
				}
			}

			rdsLcuuid := common.GenerateUUID(rdsId)
			vpcLcuuid := common.GenerateUUID(vpcId)
			retRDSInstance := model.RDSInstance{
				Lcuuid:       rdsLcuuid,
				Name:         rdsName,
				Label:        rdsId,
				VPCLcuuid:    vpcLcuuid,
				AZLcuuid:     common.GenerateUUID(a.uuidGenerate + "_" + zoneId),
				RegionLcuuid: a.getRegionLcuuid(region.Lcuuid),
				State:        rdsState,
				Type:         rdsEngine,
				Series:       rdsSeries,
				Version:      engine + " " + dbRds.Get("EngineVersion").MustString(),
				Model:        rdsModel,
			}
			retRDSInstances = append(retRDSInstances, retRDSInstance)
			a.azLcuuidToResourceNum[retRDSInstance.AZLcuuid]++
			a.regionLcuuidToResourceNum[retRDSInstance.RegionLcuuid]++

			// 获取接口信息
			tmpVInterfaces, tmpIPs, err := a.getRDSPorts(region, rdsId)
			if err != nil {
				return []model.RDSInstance{}, []model.VInterface{}, []model.IP{}, err
			}
			retVInterfaces = append(retVInterfaces, tmpVInterfaces...)
			retIPs = append(retIPs, tmpIPs...)
		}
	}
	log.Debug("get rds_instances complete")
	return retRDSInstances, retVInterfaces, retIPs, nil
}

func (a *Aliyun) getRDSPorts(region model.Region, rdsId string) ([]model.VInterface, []model.IP, error) {
	var retVInterfaces []model.VInterface
	var retIPs []model.IP

	request := rds.CreateDescribeDBInstanceNetInfoRequest()
	request.DBInstanceId = rdsId
	response, err := a.getRDSVInterfaceResponse(region.Label, request)
	if err != nil {
		log.Error(err)
		return []model.VInterface{}, []model.IP{}, err
	}

	rdsLcuuid := common.GenerateUUID(rdsId)
	for _, rNet := range response {
		for j := range rNet.Get("DBInstanceNetInfo").MustArray() {
			net := rNet.Get("DBInstanceNetInfo").GetIndex(j)

			ip := net.Get("IPAddress").MustString()
			if ip == "" {
				continue
			}
			portLcuuid := common.GenerateUUID(rdsLcuuid + ip)
			portType := common.VIF_TYPE_LAN
			vpcLcuuid := common.GenerateUUID(net.Get("VPCId").MustString())
			networkLcuuid := common.GenerateUUID(net.Get("VSwitchId").MustString())
			if net.Get("IPType").MustString() == "Public" {
				portType = common.VIF_TYPE_WAN
				networkLcuuid = common.NETWORK_ISP_LCUUID
			}
			retVInterface := model.VInterface{
				Lcuuid:        portLcuuid,
				Type:          portType,
				Mac:           common.VIF_DEFAULT_MAC,
				DeviceLcuuid:  rdsLcuuid,
				DeviceType:    common.VIF_DEVICE_TYPE_RDS_INSTANCE,
				NetworkLcuuid: networkLcuuid,
				VPCLcuuid:     vpcLcuuid,
				RegionLcuuid:  a.getRegionLcuuid(region.Lcuuid),
			}
			retVInterfaces = append(retVInterfaces, retVInterface)

			retIP := model.IP{
				Lcuuid:           common.GenerateUUID(portLcuuid + ip),
				VInterfaceLcuuid: portLcuuid,
				IP:               ip,
				SubnetLcuuid:     common.GenerateUUID(networkLcuuid),
				RegionLcuuid:     a.getRegionLcuuid(region.Lcuuid),
			}
			retIPs = append(retIPs, retIP)
		}
	}
	return retVInterfaces, retIPs, nil
}
