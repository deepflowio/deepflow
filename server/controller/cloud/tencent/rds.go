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

package tencent

import (
	"strings"

	"github.com/deepflowio/deepflow/server/controller/cloud/model"
	"github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/libs/logger"
)

func (t *Tencent) getRDSInstances(region string) ([]model.RDSInstance, []model.VInterface, []model.IP, error) {
	log.Debug("get rds instances starting", logger.NewORGPrefix(t.orgID))
	var rdss []model.RDSInstance
	var vinterfaces []model.VInterface
	var ips []model.IP

	// rds MySQL
	mInstances, mVInterfaces, mIPs, err := t.getRDSMySQL(region)
	if err != nil {
		return []model.RDSInstance{}, []model.VInterface{}, []model.IP{}, err
	}
	rdss = append(rdss, mInstances...)
	vinterfaces = append(vinterfaces, mVInterfaces...)
	ips = append(ips, mIPs...)

	// rds SQLServer
	sInstances, sVInterfaces, sIPs, err := t.getRDSSQLServer(region)
	if err != nil {
		return []model.RDSInstance{}, []model.VInterface{}, []model.IP{}, err
	}
	rdss = append(rdss, sInstances...)
	vinterfaces = append(vinterfaces, sVInterfaces...)
	ips = append(ips, sIPs...)

	// rds postgreSQL
	pInstances, pVInterfaces, pIPs, err := t.getRDSPostgreSQL(region)
	if err != nil {
		return []model.RDSInstance{}, []model.VInterface{}, []model.IP{}, err
	}
	rdss = append(rdss, pInstances...)
	vinterfaces = append(vinterfaces, pVInterfaces...)
	ips = append(ips, pIPs...)

	log.Debug("get rds instances complete", logger.NewORGPrefix(t.orgID))
	return rdss, vinterfaces, ips, nil
}

func (t *Tencent) getRDSMySQL(region string) ([]model.RDSInstance, []model.VInterface, []model.IP, error) {
	var rdss []model.RDSInstance
	var vinterfaces []model.VInterface
	var ips []model.IP

	resp, err := t.getResponse("cdb", "2017-03-20", "DescribeDBInstances", region, "Items", true, map[string]interface{}{})
	if err != nil {
		log.Errorf("rds mysql request tencent api error: (%s)", err.Error(), logger.NewORGPrefix(t.orgID))
		return []model.RDSInstance{}, []model.VInterface{}, []model.IP{}, err
	}
	for _, rData := range resp {
		rdsID := rData.Get("InstanceId").MustString()
		rdsLcuuid := common.GetUUIDByOrgID(t.orgID, rdsID)
		rdsName := rData.Get("InstanceName").MustString()
		zoneID := rData.Get("ZoneId").MustInt()
		azLcuuid, ok := t.azIDToLcuuid[zoneID]
		if !ok {
			log.Infof("rds mysql (%s) az (id:%d) not in available zones", rdsName, zoneID, logger.NewORGPrefix(t.orgID))
			continue
		}
		vpcLcuuid := common.GetUUIDByOrgID(t.orgID, rData.Get("UniqVpcId").MustString())
		var rdsModel = common.RDS_MODEL_PRIMARY
		if rData.Get("InstanceType").MustInt() != 1 {
			rdsModel = common.RDS_MODEL_SHARE
		}
		var rdsState = common.RDS_STATE_RUNNING
		if rData.Get("Status").MustInt() != 1 {
			rdsState = common.RDS_STATE_RESTORING
		}
		rdss = append(rdss, model.RDSInstance{
			Lcuuid:       rdsLcuuid,
			Name:         rdsName,
			Label:        rdsID,
			State:        rdsState,
			Type:         common.RDS_TYPE_MYSQL,
			Series:       common.RDS_SERIES_HA,
			Version:      rData.Get("EngineVersion").MustString(),
			Model:        rdsModel,
			VPCLcuuid:    vpcLcuuid,
			AZLcuuid:     azLcuuid,
			RegionLcuuid: t.regionLcuuid,
		})
		t.azLcuuidMap[azLcuuid] = 0

		address := rData.Get("Vip").MustString()
		vinterfaceLcuuid := common.GetUUIDByOrgID(t.orgID, rdsID+address)
		networkLcuuid := common.NETWORK_ISP_LCUUID
		subnetLcuuid := common.SUBNET_ISP_LCUUID
		subnetID := rData.Get("UniqSubnetId").MustString()
		if subnetID != "" {
			networkLcuuid = common.GetUUIDByOrgID(t.orgID, subnetID)
			subnetLcuuid = common.GetUUIDByOrgID(t.orgID, networkLcuuid+"_v4")
		}
		vinterfaces = append(vinterfaces, model.VInterface{
			Lcuuid:        vinterfaceLcuuid,
			Type:          common.VIF_TYPE_LAN,
			Mac:           common.VIF_DEFAULT_MAC,
			DeviceLcuuid:  rdsLcuuid,
			DeviceType:    common.VIF_DEVICE_TYPE_RDS_INSTANCE,
			VPCLcuuid:     vpcLcuuid,
			NetworkLcuuid: networkLcuuid,
			RegionLcuuid:  t.regionLcuuid,
		})

		ips = append(ips, model.IP{
			Lcuuid:           common.GetUUIDByOrgID(t.orgID, vinterfaceLcuuid+address),
			VInterfaceLcuuid: vinterfaceLcuuid,
			IP:               address,
			SubnetLcuuid:     subnetLcuuid,
			RegionLcuuid:     t.regionLcuuid,
		})
	}
	return rdss, vinterfaces, ips, nil
}

func (t *Tencent) getRDSSQLServer(region string) ([]model.RDSInstance, []model.VInterface, []model.IP, error) {
	var rdss []model.RDSInstance
	var vinterfaces []model.VInterface
	var ips []model.IP

	resp, err := t.getResponse("sqlserver", "2018-03-28", "DescribeDBInstances", region, "DBInstances", true, map[string]interface{}{})
	if err != nil {
		log.Errorf("rds sql server request tencent api error: (%s)", err.Error(), logger.NewORGPrefix(t.orgID))
		return []model.RDSInstance{}, []model.VInterface{}, []model.IP{}, err
	}
	for _, rData := range resp {
		rdsID := rData.Get("InstanceId").MustString()
		rdsLcuuid := common.GetUUIDByOrgID(t.orgID, rdsID)
		rdsName := rData.Get("Name").MustString()
		zoneID := rData.Get("ZoneId").MustInt()
		azLcuuid, ok := t.azIDToLcuuid[zoneID]
		if !ok {
			log.Infof("rds sql server (%s) az (id:%d) not in available zones", rdsName, zoneID, logger.NewORGPrefix(t.orgID))
			continue
		}
		vpcLcuuid := common.GetUUIDByOrgID(t.orgID, rData.Get("UniqVpcId").MustString())
		var rdsModel = common.RDS_MODEL_PRIMARY
		if rData.Get("InstanceType").MustInt() != 2 {
			rdsModel = common.RDS_MODEL_SHARE
		}
		var rdsSeries = common.RDS_SERIES_HA
		if !strings.HasPrefix(rData.Get("InstanceType").MustString(), "HA") {
			rdsSeries = common.RDS_SERIES_BASIC
		}
		var rdsState = common.RDS_STATE_RUNNING
		if rData.Get("Status").MustInt() != 2 {
			rdsState = common.RDS_STATE_RESTORING
		}
		rdss = append(rdss, model.RDSInstance{
			Lcuuid:       rdsLcuuid,
			Name:         rdsName,
			Label:        rdsID,
			State:        rdsState,
			Type:         common.RDS_TYPE_SQL_SERVER,
			Series:       rdsSeries,
			Version:      rData.Get("VersionName").MustString(),
			Model:        rdsModel,
			VPCLcuuid:    vpcLcuuid,
			AZLcuuid:     azLcuuid,
			RegionLcuuid: t.regionLcuuid,
		})
		t.azLcuuidMap[azLcuuid] = 0

		address := rData.Get("Vip").MustString()
		vinterfaceLcuuid := common.GetUUIDByOrgID(t.orgID, rdsID+address)
		networkLcuuid := common.NETWORK_ISP_LCUUID
		subnetLcuuid := common.SUBNET_ISP_LCUUID
		subnetID := rData.Get("UniqSubnetId").MustString()
		if subnetID != "" {
			networkLcuuid = common.GetUUIDByOrgID(t.orgID, subnetID)
			subnetLcuuid = common.GetUUIDByOrgID(t.orgID, networkLcuuid+"_v4")
		}
		vinterfaces = append(vinterfaces, model.VInterface{
			Lcuuid:        vinterfaceLcuuid,
			Type:          common.VIF_TYPE_LAN,
			Mac:           common.VIF_DEFAULT_MAC,
			DeviceLcuuid:  rdsLcuuid,
			DeviceType:    common.VIF_DEVICE_TYPE_RDS_INSTANCE,
			VPCLcuuid:     vpcLcuuid,
			NetworkLcuuid: networkLcuuid,
			RegionLcuuid:  t.regionLcuuid,
		})

		ips = append(ips, model.IP{
			Lcuuid:           common.GetUUIDByOrgID(t.orgID, vinterfaceLcuuid+address),
			VInterfaceLcuuid: vinterfaceLcuuid,
			IP:               address,
			SubnetLcuuid:     subnetLcuuid,
			RegionLcuuid:     t.regionLcuuid,
		})
	}
	return rdss, vinterfaces, ips, nil
}

func (t *Tencent) getRDSPostgreSQL(region string) ([]model.RDSInstance, []model.VInterface, []model.IP, error) {
	var rdss []model.RDSInstance
	var vinterfaces []model.VInterface
	var ips []model.IP

	resp, err := t.getResponse("postgres", "2017-03-12", "DescribeDBInstances", region, "DBInstanceSet", true, map[string]interface{}{})
	if err != nil {
		log.Errorf("rds postgresql request tencent api error: (%s)", err.Error(), logger.NewORGPrefix(t.orgID))
		return []model.RDSInstance{}, []model.VInterface{}, []model.IP{}, err
	}
	for _, rData := range resp {
		rdsID := rData.Get("DBInstanceId").MustString()
		rdsLcuuid := common.GetUUIDByOrgID(t.orgID, rdsID)
		rdsName := rData.Get("DBInstanceName").MustString()
		zone := rData.Get("Zone").MustString()
		azLcuuid, ok := t.zoneToLcuuid[zone]
		if !ok {
			log.Infof("rds postgresql (%s) az (zone:%s) not in available zones", rdsName, zone, logger.NewORGPrefix(t.orgID))
			continue
		}
		vpcLcuuid := common.GetUUIDByOrgID(t.orgID, rData.Get("VpcId").MustString())
		var rdsModel = common.RDS_MODEL_PRIMARY
		if rData.Get("DBInstanceType").MustString() != "primary" {
			rdsModel = common.RDS_MODEL_SHARE
		}
		var rdsState = common.RDS_STATE_RUNNING
		if rData.Get("DBInstanceStatus").MustString() != "running" {
			rdsState = common.RDS_STATE_RESTORING
		}
		rdss = append(rdss, model.RDSInstance{
			Lcuuid:       rdsLcuuid,
			Name:         rdsName,
			Label:        rdsID,
			State:        rdsState,
			Type:         common.RDS_TYPE_PSQL,
			Series:       common.RDS_SERIES_HA,
			Version:      rData.Get("DBVersion").MustString(),
			Model:        rdsModel,
			VPCLcuuid:    vpcLcuuid,
			AZLcuuid:     azLcuuid,
			RegionLcuuid: t.regionLcuuid,
		})
		t.azLcuuidMap[azLcuuid] = 0

		nets := rData.Get("DBInstanceNetInfo")
		for i := range nets.MustArray() {
			net := nets.GetIndex(i)
			if net.Get("Status").MustString() != "opened" {
				continue
			}
			vpcLcuuid = common.GetUUIDByOrgID(t.orgID, net.Get("VpcId").MustString())
			address := net.Get("Ip").MustString()
			vinterfaceLcuuid := common.GetUUIDByOrgID(t.orgID, rdsID+address)
			networkLcuuid := common.NETWORK_ISP_LCUUID
			subnetLcuuid := common.SUBNET_ISP_LCUUID
			subnetID := net.Get("SubnetId").MustString()
			if subnetID != "" {
				networkLcuuid = common.GetUUIDByOrgID(t.orgID, subnetID)
				subnetLcuuid = common.GetUUIDByOrgID(t.orgID, networkLcuuid+"_v4")
			}
			var netType = common.NETWORK_TYPE_LAN
			if net.Get("NetType").MustString() == "public" {
				netType = common.NETWORK_TYPE_WAN
			}
			vinterfaces = append(vinterfaces, model.VInterface{
				Lcuuid:        vinterfaceLcuuid,
				Type:          netType,
				Mac:           common.VIF_DEFAULT_MAC,
				DeviceLcuuid:  rdsLcuuid,
				DeviceType:    common.VIF_DEVICE_TYPE_RDS_INSTANCE,
				VPCLcuuid:     vpcLcuuid,
				NetworkLcuuid: networkLcuuid,
				RegionLcuuid:  t.regionLcuuid,
			})

			ips = append(ips, model.IP{
				Lcuuid:           common.GetUUIDByOrgID(t.orgID, vinterfaceLcuuid+address),
				VInterfaceLcuuid: vinterfaceLcuuid,
				IP:               address,
				SubnetLcuuid:     subnetLcuuid,
				RegionLcuuid:     t.regionLcuuid,
			})
		}
	}
	return rdss, vinterfaces, ips, nil
}
