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

package volcengine

import (
	"strings"

	"github.com/deepflowio/deepflow/server/controller/cloud/model"
	"github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/libs/logger"
	"github.com/volcengine/volcengine-go-sdk/service/rdsmssql"
	"github.com/volcengine/volcengine-go-sdk/service/rdsmysqlv2"
	"github.com/volcengine/volcengine-go-sdk/service/rdspostgresql"
	"github.com/volcengine/volcengine-go-sdk/volcengine/session"
)

func (v *VolcEngine) getRDSInstances(sess *session.Session) ([]model.RDSInstance, []model.VInterface, []model.IP, error) {
	log.Debug("get rds instances starting", logger.NewORGPrefix(v.orgID))
	var rdss []model.RDSInstance
	var vinterfaces []model.VInterface
	var ips []model.IP

	// rds MySQL
	mInstances, mVInterfaces, mIPs, err := v.getRDSMySQL(sess)
	if err != nil {
		return []model.RDSInstance{}, []model.VInterface{}, []model.IP{}, err
	}
	rdss = append(rdss, mInstances...)
	vinterfaces = append(vinterfaces, mVInterfaces...)
	ips = append(ips, mIPs...)

	// rds postgreSQL
	pInstances, pVInterfaces, pIPs, err := v.getRDSPostgreSQL(sess)
	if err != nil {
		return []model.RDSInstance{}, []model.VInterface{}, []model.IP{}, err
	}
	rdss = append(rdss, pInstances...)
	vinterfaces = append(vinterfaces, pVInterfaces...)
	ips = append(ips, pIPs...)

	// rds SQLServer
	sInstances, sVInterfaces, sIPs, err := v.getRDSSQLServer(sess)
	if err != nil {
		return []model.RDSInstance{}, []model.VInterface{}, []model.IP{}, err
	}
	rdss = append(rdss, sInstances...)
	vinterfaces = append(vinterfaces, sVInterfaces...)
	ips = append(ips, sIPs...)

	log.Debug("get rds instances complete", logger.NewORGPrefix(v.orgID))
	return rdss, vinterfaces, ips, nil
}

func (v *VolcEngine) getRDSMySQL(sess *session.Session) ([]model.RDSInstance, []model.VInterface, []model.IP, error) {
	var rdss []model.RDSInstance
	var vinterfaces []model.VInterface
	var ips []model.IP

	var retRDSs []*rdsmysqlv2.InstanceForDescribeDBInstancesOutput
	var pageNumber, pageSize int32 = 1, 100
	for {
		result, err := rdsmysqlv2.New(sess).DescribeDBInstances(&rdsmysqlv2.DescribeDBInstancesInput{PageNumber: &pageNumber, PageSize: &pageSize})
		if err != nil {
			log.Errorf("request volcengine (rdsmysqlv2.DescribeDBInstances) api error: (%s)", err.Error(), logger.NewORGPrefix(v.orgID))
			return []model.RDSInstance{}, []model.VInterface{}, []model.IP{}, err
		}
		retRDSs = append(retRDSs, result.Instances...)
		if len(result.Instances) < int(pageSize) {
			break
		}
		pageSize += 1
	}

	for _, rds := range retRDSs {
		if rds == nil || rds.InstanceId == nil {
			continue
		}

		rdsDetail, err := rdsmysqlv2.New(sess).DescribeDBInstanceDetail(&rdsmysqlv2.DescribeDBInstanceDetailInput{InstanceId: rds.InstanceId})
		if err != nil {
			log.Errorf("request volcengine (rdsmysqlv2.DescribeDBInstanceDetail) api error: (%s)", err.Error(), logger.NewORGPrefix(v.orgID))
			return []model.RDSInstance{}, []model.VInterface{}, []model.IP{}, err
		}

		if rdsDetail.BasicInfo == nil {
			continue
		}

		rdsID := v.getStringPointerValue(rds.InstanceId)
		rdsLcuuid := common.GetUUIDByOrgID(v.orgID, rdsID)
		rdsName := v.getStringPointerValue(rdsDetail.BasicInfo.InstanceName)
		azLcuuid := common.GetUUIDByOrgID(v.orgID, v.getStringPointerValue(rdsDetail.BasicInfo.ZoneId))
		vpcLcuuid := common.GetUUIDByOrgID(v.orgID, v.getStringPointerValue(rdsDetail.BasicInfo.VpcId))
		var rdsModel = common.RDS_MODEL_PRIMARY
		if strings.HasPrefix(v.getStringPointerValue(rdsDetail.BasicInfo.NodeSpec), "rds.metadb.d1.n") {
			rdsModel = common.RDS_MODEL_SHARE
		}
		rdss = append(rdss, model.RDSInstance{
			Lcuuid:       rdsLcuuid,
			Name:         rdsName,
			Label:        rdsID,
			State:        rdsStates[v.getStringPointerValue(rdsDetail.BasicInfo.InstanceStatus)],
			Type:         common.RDS_TYPE_MYSQL,
			Series:       common.RDS_SERIES_HA,
			Version:      v.getStringPointerValue(rdsDetail.BasicInfo.DBEngineVersion),
			Model:        rdsModel,
			VPCLcuuid:    vpcLcuuid,
			AZLcuuid:     azLcuuid,
			RegionLcuuid: v.regionLcuuid,
		})

		for _, ep := range rdsDetail.Endpoints {
			if ep == nil || ep.Addresses == nil {
				continue
			}

			for _, address := range ep.Addresses {
				var netType int
				networkType := v.getStringPointerValue(address.NetworkType)
				switch networkType {
				case "Private":
					netType = common.VIF_TYPE_LAN
				case "Public":
					netType = common.VIF_TYPE_WAN
				default:
					log.Infof("invalid network type (%s)", networkType, logger.NewORGPrefix(v.orgID))
					continue
				}
				netID := v.getStringPointerValue(address.EipId)
				netIP := v.getStringPointerValue(address.IPAddress)
				if netID == "" {
					netID = common.GetUUIDByOrgID(v.orgID, v.getStringPointerValue(address.Domain)+netIP)
				}
				vinterfaceLcuuid := common.GetUUIDByOrgID(v.orgID, netID+netIP)
				networkLcuuid := common.NETWORK_ISP_LCUUID
				subnetLcuuid := common.SUBNET_ISP_LCUUID
				subnetID := v.getStringPointerValue(address.SubnetId)
				if subnetID != "" {
					networkLcuuid = common.GetUUIDByOrgID(v.orgID, subnetID)
					subnetLcuuid = common.GetUUIDByOrgID(v.orgID, networkLcuuid)
				}
				vinterfaces = append(vinterfaces, model.VInterface{
					Lcuuid:        vinterfaceLcuuid,
					Type:          netType,
					Mac:           common.VIF_DEFAULT_MAC,
					DeviceLcuuid:  rdsLcuuid,
					DeviceType:    common.VIF_DEVICE_TYPE_RDS_INSTANCE,
					VPCLcuuid:     vpcLcuuid,
					NetworkLcuuid: networkLcuuid,
					RegionLcuuid:  v.regionLcuuid,
				})

				ips = append(ips, model.IP{
					Lcuuid:           common.GetUUIDByOrgID(v.orgID, netID),
					VInterfaceLcuuid: vinterfaceLcuuid,
					IP:               netIP,
					SubnetLcuuid:     subnetLcuuid,
					RegionLcuuid:     v.regionLcuuid,
				})
			}
		}
	}
	return rdss, vinterfaces, ips, nil
}

func (v *VolcEngine) getRDSPostgreSQL(sess *session.Session) ([]model.RDSInstance, []model.VInterface, []model.IP, error) {
	var rdss []model.RDSInstance
	var vinterfaces []model.VInterface
	var ips []model.IP

	var retRDSs []*rdspostgresql.InstanceForDescribeDBInstancesOutput
	var pageNumber, pageSize int32 = 1, 100
	for {
		result, err := rdspostgresql.New(sess).DescribeDBInstances(&rdspostgresql.DescribeDBInstancesInput{PageNumber: &pageNumber, PageSize: &pageSize})
		if err != nil {
			log.Errorf("request volcengine (rdspostgresql.DescribeDBInstances) api error: (%s)", err.Error(), logger.NewORGPrefix(v.orgID))
			return []model.RDSInstance{}, []model.VInterface{}, []model.IP{}, err
		}
		retRDSs = append(retRDSs, result.Instances...)
		if len(result.Instances) < int(pageSize) {
			break
		}
		pageSize += 1
	}

	for _, rds := range retRDSs {
		if rds == nil || rds.InstanceId == nil {
			continue
		}

		rdsDetail, err := rdspostgresql.New(sess).DescribeDBInstanceDetail(&rdspostgresql.DescribeDBInstanceDetailInput{InstanceId: rds.InstanceId})
		if err != nil {
			log.Errorf("request volcengine (rdspostgresql.DescribeDBInstanceDetail) api error: (%s)", err.Error(), logger.NewORGPrefix(v.orgID))
			return []model.RDSInstance{}, []model.VInterface{}, []model.IP{}, err
		}

		if rdsDetail.BasicInfo == nil {
			continue
		}

		rdsID := v.getStringPointerValue(rds.InstanceId)
		rdsLcuuid := common.GetUUIDByOrgID(v.orgID, rdsID)
		rdsName := v.getStringPointerValue(rdsDetail.BasicInfo.InstanceName)
		azLcuuid := common.GetUUIDByOrgID(v.orgID, v.getStringPointerValue(rdsDetail.BasicInfo.ZoneId))
		vpcLcuuid := common.GetUUIDByOrgID(v.orgID, v.getStringPointerValue(rdsDetail.BasicInfo.VpcID))
		rdss = append(rdss, model.RDSInstance{
			Lcuuid:       rdsLcuuid,
			Name:         rdsName,
			Label:        rdsID,
			State:        rdsStates[v.getStringPointerValue(rdsDetail.BasicInfo.InstanceStatus)],
			Type:         common.RDS_TYPE_PSQL,
			Series:       common.RDS_SERIES_HA,
			Version:      v.getStringPointerValue(rdsDetail.BasicInfo.DBEngineVersion),
			Model:        common.RDS_MODEL_PRIMARY,
			VPCLcuuid:    vpcLcuuid,
			AZLcuuid:     azLcuuid,
			RegionLcuuid: v.regionLcuuid,
		})

		for _, ep := range rdsDetail.Endpoints {
			if ep == nil || ep.Address == nil {
				continue
			}

			for _, add := range ep.Address {
				var netType int
				networkType := v.getStringPointerValue(add.NetworkType)
				switch networkType {
				case "Private":
					netType = common.VIF_TYPE_LAN
				case "Public":
					netType = common.VIF_TYPE_WAN
				default:
					log.Infof("invalid network type (%s)", networkType, logger.NewORGPrefix(v.orgID))
					continue
				}
				netID := v.getStringPointerValue(add.EipId)
				netIP := v.getStringPointerValue(add.IPAddress)
				if netID == "" {
					netID = common.GetUUIDByOrgID(v.orgID, v.getStringPointerValue(add.Domain)+netIP)
				}
				vinterfaceLcuuid := common.GetUUIDByOrgID(v.orgID, netID+netIP)
				networkLcuuid := common.NETWORK_ISP_LCUUID
				subnetLcuuid := common.SUBNET_ISP_LCUUID
				subnetID := v.getStringPointerValue(add.SubnetId)
				if subnetID != "" {
					networkLcuuid = common.GetUUIDByOrgID(v.orgID, subnetID)
					subnetLcuuid = common.GetUUIDByOrgID(v.orgID, networkLcuuid)
				}
				vinterfaces = append(vinterfaces, model.VInterface{
					Lcuuid:        vinterfaceLcuuid,
					Type:          netType,
					Mac:           common.VIF_DEFAULT_MAC,
					DeviceLcuuid:  rdsLcuuid,
					DeviceType:    common.VIF_DEVICE_TYPE_RDS_INSTANCE,
					VPCLcuuid:     vpcLcuuid,
					NetworkLcuuid: networkLcuuid,
					RegionLcuuid:  v.regionLcuuid,
				})

				ips = append(ips, model.IP{
					Lcuuid:           common.GetUUIDByOrgID(v.orgID, netID),
					VInterfaceLcuuid: vinterfaceLcuuid,
					IP:               netIP,
					SubnetLcuuid:     subnetLcuuid,
					RegionLcuuid:     v.regionLcuuid,
				})
			}
		}
	}
	return rdss, vinterfaces, ips, nil
}

func (v *VolcEngine) getRDSSQLServer(sess *session.Session) ([]model.RDSInstance, []model.VInterface, []model.IP, error) {
	var rdss []model.RDSInstance
	var vinterfaces []model.VInterface
	var ips []model.IP

	var retRDSs []*rdsmssql.InstancesInfoForDescribeDBInstancesOutput
	var pageNumber, pageSize int32 = 1, 100
	for {
		result, err := rdsmssql.New(sess).DescribeDBInstances(&rdsmssql.DescribeDBInstancesInput{PageNumber: &pageNumber, PageSize: &pageSize})
		if err != nil {
			log.Errorf("request volcengine (rdsmssql.DescribeDBInstances) api error: (%s)", err.Error(), logger.NewORGPrefix(v.orgID))
			return []model.RDSInstance{}, []model.VInterface{}, []model.IP{}, err
		}
		retRDSs = append(retRDSs, result.InstancesInfo...)
		if len(result.InstancesInfo) < int(pageSize) {
			break
		}
		pageSize += 1
	}

	for _, rds := range retRDSs {
		if rds == nil || rds.InstanceId == nil {
			continue
		}

		rdsDetail, err := rdsmssql.New(sess).DescribeDBInstanceDetail(&rdsmssql.DescribeDBInstanceDetailInput{InstanceId: rds.InstanceId})
		if err != nil {
			log.Errorf("request volcengine (rdsmssql.DescribeDBInstanceDetail) api error: (%s)", err.Error(), logger.NewORGPrefix(v.orgID))
			return []model.RDSInstance{}, []model.VInterface{}, []model.IP{}, err
		}

		if rdsDetail.BasicInfo == nil {
			continue
		}
		rdsID := v.getStringPointerValue(rds.InstanceId)
		rdsLcuuid := common.GetUUIDByOrgID(v.orgID, rdsID)
		rdsName := v.getStringPointerValue(rdsDetail.BasicInfo.InstanceName)
		azLcuuid := common.GetUUIDByOrgID(v.orgID, v.getStringPointerValue(rdsDetail.BasicInfo.ZoneId))
		vpcLcuuid := common.GetUUIDByOrgID(v.orgID, v.getStringPointerValue(rdsDetail.BasicInfo.VpcId))
		rdss = append(rdss, model.RDSInstance{
			Lcuuid:       rdsLcuuid,
			Name:         rdsName,
			Label:        rdsID,
			State:        rdsStates[v.getStringPointerValue(rdsDetail.BasicInfo.InstanceStatus)],
			Type:         common.RDS_TYPE_SQL_SERVER,
			Series:       rdsSeries[v.getStringPointerValue(rdsDetail.BasicInfo.InstanceType)],
			Version:      v.getStringPointerValue(rdsDetail.BasicInfo.DBEngineVersion) + " " + v.getStringPointerValue(rdsDetail.BasicInfo.InnerVersion),
			Model:        common.RDS_MODEL_PRIMARY, // TODO: get for rds.InstanceCategory
			VPCLcuuid:    vpcLcuuid,
			AZLcuuid:     azLcuuid,
			RegionLcuuid: v.regionLcuuid,
		})

		for _, con := range rdsDetail.ConnectionInfo {
			if con == nil || con.Address == nil {
				continue
			}
			for _, net := range con.Address {
				var netType int
				networkType := v.getStringPointerValue(net.NetworkType)
				switch networkType {
				case "Private":
					netType = common.VIF_TYPE_LAN
				case "Public":
					netType = common.VIF_TYPE_WAN
				default:
					log.Infof("invalid network type (%s)", networkType, logger.NewORGPrefix(v.orgID))
					continue
				}
				netID := v.getStringPointerValue(net.EipId)
				netIP := v.getStringPointerValue(net.IPAddress)
				if netID == "" {
					netID = common.GetUUIDByOrgID(v.orgID, v.getStringPointerValue(net.Domain)+netIP)
				}
				vinterfaceLcuuid := common.GetUUIDByOrgID(v.orgID, netID+netIP)
				networkLcuuid := common.NETWORK_ISP_LCUUID
				subnetLcuuid := common.SUBNET_ISP_LCUUID
				subnetID := v.getStringPointerValue(net.SubnetId)
				if subnetID != "" {
					networkLcuuid = common.GetUUIDByOrgID(v.orgID, subnetID)
					subnetLcuuid = common.GetUUIDByOrgID(v.orgID, networkLcuuid)
				}
				vinterfaces = append(vinterfaces, model.VInterface{
					Lcuuid:        vinterfaceLcuuid,
					Type:          netType,
					Mac:           common.VIF_DEFAULT_MAC,
					DeviceLcuuid:  rdsLcuuid,
					DeviceType:    common.VIF_DEVICE_TYPE_RDS_INSTANCE,
					VPCLcuuid:     vpcLcuuid,
					NetworkLcuuid: networkLcuuid,
					RegionLcuuid:  v.regionLcuuid,
				})

				ips = append(ips, model.IP{
					Lcuuid:           common.GetUUIDByOrgID(v.orgID, netID),
					VInterfaceLcuuid: vinterfaceLcuuid,
					IP:               netIP,
					SubnetLcuuid:     subnetLcuuid,
					RegionLcuuid:     v.regionLcuuid,
				})
			}
		}
	}
	return rdss, vinterfaces, ips, nil
}
