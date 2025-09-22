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

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	"github.com/aws/aws-sdk-go-v2/service/rds/types"
	"github.com/deepflowio/deepflow/server/controller/cloud/model"
	"github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/libs/logger"
)

var rdsTypeEnums = map[string]int{
	"mysql":         common.RDS_TYPE_MYSQL,
	"sqlserver-ex":  common.RDS_TYPE_SQL_SERVER,
	"sqlserver-web": common.RDS_TYPE_SQL_SERVER,
	"sqlserver-se":  common.RDS_TYPE_SQL_SERVER,
	"sqlserver-ee":  common.RDS_TYPE_SQL_SERVER,
	"postgres":      common.RDS_TYPE_PSQL,
	"mariadb":       common.RDS_TYPE_MARIADB,
	"oracle-ee":     common.RDS_TYPE_ORACLE,
	"oracle-se2":    common.RDS_TYPE_ORACLE,
}

func (a *Aws) getRDSInstances(region string) ([]model.RDSInstance, error) {
	log.Debug("get rds instances starting", logger.NewORGPrefix(a.orgID))
	var rdss []model.RDSInstance

	rdsClientConfig, err := config.LoadDefaultConfig(context.TODO(), a.credential, config.WithRegion(region), config.WithHTTPClient(a.httpClient))
	if err != nil {
		log.Error("client config failed (%s)", err.Error(), logger.NewORGPrefix(a.orgID))
		return []model.RDSInstance{}, err
	}

	var retRDS []types.DBInstance
	var marker string
	var maxRecords int32 = 100
	for {
		var input *rds.DescribeDBInstancesInput
		if marker == "" {
			input = &rds.DescribeDBInstancesInput{MaxRecords: &maxRecords}
		} else {
			input = &rds.DescribeDBInstancesInput{MaxRecords: &maxRecords, Marker: &marker}
		}
		result, err := rds.NewFromConfig(rdsClientConfig).DescribeDBInstances(context.TODO(), input)
		if err != nil {
			log.Errorf("rds request aws api error: (%s)", err.Error(), logger.NewORGPrefix(a.orgID))
			return []model.RDSInstance{}, err
		}
		retRDS = append(retRDS, result.DBInstances...)
		if result.Marker == nil {
			break
		}
		marker = *result.Marker
	}
	for _, rds := range retRDS {
		rdsID := a.getStringPointerValue(rds.DbiResourceId)
		rdsLcuuid := common.GetUUIDByOrgID(a.orgID, rdsID)
		rdsName := a.getStringPointerValue(rds.DBInstanceIdentifier)
		rdsEngine := a.getStringPointerValue(rds.Engine)
		rdsType, ok := rdsTypeEnums[rdsEngine]
		if !ok {
			log.Infof("rds (%s) engine (%s) is not supported", rdsName, rdsEngine, logger.NewORGPrefix(a.orgID))
			continue
		}
		azLcuuid := common.GetUUIDByOrgID(a.orgID, a.getStringPointerValue(rds.AvailabilityZone))
		vpcLcuuid := common.GetUUIDByOrgID(a.orgID, a.getStringPointerValue(rds.DBSubnetGroup.VpcId))
		var rdsState = common.RDS_STATE_RUNNING
		if a.getStringPointerValue(rds.DBInstanceStatus) != "available" {
			rdsState = common.RDS_STATE_RESTORING
		}
		rdss = append(rdss, model.RDSInstance{
			Lcuuid:       rdsLcuuid,
			Name:         rdsName,
			Label:        rdsID,
			State:        rdsState,
			Type:         rdsType,
			Series:       common.RDS_SERIES_BASIC,
			Version:      a.getStringPointerValue(rds.EngineVersion),
			Model:        common.RDS_MODEL_PRIMARY,
			VPCLcuuid:    vpcLcuuid,
			AZLcuuid:     azLcuuid,
			RegionLcuuid: a.regionLcuuid,
		})
		a.azLcuuidMap[azLcuuid] = 0
	}
	log.Debug("get rds instances complete", logger.NewORGPrefix(a.orgID))
	return rdss, nil
}
