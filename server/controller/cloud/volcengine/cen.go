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
	"github.com/deepflowio/deepflow/server/controller/cloud/model"
	"github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/libs/logger"
	"github.com/volcengine/volcengine-go-sdk/service/cen"
	"github.com/volcengine/volcengine-go-sdk/volcengine/session"
)

func (v *VolcEngine) getCens(sess *session.Session) ([]model.CEN, error) {
	log.Debug("get cens starting", logger.NewORGPrefix(v.orgID))
	var cens []model.CEN

	cenClient := cen.New(sess)
	var retCens []*cen.CenForDescribeCensOutput
	var pageNumber, pageSize int64 = 1, 100
	for {
		result, err := cenClient.DescribeCens(&cen.DescribeCensInput{PageNumber: &pageNumber, PageSize: &pageSize})
		if err != nil {
			log.Errorf("request volcengine (cen.DescribeCens) api error: (%s)", err.Error(), logger.NewORGPrefix(v.orgID))
			return []model.CEN{}, err
		}
		retCens = append(retCens, result.Cens...)
		if len(result.Cens) < int(pageSize) {
			break
		}
		pageSize += 1
	}

	for _, retCen := range retCens {
		if retCen == nil {
			continue
		}
		cenID := v.getStringPointerValue(retCen.CenId)
		if cenID == "" {
			continue
		}
		cenName := v.getStringPointerValue(retCen.CenName)
		if cenName == "" {
			cenName = cenID
		}
		cenStatus := v.getStringPointerValue(retCen.Status)
		if cenStatus != "Available" {
			log.Infof("cen (%s) status (%s) invalid", cenName, cenStatus, logger.NewORGPrefix(v.orgID))
			continue
		}

		var retCAIs []*cen.AttachedInstanceForDescribeCenAttachedInstancesOutput
		var pNumber, pSize int64 = 1, 100
		for {
			input := cen.DescribeCenAttachedInstancesInput{
				CenId:      &cenID,
				PageSize:   &pSize,
				PageNumber: &pNumber,
			}
			result, err := cenClient.DescribeCenAttachedInstances(&input)
			if err != nil {
				log.Errorf("request volcengine (cen.DescribeCenAttachedInstances) api error: (%s)", err.Error(), logger.NewORGPrefix(v.orgID))
				return []model.CEN{}, err
			}
			retCAIs = append(retCAIs, result.AttachedInstances...)
			if len(result.AttachedInstances) < int(pageSize) {
				break
			}
			pageSize += 1
		}

		vpcLcuuids := []string{}
		for _, retCAI := range retCAIs {
			if retCAI == nil {
				continue
			}
			caiStatus := v.getStringPointerValue(retCAI.Status)
			if caiStatus != "Available" {
				log.Infof("cen (%s) instances status (%s) invalid", cenName, caiStatus, logger.NewORGPrefix(v.orgID))
				continue
			}
			caiType := v.getStringPointerValue(retCAI.InstanceType)
			if caiType != "VPC" {
				log.Infof("cen (%s) instances type (%s) invalid", cenName, caiType, logger.NewORGPrefix(v.orgID))
				continue
			}
			caiInstanceID := v.getStringPointerValue(retCAI.InstanceId)
			vpcLcuuids = append(vpcLcuuids, common.GetUUIDByOrgID(v.orgID, caiInstanceID))
		}

		if len(vpcLcuuids) == 0 {
			log.Infof("cen (%s) not bind vpc", cenName, logger.NewORGPrefix(v.orgID))
			continue
		}
		cens = append(cens, model.CEN{
			Lcuuid:     common.GetUUIDByOrgID(v.orgID, cenID),
			Name:       cenName,
			Label:      cenID,
			VPCLcuuids: vpcLcuuids,
		})
	}
	log.Debug("get cens complete", logger.NewORGPrefix(v.orgID))
	return cens, nil
}
