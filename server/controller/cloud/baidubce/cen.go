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

	"github.com/baidubce/bce-sdk-go/services/csn"
	"github.com/deepflowio/deepflow/server/controller/cloud/model"
	"github.com/deepflowio/deepflow/server/controller/common"
)

func (b *BaiduBce) getCENs() ([]model.CEN, error) {
	var cens []model.CEN

	log.Debug("get cens starting")

	csnClient, _ := csn.NewClient(b.secretID, b.secretKey, "https://csn.baidubce.com")
	csnClient.Config.ConnectionTimeoutInMillis = b.httpTimeout * 1000
	marker := ""
	args := &csn.ListCsnArgs{}
	retCsns := []csn.Csn{}
	for {
		args.Marker = marker
		startTime := time.Now()
		result, err := csnClient.ListCsn(args)
		if err != nil {
			log.Error(err)
			return []model.CEN{}, err
		}
		b.cloudStatsd.RefreshAPIMoniter("ListCsn", 1, startTime)
		retCsns = append(retCsns, result.Csns...)
		if !result.IsTruncated {
			break
		}
		if result.NextMarker != nil {
			marker = *result.NextMarker
		}
	}

	b.debugger.WriteJson("ListCsn", " ", structToJson(retCsns))

	for _, c := range retCsns {
		if c.CsnId == "" {
			continue
		}
		marker := ""
		args := &csn.ListInstanceArgs{}
		retCsnInstances := []csn.Instance{}
		for {
			args.Marker = marker
			result, err := csnClient.ListInstance(c.CsnId, args)
			if err != nil {
				log.Error(err)
				return []model.CEN{}, err
			}
			retCsnInstances = append(retCsnInstances, result.Instances...)
			if !result.IsTruncated {
				break
			}
			if result.NextMarker != nil {
				marker = *result.NextMarker
			}
		}
		vpcLcuuids := []string{}
		for _, i := range retCsnInstances {
			if i.InstanceType != "vpc" {
				log.Debugf("csn (%s) instance type (%s) not is vpc", c.CsnId, i.InstanceType)
				continue
			}
			if i.InstanceId != "" {
				vpcLcuuids = append(vpcLcuuids, common.GenerateUUID(i.InstanceId))
			}
		}
		if len(vpcLcuuids) == 0 {
			continue
		}
		cens = append(cens, model.CEN{
			Lcuuid:     common.GenerateUUID(c.CsnId),
			Name:       c.Name,
			VPCLcuuids: vpcLcuuids,
		})
		b.debugger.WriteJson("CsnInstance", " ", structToJson(retCsnInstances))
	}

	log.Debug("Get cens complete")
	return cens, nil
}
