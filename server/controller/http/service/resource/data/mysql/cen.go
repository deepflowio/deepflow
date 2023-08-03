/**
 * Copyright (c) 2023 Yunshan Networks
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

package mysql

import (
	"strconv"
	"strings"

	ctrlrcommon "github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	"github.com/deepflowio/deepflow/server/controller/http/service/resource/common"
)

type CEN struct {
	DataProvider
	dataTool *cenToolData
}

func NewCEN() *CEN {
	dp := &CEN{newDataProvider(ctrlrcommon.RESOURCE_TYPE_CEN_EN), new(cenToolData)}
	dp.setGenerator(dp)
	return dp
}

func (v *CEN) generate() (data []common.ResponseElem, err error) {
	err = v.dataTool.Init().Load()
	for _, item := range v.dataTool.cens {
		data = append(data, v.generateOne(item))
	}
	return
}

func (v *CEN) generateOne(item mysql.CEN) common.ResponseElem {
	d := MySQLModelToMap(item)
	d["DOMAIN_NAME"] = v.dataTool.domainLcuuidToName[item.Domain]
	vpcInfos := make([]map[string]interface{}, 0)
	for _, item := range strings.Split(item.VPCIDs, ",") {
		vpcID, err := strconv.Atoi(item)
		if err != nil {
			log.Error("invalid vpc id: %s", item)
			continue
		}
		vpcInfos = append(vpcInfos, map[string]interface{}{"ID": vpcID, "NAME": v.dataTool.vpcIDToName[vpcID]})
	}
	d["EPCS"] = vpcInfos

	d["CREATED_AT"] = item.CreatedAt.Format(ctrlrcommon.GO_BIRTHDAY)
	d["UPDATED_AT"] = item.UpdatedAt.Format(ctrlrcommon.GO_BIRTHDAY)
	return d
}

type cenToolData struct {
	cens []mysql.CEN

	domainLcuuidToName map[string]string
	vpcIDToName        map[int]string
}

func (td *cenToolData) Init() *cenToolData {
	td.domainLcuuidToName = make(map[string]string)
	td.vpcIDToName = make(map[int]string)
	return td
}

func (td *cenToolData) Load() (err error) {
	td.cens, err = UnscopedOrderFind[mysql.CEN]("created_at DESC")
	if err != nil {
		return err
	}

	domains, err := Select[mysql.Domain]([]string{"lcuuid", "name"})
	if err != nil {
		return err
	}
	for _, item := range domains {
		td.domainLcuuidToName[item.Lcuuid] = item.Name
	}

	vpcs, err := Select[mysql.VPC]([]string{"id", "name"})
	if err != nil {
		return err
	}
	for _, item := range vpcs {
		td.vpcIDToName[item.ID] = item.Name
	}

	return nil
}
