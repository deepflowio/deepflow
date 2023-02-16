/*
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
	"github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	. "github.com/deepflowio/deepflow/server/controller/http/service/resource/common"
)

type AZ struct {
	DataProvider
	dataTool *azToolData
}

func NewAZ() *AZ {
	dp := &AZ{newDataProvider(common.RESOURCE_TYPE_AZ_EN), new(azToolData)}
	dp.setGenerator(dp)
	return dp
}

func (p *AZ) generate() (data []ResponseElem, err error) {
	err = p.dataTool.Init().Load()
	for _, item := range p.dataTool.azs {
		d := MySQLModelToMap(item)
		d["REGION_NAME"] = p.dataTool.regionLcuuidToName[item.Region]
		d["DOMAIN_NAME"] = p.dataTool.domainLcuuidToName[item.Domain]
		data = append(data, d)
	}
	return
}

type azToolData struct {
	azs []mysql.AZ

	domainLcuuidToName map[string]string
	regionLcuuidToName map[string]string
}

func (td *azToolData) Init() *azToolData {
	td.domainLcuuidToName = make(map[string]string)
	td.regionLcuuidToName = make(map[string]string)
	return td
}

func (td *azToolData) Load() (err error) {
	err = mysql.Db.Find(&td.azs).Error

	var domains []mysql.Domain
	err = mysql.Db.Select("lcuuid", "name").Find(&domains).Error
	for _, item := range domains {
		td.domainLcuuidToName[item.Lcuuid] = item.Name
	}
	var regions []mysql.Region
	err = mysql.Db.Select("lcuuid", "name").Find(&regions).Error
	for _, item := range regions {
		td.regionLcuuidToName[item.Lcuuid] = item.Name
	}
	return
}
