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
	ctrlrcommon "github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	"github.com/deepflowio/deepflow/server/controller/http/service/resource/common"
)

type AZ struct {
	DataProvider
	toolData *azToolData
}

func NewAZ() *AZ {
	dp := &AZ{newDataProvider(ctrlrcommon.RESOURCE_TYPE_AZ_EN), new(azToolData)}
	dp.setGenerator(dp)
	return dp
}

func (p *AZ) generate() ([]common.ResponseElem, error) {
	data := make([]common.ResponseElem, 0)
	err := p.toolData.Init().Load()
	if err != nil {
		return data, err
	}
	for _, item := range p.toolData.azs {
		data = append(data, p.generateOne(item))
	}
	return data, nil
}

func (a *AZ) generateOne(item mysql.AZ) common.ResponseElem {
	d := MySQLModelToMap(item)
	d["REGION_NAME"] = a.toolData.regionLcuuidToName[item.Region]
	d["DOMAIN_NAME"] = a.toolData.domainLcuuidToName[item.Domain]
	// TODO
	d["ICON_ID"] = 0
	d["VM_COUNT"] = 0
	d["POD_COUNT"] = 0
	d["ANALYZER_IPS"] = 0
	d["CONTROLLER_IPS"] = 0
	return d
}

type azToolData struct {
	azs []mysql.AZ

	domainLcuuidToName map[string]string
	regionLcuuidToName map[string]string
	azLcuuidToVMCount  map[string]int
	azLcuuidToPodCount map[string]int
}

func (td *azToolData) Init() *azToolData {
	td.domainLcuuidToName = make(map[string]string)
	td.regionLcuuidToName = make(map[string]string)
	return td
}

func (td *azToolData) Load() (err error) {
	err = mysql.Db.Find(&td.azs).Error
	if err != nil {
		return err
	}

	var domains []mysql.Domain
	err = mysql.Db.Select("lcuuid", "name").Find(&domains).Error
	if err != nil {
		return err
	}
	for _, item := range domains {
		td.domainLcuuidToName[item.Lcuuid] = item.Name
	}

	var regions []mysql.Region
	err = mysql.Db.Select("lcuuid", "name").Find(&regions).Error
	if err != nil {
		return err
	}
	for _, item := range regions {
		td.regionLcuuidToName[item.Lcuuid] = item.Name
	}
	return
}
