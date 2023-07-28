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

type Host struct {
	DataProvider
	toolData *hostToolData
}

func NewHost() *Host {
	dp := &Host{newDataProvider(ctrlrcommon.RESOURCE_TYPE_HOST_EN), new(hostToolData)}
	dp.setGenerator(dp)
	return dp
}

func (h *Host) generate() (data []common.ResponseElem, err error) {
	err = h.toolData.init().load()
	for _, item := range h.toolData.hosts {
		data = append(data, h.generateOne(item))
	}
	return
}

func (h *Host) generateOne(item mysql.Host) common.ResponseElem {
	d := MySQLModelToMap(item)
	d["REGION_NAME"] = h.toolData.regionLcuuidToName[item.Region]
	d["DOMAIN_NAME"] = h.toolData.domainLcuuidToName[item.Domain]
	return d
}

type hostToolData struct {
	hosts []mysql.Host

	domainLcuuidToName map[string]string
	regionLcuuidToName map[string]string
}

func (td *hostToolData) init() *hostToolData {
	td.domainLcuuidToName = make(map[string]string)
	td.regionLcuuidToName = make(map[string]string)
	return td
}

func (td *hostToolData) load() (err error) {
	td.hosts, err = GetAll[mysql.Host]()
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

	regions, err := Select[mysql.Region]([]string{"lcuuid", "name"})
	if err != nil {
		return err
	}
	for _, item := range regions {
		td.regionLcuuidToName[item.Lcuuid] = item.Name
	}
	return
}
