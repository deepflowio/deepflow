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
	ctrlcommon "github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	"github.com/deepflowio/deepflow/server/controller/http/service/resource/common"
)

type PodGroupPort struct {
	DataProvider
	dataTool *PodGroupPortToolData
}

func NewPodGroupPort() *PodGroupPort {
	dp := &PodGroupPort{newDataProvider(ctrlcommon.RESOURCE_TYPE_POD_GROUP_EN), new(PodGroupPortToolData)}
	dp.setGenerator(dp)
	return dp
}

func (p *PodGroupPort) generate() (data []common.ResponseElem, err error) {
	err = p.dataTool.Init().Load()
	for _, item := range p.dataTool.PodGroupPorts {
		data = append(data, p.generateOne(item))
	}
	return
}

func (p *PodGroupPort) generateOne(item mysql.PodGroupPort) common.ResponseElem {
	d := MySQLModelToMap(item)
	return d
}

type PodGroupPortToolData struct {
	PodGroupPorts []mysql.PodGroupPort
}

func (td *PodGroupPortToolData) Init() *PodGroupPortToolData {

	return td
}

func (td *PodGroupPortToolData) Load() (err error) {
	err = mysql.Db.Find(&td.PodGroupPorts).Error // TODO use db mng

	return
}
