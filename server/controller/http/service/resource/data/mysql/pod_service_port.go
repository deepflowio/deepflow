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

type PodServicePort struct {
	DataProvider
	dataTool *PodServicePortToolData
}

func NewPodServicePort() *PodServicePort {
	dp := &PodServicePort{newDataProvider(ctrlcommon.RESOURCE_TYPE_POD_SERVICE_PORT_EN), new(PodServicePortToolData)}
	dp.setGenerator(dp)
	return dp
}

func (p *PodServicePort) generate() (data []common.ResponseElem, err error) {
	err = p.dataTool.Init().Load()
	for _, item := range p.dataTool.podServicePorts {
		data = append(data, p.generateOne(item))
	}
	return
}

func (p *PodServicePort) generateOne(item mysql.PodServicePort) common.ResponseElem {
	d := MySQLModelToMap(item)

	d["EPC_ID"] = p.dataTool.podServiceIDToEPCID[item.PodServiceID]
	d["POD_SERVICE_NAME"] = p.dataTool.podServiceIDToName[item.PodServiceID]
	d["POD_NAMESPACE_ID"] = p.dataTool.podServiceIDToNamespaceID[item.PodServiceID]

	return d
}

type PodServicePortToolData struct {
	podServicePorts []mysql.PodServicePort

	podServiceIDToName        map[int]string
	podServiceIDToEPCID       map[int]int
	podServiceIDToNamespaceID map[int]int
}

func (td *PodServicePortToolData) Init() *PodServicePortToolData {
	td.podServiceIDToName = make(map[int]string)
	td.podServiceIDToEPCID = make(map[int]int)
	td.podServiceIDToNamespaceID = make(map[int]int)

	return td
}

func (td *PodServicePortToolData) Load() (err error) {
	td.podServicePorts, err = UnscopedFind[mysql.PodServicePort]()
	if err != nil {
		return err
	}

	podServices, err := Select[mysql.PodService]([]string{"id", "name", "epc_id", "pod_namespace_id"})
	if err != nil {
		return err
	}
	for _, item := range podServices {
		td.podServiceIDToName[item.ID] = item.Name
		td.podServiceIDToEPCID[item.ID] = item.VPCID
		td.podServiceIDToNamespaceID[item.ID] = item.PodNamespaceID
	}

	return nil
}
