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

type PodService struct {
	DataProvider
	dataTool *PodServiceToolData
}

func NewPodService() *PodService {
	dp := &PodService{newDataProvider(ctrlcommon.RESOURCE_TYPE_POD_SERVICE_EN), new(PodServiceToolData)}
	dp.setGenerator(dp)
	return dp
}

func (p *PodService) generate() (data []common.ResponseElem, err error) {
	err = p.dataTool.Init().Load()
	for _, item := range p.dataTool.PodServices {
		data = append(data, p.generateOne(item))
	}
	return
}

func (p *PodService) generateOne(item mysql.PodService) common.ResponseElem {
	d := MySQLModelToMap(item)
	if v, ok := d["VPC_ID"]; ok {
		d["EPC_ID"] = v
		delete(d, "VPC_ID")
	}

	d["AZ_NAME"] = p.dataTool.azLcuuidToName[item.AZ]
	d["EPC_NAME"] = p.dataTool.vpcIDToName[item.VPCID]
	d["POD_CLUSTER_NAME"] = p.dataTool.podClusterIDToName[item.PodClusterID]
	d["POD_NAMESPACE_NAME"] = p.dataTool.podNamespaceIDToName[item.PodNamespaceID]
	d["POD_COUNT"] = len(p.dataTool.podServiceIDToPodIDs[item.ID])
	d["POD_SERVICE_PORT_COUNT"] = len(p.dataTool.podServiceIDToPodServicePortIDs[item.ID])

	var podGroups []interface{}
	for _, podGroupID := range p.dataTool.podServiceIDToPodGroupIDs[item.ID] {
		podGroupName, ok := p.dataTool.podGroupIDToName[podGroupID]
		if !ok {
			continue
		}
		podGroups = append(podGroups,
			map[string]interface{}{
				"ID":   podGroupID,
				"NAME": podGroupName,
				"TYPE": p.dataTool.podGroupIDToType[podGroupID],
			},
		)
	}
	d["POD_GROUPS"] = podGroups

	return d
}

type PodServiceToolData struct {
	PodServices []mysql.PodService

	vpcIDToName          map[int]string
	azLcuuidToName       map[string]string
	podClusterIDToName   map[int]string
	podNamespaceIDToName map[int]string

	podServiceIDToPodIDs map[int][]int
	podGroupIDToPodIDs   map[int][]int

	podServiceIDToPodServicePortIDs map[int][]int

	podServiceIDToPodGroupIDs map[int][]int
	podGroupIDToName          map[int]string
	podGroupIDToType          map[int]int
}

func (td *PodServiceToolData) Init() *PodServiceToolData {
	td.azLcuuidToName = make(map[string]string)
	td.vpcIDToName = make(map[int]string)
	td.podClusterIDToName = make(map[int]string)
	td.podNamespaceIDToName = make(map[int]string)

	td.podServiceIDToPodIDs = make(map[int][]int)
	td.podGroupIDToPodIDs = make(map[int][]int)

	td.podServiceIDToPodServicePortIDs = make(map[int][]int)

	td.podServiceIDToPodGroupIDs = make(map[int][]int)
	td.podGroupIDToName = make(map[int]string)
	td.podGroupIDToType = make(map[int]int)

	return td
}

func (td *PodServiceToolData) Load() (err error) {
	err = mysql.Db.Unscoped().Find(&td.PodServices).Error // TODO use db mng

	var azs []mysql.AZ
	err = mysql.Db.Unscoped().Select("lcuuid", "name").Find(&azs).Error
	for _, item := range azs {
		td.azLcuuidToName[item.Lcuuid] = item.Name
	}
	var vpcs []mysql.VPC
	err = mysql.Db.Unscoped().Select("id", "name").Find(&vpcs).Error
	for _, item := range vpcs {
		td.vpcIDToName[item.ID] = item.Name
	}
	var podClusters []mysql.PodCluster
	err = mysql.Db.Unscoped().Select("id", "name", "epc_id").Find(&podClusters).Error
	for _, item := range podClusters {
		td.podClusterIDToName[item.ID] = item.Name
	}
	var podNamespaces []mysql.PodNamespace
	err = mysql.Db.Unscoped().Select("id", "name").Find(&podNamespaces).Error
	for _, item := range podNamespaces {
		td.podNamespaceIDToName[item.ID] = item.Name
	}

	var pods []mysql.Pod
	err = mysql.Db.Unscoped().Select("id", "pod_group_id").Find(&pods).Error
	for _, item := range pods {
		td.podGroupIDToPodIDs[item.PodGroupID] = append(td.podGroupIDToPodIDs[item.PodGroupID], item.ID)
	}
	var podGroupPorts []mysql.PodGroupPort
	err = mysql.Db.Unscoped().Select("pod_group_id", "pod_service_id").Find(&podGroupPorts).Error
	podServiceIDToPodGroupIDs := make(map[int]map[int]struct{})
	for _, item := range podGroupPorts {
		podIDs := td.podGroupIDToPodIDs[item.PodGroupID]
		dedup := make(map[int]struct{}, len(podIDs))
		for _, podID := range podIDs {
			if _, ok := dedup[podID]; !ok {
				dedup[podID] = struct{}{}
				td.podServiceIDToPodIDs[item.PodServiceID] =
					append(td.podServiceIDToPodIDs[item.PodServiceID], podID)
			}
		}

		if podServiceIDToPodGroupIDs[item.PodServiceID] == nil {
			podServiceIDToPodGroupIDs[item.PodServiceID] = make(map[int]struct{})
		}
		podServiceIDToPodGroupIDs[item.PodServiceID][item.PodGroupID] = struct{}{}
	}
	td.podServiceIDToPodGroupIDs = convertMapToSlice(podServiceIDToPodGroupIDs)

	var podServicePorts []mysql.PodServicePort
	err = mysql.Db.Unscoped().Select("id", "pod_service_id").Find(&podServicePorts).Error
	for _, item := range podServicePorts {
		td.podServiceIDToPodServicePortIDs[item.PodServiceID] =
			append(td.podServiceIDToPodServicePortIDs[item.PodServiceID], item.ID)
	}

	var podGroups []mysql.PodGroup
	err = mysql.Db.Unscoped().Select("id", "name", "type").Find(&podGroups).Error
	for _, item := range podGroups {
		td.podGroupIDToName[item.ID] = item.Name
		td.podGroupIDToType[item.ID] = item.Type
	}

	return
}
