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

type PodNamespace struct {
	DataProvider
	dataTool *PodNamespaceToolData
}

func NewPodNamespace() *PodNamespace {
	dp := &PodNamespace{newDataProvider(ctrlcommon.RESOURCE_TYPE_POD_NAMESPACE_EN), new(PodNamespaceToolData)}
	dp.setGenerator(dp)
	return dp
}

func (p *PodNamespace) generate() (data []common.ResponseElem, err error) {
	err = p.dataTool.Init().Load()
	for _, item := range p.dataTool.PodNamespaces {
		data = append(data, p.generateOne(item))
	}
	return
}

func (p *PodNamespace) generateOne(item mysql.PodNamespace) common.ResponseElem {
	d := MySQLModelToMap(item)
	d["AZ_NAME"] = p.dataTool.azLcuuidToName[item.AZ]

	podCluster := p.dataTool.idToPodCluster[item.PodClusterID]
	d["EPC_ID"] = podCluster.VPCID
	d["EPC_NAME"] = p.dataTool.vpcIDToName[podCluster.VPCID]
	d["POD_CLUSTER_NAME"] = podCluster.Name

	d["POD_COUNT"] = len(p.dataTool.podNamespaceIDToPodIDs[item.ID])
	d["POD_GROUP_COUNT"] = len(p.dataTool.podNamespaceIDToPodGroupIDs[item.ID])
	d["POD_REPLICA_SET_COUNT"] = len(p.dataTool.podNamespaceIDToPodRSIDs[item.ID])

	return d
}

type PodNamespaceToolData struct {
	PodNamespaces []mysql.PodNamespace

	azLcuuidToName map[string]string
	idToPodCluster map[int]mysql.PodCluster
	vpcIDToName    map[int]string

	podNamespaceIDToPodIDs      map[int][]int
	podNamespaceIDToPodGroupIDs map[int][]int
	podNamespaceIDToPodRSIDs    map[int][]int
}

func (td *PodNamespaceToolData) Init() *PodNamespaceToolData {
	td.azLcuuidToName = make(map[string]string)
	td.idToPodCluster = make(map[int]mysql.PodCluster)
	td.vpcIDToName = make(map[int]string)

	td.podNamespaceIDToPodIDs = make(map[int][]int)
	td.podNamespaceIDToPodGroupIDs = make(map[int][]int)
	td.podNamespaceIDToPodRSIDs = make(map[int][]int)

	return td
}

func (td *PodNamespaceToolData) Load() (err error) {
	td.PodNamespaces, err = UnscopedFind[mysql.PodNamespace]()
	if err != nil {
		return err
	}

	azs, err := Select[mysql.AZ]([]string{"lcuuid", "name"})
	if err != nil {
		return err
	}
	for _, item := range azs {
		td.azLcuuidToName[item.Lcuuid] = item.Name
	}

	podClusters, err := UnscopedFind[mysql.PodCluster]()
	if err != nil {
		return err
	}
	for _, item := range podClusters {
		td.idToPodCluster[item.ID] = item
	}

	vpcs, err := UnscopedSelect[mysql.VPC]([]string{"id", "name"})
	if err != nil {
		return err
	}
	for _, item := range vpcs {
		td.vpcIDToName[item.ID] = item.Name
	}

	pods, err := UnscopedSelect[mysql.Pod]([]string{"id", "pod_namespace_id"})
	if err != nil {
		return err
	}
	for _, item := range pods {
		td.podNamespaceIDToPodIDs[item.PodNamespaceID] = append(td.podNamespaceIDToPodIDs[item.PodNamespaceID], item.ID)
	}

	podGroups, err := UnscopedSelect[mysql.PodGroup]([]string{"id", "pod_namespace_id"})
	if err != nil {
		return err
	}
	for _, item := range podGroups {
		td.podNamespaceIDToPodGroupIDs[item.PodNamespaceID] =
			append(td.podNamespaceIDToPodGroupIDs[item.PodNamespaceID], item.ID)
	}

	podRSs, err := UnscopedSelect[mysql.PodReplicaSet]([]string{"id", "pod_namespace_id"})
	if err != nil {
		return err
	}
	for _, item := range podRSs {
		td.podNamespaceIDToPodRSIDs[item.PodNamespaceID] =
			append(td.podNamespaceIDToPodRSIDs[item.PodNamespaceID], item.ID)
	}

	return nil
}
