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

type PodCluster struct {
	DataProvider
	dataTool *PodClusterToolData
}

func NewPodCluster() *PodCluster {
	dp := &PodCluster{newDataProvider(ctrlcommon.RESOURCE_TYPE_POD_SERVICE_PORT_EN), new(PodClusterToolData)}
	dp.setGenerator(dp)
	return dp
}

func (p *PodCluster) generate() (data []common.ResponseElem, err error) {
	err = p.dataTool.Init().Load()
	for _, item := range p.dataTool.podClusters {
		data = append(data, p.generateOne(item))
	}
	return
}

func (p *PodCluster) generateOne(item mysql.PodCluster) common.ResponseElem {
	d := MySQLModelToMap(item)
	if _, ok := d["VPC_ID"]; ok {
		d["EPC_ID"] = item.VPCID
		delete(d, "VPC_ID")
	}

	d["DOMAIN_NAME"] = p.dataTool.domainLcuuidToName[item.Domain]
	d["AZ_NAME"] = p.dataTool.azLcuuidToName[item.AZ]
	d["REGION_NAME"] = p.dataTool.regionLcuuidToName[item.Region]
	d["EPC_NAME"] = p.dataTool.vpcIDToName[item.VPCID]
	d["NODE_COUNT"] = len(p.dataTool.podClusterIDToPodNodeIDs[item.ID])

	return d
}

type PodClusterToolData struct {
	podClusters []mysql.PodCluster

	domainLcuuidToName       map[string]string
	regionLcuuidToName       map[string]string
	azLcuuidToName           map[string]string
	vpcIDToName              map[int]string
	podClusterIDToPodNodeIDs map[int][]int
}

func (td *PodClusterToolData) Init() *PodClusterToolData {
	td.domainLcuuidToName = make(map[string]string)
	td.regionLcuuidToName = make(map[string]string)
	td.azLcuuidToName = make(map[string]string)
	td.vpcIDToName = make(map[int]string)
	td.podClusterIDToPodNodeIDs = make(map[int][]int)

	return td
}

func (td *PodClusterToolData) Load() (err error) {
	td.podClusters, err = UnscopedFind[mysql.PodCluster]()
	if err != nil {
		return err
	}

	domains, err := UnscopedSelect[mysql.Domain]([]string{"lcuuid", "name"})
	if err != nil {
		return err
	}
	for _, item := range domains {
		td.domainLcuuidToName[item.Lcuuid] = item.Name
	}

	regions, err := UnscopedSelect[mysql.Region]([]string{"lcuuid", "name"})
	if err != nil {
		return err
	}
	for _, item := range regions {
		td.regionLcuuidToName[item.Lcuuid] = item.Name
	}

	azs, err := UnscopedSelect[mysql.AZ]([]string{"lcuuid", "name"})
	if err != nil {
		return err
	}
	for _, item := range azs {
		td.azLcuuidToName[item.Lcuuid] = item.Name
	}

	vpcs, err := UnscopedSelect[mysql.VPC]([]string{"id", "name"})
	if err != nil {
		return err
	}
	for _, item := range vpcs {
		td.vpcIDToName[item.ID] = item.Name
	}

	podNodes, err := UnscopedSelect[mysql.PodNode]([]string{"id", "pod_cluster_id"})
	if err != nil {
		return err
	}
	for _, item := range podNodes {
		td.podClusterIDToPodNodeIDs[item.PodClusterID] =
			append(td.podClusterIDToPodNodeIDs[item.PodClusterID], item.ID)
	}

	return nil
}
