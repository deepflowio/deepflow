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

type PodIngress struct {
	DataProvider
	dataTool *PodIngressToolData
}

func NewPodIngress() *PodIngress {
	dp := &PodIngress{newDataProvider(ctrlcommon.RESOURCE_TYPE_POD_SERVICE_PORT_EN), new(PodIngressToolData)}
	dp.setGenerator(dp)
	return dp
}

func (p *PodIngress) generate() (data []common.ResponseElem, err error) {
	err = p.dataTool.Init().Load()
	for _, item := range p.dataTool.podIngresses {
		data = append(data, p.generateOne(item))
	}
	return
}

func (p *PodIngress) generateOne(item mysql.PodIngress) common.ResponseElem {
	d := MySQLModelToMap(item)

	d["AZ_NAME"] = p.dataTool.azLcuuidToName[item.AZ]
	epcID := p.dataTool.podClusterIDToEPCID[item.PodClusterID]
	d["EPC_ID"] = epcID
	d["EPC_NAME"] = p.dataTool.vpcIDToName[epcID]
	d["POD_CLUSTER_NAME"] = p.dataTool.podClusterIDToName[item.PodClusterID]
	d["POD_NAMESPACE_NAME"] = p.dataTool.podNamespaceIDToName[item.PodNamespaceID]
	d["POD_SERVICE_COUNT"] = len(p.dataTool.podIngressIDToPodServiceIDs[item.ID])
	d["POD_INGRESS_RULE_COUNT"] = len(p.dataTool.podIngressIDToPodIngressRuleBackendIDs[item.ID])

	return d
}

type PodIngressToolData struct {
	podIngresses []mysql.PodIngress

	azLcuuidToName       map[string]string
	podClusterIDToName   map[int]string
	podClusterIDToEPCID  map[int]int
	vpcIDToName          map[int]string
	podNamespaceIDToName map[int]string

	podIngressIDToPodServiceIDs            map[int][]int
	podIngressIDToPodIngressRuleBackendIDs map[int][]int
}

func (td *PodIngressToolData) Init() *PodIngressToolData {
	td.azLcuuidToName = make(map[string]string)
	td.podClusterIDToName = make(map[int]string)
	td.podClusterIDToEPCID = make(map[int]int)
	td.vpcIDToName = make(map[int]string)
	td.podNamespaceIDToName = make(map[int]string)

	td.podIngressIDToPodServiceIDs = make(map[int][]int)
	td.podIngressIDToPodIngressRuleBackendIDs = make(map[int][]int)

	return td
}

func (td *PodIngressToolData) Load() (err error) {
	td.podIngresses, err = UnscopedFind[mysql.PodIngress]()
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

	podClusters, err := Select[mysql.PodCluster]([]string{"id", "name", "epc_id"})
	if err != nil {
		return err
	}
	for _, item := range podClusters {
		td.podClusterIDToName[item.ID] = item.Name
		td.podClusterIDToEPCID[item.ID] = item.VPCID
	}
	vpcs, err := Select[mysql.VPC]([]string{"id", "name"})
	if err != nil {
		return err
	}
	for _, item := range vpcs {
		td.vpcIDToName[item.ID] = item.Name
	}

	podNamespaces, err := Select[mysql.PodNamespace]([]string{"id", "name"})
	if err != nil {
		return err
	}
	for _, item := range podNamespaces {
		td.podNamespaceIDToName[item.ID] = item.Name
	}

	podServices, err := Select[mysql.PodService]([]string{"id", "pod_ingress_id"})
	if err != nil {
		return err
	}
	for _, item := range podServices {
		td.podIngressIDToPodServiceIDs[item.PodIngressID] =
			append(td.podIngressIDToPodServiceIDs[item.PodIngressID], item.ID)
	}

	ruleBackends, err := Select[mysql.PodIngressRuleBackend]([]string{"pod_ingress_id", "pod_ingress_rule_id"})
	if err != nil {
		return err
	}
	for _, item := range ruleBackends {
		td.podIngressIDToPodIngressRuleBackendIDs[item.PodIngressID] =
			append(td.podIngressIDToPodIngressRuleBackendIDs[item.PodIngressID], item.PodIngressRuleID)
	}

	return nil
}
