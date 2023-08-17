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
	"strings"

	ctrlcommon "github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	"github.com/deepflowio/deepflow/server/controller/http/service/resource/common"
)

type PodIngressRule struct {
	DataProvider
	dataTool *PodIngressRuleToolData
}

func NewPodIngressRule() *PodIngressRule {
	dp := &PodIngressRule{newDataProvider(ctrlcommon.RESOURCE_TYPE_POD_INGRESS_RULE_EN), new(PodIngressRuleToolData)}
	dp.setGenerator(dp)
	return dp
}

func (p *PodIngressRule) generate() (data []common.ResponseElem, err error) {
	err = p.dataTool.Init().Load()
	for _, item := range p.dataTool.podIngressRuleBackend {
		data = append(data, p.generateOne(item))
	}
	return
}

func (p *PodIngressRule) generateOne(item mysql.PodIngressRuleBackend) common.ResponseElem {
	podIngressRule := p.dataTool.podIngressRuleIDToPodIngressRule[item.PodIngressRuleID]
	d := MySQLModelToMap(podIngressRule)
	d["PROTOCOL"] = strings.ToLower(podIngressRule.Protocol)

	d["POD_INGRESS_NAME"] = ""
	d["POD_NAMESPACE_ID"] = ""
	podIngress, ok := p.dataTool.podIngressIDToPodIngress[item.PodIngressID]
	if ok {
		d["POD_INGRESS_NAME"] = podIngress.Name
		d["POD_NAMESPACE_ID"] = podIngress.PodNamespaceID
	}

	d["EPC_ID"] = 0
	if podCluster, ok := p.dataTool.podClusterIDToPodCluster[podIngress.PodClusterID]; ok {
		d["EPC_ID"] = podCluster.VPCID
	}

	d["POD_SERVICE_NAME"] = p.dataTool.podServiceIDToName[item.PodServiceID]
	d["PATH"] = item.Path
	d["PORT"] = item.Port
	d["POD_SERVICE_ID"] = item.PodServiceID

	return d
}

type PodIngressRuleToolData struct {
	podIngressRuleBackend []mysql.PodIngressRuleBackend

	podIngressRuleIDToPodIngressRule map[int]mysql.PodIngressRule
	podIngressIDToPodIngress         map[int]mysql.PodIngress
	podClusterIDToPodCluster         map[int]mysql.PodCluster
	podServiceIDToName               map[int]string
}

func (td *PodIngressRuleToolData) Init() *PodIngressRuleToolData {
	td.podIngressRuleIDToPodIngressRule = make(map[int]mysql.PodIngressRule)
	td.podIngressIDToPodIngress = make(map[int]mysql.PodIngress)
	td.podClusterIDToPodCluster = make(map[int]mysql.PodCluster)
	td.podServiceIDToName = make(map[int]string)
	return td
}

func (td *PodIngressRuleToolData) Load() (err error) {
	td.podIngressRuleBackend, err = UnscopedFind[mysql.PodIngressRuleBackend]()
	if err != nil {
		return err
	}

	podIngressRules, err := UnscopedFind[mysql.PodIngressRule]()
	if err != nil {
		return err
	}
	for _, item := range podIngressRules {
		td.podIngressRuleIDToPodIngressRule[item.ID] = item
	}

	podIngresses, err := Select[mysql.PodIngress]([]string{"id", "name", "pod_namespace_id", "pod_cluster_id"})
	if err != nil {
		return err
	}
	for _, item := range podIngresses {
		td.podIngressIDToPodIngress[item.ID] = item
	}

	podClusters, err := Select[mysql.PodCluster]([]string{"id", "epc_id"})
	if err != nil {
		return err
	}
	for _, item := range podClusters {
		td.podClusterIDToPodCluster[item.ID] = item
	}

	podServices, err := Select[mysql.PodService]([]string{"id", "name"})
	if err != nil {
		return err
	}
	for _, item := range podServices {
		td.podServiceIDToName[item.ID] = item.Name
	}

	return nil
}
