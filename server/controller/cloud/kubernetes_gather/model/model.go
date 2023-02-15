/*
 * Copyright (c) 2022 Yunshan Networks
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

package model

import (
	"github.com/deepflowio/deepflow/server/controller/cloud/model"
	"time"
)

type KubernetesGatherResource struct {
	ErrorState             int
	ErrorMessage           string
	Region                 model.Region
	AZ                     model.AZ
	VPC                    model.VPC
	PodCluster             model.PodCluster
	PodNodes               []model.PodNode
	PodNamespaces          []model.PodNamespace
	PodGroups              []model.PodGroup
	PodReplicaSets         []model.PodReplicaSet
	Pods                   []model.Pod
	PodServices            []model.PodService
	PodServicePorts        []model.PodServicePort
	PodGroupPorts          []model.PodGroupPort
	PodIngresses           []model.PodIngress
	PodIngressRules        []model.PodIngressRule
	PodIngressRuleBackends []model.PodIngressRuleBackend
	PodNodeNetwork         model.Network
	PodNodeSubnets         []model.Subnet
	PodNodeVInterfaces     []model.VInterface
	PodNodeIPs             []model.IP
	PodServiceNetwork      model.Network
	PodServiceSubnets      []model.Subnet
	PodServiceVInterfaces  []model.VInterface
	PodServiceIPs          []model.IP
	PodNetwork             model.Network
	PodSubnets             []model.Subnet
	PodVInterfaces         []model.VInterface
	PodIPs                 []model.IP
}

type KubernetesGatherBasicInfo struct {
	Lcuuid                string        `json:"lcuuid"`
	Name                  string        `json:"name"`
	ClusterID             string        `json:"cluster_id"`
	PortNameRegex         string        `json:"port_name_regex"`
	PodNetIPv4CIDRMaxMask int           `json:"pod_net_ipv4_cidr_max_mask"`
	PodNetIPv6CIDRMaxMask int           `json:"pod_net_ipv6_cidr_max_mask"`
	Interval              time.Duration `json:"interval"`
	LastStartedAt         time.Time     `json:"last_started_at"`
	LastCompletedAt       time.Time     `json:"last_completed_at"`
}
