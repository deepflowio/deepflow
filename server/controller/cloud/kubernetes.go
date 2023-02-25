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

package cloud

import (
	"fmt"

	"github.com/deepflowio/deepflow/server/controller/cloud/model"
	"github.com/deepflowio/deepflow/server/controller/common"
	"github.com/satori/go.uuid"
)

// Kubernetes平台直接使用对应kubernetesgather的resource作为cloud的resource
func (c *Cloud) getKubernetesData() model.Resource {
	k8sGatherTask, ok := c.kubernetesGatherTaskMap[c.basicInfo.Lcuuid]
	if !ok {
		errMSG := fmt.Sprintf("domain (%s) no related kubernetes_gather_task", c.basicInfo.Name)
		log.Error(errMSG)
		return model.Resource{
			ErrorMessage: errMSG,
			ErrorState:   common.RESOURCE_STATE_CODE_EXCEPTION,
		}
	}
	kubernetesGatherResource := k8sGatherTask.GetResource()

	// 避免合并时产生默认的空值，对kubernetes_gather resource的az做判断
	if kubernetesGatherResource.AZ.Lcuuid == "" {
		log.Infof("domain (%s) kubernetes_gather_task resource is null", c.basicInfo.Name)
		// return k8s gather error info
		return model.Resource{
			ErrorState:   kubernetesGatherResource.ErrorState,
			ErrorMessage: kubernetesGatherResource.ErrorMessage,
		}
	}

	// 合并网络
	networks := []model.Network{}
	networks = append(
		networks,
		kubernetesGatherResource.PodNetwork,
		kubernetesGatherResource.PodNodeNetwork,
		kubernetesGatherResource.PodServiceNetwork,
	)

	// 合并子网
	subnets := []model.Subnet{}
	subnets = append(subnets, kubernetesGatherResource.PodSubnets...)
	subnets = append(subnets, kubernetesGatherResource.PodNodeSubnets...)
	subnets = append(subnets, kubernetesGatherResource.PodServiceSubnets...)

	// 合并接口
	vinterfaces := []model.VInterface{}
	vinterfaces = append(vinterfaces, kubernetesGatherResource.PodVInterfaces...)
	vinterfaces = append(vinterfaces, kubernetesGatherResource.PodNodeVInterfaces...)
	vinterfaces = append(vinterfaces, kubernetesGatherResource.PodServiceVInterfaces...)

	// 合并IP
	ips := []model.IP{}
	ips = append(ips, kubernetesGatherResource.PodIPs...)
	ips = append(ips, kubernetesGatherResource.PodNodeIPs...)
	ips = append(ips, kubernetesGatherResource.PodServiceIPs...)

	// 合并region, 创建云平台的时候如果指定的有region这里就不会返回region,为了避免出现空值,这里要判断一下
	regions := []model.Region{}
	if kubernetesGatherResource.Region.Lcuuid != "" {
		regions = append(regions, kubernetesGatherResource.Region)
	}

	// 将所有容器节点默认同步为云服务器
	vms := []model.VM{}
	vmPodNodeConnections := []model.VMPodNodeConnection{}
	for _, node := range kubernetesGatherResource.PodNodes {
		state := common.VM_STATE_RUNNING
		if node.State == common.POD_NODE_STATE_EXCEPTION {
			state = common.VM_STATE_EXCEPTION
		}
		vmLcuuid := "ff" + common.GetUUID(node.Name, uuid.Nil)[2:]
		vms = append(vms, model.VM{
			Lcuuid:       vmLcuuid,
			Name:         node.Name,
			Label:        node.Lcuuid,
			HType:        common.VM_HTYPE_VM_C,
			State:        state,
			VPCLcuuid:    node.VPCLcuuid,
			AZLcuuid:     node.AZLcuuid,
			RegionLcuuid: node.RegionLcuuid,
		})
		vmPodNodeConnections = append(vmPodNodeConnections, model.VMPodNodeConnection{
			Lcuuid:        common.GetUUID(vmLcuuid+node.Lcuuid, uuid.Nil),
			VMLcuuid:      vmLcuuid,
			PodNodeLcuuid: node.Lcuuid,
		})
	}

	return model.Resource{
		Verified:               true,
		AZs:                    []model.AZ{kubernetesGatherResource.AZ},
		VPCs:                   []model.VPC{kubernetesGatherResource.VPC},
		PodClusters:            []model.PodCluster{kubernetesGatherResource.PodCluster},
		ErrorState:             kubernetesGatherResource.ErrorState,
		ErrorMessage:           kubernetesGatherResource.ErrorMessage,
		PodNodes:               kubernetesGatherResource.PodNodes,
		PodServices:            kubernetesGatherResource.PodServices,
		PodNamespaces:          kubernetesGatherResource.PodNamespaces,
		Pods:                   kubernetesGatherResource.Pods,
		PodGroups:              kubernetesGatherResource.PodGroups,
		PodIngresses:           kubernetesGatherResource.PodIngresses,
		PodGroupPorts:          kubernetesGatherResource.PodGroupPorts,
		PodReplicaSets:         kubernetesGatherResource.PodReplicaSets,
		PodServicePorts:        kubernetesGatherResource.PodServicePorts,
		PodIngressRules:        kubernetesGatherResource.PodIngressRules,
		PodIngressRuleBackends: kubernetesGatherResource.PodIngressRuleBackends,
		IPs:                    ips,
		VMs:                    vms,
		Regions:                regions,
		Subnets:                subnets,
		Networks:               networks,
		VInterfaces:            vinterfaces,
		VMPodNodeConnections:   vmPodNodeConnections,
	}
}
