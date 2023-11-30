/*
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

package cloud

import (
	"net"
	"time"

	"inet.af/netaddr"

	kubernetes_model "github.com/deepflowio/deepflow/server/controller/cloud/kubernetes_gather/model"
	"github.com/deepflowio/deepflow/server/controller/cloud/model"
	"github.com/deepflowio/deepflow/server/controller/common"
)

// 合并附属容器集群的资源到云平台资源中
// 遍历Cloud下所有KubernetesGather的数据，更新部分属性信息，并合并到Cloud的resource中
func (c *Cloud) getSubDomainData(cResource model.Resource) map[string]model.SubDomainResource {

	subDomainResources := make(map[string]model.SubDomainResource)
	for lcuuid, kubernetesGatherTask := range c.kubernetesGatherTaskMap {
		kubernetesGatherResource := kubernetesGatherTask.GetResource()

		// 容器节点及与虚拟机关联关系
		podNodes, vmPodNodeConnections := c.getSubDomainPodNodes(lcuuid, cResource, &kubernetesGatherResource)
		// 如果当前KubernetesGather数据中没有容器节点，则跳过该集群
		if len(podNodes) == 0 {
			log.Info("cloud merge subdomain data: k8s gather resource not found pod node")
			subDomainResources[lcuuid] = model.SubDomainResource{
				ErrorState:   kubernetesGatherResource.ErrorState,
				ErrorMessage: kubernetesGatherResource.ErrorMessage,
			}
			continue
		}
		// 取集群中某个容器节点的az信息作为集群的az，当前不支持附属容器集群跨可用区
		azLcuuid := podNodes[0].AZLcuuid

		// 容器集群
		podClusters := c.getSubDomainPodClusters(lcuuid, &kubernetesGatherResource, azLcuuid)

		// 命名空间
		podNamespaces := c.getSubDomainPodNamespaces(lcuuid, &kubernetesGatherResource, azLcuuid)

		// Ingress及规则
		podIngresses, podIngressRules, podIngressRuleBackends := c.getSubDomainIngresses(
			lcuuid, &kubernetesGatherResource, azLcuuid,
		)

		// 容器服务及规则
		podServices, podServicePorts := c.getSubDomainPodServices(
			lcuuid, &kubernetesGatherResource, azLcuuid,
		)

		// podGroups
		podGroups, podGroupPorts := c.getSubDomainPodGroups(lcuuid, &kubernetesGatherResource, azLcuuid)

		// podReplicaSets
		podReplicaSets := c.getSubDomainPodReplicaSets(lcuuid, &kubernetesGatherResource, azLcuuid)

		// pods
		pods := c.getSubDomainPods(lcuuid, &kubernetesGatherResource, azLcuuid)

		// IP
		ips, reservedPodSubnetLcuuidToIPNum, updatedVInterfaceLcuuidToNetworkLcuuid :=
			c.getSubDomainIPs(lcuuid, cResource, &kubernetesGatherResource)

		// vinterfaces
		vinterfaces := c.getSubDomainVInterfaces(
			lcuuid, &kubernetesGatherResource, updatedVInterfaceLcuuidToNetworkLcuuid,
		)

		// subnets
		subnets := c.getSubDomainSubnets(
			lcuuid, &kubernetesGatherResource, reservedPodSubnetLcuuidToIPNum,
		)

		// networks
		networks := c.getSubDomainNetworks(lcuuid, &kubernetesGatherResource, azLcuuid)

		// prometheusTargets
		prometheusTargets := c.getSubDomainPrometheusTargets(lcuuid, &kubernetesGatherResource)

		// 生成SubDomainResource
		subDomainResource := model.SubDomainResource{
			Verified:               true,
			SyncAt:                 time.Now(),
			ErrorState:             kubernetesGatherResource.ErrorState,
			ErrorMessage:           kubernetesGatherResource.ErrorMessage,
			PodClusters:            podClusters,
			PodNodes:               podNodes,
			VMPodNodeConnections:   vmPodNodeConnections,
			PodNamespaces:          podNamespaces,
			PodIngresses:           podIngresses,
			PodIngressRules:        podIngressRules,
			PodIngressRuleBackends: podIngressRuleBackends,
			PodServices:            podServices,
			PodServicePorts:        podServicePorts,
			PodGroups:              podGroups,
			PodGroupPorts:          podGroupPorts,
			PodReplicaSets:         podReplicaSets,
			Pods:                   pods,
			Networks:               networks,
			Subnets:                subnets,
			VInterfaces:            vinterfaces,
			IPs:                    ips,
			PrometheusTargets:      prometheusTargets,
		}
		subDomainResources[lcuuid] = subDomainResource
	}

	return subDomainResources
}

// - 根据IP查询对应的虚拟机，生成与虚拟机的关联关系
// - 根据虚拟机的az属性，确定容器节点的az信息
func (c *Cloud) getSubDomainPodNodes(subDomainLcuuid string, cResource model.Resource, kResource *kubernetes_model.KubernetesGatherResource) ([]model.PodNode, []model.VMPodNodeConnection) {
	var retPodNodes []model.PodNode
	var retVMPodNodeConnections []model.VMPodNodeConnection

	if len(kResource.PodNodes) == 0 {
		return retPodNodes, retVMPodNodeConnections
	}
	vpcLcuuid := kResource.PodNodes[0].VPCLcuuid

	lcuuidToVM := make(map[string]*model.VM)
	for index, vm := range cResource.VMs {
		if vm.VPCLcuuid != vpcLcuuid {
			continue
		}
		lcuuidToVM[vm.Lcuuid] = &cResource.VMs[index]
	}

	vinterfaceLcuuidToVMLcuuid := make(map[string]string)
	for _, vinterface := range cResource.VInterfaces {
		if vinterface.VPCLcuuid != vpcLcuuid || vinterface.DeviceType != common.VIF_DEVICE_TYPE_VM {
			continue
		}
		vinterfaceLcuuidToVMLcuuid[vinterface.Lcuuid] = vinterface.DeviceLcuuid
	}

	ipToVM := make(map[string]*model.VM)
	for _, ip := range cResource.IPs {
		vmLcuuid, ok := vinterfaceLcuuidToVMLcuuid[ip.VInterfaceLcuuid]
		if !ok {
			continue
		}
		vm, ok := lcuuidToVM[vmLcuuid]
		if !ok {
			continue
		}
		ipToVM[ip.IP] = vm
	}

	networkLcuuidToAZLcuuid := make(map[string]string)
	for _, network := range cResource.Networks {
		if network.VPCLcuuid != vpcLcuuid {
			continue
		}
		if network.AZLcuuid == "" {
			continue
		}
		networkLcuuidToAZLcuuid[network.Lcuuid] = network.AZLcuuid
	}

	cidrToAZLcuuid := make(map[string]string)
	for _, subnet := range cResource.Subnets {
		if subnet.VPCLcuuid != vpcLcuuid {
			continue
		}
		azLcuuid, ok := networkLcuuidToAZLcuuid[subnet.NetworkLcuuid]
		if !ok {
			continue
		}
		cidrToAZLcuuid[subnet.CIDR] = azLcuuid
	}

	for _, podNode := range kResource.PodNodes {
		podNodeAZLcuuid := ""
		vm, ok := ipToVM[podNode.IP]
		if ok {
			// generate vm_pod_node_connection
			retVMPodNodeConnections = append(retVMPodNodeConnections, model.VMPodNodeConnection{
				Lcuuid:          common.GenerateUUID(vm.Lcuuid + podNode.Lcuuid),
				VMLcuuid:        vm.Lcuuid,
				PodNodeLcuuid:   podNode.Lcuuid,
				SubDomainLcuuid: subDomainLcuuid,
			})
			podNodeAZLcuuid = vm.AZLcuuid
		} else {
			// check if pod_node ip in vpc cidr
			for cidr, azLcuuid := range cidrToAZLcuuid {
				ip := net.ParseIP(podNode.IP)
				_, ipNet, err := net.ParseCIDR(cidr)
				if err != nil {
					log.Error(err)
					continue
				}
				if ipNet.Contains(ip) {
					podNodeAZLcuuid = azLcuuid
					break
				}
			}
			// if not in vpc cidrs, skip the pod node
			if podNodeAZLcuuid == "" {
				continue
			}
		}
		// 生成容器节点
		retPodNodes = append(retPodNodes, model.PodNode{
			Lcuuid:           podNode.Lcuuid,
			Name:             podNode.Name,
			Type:             podNode.Type,
			ServerType:       podNode.ServerType,
			State:            podNode.State,
			IP:               podNode.IP,
			VCPUNum:          podNode.VCPUNum,
			MemTotal:         podNode.MemTotal,
			PodClusterLcuuid: podNode.PodClusterLcuuid,
			VPCLcuuid:        vpcLcuuid,
			AZLcuuid:         podNodeAZLcuuid,
			RegionLcuuid:     podNode.RegionLcuuid,
			SubDomainLcuuid:  subDomainLcuuid,
		})
	}
	return retPodNodes, retVMPodNodeConnections
}

func (c *Cloud) getSubDomainPodClusters(
	subDomainLcuuid string, resource *kubernetes_model.KubernetesGatherResource, azLcuuid string,
) []model.PodCluster {
	var retPodClusters []model.PodCluster

	// 通过PodClusters，更新az信息；并添加到Cloud的Resource中
	retPodClusters = append(retPodClusters, model.PodCluster{
		Lcuuid:          resource.PodCluster.Lcuuid,
		Name:            resource.PodCluster.Name,
		ClusterName:     resource.PodCluster.ClusterName,
		Version:         resource.PodCluster.Version,
		VPCLcuuid:       resource.PodCluster.VPCLcuuid,
		AZLcuuid:        azLcuuid,
		RegionLcuuid:    resource.PodCluster.RegionLcuuid,
		SubDomainLcuuid: subDomainLcuuid,
	})
	return retPodClusters
}

func (c *Cloud) getSubDomainPodNamespaces(
	subDomainLcuuid string, resource *kubernetes_model.KubernetesGatherResource, azLcuuid string,
) []model.PodNamespace {
	var retPodNamespaces []model.PodNamespace

	// 遍历PodNamespaces，更新az信息；并添加到Cloud的Resource中
	for _, podNamespace := range resource.PodNamespaces {
		retPodNamespaces = append(retPodNamespaces, model.PodNamespace{
			Lcuuid:           podNamespace.Lcuuid,
			Name:             podNamespace.Name,
			PodClusterLcuuid: podNamespace.PodClusterLcuuid,
			AZLcuuid:         azLcuuid,
			RegionLcuuid:     podNamespace.RegionLcuuid,
			SubDomainLcuuid:  subDomainLcuuid,
		})
	}
	return retPodNamespaces
}

func (c *Cloud) getSubDomainIngresses(
	subDomainLcuuid string, resource *kubernetes_model.KubernetesGatherResource, azLcuuid string,
) ([]model.PodIngress, []model.PodIngressRule, []model.PodIngressRuleBackend) {
	var retPodIngresses []model.PodIngress
	var retPodIngressRules []model.PodIngressRule
	var retPodIngressRuleBackends []model.PodIngressRuleBackend

	// 遍历PodIngresses，更新az信息；并添加到Cloud的Resource中
	for _, podIngress := range resource.PodIngresses {
		retPodIngresses = append(retPodIngresses, model.PodIngress{
			Lcuuid:             podIngress.Lcuuid,
			Name:               podIngress.Name,
			PodNamespaceLcuuid: podIngress.PodNamespaceLcuuid,
			PodClusterLcuuid:   podIngress.PodClusterLcuuid,
			AZLcuuid:           azLcuuid,
			RegionLcuuid:       podIngress.RegionLcuuid,
			SubDomainLcuuid:    subDomainLcuuid,
		})
	}
	for _, podIngressRule := range resource.PodIngressRules {
		retPodIngressRules = append(retPodIngressRules, model.PodIngressRule{
			Lcuuid:           podIngressRule.Lcuuid,
			Name:             podIngressRule.Name,
			Protocol:         podIngressRule.Protocol,
			Host:             podIngressRule.Host,
			PodIngressLcuuid: podIngressRule.PodIngressLcuuid,
			SubDomainLcuuid:  subDomainLcuuid,
		})
	}
	for _, podIngressRuleBackend := range resource.PodIngressRuleBackends {
		retPodIngressRuleBackends = append(retPodIngressRuleBackends, model.PodIngressRuleBackend{
			Lcuuid:               podIngressRuleBackend.Lcuuid,
			Path:                 podIngressRuleBackend.Path,
			Port:                 podIngressRuleBackend.Port,
			PodServiceLcuuid:     podIngressRuleBackend.PodServiceLcuuid,
			PodIngressLcuuid:     podIngressRuleBackend.PodIngressLcuuid,
			PodIngressRuleLcuuid: podIngressRuleBackend.PodIngressRuleLcuuid,
			SubDomainLcuuid:      subDomainLcuuid,
		})
	}
	return retPodIngresses, retPodIngressRules, retPodIngressRuleBackends
}

func (c *Cloud) getSubDomainPodServices(
	subDomainLcuuid string, resource *kubernetes_model.KubernetesGatherResource, azLcuuid string,
) ([]model.PodService, []model.PodServicePort) {
	var retPodServices []model.PodService
	var retPodServicePorts []model.PodServicePort

	// 遍历PodServices，更新az信息；并添加到Cloud的Resource中
	for _, podService := range resource.PodServices {
		retPodServices = append(retPodServices, model.PodService{
			Lcuuid:             podService.Lcuuid,
			Name:               podService.Name,
			Label:              podService.Label,
			Annotation:         podService.Annotation,
			Type:               podService.Type,
			Selector:           podService.Selector,
			ServiceClusterIP:   podService.ServiceClusterIP,
			PodIngressLcuuid:   podService.PodIngressLcuuid,
			PodNamespaceLcuuid: podService.PodNamespaceLcuuid,
			PodClusterLcuuid:   podService.PodClusterLcuuid,
			VPCLcuuid:          podService.VPCLcuuid,
			AZLcuuid:           azLcuuid,
			RegionLcuuid:       podService.RegionLcuuid,
			SubDomainLcuuid:    subDomainLcuuid,
		})
	}
	for _, podServicePort := range resource.PodServicePorts {
		retPodServicePorts = append(retPodServicePorts, model.PodServicePort{
			Lcuuid:           podServicePort.Lcuuid,
			Name:             podServicePort.Name,
			Protocol:         podServicePort.Protocol,
			Port:             podServicePort.Port,
			TargetPort:       podServicePort.TargetPort,
			NodePort:         podServicePort.NodePort,
			PodServiceLcuuid: podServicePort.PodServiceLcuuid,
			SubDomainLcuuid:  subDomainLcuuid,
		})
	}
	return retPodServices, retPodServicePorts
}

func (c *Cloud) getSubDomainPodGroups(
	subDomainLcuuid string, resource *kubernetes_model.KubernetesGatherResource, azLcuuid string,
) ([]model.PodGroup, []model.PodGroupPort) {
	var retPodGroups []model.PodGroup
	var retPodGroupPorts []model.PodGroupPort

	// 遍历PodGroups，更新az信息；并添加到Cloud的Resource中
	for _, podGroup := range resource.PodGroups {
		retPodGroups = append(retPodGroups, model.PodGroup{
			Lcuuid:             podGroup.Lcuuid,
			Name:               podGroup.Name,
			Label:              podGroup.Label,
			Type:               podGroup.Type,
			PodNum:             podGroup.PodNum,
			PodNamespaceLcuuid: podGroup.PodNamespaceLcuuid,
			PodClusterLcuuid:   podGroup.PodClusterLcuuid,
			AZLcuuid:           azLcuuid,
			RegionLcuuid:       podGroup.RegionLcuuid,
			SubDomainLcuuid:    subDomainLcuuid,
		})
	}
	for _, podGroupPort := range resource.PodGroupPorts {
		retPodGroupPorts = append(retPodGroupPorts, model.PodGroupPort{
			Lcuuid:           podGroupPort.Lcuuid,
			Name:             podGroupPort.Name,
			Protocol:         podGroupPort.Protocol,
			Port:             podGroupPort.Port,
			PodGroupLcuuid:   podGroupPort.PodGroupLcuuid,
			PodServiceLcuuid: podGroupPort.PodServiceLcuuid,
			SubDomainLcuuid:  subDomainLcuuid,
		})
	}
	return retPodGroups, retPodGroupPorts
}

func (c *Cloud) getSubDomainPodReplicaSets(
	subDomainLcuuid string, resource *kubernetes_model.KubernetesGatherResource, azLcuuid string,
) []model.PodReplicaSet {
	var retPodReplicaSets []model.PodReplicaSet

	// 遍历PodReplicaSets，更新az信息；并添加到Cloud的Resource中
	for _, podReplicaSet := range resource.PodReplicaSets {
		retPodReplicaSets = append(retPodReplicaSets, model.PodReplicaSet{
			Lcuuid:             podReplicaSet.Lcuuid,
			Name:               podReplicaSet.Name,
			Label:              podReplicaSet.Label,
			PodNum:             podReplicaSet.PodNum,
			PodGroupLcuuid:     podReplicaSet.PodGroupLcuuid,
			PodNamespaceLcuuid: podReplicaSet.PodNamespaceLcuuid,
			PodClusterLcuuid:   podReplicaSet.PodClusterLcuuid,
			AZLcuuid:           azLcuuid,
			RegionLcuuid:       podReplicaSet.RegionLcuuid,
			SubDomainLcuuid:    subDomainLcuuid,
		})
	}
	return retPodReplicaSets
}

func (c *Cloud) getSubDomainPods(
	subDomainLcuuid string, resource *kubernetes_model.KubernetesGatherResource, azLcuuid string,
) []model.Pod {
	var retPods []model.Pod

	// 遍历Pods，更新az信息；并添加到Cloud的Resource中
	for _, pod := range resource.Pods {
		retPods = append(retPods, model.Pod{
			Lcuuid:              pod.Lcuuid,
			Name:                pod.Name,
			Annotation:          pod.Annotation,
			ENV:                 pod.ENV,
			Label:               pod.Label,
			ContainerIDs:        pod.ContainerIDs,
			State:               pod.State,
			CreatedAt:           pod.CreatedAt,
			PodReplicaSetLcuuid: pod.PodReplicaSetLcuuid,
			PodNodeLcuuid:       pod.PodNodeLcuuid,
			PodGroupLcuuid:      pod.PodGroupLcuuid,
			PodNamespaceLcuuid:  pod.PodNamespaceLcuuid,
			PodClusterLcuuid:    pod.PodClusterLcuuid,
			VPCLcuuid:           pod.VPCLcuuid,
			AZLcuuid:            azLcuuid,
			RegionLcuuid:        pod.RegionLcuuid,
			SubDomainLcuuid:     subDomainLcuuid,
		})
	}
	return retPods
}

func (c *Cloud) getSubDomainIPs(
	subDomainLcuuid string, cResource model.Resource, kResource *kubernetes_model.KubernetesGatherResource,
) ([]model.IP, map[string]int, map[string]string) {
	var retIPs []model.IP
	var reservedPodSubnetLcuuidToIPNum map[string]int
	var updatedVInterfaceLcuuidToNetworkLcuuid map[string]string

	// POD/Service IP无需处理子网信息，直接补充subDomainLcuuid
	for _, ips := range [][]model.IP{kResource.PodIPs, kResource.PodServiceIPs} {
		for _, ip := range ips {
			retIPs = append(retIPs, model.IP{
				Lcuuid:           ip.Lcuuid,
				VInterfaceLcuuid: ip.VInterfaceLcuuid,
				IP:               ip.IP,
				SubnetLcuuid:     ip.SubnetLcuuid,
				RegionLcuuid:     ip.RegionLcuuid,
				SubDomainLcuuid:  subDomainLcuuid,
			})
		}
	}
	// 容器节点IP需要检查是否属于云平台已有子网
	// - 如果属于，更新SubnetLcuuid为云平台已有子网
	// - 否则，保持原有SubnetLcuuid
	// 针对KubernetesGather返回的子网，记录子网下剩余的IP个数，用于后期生成子网返回结果
	subnets := []model.Subnet{}
	reservedPodSubnetLcuuidToIPNum = make(map[string]int)
	updatedVInterfaceLcuuidToNetworkLcuuid = make(map[string]string)
	for _, subnet := range cResource.Subnets {
		if subnet.VPCLcuuid != kResource.VPC.Lcuuid {
			continue
		}
		subnets = append(subnets, subnet)
	}
	for _, ip := range kResource.PodNodeIPs {
		ipAddr, _ := netaddr.ParseIP(ip.IP)
		subnetLcuuid := ""
		for _, subnet := range subnets {
			subnetCidr, _ := netaddr.ParseIPPrefix(subnet.CIDR)
			if subnetCidr.Contains(ipAddr) {
				subnetLcuuid = subnet.Lcuuid
				updatedVInterfaceLcuuidToNetworkLcuuid[ip.VInterfaceLcuuid] = subnet.NetworkLcuuid
				break
			}
		}
		// 如果IP不在云平台已有子网中，则更新需要保留的kubernetesGather子网信息
		if subnetLcuuid == "" {
			reservedPodSubnetLcuuidToIPNum[ip.SubnetLcuuid] += 1
			subnetLcuuid = ip.SubnetLcuuid
		}
		retIPs = append(retIPs, model.IP{
			Lcuuid:           ip.Lcuuid,
			VInterfaceLcuuid: ip.VInterfaceLcuuid,
			IP:               ip.IP,
			SubnetLcuuid:     subnetLcuuid,
			RegionLcuuid:     ip.RegionLcuuid,
			SubDomainLcuuid:  subDomainLcuuid,
		})
	}
	return retIPs, reservedPodSubnetLcuuidToIPNum, updatedVInterfaceLcuuidToNetworkLcuuid
}

func (c *Cloud) getSubDomainVInterfaces(
	subDomainLcuuid string, resource *kubernetes_model.KubernetesGatherResource,
	updatedVInterfaceLcuuidToNetworkLcuuid map[string]string,
) []model.VInterface {
	var retVInterfaces []model.VInterface

	// POD/Service 接口无需处理子网信息，直接补充subDomainLcuuid
	for _, vinterfaces := range [][]model.VInterface{
		resource.PodVInterfaces, resource.PodServiceVInterfaces,
	} {
		for _, vinterface := range vinterfaces {
			retVInterfaces = append(retVInterfaces, model.VInterface{
				Lcuuid:          vinterface.Lcuuid,
				Name:            vinterface.Name,
				Type:            vinterface.Type,
				Mac:             vinterface.Mac,
				NetnsID:         vinterface.NetnsID,
				VTapID:          vinterface.VTapID,
				TapMac:          vinterface.TapMac,
				DeviceType:      vinterface.DeviceType,
				DeviceLcuuid:    vinterface.DeviceLcuuid,
				NetworkLcuuid:   vinterface.NetworkLcuuid,
				VPCLcuuid:       vinterface.VPCLcuuid,
				RegionLcuuid:    vinterface.RegionLcuuid,
				SubDomainLcuuid: subDomainLcuuid,
			})
		}
	}
	// 检查容器节点接口是否需要更新子网信息，并补充subDomainLcuuid
	for _, vinterface := range resource.PodNodeVInterfaces {
		networkLcuuid := vinterface.NetworkLcuuid
		networkType := vinterface.Type
		if updateNetworkLcuuid, ok := updatedVInterfaceLcuuidToNetworkLcuuid[vinterface.Lcuuid]; ok {
			networkLcuuid = updateNetworkLcuuid
		} else {
			// for addtional route interface, set type = LAN
			networkType = common.VIF_TYPE_LAN
		}
		retVInterfaces = append(retVInterfaces, model.VInterface{
			Lcuuid:          vinterface.Lcuuid,
			Name:            vinterface.Name,
			Type:            networkType,
			Mac:             vinterface.Mac,
			NetnsID:         vinterface.NetnsID,
			VTapID:          vinterface.VTapID,
			TapMac:          vinterface.TapMac,
			DeviceType:      vinterface.DeviceType,
			DeviceLcuuid:    vinterface.DeviceLcuuid,
			NetworkLcuuid:   networkLcuuid,
			VPCLcuuid:       vinterface.VPCLcuuid,
			RegionLcuuid:    vinterface.RegionLcuuid,
			SubDomainLcuuid: subDomainLcuuid,
		})
	}
	return retVInterfaces
}

func (c *Cloud) getSubDomainSubnets(
	subDomainLcuuid string, resource *kubernetes_model.KubernetesGatherResource,
	reservedPodSubnetLcuuidToIPNum map[string]int,
) []model.Subnet {
	var retSubnets []model.Subnet

	// POD/Service子网无需处理，直接补充subDomainLcuuid
	for _, subnets := range [][]model.Subnet{
		resource.PodSubnets, resource.PodServiceSubnets,
	} {
		for _, subnet := range subnets {
			retSubnets = append(retSubnets, model.Subnet{
				Lcuuid:          subnet.Lcuuid,
				Name:            subnet.Name,
				Label:           subnet.Label,
				CIDR:            subnet.CIDR,
				NetworkLcuuid:   subnet.NetworkLcuuid,
				VPCLcuuid:       subnet.VPCLcuuid,
				SubDomainLcuuid: subDomainLcuuid,
			})
		}
	}

	// 容器节点子网需要检查是否在保留子网中，如果在则补充subDomainLcuuid；否则跳过
	for _, subnet := range resource.PodNodeSubnets {
		if _, ok := reservedPodSubnetLcuuidToIPNum[subnet.Lcuuid]; !ok {
			continue
		}
		retSubnets = append(retSubnets, model.Subnet{
			Lcuuid:          subnet.Lcuuid,
			Name:            subnet.Name,
			Label:           subnet.Label,
			CIDR:            subnet.CIDR,
			NetworkLcuuid:   subnet.NetworkLcuuid,
			VPCLcuuid:       subnet.VPCLcuuid,
			SubDomainLcuuid: subDomainLcuuid,
		})
	}

	return retSubnets
}

func (c *Cloud) getSubDomainNetworks(
	subDomainLcuuid string, resource *kubernetes_model.KubernetesGatherResource, azLcuuid string,
) []model.Network {
	var retNetworks []model.Network

	// 遍历Networks，更新az和subDomain信息
	for _, network := range []model.Network{
		resource.PodNetwork, resource.PodServiceNetwork,
	} {
		retNetworks = append(retNetworks, model.Network{
			Lcuuid:          network.Lcuuid,
			Name:            network.Name,
			Label:           network.Label,
			NetType:         network.NetType,
			VPCLcuuid:       network.VPCLcuuid,
			AZLcuuid:        azLcuuid,
			RegionLcuuid:    network.RegionLcuuid,
			SubDomainLcuuid: subDomainLcuuid,
		})
	}

	// set podNodeNetwork netType = LAN
	for _, network := range []model.Network{resource.PodNodeNetwork} {
		retNetworks = append(retNetworks, model.Network{
			Lcuuid:          network.Lcuuid,
			Name:            network.Name,
			Label:           network.Label,
			NetType:         common.NETWORK_TYPE_LAN,
			VPCLcuuid:       network.VPCLcuuid,
			AZLcuuid:        azLcuuid,
			RegionLcuuid:    network.RegionLcuuid,
			SubDomainLcuuid: subDomainLcuuid,
		})
	}

	return retNetworks
}

func (c *Cloud) getSubDomainPrometheusTargets(
	subDomainLcuuid string, resource *kubernetes_model.KubernetesGatherResource) []model.PrometheusTarget {
	var retPrometheusTargets []model.PrometheusTarget

	// 遍历PrometheusTargets，更新subDomain信息
	for _, p := range resource.PrometheusTargets {
		retPrometheusTargets = append(retPrometheusTargets, model.PrometheusTarget{
			Lcuuid:          p.Lcuuid,
			ScrapeURL:       p.ScrapeURL,
			Instance:        p.Instance,
			Job:             p.Job,
			OtherLabels:     p.OtherLabels,
			SubDomainLcuuid: subDomainLcuuid,
		})
	}

	return retPrometheusTargets
}
