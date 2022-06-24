package cloud

import (
	"server/controller/cloud/model"
)

// Kubernetes平台直接使用对应kubernetesgather的resource作为cloud的resource
func (c *Cloud) getKubernetesData() {
	k8sGatherTask, ok := c.kubernetesGatherTaskMap[c.basicInfo.Lcuuid]
	if !ok {
		log.Infof("domain (%s) no related kubernetes_gather_task", c.basicInfo.Name)
		return
	}
	kubernetesGatherResource := k8sGatherTask.GetResource()

	// 避免合并时产生默认的空值，对kubernetes_gather resource的az做判断
	if kubernetesGatherResource.AZ.Lcuuid == "" {
		log.Infof("domain (%s) kubernetes_gather_task resource is null", c.basicInfo.Name)
		// return k8s gather error info
		c.resource = model.Resource{
			ErrorState:   kubernetesGatherResource.ErrorState,
			ErrorMessage: kubernetesGatherResource.ErrorMessage,
		}
		return
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

	// 更新resource资源
	c.resource = model.Resource{
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
		Regions:                regions,
		Subnets:                subnets,
		Networks:               networks,
		VInterfaces:            vinterfaces,
	}
}
