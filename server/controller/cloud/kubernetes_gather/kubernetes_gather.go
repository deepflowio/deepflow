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

package kubernetes_gather

import (
	"github.com/deepflowio/deepflow/server/controller/cloud/kubernetes_gather/model"
	"github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	"github.com/deepflowio/deepflow/server/controller/genesis"
	"github.com/deepflowio/deepflow/server/controller/statsd"

	"regexp"

	simplejson "github.com/bitly/go-simplejson"
	mapset "github.com/deckarep/golang-set"
	logging "github.com/op/go-logging"
)

const (
	K8S_VINTERFACE_NAME_REGEX = "^(cni|flannel|cali|vxlan.calico|tunl|en[ospx])"
	K8S_VPC_NAME              = "kubernetes_vpc"
	K8S_VERSION_PREFIX        = "Kubernetes"
)

var log = logging.MustGetLogger("cloud.kubernetes_gather")

type KubernetesGather struct {
	Name                         string
	Lcuuid                       string
	UuidGenerate                 string
	ClusterID                    string
	RegionUuid                   string
	VPCUuid                      string
	PortNameRegex                string
	PodNetIPv4CIDRMaxMask        int
	PodNetIPv6CIDRMaxMask        int
	isSubDomain                  bool
	azLcuuid                     string
	podGroupLcuuids              mapset.Set
	podNetworkLcuuidCIDRs        networkLcuuidCIDRs
	nodeNetworkLcuuidCIDRs       networkLcuuidCIDRs
	podIPToLcuuid                map[string]string
	nodeIPToLcuuid               map[string]string
	namespaceToLcuuid            map[string]string
	rsLcuuidToPodGroupLcuuid     map[string]string
	serviceLcuuidToIngressLcuuid map[string]string
	k8sInfo                      map[string][]string
	nsLabelToGroupLcuuids        map[string]mapset.Set
	pgLcuuidTopodTargetPorts     map[string]map[string]int
	nsServiceNameToService       map[string]map[string]map[string]int
	cloudStatsd                  statsd.CloudStatsd
}

// 使用结构体代替python中的元组
type networkLcuuidCIDRs struct {
	networkLcuuid string
	cidrs         []string
}

func NewKubernetesGather(domain *mysql.Domain, subDomain *mysql.SubDomain, isSubDomain bool) *KubernetesGather {
	var name string
	var displayName string
	var clusterID string
	var lcuuid string
	var configJson *simplejson.Json
	var err error

	// 如果是K8s云平台，转换domain表的config
	if domain != nil {
		name = domain.Name
		lcuuid = domain.Lcuuid
		displayName = domain.DisplayName
		clusterID = domain.ClusterID
		configJson, err = simplejson.NewJson([]byte(domain.Config))
	} else if subDomain != nil {
		name = subDomain.Name
		lcuuid = subDomain.Lcuuid
		displayName = subDomain.DisplayName
		clusterID = subDomain.ClusterID
		configJson, err = simplejson.NewJson([]byte(subDomain.Config))
	} else {
		log.Error("domain and sub_domain are nil")
		return nil
	}
	if err != nil {
		log.Error(err)
		return nil
	}

	portNameRegex := configJson.Get("port_name_regex").MustString()
	if portNameRegex == "" {
		portNameRegex = K8S_VINTERFACE_NAME_REGEX
	}
	_, regxErr := regexp.Compile(portNameRegex)
	if regxErr != nil {
		log.Errorf("newkubernetesgather portnameregex (%s) compile error: (%s)", portNameRegex, regxErr.Error())
		return nil
	}

	podNetIPv4CIDRMaxMask, err := configJson.Get("pod_net_ipv4_cidr_max_mask").Int()
	if err != nil {
		podNetIPv4CIDRMaxMask = common.K8S_POD_IPV4_NETMASK
	}

	podNetIPv6CIDRMaxMask, err := configJson.Get("pod_net_ipv6_cidr_max_mask").Int()
	if err != nil {
		podNetIPv6CIDRMaxMask = common.K8S_POD_IPV6_NETMASK
	}

	return &KubernetesGather{
		// TODO: display_name后期需要修改为uuid_generate
		Name:                  name,
		Lcuuid:                lcuuid,
		UuidGenerate:          displayName,
		ClusterID:             clusterID,
		RegionUuid:            configJson.Get("region_uuid").MustString(),
		VPCUuid:               configJson.Get("vpc_uuid").MustString(),
		PodNetIPv4CIDRMaxMask: podNetIPv4CIDRMaxMask,
		PodNetIPv6CIDRMaxMask: podNetIPv6CIDRMaxMask,
		PortNameRegex:         portNameRegex,

		// 以下属性为获取资源所用的关联关系
		azLcuuid:                     "",
		isSubDomain:                  isSubDomain,
		podGroupLcuuids:              mapset.NewSet(),
		nodeNetworkLcuuidCIDRs:       networkLcuuidCIDRs{},
		podNetworkLcuuidCIDRs:        networkLcuuidCIDRs{},
		podIPToLcuuid:                map[string]string{},
		nodeIPToLcuuid:               map[string]string{},
		namespaceToLcuuid:            map[string]string{},
		rsLcuuidToPodGroupLcuuid:     map[string]string{},
		serviceLcuuidToIngressLcuuid: map[string]string{},
		k8sInfo:                      map[string][]string{},
		nsLabelToGroupLcuuids:        map[string]mapset.Set{},
		pgLcuuidTopodTargetPorts:     map[string]map[string]int{},
		nsServiceNameToService:       map[string]map[string]map[string]int{},
		cloudStatsd: statsd.CloudStatsd{
			APICount: make(map[string][]int),
			APICost:  make(map[string][]int),
			ResCount: make(map[string][]int),
		},
	}
}

func (k *KubernetesGather) getKubernetesInfo() (map[string][]string, error) {
	kData, err := genesis.GenesisService.GetKubernetesResponse(k.ClusterID)
	if err != nil {
		return map[string][]string{}, err
	}

	for key, v := range kData {
		// resource from genesis , so api cost is 0 ms
		k.cloudStatsd.APICost[key] = []int{0}

		k.cloudStatsd.APICount[key] = []int{len(v)}

	}
	return kData, nil
}

func (k *KubernetesGather) GetStatter() statsd.StatsdStatter {
	globalTags := map[string]string{
		"domain_name": k.Name,
		"domain":      k.Lcuuid,
		"platform":    common.KUBERNETES_EN,
	}

	return statsd.StatsdStatter{
		GlobalTags: globalTags,
		Element:    statsd.GetCloudStatsd(k.cloudStatsd),
	}
}

func (k *KubernetesGather) GetKubernetesGatherData() (model.KubernetesGatherResource, error) {
	// 任务循环的是同一个实例，所以这里要对关联关系进行初始化
	k.azLcuuid = ""
	k.k8sInfo = nil
	k.podNetworkLcuuidCIDRs = networkLcuuidCIDRs{}
	k.nodeNetworkLcuuidCIDRs = networkLcuuidCIDRs{}
	k.podGroupLcuuids = mapset.NewSet()
	k.nodeIPToLcuuid = map[string]string{}
	k.namespaceToLcuuid = map[string]string{}
	k.rsLcuuidToPodGroupLcuuid = map[string]string{}
	k.serviceLcuuidToIngressLcuuid = map[string]string{}
	k.nsLabelToGroupLcuuids = map[string]mapset.Set{}
	k.pgLcuuidTopodTargetPorts = map[string]map[string]int{}
	k.nsServiceNameToService = map[string]map[string]map[string]int{}
	k.cloudStatsd.APICount = map[string][]int{}
	k.cloudStatsd.APICost = map[string][]int{}
	k.cloudStatsd.ResCount = map[string][]int{}

	region, err := k.getRegion()
	if err != nil {
		return model.KubernetesGatherResource{}, err
	}

	az, err := k.getAZ()
	if err != nil {
		return model.KubernetesGatherResource{}, err
	}

	vpc, err := k.getVPC()
	if err != nil {
		return model.KubernetesGatherResource{}, err
	}

	k8sInfo, err := k.getKubernetesInfo()
	if err != nil {
		log.Warning(err.Error())
		return model.KubernetesGatherResource{
			ErrorState:   common.RESOURCE_STATE_CODE_WARNING,
			ErrorMessage: err.Error(),
		}, err
	}
	k.k8sInfo = k8sInfo

	podCluster, err := k.getPodCluster()
	if err != nil {
		return model.KubernetesGatherResource{}, err
	}

	podNodes, nodeNetwork, podNetwork, err := k.getPodNodes()
	if err != nil {
		return model.KubernetesGatherResource{}, err
	}

	podNamespaces, err := k.getPodNamespaces()
	if err != nil {
		return model.KubernetesGatherResource{}, err
	}

	podGroups, err := k.getPodGroups()
	if err != nil {
		return model.KubernetesGatherResource{}, err
	}

	podRCs, err := k.getPodReplicationControllers()
	if err != nil {
		return model.KubernetesGatherResource{}, err
	}

	podGroups = append(podGroups, podRCs...)

	replicaSets, podRSCs, err := k.getReplicaSetsAndReplicaSetControllers()
	if err != nil {
		return model.KubernetesGatherResource{}, err
	}

	podGroups = append(podGroups, podRSCs...)

	podServices, servicePorts, podGroupPorts, serviceNetworks, serviceSubnets, serviceVinterfaces, serviceIPs, err := k.getPodServices()
	if err != nil {
		return model.KubernetesGatherResource{}, err
	}

	ingresses, ingressRules, ingressRuleBackends, err := k.getPodIngresses()
	if err != nil {
		return model.KubernetesGatherResource{}, err
	}
	for index, s := range podServices {
		if ingressLcuuid, ok := k.serviceLcuuidToIngressLcuuid[s.Lcuuid]; ok {
			podServices[index].PodIngressLcuuid = ingressLcuuid
		}
	}

	pods, abstractNodes, err := k.getPods()
	if err != nil {
		return model.KubernetesGatherResource{}, err
	}
	podNodes = append(podNodes, abstractNodes...)

	nodeSubnets, podSubnets, nodeVInterfaces, podVInterfaces, nodeIPs, podIPs, err := k.getVInterfacesAndIPs()
	if err != nil {
		return model.KubernetesGatherResource{}, err
	}

	resource := model.KubernetesGatherResource{
		Region:                 region,
		AZ:                     az,
		VPC:                    vpc,
		PodNodes:               podNodes,
		PodCluster:             podCluster,
		PodServices:            podServices,
		PodNamespaces:          podNamespaces,
		PodNetwork:             podNetwork,
		PodSubnets:             podSubnets,
		PodVInterfaces:         podVInterfaces,
		PodIPs:                 podIPs,
		PodNodeNetwork:         nodeNetwork,
		PodNodeSubnets:         nodeSubnets,
		PodNodeVInterfaces:     nodeVInterfaces,
		PodNodeIPs:             nodeIPs,
		PodServiceNetwork:      serviceNetworks,
		PodServiceSubnets:      serviceSubnets,
		PodServiceVInterfaces:  serviceVinterfaces,
		PodServiceIPs:          serviceIPs,
		PodServicePorts:        servicePorts,
		PodGroupPorts:          podGroupPorts,
		PodIngresses:           ingresses,
		PodIngressRules:        ingressRules,
		PodIngressRuleBackends: ingressRuleBackends,
		PodReplicaSets:         replicaSets,
		PodGroups:              podGroups,
		Pods:                   pods,
	}
	k.cloudStatsd.ResCount = statsd.GetResCount(resource)
	statsd.MetaStatsd.RegisterStatsdTable(k)
	return resource, nil
}

func (k *KubernetesGather) CheckAuth() error {
	return nil
}
