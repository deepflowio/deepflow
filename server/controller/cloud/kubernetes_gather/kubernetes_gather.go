package kubernetes_gather

import (
	"server/controller/cloud/kubernetes_gather/model"
	"server/controller/common"
	"server/controller/db/mysql"
	"server/controller/genesis"

	"errors"
	"regexp"

	simplejson "github.com/bitly/go-simplejson"
	mapset "github.com/deckarep/golang-set"
	logging "github.com/op/go-logging"
)

const (
	K8S_POD_IPV4_NETMASK = 16
	K8S_POD_IPV6_NETMASK = 64
	// TODO: golang不支持 ?=( 的语法,此处的regex暂时置空，等待后续更新
	K8S_VINTERFACE_NAME_REGEX = ""
	K8S_VPC_NAME              = "kubernetes_vpc"
	K8S_VERSION_PREFIX        = "Kubernetes"
)

var log = logging.MustGetLogger("cloud.kubernetes_gather")

type KubernetesGather struct {
	Name                         string
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
	podTargetPorts               map[string]int
	podIPToLcuuid                map[string]string
	nodeIPToLcuuid               map[string]string
	namespaceToLcuuid            map[string]string
	rsLcuuidToPodGroupLcuuid     map[string]string
	serviceLcuuidToIngressLcuuid map[string]string
	k8sInfo                      map[string][]string
	nsLabelToGroupLcuuids        map[string]mapset.Set
	nsServiceNameToService       map[string]map[string]map[string]int
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
	var configJson *simplejson.Json
	var err error

	// 如果是K8s云平台，转换domain表的config
	if domain != nil {
		name = domain.Name
		displayName = domain.DisplayName
		clusterID = domain.ClusterID
		configJson, err = simplejson.NewJson([]byte(domain.Config))
	} else if subDomain != nil {
		name = subDomain.Name
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
		podNetIPv4CIDRMaxMask = K8S_POD_IPV4_NETMASK
	}

	podNetIPv6CIDRMaxMask, err := configJson.Get("pod_net_ipv6_cidr_max_mask").Int()
	if err != nil {
		podNetIPv6CIDRMaxMask = K8S_POD_IPV6_NETMASK
	}

	return &KubernetesGather{
		// TODO: display_name后期需要修改为uuid_generate
		Name:                  name,
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
		podTargetPorts:               map[string]int{},
		podIPToLcuuid:                map[string]string{},
		nodeIPToLcuuid:               map[string]string{},
		namespaceToLcuuid:            map[string]string{},
		rsLcuuidToPodGroupLcuuid:     map[string]string{},
		serviceLcuuidToIngressLcuuid: map[string]string{},
		k8sInfo:                      map[string][]string{},
		nsLabelToGroupLcuuids:        map[string]mapset.Set{},
		nsServiceNameToService:       map[string]map[string]map[string]int{},
	}
}

func (k *KubernetesGather) getKubernetesInfo() (map[string][]string, error) {
	kDataResource := genesis.GenesisService.GetKubernetesData()
	kData, ok := kDataResource[k.ClusterID]
	if !ok {
		msg := "no vtap report cluster id:" + k.ClusterID
		log.Warning(msg)
		return map[string][]string{}, errors.New(msg)
	}
	if kData.ErrorMSG != "" {
		log.Warningf("cluster id (%s) Error: %s", k.ClusterID, kData.ErrorMSG)
	}
	return kData.Resources, nil
}

func (k *KubernetesGather) GetKubernetesGatherData() (model.KubernetesGatherResource, error) {
	// 任务循环的是同一个实例，所以这里要对关联关系进行初始化
	k.azLcuuid = ""
	k.k8sInfo = nil
	k.podNetworkLcuuidCIDRs = networkLcuuidCIDRs{}
	k.nodeNetworkLcuuidCIDRs = networkLcuuidCIDRs{}
	k.podGroupLcuuids = mapset.NewSet()
	k.podTargetPorts = map[string]int{}
	k.nodeIPToLcuuid = map[string]string{}
	k.namespaceToLcuuid = map[string]string{}
	k.rsLcuuidToPodGroupLcuuid = map[string]string{}
	k.serviceLcuuidToIngressLcuuid = map[string]string{}
	k.nsLabelToGroupLcuuids = map[string]mapset.Set{}
	k.nsServiceNameToService = map[string]map[string]map[string]int{}

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
	for _, s := range podServices {
		if ingressLcuuid, ok := k.serviceLcuuidToIngressLcuuid[s.Lcuuid]; ok {
			s.PodIngressLcuuid = ingressLcuuid
		}
	}

	pods, err := k.getPods()
	if err != nil {
		return model.KubernetesGatherResource{}, err
	}

	nodeSubnets, podSubnets, nodeVInterfaces, podVInterfaces, nodeIPs, podIPs, err := k.getVInterfacesAndIPs()
	if err != nil {
		return model.KubernetesGatherResource{}, err
	}

	return model.KubernetesGatherResource{
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
	}, nil
}

func (k *KubernetesGather) CheckAuth() error {
	return nil
}
