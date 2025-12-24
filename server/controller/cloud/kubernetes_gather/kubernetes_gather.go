/*
 * Copyright (c) 2024 Yunshan Networks
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
	"regexp"
	"strings"
	"time"

	simplejson "github.com/bitly/go-simplejson"
	mapset "github.com/deckarep/golang-set"
	"gorm.io/gorm"

	cloudcommon "github.com/deepflowio/deepflow/server/controller/cloud/common"
	"github.com/deepflowio/deepflow/server/controller/cloud/config"
	"github.com/deepflowio/deepflow/server/controller/cloud/kubernetes_gather/model"
	cloudmodel "github.com/deepflowio/deepflow/server/controller/cloud/model"
	"github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/db/metadb"
	metadbmodel "github.com/deepflowio/deepflow/server/controller/db/metadb/model"
	"github.com/deepflowio/deepflow/server/controller/genesis"
	"github.com/deepflowio/deepflow/server/controller/statsd"
	"github.com/deepflowio/deepflow/server/libs/logger"
)

var log = logger.MustGetLogger("cloud.kubernetes_gather")

type KubernetesGather struct {
	orgID                        int
	TeamID                       int
	Name                         string
	Lcuuid                       string
	UuidGenerate                 string
	ClusterID                    string
	RegionUUID                   string
	VPCUUID                      string
	PortNameRegex                string
	PodExposedPorts              string
	PodNetIPv4CIDRMaxMask        int
	PodNetIPv6CIDRMaxMask        int
	customTagLenMax              int
	isSubDomain                  bool
	azLcuuid                     string
	podClusterLcuuid             string
	db                           *gorm.DB
	labelRegex                   *regexp.Regexp
	envRegex                     *regexp.Regexp
	annotationRegex              *regexp.Regexp
	podGroupLcuuids              mapset.Set
	podNetworkLcuuidCIDRs        networkLcuuidCIDRs
	nodeNetworkLcuuidCIDRs       networkLcuuidCIDRs
	podIPToLcuuid                map[string]string
	nodeIPToLcuuid               map[string]string
	namespaceToLcuuid            map[string]string
	rsLcuuidToPodGroupLcuuid     map[string]string
	serviceLcuuidToIngressLcuuid map[string]string
	k8sEntries                   map[string][][]byte
	pgLcuuidToPSLcuuids          map[string][]string
	configMapToLcuuid            map[[2]string]string
	podLcuuidToPGInfo            map[string][2]string
	nsLabelToGroupLcuuids        map[string]mapset.Set
	pgLcuuidTopodTargetPorts     map[string]map[string]int
	namespaceToExLabels          map[string]map[string]interface{}
	nsServiceNameToService       map[string]map[string]map[string]int
	cloudStatsd                  statsd.CloudStatsd
}

// 使用结构体代替python中的元组
type networkLcuuidCIDRs struct {
	networkLcuuid string
	cidrs         []string
}

func NewKubernetesGather(db *metadb.DB, domain *metadbmodel.Domain, subDomain *metadbmodel.SubDomain, cfg config.CloudConfig, isSubDomain bool) *KubernetesGather {
	var teamID int
	var name string
	var displayName string
	var clusterID string
	var lcuuid string
	var configJson *simplejson.Json
	var domainConfigJson *simplejson.Json
	var err error

	domainConfigJson, err = simplejson.NewJson([]byte(domain.Config))
	portNameRegex := domainConfigJson.Get("node_port_name_regex").MustString()
	if portNameRegex == "" {
		portNameRegex = common.DEFAULT_PORT_NAME_REGEX
	}

	// 如果是K8s云平台，转换domain表的config
	if isSubDomain {
		if subDomain == nil {
			log.Error("subdomain model is nil", db.LogPrefixORGID)
			return nil
		}
		teamID = subDomain.TeamID
		name = subDomain.Name
		lcuuid = subDomain.Lcuuid
		displayName = subDomain.DisplayName
		clusterID = subDomain.ClusterID
		configJson, err = simplejson.NewJson([]byte(subDomain.Config))
		sPortNameRegex := configJson.Get("port_name_regex").MustString()
		if sPortNameRegex != "" {
			portNameRegex = sPortNameRegex
		}
	} else {
		if domain == nil {
			log.Error("domain model is nil", db.LogPrefixORGID)
			return nil
		}
		teamID = domain.TeamID
		name = domain.Name
		lcuuid = domain.Lcuuid
		displayName = domain.DisplayName
		clusterID = domain.ClusterID
		configJson = domainConfigJson
	}
	if err != nil {
		log.Error(err, logger.NewORGPrefix(db.ORGID))
		return nil
	}

	_, err = regexp.Compile(portNameRegex)
	if err != nil {
		log.Errorf("port name regex compile error: (%s)", err.Error(), db.LogPrefixORGID)
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

	labelRegString := configJson.Get("label_regex").MustString()
	if labelRegString == "" {
		labelRegString = common.DEFAULT_ALL_MATCH_REGEX
	}
	labelR, err := regexp.Compile(labelRegString)
	if err != nil {
		log.Errorf("label regex compile error: (%s)", err.Error(), db.LogPrefixORGID)
		return nil
	}
	envRegString := configJson.Get("env_regex").MustString()
	if envRegString == "" {
		envRegString = common.DEFAULT_NOT_MATCH_REGEX
	}
	envR, err := regexp.Compile(envRegString)
	if err != nil {
		log.Errorf("env regex compile error: (%s)", err.Error(), db.LogPrefixORGID)
		return nil
	}
	annotationRegString := configJson.Get("annotation_regex").MustString()
	if annotationRegString == "" {
		annotationRegString = common.DEFAULT_NOT_MATCH_REGEX
	}
	annotationR, err := regexp.Compile(annotationRegString)
	if err != nil {
		log.Errorf("annotation regex compile error: (%s)", err.Error(), db.LogPrefixORGID)
		return nil
	}

	return &KubernetesGather{
		// TODO: display_name后期需要修改为uuid_generate
		Name:                  name,
		Lcuuid:                lcuuid,
		UuidGenerate:          displayName,
		ClusterID:             clusterID,
		TeamID:                teamID,
		orgID:                 db.ORGID,
		db:                    db.DB,
		RegionUUID:            configJson.Get("region_uuid").MustString(),
		VPCUUID:               configJson.Get("vpc_uuid").MustString(),
		PodExposedPorts:       configJson.Get("pod_exposed_ports").MustString(),
		PodNetIPv4CIDRMaxMask: podNetIPv4CIDRMaxMask,
		PodNetIPv6CIDRMaxMask: podNetIPv6CIDRMaxMask,
		PortNameRegex:         portNameRegex,
		labelRegex:            labelR,
		envRegex:              envR,
		annotationRegex:       annotationR,

		// 以下属性为获取资源所用的关联关系
		azLcuuid:                     "",
		customTagLenMax:              cfg.CustomTagLenMax,
		isSubDomain:                  isSubDomain,
		podGroupLcuuids:              mapset.NewSet(),
		nodeNetworkLcuuidCIDRs:       networkLcuuidCIDRs{},
		podNetworkLcuuidCIDRs:        networkLcuuidCIDRs{},
		podIPToLcuuid:                map[string]string{},
		nodeIPToLcuuid:               map[string]string{},
		namespaceToLcuuid:            map[string]string{},
		rsLcuuidToPodGroupLcuuid:     map[string]string{},
		serviceLcuuidToIngressLcuuid: map[string]string{},
		k8sEntries:                   map[string][][]byte{},
		pgLcuuidToPSLcuuids:          map[string][]string{},
		configMapToLcuuid:            map[[2]string]string{},
		podLcuuidToPGInfo:            map[string][2]string{},
		nsLabelToGroupLcuuids:        map[string]mapset.Set{},
		pgLcuuidTopodTargetPorts:     map[string]map[string]int{},
		namespaceToExLabels:          map[string]map[string]interface{}{},
		nsServiceNameToService:       map[string]map[string]map[string]int{},
		cloudStatsd:                  statsd.NewCloudStatsd(),
	}
}

func (k *KubernetesGather) getKubernetesEntries() (map[string][][]byte, error) {
	entries, err := genesis.GenesisService.GetKubernetesResponse(k.orgID, k.ClusterID)
	if err != nil {
		return map[string][][]byte{}, err
	}

	for key, v := range entries {
		// resource from genesis , so api start is 0
		k.cloudStatsd.RefreshAPIMoniter(key, len(v), time.Time{})
	}
	return entries, nil
}

func (k *KubernetesGather) GetStatter() statsd.StatsdStatter {
	globalTags := map[string]string{
		"domain_name": k.Name,
		"domain":      k.Lcuuid,
		"platform":    common.KUBERNETES_EN,
	}

	return statsd.StatsdStatter{
		OrgID:      k.orgID,
		TeamID:     k.TeamID,
		GlobalTags: globalTags,
		Element:    statsd.GetCloudStatsd(k.cloudStatsd),
	}
}

func (k *KubernetesGather) GetLabel(labelMap map[string]interface{}) string {
	labelSlice := cloudcommon.GenerateCustomTag(labelMap, k.labelRegex, k.customTagLenMax, ":")
	return strings.Join(labelSlice, ", ")
}

func (k *KubernetesGather) simpleJsonMarshal(json *simplejson.Json) string {
	bytes, err := json.MarshalJSON()
	if err != nil {
		log.Infof("simplejson (%s) marshal failed: %s", json, err.Error(), logger.NewORGPrefix(k.orgID))
		return ""
	}
	return string(bytes)
}

func (k *KubernetesGather) pgSpecGenerateConnections(nsName, pgName, pgLcuuid string, mainSpec *simplejson.Json) []cloudmodel.PodGroupConfigMapConnection {
	var connections []cloudmodel.PodGroupConfigMapConnection

	existSet := map[string]bool{}
	spec := mainSpec.GetPath("template", "spec")
	containers := spec.Get("containers")
	for c := range containers.MustArray() {
		envs := containers.GetIndex(c).Get("env")
		for e := range envs.MustArray() {
			env := envs.GetIndex(e)
			ref, ok := env.Get("valueFrom").CheckGet("configMapKeyRef")
			if !ok {
				continue
			}
			cmName := ref.Get("Name").MustString()
			cmLcuuid, ok := k.configMapToLcuuid[[2]string{nsName, cmName}]
			if !ok {
				log.Infof("pod group (%s) imported env config map (%s) not found", pgName, cmName, logger.NewORGPrefix(k.orgID))
				continue
			}
			if _, ok := existSet[pgLcuuid+cmLcuuid]; ok {
				log.Debugf("env pod group (%s) and config map (%s) connections already exists", pgName, cmName, logger.NewORGPrefix(k.orgID))
				continue
			}
			connections = append(connections, cloudmodel.PodGroupConfigMapConnection{
				Lcuuid:          common.GetUUIDByOrgID(k.orgID, pgLcuuid+cmLcuuid),
				PodGroupLcuuid:  pgLcuuid,
				ConfigMapLcuuid: cmLcuuid,
			})
			existSet[pgLcuuid+cmLcuuid] = false
		}
	}

	volumes := spec.Get("volumes")
	for v := range volumes.MustArray() {
		volume := volumes.GetIndex(v)
		cm, ok := volume.CheckGet("configMap")
		if !ok {
			continue
		}
		cmName := cm.Get("name").MustString()
		cmLcuuid, ok := k.configMapToLcuuid[[2]string{nsName, cmName}]
		if !ok {
			log.Infof("pod group (%s) imported volumes config map (%s) not found", pgName, cmName, logger.NewORGPrefix(k.orgID))
			continue
		}
		if _, ok := existSet[pgLcuuid+cmLcuuid]; ok {
			log.Debugf("volumes pod group (%s) and config map (%s) connections already exists", pgName, cmName, logger.NewORGPrefix(k.orgID))
			continue
		}
		connections = append(connections, cloudmodel.PodGroupConfigMapConnection{
			Lcuuid:          common.GetUUIDByOrgID(k.orgID, pgLcuuid+cmLcuuid),
			PodGroupLcuuid:  pgLcuuid,
			ConfigMapLcuuid: cmLcuuid,
		})
		existSet[pgLcuuid+cmLcuuid] = false
	}

	return connections
}

func (k *KubernetesGather) GetKubernetesGatherData() (model.KubernetesGatherResource, error) {
	// 任务循环的是同一个实例，所以这里要对关联关系进行初始化
	k.azLcuuid = ""
	k.k8sEntries = nil
	k.podNetworkLcuuidCIDRs = networkLcuuidCIDRs{}
	k.nodeNetworkLcuuidCIDRs = networkLcuuidCIDRs{}
	k.podGroupLcuuids = mapset.NewSet()
	k.podIPToLcuuid = map[string]string{}
	k.nodeIPToLcuuid = map[string]string{}
	k.namespaceToLcuuid = map[string]string{}
	k.rsLcuuidToPodGroupLcuuid = map[string]string{}
	k.serviceLcuuidToIngressLcuuid = map[string]string{}
	k.nsLabelToGroupLcuuids = map[string]mapset.Set{}
	k.pgLcuuidToPSLcuuids = map[string][]string{}
	k.configMapToLcuuid = map[[2]string]string{}
	k.podLcuuidToPGInfo = map[string][2]string{}
	k.pgLcuuidTopodTargetPorts = map[string]map[string]int{}
	k.namespaceToExLabels = map[string]map[string]interface{}{}
	k.nsServiceNameToService = map[string]map[string]map[string]int{}
	k.cloudStatsd = statsd.NewCloudStatsd()

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

	exposedServices, exposedServicePorts, err := k.getPodExposedServices()
	if err != nil {
		return model.KubernetesGatherResource{
			ErrorState:   common.RESOURCE_STATE_CODE_WARNING,
			ErrorMessage: err.Error(),
		}, err
	}

	k.k8sEntries, err = k.getKubernetesEntries()
	if err != nil {
		log.Warning(err.Error(), logger.NewORGPrefix(k.orgID))
		return model.KubernetesGatherResource{
			ErrorState:   common.RESOURCE_STATE_CODE_WARNING,
			ErrorMessage: err.Error(),
		}, err
	}

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

	configMaps, err := k.getConfigMaps()
	if err != nil {
		return model.KubernetesGatherResource{}, err
	}

	podGroups, podGroupConfigMapConnections, err := k.getPodGroups()
	if err != nil {
		return model.KubernetesGatherResource{}, err
	}

	podRCs, podRCsConfigMapConnections, err := k.getPodReplicationControllers()
	if err != nil {
		return model.KubernetesGatherResource{}, err
	}

	podGroups = append(podGroups, podRCs...)
	podGroupConfigMapConnections = append(podGroupConfigMapConnections, podRCsConfigMapConnections...)

	replicaSets, podRSCs, podRSCsConfigMapConnections, err := k.getReplicaSetsAndReplicaSetControllers()
	if err != nil {
		return model.KubernetesGatherResource{}, err
	}

	podGroups = append(podGroups, podRSCs...)
	podGroupConfigMapConnections = append(podGroupConfigMapConnections, podRSCsConfigMapConnections...)

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

	pods, err := k.getPods()
	if err != nil {
		return model.KubernetesGatherResource{}, err
	}

	nodeSubnets, podSubnets, nodeVInterfaces, podVInterfaces, nodeIPs, podIPs, err := k.getVInterfacesAndIPs()
	if err != nil {
		return model.KubernetesGatherResource{}, err
	}

	podServices = append(podServices, exposedServices...)
	servicePorts = append(servicePorts, exposedServicePorts...)

	resource := model.KubernetesGatherResource{
		Region:                       region,
		AZ:                           az,
		VPC:                          vpc,
		PodNodes:                     podNodes,
		PodCluster:                   podCluster,
		PodServices:                  podServices,
		PodNamespaces:                podNamespaces,
		PodNetwork:                   podNetwork,
		PodSubnets:                   podSubnets,
		PodVInterfaces:               podVInterfaces,
		PodIPs:                       podIPs,
		PodNodeNetwork:               nodeNetwork,
		PodNodeSubnets:               nodeSubnets,
		PodNodeVInterfaces:           nodeVInterfaces,
		PodNodeIPs:                   nodeIPs,
		PodServiceNetwork:            serviceNetworks,
		PodServiceSubnets:            serviceSubnets,
		PodServiceVInterfaces:        serviceVinterfaces,
		PodServiceIPs:                serviceIPs,
		PodServicePorts:              servicePorts,
		PodGroupPorts:                podGroupPorts,
		PodGroupConfigMapConnections: podGroupConfigMapConnections,
		PodIngresses:                 ingresses,
		PodIngressRules:              ingressRules,
		PodIngressRuleBackends:       ingressRuleBackends,
		PodReplicaSets:               replicaSets,
		PodGroups:                    podGroups,
		ConfigMaps:                   configMaps,
		Pods:                         pods,
	}

	k.cloudStatsd.ResCount = statsd.GetResCount(resource)
	statsd.MetaStatsd.RegisterStatsdTable(k)
	return resource, nil
}

func (k *KubernetesGather) CheckAuth() error {
	return nil
}
