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
	"strconv"
	"strings"

	"github.com/bitly/go-simplejson"
	mapset "github.com/deckarep/golang-set"
	cloudcommon "github.com/deepflowio/deepflow/server/controller/cloud/common"
	"github.com/deepflowio/deepflow/server/controller/cloud/kubernetes_gather/expand"
	"github.com/deepflowio/deepflow/server/controller/cloud/model"
	"github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/libs/logger"
)

func (k *KubernetesGather) getPodServices() (services []model.PodService, servicePorts []model.PodServicePort, podGroupPorts []model.PodGroupPort, network model.Network, subnets []model.Subnet, vinterfaces []model.VInterface, ips []model.IP, err error) {
	log.Debug("get services starting", logger.NewORGPrefix(k.orgID))
	serviceLcuuidToClusterIP := map[string]string{}
	serviceTypes := map[string]int{
		"NodePort":     common.POD_SERVICE_TYPE_NODEPORT,
		"ClusterIP":    common.POD_SERVICE_TYPE_CLUSTERIP,
		"LoadBalancer": common.POD_SERVICE_TYPE_LOADBALANCER,
	}
	servicesArrays := [][][]byte{k.k8sEntries["*v1.Service"]}
	servicesArrays = append(servicesArrays, k.k8sEntries["*v1.ServiceRule"])
	for i, servicesArray := range servicesArrays {
		for _, s := range servicesArray {
			sData, sErr := simplejson.NewJson(s)
			if sErr != nil {
				err = sErr
				log.Errorf("service initialization simplejson error: (%s)", sErr.Error(), logger.NewORGPrefix(k.orgID))
				return
			}
			metaData, ok := sData.CheckGet("metadata")
			if !ok {
				log.Info("service metadata not found", logger.NewORGPrefix(k.orgID))
				continue
			}
			uID := metaData.Get("uid").MustString()
			if uID == "" {
				log.Info("service uid not found", logger.NewORGPrefix(k.orgID))
				continue
			}
			name := metaData.Get("name").MustString()
			if name == "" {
				log.Infof("service (%s) name not found", uID, logger.NewORGPrefix(k.orgID))
				continue
			}
			namespace := metaData.Get("namespace").MustString()
			namespaceLcuuid, ok := k.namespaceToLcuuid[namespace]
			if !ok {
				log.Infof("service (%s) namespace not found", name, logger.NewORGPrefix(k.orgID))
				continue
			}
			spec := sData.Get("spec")
			selector := spec.Get("selector").MustMap()
			if len(selector) == 0 {
				log.Infof("service (%s) selector not found", name, logger.NewORGPrefix(k.orgID))
				continue
			}
			selectorSlice := cloudcommon.GenerateCustomTag(selector, nil, 0, ":")
			specTypeString := spec.Get("type").MustString()
			specType, ok := serviceTypes[specTypeString]
			if !ok {
				log.Infof("service (%s) type (%s) not support", name, specTypeString, logger.NewORGPrefix(k.orgID))
				continue
			}
			clusterIP := spec.Get("clusterIP").MustString()
			if clusterIP == "None" {
				clusterIP = ""
			}
			labels := metaData.Get("labels").MustMap()
			switch i {
			case 1:
				if v, ok := labels[cloudcommon.SVC_RULE_RESOURCE_NAME]; ok {
					delete(labels, cloudcommon.SVC_RULE_RESOURCE_NAME)
					labels[cloudcommon.SVC_RULE_RESOURCE_NAME+"_servicerule"] = v
				}
			}

			annotations := metaData.Get("annotations")
			annotationString := expand.GetAnnotation(annotations, k.annotationRegex, k.customTagLenMax)

			externalIPs := []string{}
			svcIngress := sData.GetPath("status", "loadBalancer", "ingress")
			for i := range svcIngress.MustArray() {
				ingress := svcIngress.GetIndex(i)
				externalIPs = append(externalIPs, ingress.Get("ip").MustString())
			}
			uLcuuid := common.IDGenerateUUID(k.orgID, uID)
			metaDataStr := k.simpleJsonMarshal(metaData)
			specStr := k.simpleJsonMarshal(spec)
			service := model.PodService{
				Lcuuid:             uLcuuid,
				Name:               name,
				Metadata:           metaDataStr,
				MetadataHash:       cloudcommon.GenerateMD5Sum(metaDataStr),
				Spec:               specStr,
				SpecHash:           cloudcommon.GenerateMD5Sum(specStr),
				Label:              k.GetLabel(labels),
				Annotation:         annotationString,
				Type:               specType,
				Selector:           strings.Join(selectorSlice, ", "),
				ExternalIP:         strings.Join(externalIPs, ", "),
				ServiceClusterIP:   clusterIP,
				PodNamespaceLcuuid: namespaceLcuuid,
				VPCLcuuid:          k.VPCUUID,
				AZLcuuid:           k.azLcuuid,
				RegionLcuuid:       k.RegionUUID,
				PodClusterLcuuid:   k.podClusterLcuuid,
			}
			specPorts := sData.Get("spec").Get("ports")
			var hasPodGroup bool
			for i := range specPorts.MustArray() {
				podGroupLcuuids := mapset.NewSet()
				labels, fErr := metaData.Get("annotations").Get("field.cattle.io/targetWorkloadIds").String()
				if fErr == nil && labels != "[]" && labels != "null" {
					labelArray, lErr := simplejson.NewJson([]byte(labels))
					if lErr != nil {
						log.Infof("service annotation (%s) init json error: (%s)", labels, lErr.Error(), logger.NewORGPrefix(k.orgID))
						continue
					}
					for i := range labelArray.MustArray() {
						if groupLcuuids, ok := k.nsLabelToGroupLcuuids[namespace+labelArray.GetIndex(i).MustString()]; ok {
							if groupLcuuids.Cardinality() > 0 {
								podGroupLcuuids = podGroupLcuuids.Union(groupLcuuids)
							}
						}
					}
				}

				groupLcuuidsList := []mapset.Set{}
				for key, v := range selector {
					vString, ok := v.(string)
					if !ok {
						vString = ""
					}
					nsLabel := namespace + key + "_" + vString
					groupLcuuids, ok := k.nsLabelToGroupLcuuids[nsLabel]
					if !ok {
						continue
					}
					groupLcuuidsList = append(groupLcuuidsList, groupLcuuids)
				}

				// support OpenGaussCluster
				if ogcName, ok := sData.GetPath("spec", "selector").CheckGet("opengauss.cluster"); ok {
					nsLabel := namespace + "statefulset:" + namespace + ":" + ogcName.MustString()
					if groupLcuuids, ok := k.nsLabelToGroupLcuuids[nsLabel]; ok {
						if groupLcuuids.Cardinality() > 0 {
							podGroupLcuuids = podGroupLcuuids.Union(groupLcuuids)
						}
					}
				} else {
					// 如果存在label匹配不到PodGroup，则认为找不到匹配的PodGroup
					if len(groupLcuuidsList) != len(selector) {
						continue
					}
				}

				// 各Label的PodGroup求交集，作为service关联的PodGroup
				intersectGroupLcuuids := mapset.NewSet()
				if len(groupLcuuidsList) == 1 {
					intersectGroupLcuuids = groupLcuuidsList[0]
				} else if len(groupLcuuidsList) > 1 {
					intersectGroupLcuuids = groupLcuuidsList[0]
					for _, lcuuids := range groupLcuuidsList[1:] {
						intersectGroupLcuuids = intersectGroupLcuuids.Intersect(lcuuids)
					}
				}
				if intersectGroupLcuuids.Cardinality() > 0 {
					podGroupLcuuids = podGroupLcuuids.Union(intersectGroupLcuuids)
				}
				// 如果没有找到关联PodGroup，进入下一循环
				if podGroupLcuuids.Cardinality() == 0 {
					log.Infof("service (%s) pod group id not found", name, logger.NewORGPrefix(k.orgID))
					continue
				}
				hasPodGroup = true

				// 在service确定有pod group的时候添加pod service port
				targetNameToPorts := map[string][]int{}
				for _, lcuuid := range podGroupLcuuids.ToSlice() {
					podGroupLcuuid, ok := lcuuid.(string)
					if !ok {
						continue
					}
					targetPorts, ok := k.pgLcuuidTopodTargetPorts[podGroupLcuuid]
					if !ok {
						continue
					}
					for name, port := range targetPorts {
						targetNameToPorts[name] = append(targetNameToPorts[name], port)
					}
				}
				port := specPorts.GetIndex(i)
				targetPorts := []int{}
				targetPortTBD := port.Get("targetPort")
				targetPorts = targetNameToPorts[targetPortTBD.MustString()]
				if len(targetPorts) == 0 {
					if targetPortTBD.MustInt() == 0 {
						log.Infof("service (%s) targetPort not match", name, logger.NewORGPrefix(k.orgID))
						continue
					}
					targetPorts = append(targetPorts, targetPortTBD.MustInt())
				}
				nameToPort := map[string]int{}
				portName := port.Get("name").MustString()
				portInt := port.Get("port").MustInt()
				portProtocol := port.Get("protocol").MustString()
				portNodePort := port.Get("nodePort").MustInt()
				nameToPort[portName] = portInt
				uidToName := map[string]map[string]int{}
				uidToName[uLcuuid] = nameToPort
				k.nsServiceNameToService[namespace+name] = uidToName
				// remove duplicates
				targetPortsMap := map[int]bool{}
				for _, tPort := range targetPorts {
					targetPortsMap[tPort] = false
				}
				portString := strconv.Itoa(portInt)
				for targetPort := range targetPortsMap {
					key := portString + portProtocol + strconv.Itoa(portNodePort) + strconv.Itoa(targetPort)
					servicePort := model.PodServicePort{
						Lcuuid:           common.GetUUIDByOrgID(k.orgID, uLcuuid+key),
						Name:             portName,
						Protocol:         strings.ToUpper(portProtocol),
						Port:             portInt,
						TargetPort:       targetPort,
						NodePort:         portNodePort,
						PodServiceLcuuid: uLcuuid,
					}
					servicePorts = append(servicePorts, servicePort)
				}

				for _, lcuuid := range podGroupLcuuids.ToSlice() {
					podGroupLcuuid, ok := lcuuid.(string)
					if !ok {
						continue
					}
					for targetPort := range targetPortsMap {
						key := portName + portString + portProtocol + strconv.Itoa(targetPort)
						podGroupPort := model.PodGroupPort{
							Lcuuid:           common.GetUUIDByOrgID(k.orgID, uLcuuid+podGroupLcuuid+key),
							Name:             portName,
							Port:             targetPort,
							Protocol:         strings.ToUpper(portProtocol),
							PodGroupLcuuid:   podGroupLcuuid,
							PodServiceLcuuid: uLcuuid,
						}
						podGroupPorts = append(podGroupPorts, podGroupPort)
					}
					k.pgLcuuidToPSLcuuids[podGroupLcuuid] = append(k.pgLcuuidToPSLcuuids[podGroupLcuuid], uLcuuid)
				}
			}
			if !hasPodGroup {
				delete(k.nsServiceNameToService, namespace+name)
				log.Infof("service (%s) pod group not found", name, logger.NewORGPrefix(k.orgID))
				continue
			}
			services = append(services, service)
			if clusterIP != "" && clusterIP != "None" {
				serviceLcuuidToClusterIP[uLcuuid] = clusterIP
			}
		}
	}

	serviceNetworkName := k.Name + "_SVC_NET"
	serviceNetworkLcuuid := common.GetUUIDByOrgID(k.orgID, k.UuidGenerate+serviceNetworkName)
	clusterIPs := cloudcommon.StringStringMapValues(serviceLcuuidToClusterIP)
	serviceCIDR := []string{}
	if len(clusterIPs) != 0 {
		v4Prefixs, v6Prefixs, tErr := cloudcommon.TidyIPString(clusterIPs)
		if tErr != nil {
			err = tErr
			log.Error("service tidy cluster ip Error"+tErr.Error(), logger.NewORGPrefix(k.orgID))
			return
		}
		if len(v4Prefixs) != 0 {
			v4cidrs := cloudcommon.AggregateCIDR(v4Prefixs, 0)
			serviceCIDR = append(serviceCIDR, v4cidrs...)
		}
		if len(v6Prefixs) != 0 {
			v6cidrs := cloudcommon.AggregateCIDR(v6Prefixs, 0)
			serviceCIDR = append(serviceCIDR, v6cidrs...)
		}
	}

	serviceSubnetLcuuid := common.GetUUIDByOrgID(k.orgID, serviceNetworkLcuuid)
	for i, sCIDR := range serviceCIDR {
		if i > 1 {
			serviceSubnetLcuuid = common.GetUUIDByOrgID(k.orgID, serviceNetworkLcuuid+sCIDR)
		}
		nodeSubnet := model.Subnet{
			Lcuuid:        serviceSubnetLcuuid,
			Name:          serviceNetworkName,
			CIDR:          sCIDR,
			NetworkLcuuid: serviceNetworkLcuuid,
			VPCLcuuid:     k.VPCUUID,
		}
		subnets = append(subnets, nodeSubnet)
	}

	network = model.Network{
		Lcuuid:         serviceNetworkLcuuid,
		Name:           serviceNetworkName,
		SegmentationID: 1,
		Shared:         false,
		External:       false,
		NetType:        common.NETWORK_TYPE_LAN,
		AZLcuuid:       k.azLcuuid,
		VPCLcuuid:      k.VPCUUID,
		RegionLcuuid:   k.RegionUUID,
	}
	for Lcuuid, IP := range serviceLcuuidToClusterIP {
		vinterfaceID := common.GetUUIDByOrgID(k.orgID, Lcuuid+common.VIF_DEFAULT_MAC+IP)
		vinterface := model.VInterface{
			Lcuuid:        vinterfaceID,
			Type:          common.VIF_TYPE_LAN,
			Mac:           common.VIF_DEFAULT_MAC,
			DeviceLcuuid:  Lcuuid,
			DeviceType:    common.VIF_DEVICE_TYPE_POD_SERVICE,
			NetworkLcuuid: serviceNetworkLcuuid,
			VPCLcuuid:     k.VPCUUID,
			RegionLcuuid:  k.RegionUUID,
		}
		vinterfaces = append(vinterfaces, vinterface)
		ip := model.IP{
			Lcuuid:           common.GetUUIDByOrgID(k.orgID, Lcuuid+IP),
			VInterfaceLcuuid: vinterfaceID,
			IP:               IP,
			RegionLcuuid:     k.RegionUUID,
			SubnetLcuuid:     common.GetUUIDByOrgID(k.orgID, serviceNetworkLcuuid),
		}
		ips = append(ips, ip)
	}
	log.Debug("get services complete", logger.NewORGPrefix(k.orgID))
	return
}
