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
	"encoding/json"
	"strconv"

	"github.com/deepflowio/deepflow/server/controller/cloud/model"
	"github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/libs/logger"
)

func (k *KubernetesGather) getPodIngresses() (ingresses []model.PodIngress, ingressRules []model.PodIngressRule, ingressRuleBackends []model.PodIngressRuleBackend, err error) {
	log.Debug("get ingresses starting", logger.NewORGPrefix(k.orgID))
	var ingressInfo []string
	switch {
	case len(k.k8sInfo["*v1.Ingress"]) != 0:
		ingressInfo = k.k8sInfo["*v1.Ingress"]
	case len(k.k8sInfo["*v1.Route"]) != 0:
		ingressInfo = k.k8sInfo["*v1.Route"]
	case len(k.k8sInfo["*v1beta1.Ingress"]) != 0:
		ingressInfo = k.k8sInfo["*v1beta1.Ingress"]
	}
	for _, i := range ingressInfo {
		iRaw := json.RawMessage(i)
		iData, iErr := rawMessageToMap(iRaw)
		if iErr != nil {
			err = iErr
			log.Errorf("ingress initialization json error: (%s)", iErr.Error(), logger.NewORGPrefix(k.orgID))
			return
		}
		metaData, ok := getJSONMap(iData, "metadata")
		if !ok {
			log.Info("ingress metadata not found", logger.NewORGPrefix(k.orgID))
			continue
		}
		uID := getJSONString(metaData, "uid")
		if uID == "" {
			log.Info("ingress uid not found", logger.NewORGPrefix(k.orgID))
			continue
		}
		name := getJSONString(metaData, "name")
		if name == "" {
			log.Infof("ingress (%s) name not found", uID, logger.NewORGPrefix(k.orgID))
			continue
		}
		namespace := getJSONString(metaData, "namespace")
		namespaceLcuuid, ok := k.namespaceToLcuuid[namespace]
		if !ok {
			log.Infof("ingress (%s) namespace not found", name, logger.NewORGPrefix(k.orgID))
			continue
		}
		uLcuuid := common.IDGenerateUUID(k.orgID, uID)
		ingress := model.PodIngress{
			Lcuuid:             uLcuuid,
			Name:               name,
			PodNamespaceLcuuid: namespaceLcuuid,
			AZLcuuid:           k.azLcuuid,
			RegionLcuuid:       k.RegionUUID,
			PodClusterLcuuid:   k.podClusterLcuuid,
		}
		ingresses = append(ingresses, ingress)
		spec, _ := getJSONMap(iData, "spec")
		rules, _ := getJSONArray(spec, "rules")
		for index, ruleInterface := range rules {
			rule, ok := ruleInterface.(map[string]interface{})
			if !ok {
				continue
			}
			host := interfaceToString(rule["host"])
			ruleLcuuid := common.GetUUIDByOrgID(k.orgID, uLcuuid+host+"_"+strconv.Itoa(index))
			ingressRule := model.PodIngressRule{
				Lcuuid:           ruleLcuuid,
				Host:             host,
				Protocol:         "HTTP",
				PodIngressLcuuid: uLcuuid,
			}
			ingressRules = append(ingressRules, ingressRule)
			httpConfig, _ := getJSONMap(rule, "http")
			paths, _ := getJSONArray(httpConfig, "paths")
			for _, pathInterface := range paths {
				path, ok := pathInterface.(map[string]interface{})
				if !ok {
					continue
				}
				backend, ok := getJSONMap(path, "backend")
				if !ok {
					continue
				}
				serviceConfig, _ := getJSONMap(backend, "service")
				serviceName := ""
				if serviceConfig != nil {
					serviceName = interfaceToString(serviceConfig["name"])
				}
				if serviceName == "" {
					serviceName = interfaceToString(backend["serviceName"])
				}
				service, ok := k.nsServiceNameToService[namespace+serviceName]
				if !ok {
					log.Infof("ingress backend service (%s) not found", serviceName, logger.NewORGPrefix(k.orgID))
					continue
				}
				serviceLcuuid, ports := "", map[string]int{}
				for key, v := range service {
					serviceLcuuid = key
					ports = v
					break
				}
				if ingressLcuuid, ok := k.serviceLcuuidToIngressLcuuid[serviceLcuuid]; ok && ingressLcuuid != uLcuuid {
					log.Infof("ingress (%s) is already associated with the service (%s), and ingress (%s) cannot be associated", ingressLcuuid, serviceLcuuid, uID, logger.NewORGPrefix(k.orgID))
				} else {
					k.serviceLcuuidToIngressLcuuid[serviceLcuuid] = uLcuuid
				}
				portString := interfaceToString(backend["servicePort"])
				if portString == "" && serviceConfig != nil {
					if servicePort, _ := getJSONMap(serviceConfig, "port"); servicePort != nil {
						portString = interfaceToString(servicePort["name"])
					}
				}
				port, ok := ports[portString]
				if !ok {
					port = interfaceToInt(backend["servicePort"])
					if port == 0 && serviceConfig != nil {
						if servicePort, _ := getJSONMap(serviceConfig, "port"); servicePort != nil {
							port = interfaceToInt(servicePort["number"])
						}
					}
				}
				if port == 0 {
					log.Infof("ingress (%s) backend service (%s) no servicePort", uID, serviceName, logger.NewORGPrefix(k.orgID))
					continue
				}
				pathValue := interfaceToString(path["path"])
				key := serviceName + "_" + strconv.Itoa(port)
				ingressRuleBackend := model.PodIngressRuleBackend{
					Lcuuid:               common.GetUUIDByOrgID(k.orgID, uLcuuid+key+pathValue),
					Path:                 pathValue,
					Port:                 port,
					PodServiceLcuuid:     serviceLcuuid,
					PodIngressRuleLcuuid: ruleLcuuid,
					PodIngressLcuuid:     uLcuuid,
				}
				ingressRuleBackends = append(ingressRuleBackends, ingressRuleBackend)
			}
		}
		backend, ok := getJSONMap(spec, "backend")
		if !ok {
			backend, ok = getJSONMap(spec, "defaultBackend")
		}
		if ok {
			ruleLcuuid := common.GetUUIDByOrgID(k.orgID, uLcuuid+"defaultBackend")
			ingressRule := model.PodIngressRule{
				Lcuuid:           ruleLcuuid,
				Protocol:         "HTTP",
				PodIngressLcuuid: uLcuuid,
			}
			ingressRules = append(ingressRules, ingressRule)
			serviceName := interfaceToString(backend["serviceName"])
			if serviceName == "" {
				if serviceConfig, _ := getJSONMap(backend, "service"); serviceConfig != nil {
					serviceName = interfaceToString(serviceConfig["name"])
				}
			}
			service, ok := k.nsServiceNameToService[namespace+serviceName]
			if !ok {
				log.Infof("ingress backend service (%s) not found", serviceName, logger.NewORGPrefix(k.orgID))
				continue
			}
			serviceLcuuid, ports := "", map[string]int{}
			for key, v := range service {
				serviceLcuuid = key
				ports = v
				break
			}
			if ingressLcuuid, ok := k.serviceLcuuidToIngressLcuuid[serviceLcuuid]; ok && ingressLcuuid != uLcuuid {
				log.Infof("ingress (%s) is already associated with the service (%s), and ingress (%s) cannot be associated", ingressLcuuid, serviceLcuuid, uID, logger.NewORGPrefix(k.orgID))

			} else {
				k.serviceLcuuidToIngressLcuuid[serviceLcuuid] = uLcuuid
			}
			portString := interfaceToString(backend["servicePort"])
			if portString == "" {
				if serviceConfig, _ := getJSONMap(backend, "service"); serviceConfig != nil {
					if servicePort, _ := getJSONMap(serviceConfig, "port"); servicePort != nil {
						portString = interfaceToString(servicePort["name"])
					}
				}
			}
			port, ok := ports[portString]
			if !ok {
				port = interfaceToInt(backend["servicePort"])
				if port == 0 {
					if serviceConfig, _ := getJSONMap(backend, "service"); serviceConfig != nil {
						if servicePort, _ := getJSONMap(serviceConfig, "port"); servicePort != nil {
							port = interfaceToInt(servicePort["number"])
						}
					}
				}
			}
			if port == 0 {
				log.Infof("ingress (%s) backend service (%s) no servicePort", uID, serviceName, logger.NewORGPrefix(k.orgID))
				continue
			}
			key := serviceName + "_" + strconv.Itoa(port)
			ingressRuleBackend := model.PodIngressRuleBackend{
				Lcuuid:               common.GetUUIDByOrgID(k.orgID, uLcuuid+key+"default"),
				Port:                 port,
				PodServiceLcuuid:     serviceLcuuid,
				PodIngressRuleLcuuid: ruleLcuuid,
				PodIngressLcuuid:     uLcuuid,
			}
			ingressRuleBackends = append(ingressRuleBackends, ingressRuleBackend)
		}
		if host := interfaceToString(spec["host"]); host != "" {
			ruleLcuuid := common.GetUUIDByOrgID(k.orgID, uLcuuid+host)
			ingressRule := model.PodIngressRule{
				Lcuuid:           ruleLcuuid,
				Protocol:         "HTTP",
				Host:             host,
				PodIngressLcuuid: uLcuuid,
			}
			ingressRules = append(ingressRules, ingressRule)
			if to, _ := getJSONMap(spec, "to"); to != nil {
				serviceName := interfaceToString(to["name"])
				service, ok := k.nsServiceNameToService[namespace+serviceName]
				if !ok {
					log.Infof("ingress service (%s) not found", serviceName, logger.NewORGPrefix(k.orgID))
					continue
				}
				serviceLcuuid, ports := "", map[string]int{}
				for key, v := range service {
					serviceLcuuid = key
					ports = v
					break
				}
				if ingressLcuuid, ok := k.serviceLcuuidToIngressLcuuid[serviceLcuuid]; ok && ingressLcuuid != uLcuuid {
					log.Infof("ingress (%s) is already associated with the service (%s), and ingress (%s) cannot be associated", ingressLcuuid, serviceLcuuid, uID, logger.NewORGPrefix(k.orgID))

				} else {
					k.serviceLcuuidToIngressLcuuid[serviceLcuuid] = uLcuuid
				}
				portString := interfaceToString(to["port"])
				port := ports[portString]
				if port == 0 {
					port = interfaceToInt(to["port"])
				}
				if port == 0 {
					log.Infof("ingress (%s) service (%s) no servicePort", uID, serviceName, logger.NewORGPrefix(k.orgID))
					continue
				}
				key := serviceName + "_" + strconv.Itoa(port)
				ingressRuleBackend := model.PodIngressRuleBackend{
					Lcuuid:               common.GetUUIDByOrgID(k.orgID, uLcuuid+key+host),
					Port:                 port,
					PodServiceLcuuid:     serviceLcuuid,
					PodIngressRuleLcuuid: ruleLcuuid,
					PodIngressLcuuid:     uLcuuid,
				}
				ingressRuleBackends = append(ingressRuleBackends, ingressRuleBackend)
			}
		}
	}
	log.Debug("get ingresses complete", logger.NewORGPrefix(k.orgID))
	return
}
