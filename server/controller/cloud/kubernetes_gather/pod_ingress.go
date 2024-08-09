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

	"github.com/bitly/go-simplejson"
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
		iData, iErr := simplejson.NewJson([]byte(i))
		if iErr != nil {
			err = iErr
			log.Errorf("ingress initialization simplejson error: (%s)", iErr.Error(), logger.NewORGPrefix(k.orgID))
			return
		}
		metaData, ok := iData.CheckGet("metadata")
		if !ok {
			log.Info("ingress metadata not found", logger.NewORGPrefix(k.orgID))
			continue
		}
		uID := metaData.Get("uid").MustString()
		if uID == "" {
			log.Info("ingress uid not found", logger.NewORGPrefix(k.orgID))
			continue
		}
		name := metaData.Get("name").MustString()
		if name == "" {
			log.Infof("ingress (%s) name not found", uID, logger.NewORGPrefix(k.orgID))
			continue
		}
		namespace := metaData.Get("namespace").MustString()
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
		rules := iData.Get("spec").Get("rules")
		for index := range rules.MustArray() {
			rule := rules.GetIndex(index)
			ruleLcuuid := common.GetUUIDByOrgID(k.orgID, uLcuuid+rule.Get("host").MustString()+"_"+strconv.Itoa(index))
			ingressRule := model.PodIngressRule{
				Lcuuid:           ruleLcuuid,
				Host:             rule.Get("host").MustString(),
				Protocol:         "HTTP",
				PodIngressLcuuid: uLcuuid,
			}
			ingressRules = append(ingressRules, ingressRule)
			for p := range rule.Get("http").Get("paths").MustArray() {
				path := rule.Get("http").Get("paths").GetIndex(p)
				backend, ok := path.CheckGet("backend")
				if !ok {
					continue
				}
				serviceName := backend.Get("service").Get("name").MustString()
				if serviceName == "" {
					serviceName = backend.Get("serviceName").MustString()
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
				portString := backend.Get("servicePort").MustString()
				if portString == "" {
					portString = backend.Get("service").Get("port").Get("name").MustString()
				}
				port, ok := ports[portString]
				if !ok {
					port = backend.Get("servicePort").MustInt()
					if port == 0 {
						port = backend.Get("service").Get("port").Get("number").MustInt()
					}
				}
				if port == 0 {
					log.Infof("ingress (%s) backend service (%s) no servicePort", uID, serviceName, logger.NewORGPrefix(k.orgID))
					continue
				}
				key := serviceName + "_" + strconv.Itoa(port)
				ingressRuleBackend := model.PodIngressRuleBackend{
					Lcuuid:               common.GetUUIDByOrgID(k.orgID, uLcuuid+key+path.Get("path").MustString()),
					Path:                 path.Get("path").MustString(),
					Port:                 port,
					PodServiceLcuuid:     serviceLcuuid,
					PodIngressRuleLcuuid: ruleLcuuid,
					PodIngressLcuuid:     uLcuuid,
				}
				ingressRuleBackends = append(ingressRuleBackends, ingressRuleBackend)
			}
		}
		backend, ok := iData.Get("spec").CheckGet("backend")
		if !ok {
			backend, ok = iData.Get("spec").CheckGet("defaultBackend")
		}
		if ok {
			ruleLcuuid := common.GetUUIDByOrgID(k.orgID, uLcuuid+"defaultBackend")
			ingressRule := model.PodIngressRule{
				Lcuuid:           ruleLcuuid,
				Protocol:         "HTTP",
				PodIngressLcuuid: uLcuuid,
			}
			ingressRules = append(ingressRules, ingressRule)
			serviceName := backend.Get("serviceName").MustString()
			if serviceName == "" {
				serviceName = backend.Get("service").Get("name").MustString()
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
			portString := backend.Get("servicePort").MustString()
			if portString == "" {
				portString = backend.Get("service").Get("port").Get("name").MustString()
			}
			port, ok := ports[portString]
			if !ok {
				port = backend.Get("servicePort").MustInt()
				if port == 0 {
					port = backend.Get("service").Get("port").Get("number").MustInt()
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
		if _, ok := iData.Get("spec").CheckGet("host"); ok {
			spec := iData.Get("spec")
			host := spec.Get("host").MustString()
			ruleLcuuid := common.GetUUIDByOrgID(k.orgID, uLcuuid+host)
			ingressRule := model.PodIngressRule{
				Lcuuid:           ruleLcuuid,
				Protocol:         "HTTP",
				Host:             host,
				PodIngressLcuuid: uLcuuid,
			}
			ingressRules = append(ingressRules, ingressRule)
			serviceName := spec.Get("to").Get("name").MustString()
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
			if _, ok := spec.CheckGet("port"); !ok {
				log.Infof("ingress (%s) port not found", uID, logger.NewORGPrefix(k.orgID))
				continue
			}
			port, ok := ports[spec.Get("port").MustString()]
			if !ok {
				port = spec.Get("targetPort").MustInt()
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
	}
	log.Debug("get ingresses complete", logger.NewORGPrefix(k.orgID))
	return
}
