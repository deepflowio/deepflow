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

package kubernetes

import (
	"regexp"

	simplejson "github.com/bitly/go-simplejson"
	logging "github.com/op/go-logging"

	k8sGather "github.com/deepflowio/deepflow/server/controller/cloud/kubernetes_gather"
	"github.com/deepflowio/deepflow/server/controller/cloud/model"
	"github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
)

var log = logging.MustGetLogger("cloud.kubernetes")

type Kubernetes struct {
	name                  string
	uuidGenerate          string
	clusterID             string
	regionUuid            string
	vpcUuid               string
	podNetIPv4CIDRMaxMask int
	podNetIPv6CIDRMaxMask int
	portNameRegex         string
}

func NewKubernetes(domain mysql.Domain) (*Kubernetes, error) {
	configJson, err := simplejson.NewJson([]byte(domain.Config))
	if err != nil {
		log.Error(err)
		return nil, err
	}

	portNameRegex := configJson.Get("port_name_regex").MustString()
	if portNameRegex == "" {
		portNameRegex = k8sGather.K8S_VINTERFACE_NAME_REGEX
	}
	_, regxErr := regexp.Compile(portNameRegex)
	if regxErr != nil {
		log.Errorf("newkubernetes portnameregex (%s) compile error : (%s)", portNameRegex, regxErr.Error())
		return nil, regxErr
	}

	podNetIPv4CIDRMaxMask, err := configJson.Get("pod_net_ipv4_cidr_max_mask").Int()
	if err != nil {
		podNetIPv4CIDRMaxMask = common.K8S_POD_IPV4_NETMASK
	}

	podNetIPv6CIDRMaxMask, err := configJson.Get("pod_net_ipv6_cidr_max_mask").Int()
	if err != nil {
		podNetIPv6CIDRMaxMask = common.K8S_POD_IPV6_NETMASK
	}

	return &Kubernetes{
		// TODO: display_name后期需要修改为uuid_generate
		name:                  domain.Name,
		uuidGenerate:          domain.DisplayName,
		clusterID:             domain.ClusterID,
		regionUuid:            configJson.Get("region_uuid").MustString(),
		vpcUuid:               configJson.Get("vpc_uuid").MustString(),
		podNetIPv4CIDRMaxMask: podNetIPv4CIDRMaxMask,
		podNetIPv6CIDRMaxMask: podNetIPv6CIDRMaxMask,
		portNameRegex:         portNameRegex,
	}, nil
}

func (k *Kubernetes) ClearDebugLog() {}

func (k *Kubernetes) GetCloudData() (model.Resource, error) {
	return model.Resource{}, nil
}

func (k *Kubernetes) CheckAuth() error {
	return nil
}
