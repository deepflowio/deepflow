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

package node

import (
	"github.com/google/uuid"

	. "github.com/deepflowio/deepflow/server/controller/common"
	metadbmodel "github.com/deepflowio/deepflow/server/controller/db/metadb/model"
	. "github.com/deepflowio/deepflow/server/controller/trisolaris/common"
	. "github.com/deepflowio/deepflow/server/controller/trisolaris/utils"
	"github.com/deepflowio/deepflow/server/libs/logger"
	"github.com/deepflowio/deepflow/server/libs/utils"
)

type ControllerDiscovery struct {
	ctrlIP             string
	nodeType           int
	regionDomainPrefix string
	ORGID
}

func newControllerDiscovery(masterIP string, nodeType string, regionDomainPrefix string, orgID ORGID) *ControllerDiscovery {
	log.Infof("node info: ip=%s, nodeType=%s, regionDomainPrefix=%s", masterIP, nodeType, regionDomainPrefix, logger.NewORGPrefix(int(orgID)))
	nodeTypeInt := CONTROLLER_NODE_TYPE_MASTER
	if nodeType == "slave" {
		nodeTypeInt = CONTROLLER_NODE_TYPE_SLAVE
	}
	return &ControllerDiscovery{
		ctrlIP:             masterIP,
		nodeType:           nodeTypeInt,
		regionDomainPrefix: regionDomainPrefix,
		ORGID:              orgID,
	}
}

func (c *ControllerDiscovery) GetControllerData() *metadbmodel.Controller {
	if c.ctrlIP == "" {
		log.Errorf(c.Logf("get env(%s) data failed", NODE_IP_KEY))
		return nil
	}
	envData := utils.GetRuntimeEnv()
	name := GetNodeName()
	if name == "" {
		log.Errorf(c.Logf("get env(%s) data failed", NODE_NAME_KEY))
		return nil
	}
	nodeName := GetNodeName()
	if nodeName == "" {
		log.Errorf(c.Logf("get env(%s) data failed", NODE_NAME_KEY))
		return nil
	}
	podIP := GetPodIP()
	if podIP == "" {
		log.Errorf(c.Logf("get env(%s) data failed", POD_IP_KEY))
		return nil
	}
	podName := GetPodName()
	if podName == "" {
		log.Errorf(c.Logf("get env(%s) data failed", POD_NAME_KEY))
		return nil
	}

	log.Infof(c.Logf("controller name (%s), node_name (%s)", name, nodeName))
	return &metadbmodel.Controller{
		Name:               name,
		CPUNum:             int(envData.CpuNum),
		MemorySize:         int64(envData.MemorySize),
		Arch:               envData.Arch,
		Os:                 envData.OS,
		KernelVersion:      envData.KernelVersion,
		IP:                 c.ctrlIP,
		NodeType:           c.nodeType,
		State:              HOST_STATE_COMPLETE,
		VTapMax:            CONTROLLER_VTAP_MAX,
		Lcuuid:             uuid.NewString(),
		RegionDomainPrefix: c.regionDomainPrefix,
		NodeName:           nodeName,
		PodIP:              podIP,
		PodName:            podName,
		CAMD5:              GetCAMD5(),
	}
}
