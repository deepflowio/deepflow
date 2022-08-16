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

package node

import (
	"os"

	"github.com/google/uuid"

	. "github.com/deepflowys/deepflow/server/controller/common"
	models "github.com/deepflowys/deepflow/server/controller/db/mysql"
	. "github.com/deepflowys/deepflow/server/controller/trisolaris/common"
	"github.com/deepflowys/deepflow/server/libs/utils"
)

type ControllerDiscovery struct {
	ctrlIP             string
	nodeType           int
	regionDomainPrefix string
}

func newControllerDiscovery(masterIP string, nodeType string, regionDomainPrefix string) *ControllerDiscovery {
	log.Info("node info: ", masterIP, nodeType, regionDomainPrefix)
	nodeTypeInt := CONTROLLER_NODE_TYPE_MASTER
	if nodeType == "slave" {
		nodeTypeInt = CONTROLLER_NODE_TYPE_SLAVE
	}
	return &ControllerDiscovery{
		ctrlIP:             masterIP,
		nodeType:           nodeTypeInt,
		regionDomainPrefix: regionDomainPrefix,
	}
}

func (c *ControllerDiscovery) GetControllerData() *models.Controller {
	envData := utils.GetRuntimeEnv()
	return &models.Controller{
		Name:               os.Getenv(POD_NAME_KEY),
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
	}
}
