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
	"sync"

	"github.com/google/uuid"

	"github.com/deepflowio/deepflow/message/trident"
	. "github.com/deepflowio/deepflow/server/controller/common"
	models "github.com/deepflowio/deepflow/server/controller/db/mysql"
	. "github.com/deepflowio/deepflow/server/controller/trisolaris/common"
)

type TSDBDiscovery struct {
	sync.Mutex
	registration map[string]*models.Analyzer
}

func newTSDBDiscovery() *TSDBDiscovery {
	return &TSDBDiscovery{
		registration: make(map[string]*models.Analyzer),
	}
}

func (a *TSDBDiscovery) register(request *trident.SyncRequest) {
	pcapDataMountPath := ""
	if request.GetTsdbReportInfo() != nil {
		pcapDataMountPath = request.GetTsdbReportInfo().GetPcapDataMountPath()
	}
	podIP := GetPodIP()
	if podIP == "" {
		log.Errorf("get env(%s) data failed", POD_IP_KEY)
		return
	}
	podName := GetPodName()
	if podName == "" {
		log.Errorf("get env(%s) data failed", POD_NAME_KEY)
		return
	}
	nodeName := GetNodeName()
	if nodeName == "" {
		log.Errorf("get env(%s) data failed", NODE_NAME_KEY)
		return
	}
	tsdb := &models.Analyzer{
		IP:                request.GetCtrlIp(),
		NATIPEnabled:      0,
		NATIP:             "",
		Name:              nodeName,
		CPUNum:            int(request.GetCpuNum()),
		MemorySize:        int64(request.GetMemorySize()),
		Arch:              request.GetArch(),
		Os:                request.GetOs(),
		KernelVersion:     request.GetKernelVersion(),
		VTapMax:           TSDB_VTAP_MAX,
		State:             HOST_STATE_COMPLETE,
		Lcuuid:            uuid.NewString(),
		PcapDataMountPath: pcapDataMountPath,
		PodIP:             podIP,
		PodName:           podName,
		CAMD5:             GetCAMD5(),
	}
	a.Lock()
	defer a.Unlock()
	a.registration[request.GetCtrlIp()] = tsdb
}

func (a *TSDBDiscovery) getRegisterData() map[string]*models.Analyzer {
	a.Lock()
	defer a.Unlock()
	data := a.registration
	a.registration = make(map[string]*models.Analyzer)
	return data
}
