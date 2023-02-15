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

package genesis

import (
	"github.com/deepflowio/deepflow/server/controller/cloud/model"
	"github.com/deepflowio/deepflow/server/controller/common"

	uuid "github.com/satori/go.uuid"
)

func (g *Genesis) getHosts() ([]model.Host, error) {
	log.Debug("get hosts starting")
	hosts := []model.Host{}
	hostsData := g.genesisData.Hosts

	g.cloudStatsd.APICost["hosts"] = []int{0}
	g.cloudStatsd.APICount["hosts"] = []int{len(hostsData)}

	for _, h := range hostsData {
		host := model.Host{
			Lcuuid:       common.GetUUID(h.IP, uuid.Nil),
			IP:           h.IP,
			Name:         h.Hostname,
			HType:        common.HOST_HTYPE_KVM,
			VCPUNum:      common.HOST_VCPUS,
			MemTotal:     common.HOST_MEMORY_MB,
			Type:         common.HOST_TYPE_VM,
			AZLcuuid:     g.azLcuuid,
			RegionLcuuid: g.regionUuid,
		}
		hosts = append(hosts, host)
	}
	log.Debug("get hosts complete")
	return hosts, nil
}
