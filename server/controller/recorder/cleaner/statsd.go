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

package cleaner

import (
	"fmt"
	"sync/atomic"

	metadbmodel "github.com/deepflowio/deepflow/server/controller/db/metadb/model"
	"github.com/deepflowio/deepflow/server/controller/recorder/common"
	"github.com/deepflowio/deepflow/server/libs/stats"
)

const (
	tagTypeDeviceIPConn     = "device_ip_connection"
	tagTypeCHostPodNodeConn = "chost_pod_node_connection"
)

type domainStatsd struct {
	org    *common.ORG
	lcuuid string
	name   string
	teamID int

	deviceIPConn     *CleanerCounter
	chostPodNodeConn *CleanerCounter
}

func newDomainStatsd(org *common.ORG, domain *metadbmodel.Domain) *domainStatsd {
	return &domainStatsd{
		org:    org,
		lcuuid: domain.Lcuuid,
		name:   domain.Name,
		teamID: domain.TeamID,

		deviceIPConn:     newCleanerCounter(),
		chostPodNodeConn: newCleanerCounter(),
	}
}

func (d *domainStatsd) close() {
	log.Info("close cleaner statsd of domain (lcuuid: %s)", d.lcuuid, d.org.LogPrefix)
	d.deviceIPConn.Closed()
	d.chostPodNodeConn.Closed()
}

func (d *domainStatsd) get(tagType string) *CleanerCounter {
	switch tagType {
	case tagTypeDeviceIPConn:
		return d.deviceIPConn
	case tagTypeCHostPodNodeConn:
		return d.chostPodNodeConn
	}
	return nil
}

func (d *domainStatsd) start() {
	log.Infof("start cleaner statsd of domain (lcuuid: %s)", d.lcuuid, d.org.LogPrefix)
	err := stats.RegisterCountableWithModulePrefix(
		"controller_",
		"resource_relation_exception",
		d.deviceIPConn,
		stats.OptionStatTags{
			"tenant_org_id":  fmt.Sprintf("%d", d.org.ID),
			"tenant_team_id": fmt.Sprintf("%d", d.teamID),
			"domain":         d.name,
			"type":           tagTypeDeviceIPConn,
		},
	)
	if err != nil {
		log.Errorf("failed to register cleaner statsd of domain (lcuuid: %s) device_ip_connection: %s", d.lcuuid, err.Error(), d.org.LogPrefix)
	}

	err = stats.RegisterCountableWithModulePrefix(
		"controller_",
		"resource_relation_exception",
		d.chostPodNodeConn,
		stats.OptionStatTags{
			"tenant_org_id":  fmt.Sprintf("%d", d.org.ID),
			"tenant_team_id": fmt.Sprintf("%d", d.teamID),
			"domain":         d.name,
			"type":           tagTypeCHostPodNodeConn,
		},
	)
	if err != nil {
		log.Errorf("failed to register cleaner statsd of domain (lcuuid: %s) chost_pod_node_connection: %s", d.lcuuid, err.Error(), d.org.LogPrefix)
	}
}

type TmpCounter struct {
	Count uint64 `statsd:"count"`
}

func (c *TmpCounter) Fill(count int) {
	atomic.AddUint64(&c.Count, uint64(count))
}

type CleanerCounter struct {
	*TmpCounter
}

func newCleanerCounter() *CleanerCounter {
	return &CleanerCounter{
		TmpCounter: &TmpCounter{},
	}
}

func (c *CleanerCounter) GetCounter() interface{} {
	counter := &TmpCounter{}
	counter, c.TmpCounter = c.TmpCounter, counter
	if counter.Count != 0 {
		log.Infof("cleaner counter count: %d", counter.Count)
	}
	return counter
}

func (c *CleanerCounter) Closed() bool {
	return false
}
