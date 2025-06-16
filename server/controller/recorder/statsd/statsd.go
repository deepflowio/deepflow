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

package statsd

import (
	"fmt"

	"github.com/deepflowio/deepflow/server/controller/recorder/common"
	"github.com/deepflowio/deepflow/server/libs/logger"
	"github.com/deepflowio/deepflow/server/libs/stats"
)

var log = logger.MustGetLogger("recorder.statsd")

const (
	TagTypeSyncCost     = "sync_cost"
	TagTypeVMSyncDelay  = "vm_sync_delay"
	TagTypePodSyncDelay = "pod_sync_delay"

	counterModulePrefix                = "controller_"
	counterModuleTypeCloudTaskCost     = "cloud_task_cost"
	counterModuleTypeResourceSyncDelay = "resource_sync_delay"
	resourceSyncDelayTypeChost         = "chost"
	resourceSyncDelayTypePod           = "pod"

	optStatTagORGID     = "tenant_org_id"
	optStatTagTeamID    = "tenant_team_id"
	optStatTagDomain    = "domain"
	optStatTagSubDomain = "sub_domain"
	optStatTagType      = "type"
)

type Statsd interface {
	GetMonitor(tagType string) Monitor
	GetMetadata() *common.Metadata
}

func NewDomainStatsd(md *common.Metadata) *DomainStatsd {
	s := &DomainStatsd{
		md: md,

		syncCost:     newSyncCost(),
		vmSyncDelay:  newResourceDalay(),
		podSyncDelay: newResourceDalay(),
	}
	s.Start()
	return s
}

type DomainStatsd struct {
	md *common.Metadata

	syncCost     *SyncCost
	vmSyncDelay  *ResourceSyncDelay
	podSyncDelay *ResourceSyncDelay
}

func (r *DomainStatsd) GetMetadata() *common.Metadata {
	return r.md
}

func (r *DomainStatsd) Start() {
	log.Info("start statsd", r.md.LogPrefixes)
	err := stats.RegisterCountableWithModulePrefix(
		counterModulePrefix,
		counterModuleTypeCloudTaskCost,
		r.syncCost,
		stats.OptionStatTags{
			optStatTagORGID:  fmt.Sprintf("%d", r.md.GetORGID()),
			optStatTagTeamID: fmt.Sprintf("%d", r.md.GetTeamID()),
			optStatTagDomain: r.md.GetDomainInfo().Name,
		},
	)
	if err != nil {
		log.Errorf("failed to register statsd %s: %s", TagTypeSyncCost, err.Error(), r.md.LogPrefixes)
	}

	err = stats.RegisterCountableWithModulePrefix(
		counterModulePrefix,
		counterModuleTypeResourceSyncDelay,
		r.vmSyncDelay,
		stats.OptionStatTags{
			optStatTagORGID:  fmt.Sprintf("%d", r.md.GetORGID()),
			optStatTagTeamID: fmt.Sprintf("%d", r.md.GetTeamID()),
			optStatTagDomain: r.md.GetDomainInfo().Name,
			optStatTagType:   resourceSyncDelayTypeChost,
		},
	)
	if err != nil {
		log.Errorf("failed to register statsd %s: %s", TagTypeVMSyncDelay, err.Error(), r.md.LogPrefixes)
	}

	err = stats.RegisterCountableWithModulePrefix(
		counterModulePrefix,
		counterModuleTypeResourceSyncDelay,
		r.podSyncDelay,
		stats.OptionStatTags{
			optStatTagORGID:  fmt.Sprintf("%d", r.md.GetORGID()),
			optStatTagTeamID: fmt.Sprintf("%d", r.md.GetTeamID()),
			optStatTagDomain: r.md.GetDomainInfo().Name,
			optStatTagType:   resourceSyncDelayTypePod,
		},
	)
	if err != nil {
		log.Errorf("failed to register statsd %s: %s", TagTypePodSyncDelay, err.Error(), r.md.LogPrefixes)
	}
}

func (r *DomainStatsd) GetMonitor(tagType string) Monitor {
	switch tagType {
	case TagTypeSyncCost:
		return r.syncCost
	case TagTypeVMSyncDelay:
		return r.vmSyncDelay
	case TagTypePodSyncDelay:
		return r.podSyncDelay
	default:
		return nil
	}
}

func (r *DomainStatsd) Close() {
	r.syncCost.Closed()
	r.vmSyncDelay.Closed()
}

func NewSubDomainStatsd(md *common.Metadata) *SubDomainStatsd {
	s := &SubDomainStatsd{
		md: md,

		podSyncDelay: newResourceDalay(),
	}
	s.Start()
	return s
}

type SubDomainStatsd struct {
	md *common.Metadata

	podSyncDelay *ResourceSyncDelay
}

func (r *SubDomainStatsd) GetMetadata() *common.Metadata {
	return r.md
}

func (r *SubDomainStatsd) Start() {
	log.Info("start statsd", r.md.LogPrefixes)
	err := stats.RegisterCountableWithModulePrefix(
		counterModulePrefix,
		counterModuleTypeResourceSyncDelay,
		r.podSyncDelay,
		stats.OptionStatTags{
			optStatTagORGID:     fmt.Sprintf("%d", r.md.GetORGID()),
			optStatTagTeamID:    fmt.Sprintf("%d", r.md.GetTeamID()),
			optStatTagDomain:    r.md.GetDomainInfo().Name,
			optStatTagSubDomain: r.md.GetSubDomainInfo().Name,
			optStatTagType:      resourceSyncDelayTypePod,
		},
	)
	if err != nil {
		log.Errorf("failed to register statsd %s: %s", TagTypePodSyncDelay, err.Error(), r.md.LogPrefixes)
	}
}

func (r *SubDomainStatsd) GetMonitor(tagType string) Monitor {
	switch tagType {
	case TagTypePodSyncDelay:
		return r.podSyncDelay
	default:
		return nil
	}
}

func (r *SubDomainStatsd) Close() {
	r.podSyncDelay.Closed()
}
