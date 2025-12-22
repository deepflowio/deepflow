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

package cache

import (
	ctrlrcommon "github.com/deepflowio/deepflow/server/controller/common"
	metadb "github.com/deepflowio/deepflow/server/controller/db/metadb"
	metadbmodel "github.com/deepflowio/deepflow/server/controller/db/metadb/model"
	"github.com/deepflowio/deepflow/server/controller/recorder/cache/diffbase"
	"github.com/deepflowio/deepflow/server/controller/recorder/cache/tool"
	rcommon "github.com/deepflowio/deepflow/server/controller/recorder/common"
)

// loadFunc loads DB items by query condition and returns them as interface{} (actually a typed slice).
type loadFunc func(db *metadb.DB, cond map[string]interface{}) (interface{}, error)

// makeLoadFunc creates a loadFunc for a specific metadb model type using generics at the call site only.
// This keeps the generic parameter localized to construction time while the refresher struct stays non-generic.
func makeLoadFunc[MPT any]() loadFunc {
	return func(db *metadb.DB, cond map[string]interface{}) (interface{}, error) {
		var items []MPT
		err := db.Where(cond).Find(&items).Error
		return items, err
	}
}

// refresher is the non-generic cache refresher that loads data from DB and populates diffbase/tool.
// It embeds subscriberComponent for pubsub subscription support.
// Use newRefresher() with builder-style withXxx() methods to construct.
type refresher struct {
	subscriberComponent

	filterSubDomain    bool
	filterCreateMethod bool

	queryCondition map[string]interface{}
	load           loadFunc
}

// newRefresher creates a refresher with the required diffbase operator and load function.
// Optional configuration is set via builder-style methods (withTool, withSubDomainFilter, etc.).
func newRefresher(db diffbase.CollectionOperator, load loadFunc) *refresher {
	r := &refresher{load: load}
	r.subscriberComponent.resourceType = db.GetResourceType()
	r.subscriberComponent.diffBase = db
	return r
}

// withTool sets the tool collection operator. If not called, tool operations are no-ops.
func (r *refresher) withTool(t tool.CollectionOperator) *refresher {
	r.subscriberComponent.tool = t
	return r
}

// withMetadata sets the metadata for query condition building and logging.
func (r *refresher) withMetadata(md *rcommon.Metadata) *refresher {
	r.subscriberComponent.md = md
	return r
}

// withSubDomainFilter enables sub_domain filtering in the DB query condition.
func (r *refresher) withSubDomainFilter() *refresher {
	r.filterSubDomain = true
	return r
}

// withCreateMethodFilter enables create_method filtering in the DB query condition.
func (r *refresher) withCreateMethodFilter() *refresher {
	r.filterCreateMethod = true
	return r
}

// build finalizes the refresher by building the query condition from metadata.
// Must be called after all withXxx() methods.
func (r *refresher) build() *refresher {
	if r.md == nil {
		return r
	}
	r.queryCondition = map[string]interface{}{"domain": r.md.GetDomainLcuuid()}
	if r.filterSubDomain {
		r.queryCondition["sub_domain"] = r.md.GetSubDomainLcuuid()
	}
	if r.filterCreateMethod {
		r.queryCondition["create_method"] = ctrlrcommon.CREATE_METHOD_LEARN
	}
	return r
}

// refresh loads all matching items from DB and adds them to diffbase and tool caches.
// Returns true on success, false on failure.
func (r *refresher) refresh(seq int) bool {
	if r.md == nil {
		log.Warning("refresher has no metadata, skip refresh", r.resourceType)
		return false
	}
	log.Info(r.resourceType, r.md.LogPrefixes)
	dbItems, err := r.load(r.md.DB, r.queryCondition)
	if err != nil {
		log.Error(dbQueryResourceFailed(r.resourceType, err), r.md.LogPrefixes)
		return false
	}
	r.onBatchAdded(seq, dbItems)
	return true
}

// refreshers is a map from resource type to its refresher.
type refreshers map[string]*refresher

// get returns the refresher for the given resource type, or nil if not found.
func (rs refreshers) get(resourceType string) *refresher {
	return rs[resourceType]
}

// refresh calls refresh on the refresher for the given resource type.
// Returns true on success, false on failure or if not found.
func (rs refreshers) refresh(resourceType string, seq int) bool {
	if r := rs[resourceType]; r != nil {
		return r.refresh(seq)
	}
	return false
}

// newRefreshers initializes all refreshers keyed by resource type.
func newRefreshers(md *rcommon.Metadata, diffBases *diffbase.DiffBases, tools *tool.Tool) refreshers {
	rs := make(refreshers)
	register := func(r *refresher) { rs[r.resourceType] = r }

	// Clouds
	register(newRefresher(diffBases.SubDomain(), makeLoadFunc[*metadbmodel.SubDomain]()).withMetadata(md).build())
	register(newRefresher(diffBases.Region(), makeLoadFunc[*metadbmodel.Region]()).withTool(tools.Region()).withMetadata(md).withCreateMethodFilter().build())
	register(newRefresher(diffBases.AZ(), makeLoadFunc[*metadbmodel.AZ]()).withTool(tools.Az()).withMetadata(md).withCreateMethodFilter().build())

	// Computes
	register(newRefresher(diffBases.Host(), makeLoadFunc[*metadbmodel.Host]()).withTool(tools.Host()).withMetadata(md).withCreateMethodFilter().build())
	register(newRefresher(diffBases.VM(), makeLoadFunc[*metadbmodel.VM]()).withTool(tools.Vm()).withMetadata(md).withCreateMethodFilter().build())

	// Networks
	register(newRefresher(diffBases.VPC(), makeLoadFunc[*metadbmodel.VPC]()).withTool(tools.Vpc()).withMetadata(md).withCreateMethodFilter().build())
	register(newRefresher(diffBases.Network(), makeLoadFunc[*metadbmodel.Network]()).withTool(tools.Network()).withMetadata(md).build())
	register(newRefresher(diffBases.Subnet(), makeLoadFunc[*metadbmodel.Subnet]()).withTool(tools.Subnet()).withMetadata(md).build())
	register(newRefresher(diffBases.VRouter(), makeLoadFunc[*metadbmodel.VRouter]()).withTool(tools.Vrouter()).withMetadata(md).build())
	register(newRefresher(diffBases.RoutingTable(), makeLoadFunc[*metadbmodel.RoutingTable]()).withMetadata(md).build())
	register(newRefresher(diffBases.DHCPPort(), makeLoadFunc[*metadbmodel.DHCPPort]()).withTool(tools.DhcpPort()).withMetadata(md).build())
	register(newRefresher(diffBases.VInterface(), makeLoadFunc[*metadbmodel.VInterface]()).withTool(tools.Vinterface()).withMetadata(md).build())
	register(newRefresher(diffBases.LANIP(), makeLoadFunc[*metadbmodel.LANIP]()).withTool(tools.LanIP()).withMetadata(md).build())
	register(newRefresher(diffBases.WANIP(), makeLoadFunc[*metadbmodel.WANIP]()).withTool(tools.WanIP()).withMetadata(md).build())
	register(newRefresher(diffBases.FloatingIP(), makeLoadFunc[*metadbmodel.FloatingIP]()).withMetadata(md).build())
	register(newRefresher(diffBases.VIP(), makeLoadFunc[*metadbmodel.VIP]()).withMetadata(md).build())

	// Network services
	register(newRefresher(diffBases.NATGateway(), makeLoadFunc[*metadbmodel.NATGateway]()).withTool(tools.NatGateway()).withMetadata(md).build())
	register(newRefresher(diffBases.NATRule(), makeLoadFunc[*metadbmodel.NATRule]()).withMetadata(md).build())
	register(newRefresher(diffBases.NATVMConnection(), makeLoadFunc[*metadbmodel.NATVMConnection]()).withMetadata(md).build())
	register(newRefresher(diffBases.LB(), makeLoadFunc[*metadbmodel.LB]()).withTool(tools.Lb()).withMetadata(md).build())
	register(newRefresher(diffBases.LBListener(), makeLoadFunc[*metadbmodel.LBListener]()).withTool(tools.LbListener()).withMetadata(md).build())
	register(newRefresher(diffBases.LBTargetServer(), makeLoadFunc[*metadbmodel.LBTargetServer]()).withMetadata(md).build())
	register(newRefresher(diffBases.LBVMConnection(), makeLoadFunc[*metadbmodel.LBVMConnection]()).withMetadata(md).build())
	register(newRefresher(diffBases.CEN(), makeLoadFunc[*metadbmodel.CEN]()).withMetadata(md).build())
	register(newRefresher(diffBases.PeerConnection(), makeLoadFunc[*metadbmodel.PeerConnection]()).withMetadata(md).build())

	// Storage services
	register(newRefresher(diffBases.RDSInstance(), makeLoadFunc[*metadbmodel.RDSInstance]()).withTool(tools.RdsInstance()).withMetadata(md).build())
	register(newRefresher(diffBases.RedisInstance(), makeLoadFunc[*metadbmodel.RedisInstance]()).withTool(tools.RedisInstance()).withMetadata(md).build())

	// Kubernetes
	register(newRefresher(diffBases.PodCluster(), makeLoadFunc[*metadbmodel.PodCluster]()).withTool(tools.PodCluster()).withMetadata(md).withSubDomainFilter().build())
	register(newRefresher(diffBases.PodNode(), makeLoadFunc[*metadbmodel.PodNode]()).withTool(tools.PodNode()).withMetadata(md).withSubDomainFilter().build())
	register(newRefresher(diffBases.PodNamespace(), makeLoadFunc[*metadbmodel.PodNamespace]()).withTool(tools.PodNamespace()).withMetadata(md).withSubDomainFilter().build())
	register(newRefresher(diffBases.PodIngress(), makeLoadFunc[*metadbmodel.PodIngress]()).withTool(tools.PodIngress()).withMetadata(md).withSubDomainFilter().build())
	register(newRefresher(diffBases.PodIngressRule(), makeLoadFunc[*metadbmodel.PodIngressRule]()).withTool(tools.PodIngressRule()).withMetadata(md).withSubDomainFilter().build())
	register(newRefresher(diffBases.PodService(), makeLoadFunc[*metadbmodel.PodService]()).withTool(tools.PodService()).withMetadata(md).withSubDomainFilter().build())
	register(newRefresher(diffBases.PodGroup(), makeLoadFunc[*metadbmodel.PodGroup]()).withTool(tools.PodGroup()).withMetadata(md).withSubDomainFilter().build())
	register(newRefresher(diffBases.Pod(), makeLoadFunc[*metadbmodel.Pod]()).withTool(tools.Pod()).withMetadata(md).withSubDomainFilter().build())
	register(newRefresher(diffBases.PodGroupPort(), makeLoadFunc[*metadbmodel.PodGroupPort]()).withMetadata(md).withSubDomainFilter().build())
	register(newRefresher(diffBases.PodReplicaSet(), makeLoadFunc[*metadbmodel.PodReplicaSet]()).withTool(tools.PodReplicaSet()).withMetadata(md).withSubDomainFilter().build())
	register(newRefresher(diffBases.PodServicePort(), makeLoadFunc[*metadbmodel.PodServicePort]()).withMetadata(md).withSubDomainFilter().build())
	register(newRefresher(diffBases.PodIngressRuleBackend(), makeLoadFunc[*metadbmodel.PodIngressRuleBackend]()).withMetadata(md).withSubDomainFilter().build())
	register(newRefresher(diffBases.VMPodNodeConnection(), makeLoadFunc[*metadbmodel.VMPodNodeConnection]()).withTool(tools.VmPodNodeConnection()).withMetadata(md).withSubDomainFilter().build())
	register(newRefresher(diffBases.ConfigMap(), makeLoadFunc[*metadbmodel.ConfigMap]()).withTool(tools.ConfigMap()).withMetadata(md).withSubDomainFilter().build())
	register(newRefresher(diffBases.PodGroupConfigMapConnection(), makeLoadFunc[*metadbmodel.PodGroupConfigMapConnection]()).withTool(tools.PodGroupConfigMapConnection()).withMetadata(md).withSubDomainFilter().build())

	// Processes
	register(newRefresher(diffBases.Process(), makeLoadFunc[*metadbmodel.Process]()).withTool(tools.Process()).withMetadata(md).build())

	return rs
}
