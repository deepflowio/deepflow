/**
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

package tagrecorder

import (
	"slices"
	"sync"

	"github.com/deepflowio/deepflow/server/controller/config"
	"github.com/deepflowio/deepflow/server/controller/db/metadb"
	metadbmodel "github.com/deepflowio/deepflow/server/controller/db/metadb/model"
	"github.com/deepflowio/deepflow/server/controller/recorder/pubsub"
	"github.com/deepflowio/deepflow/server/controller/recorder/pubsub/message"
	msgconstraint "github.com/deepflowio/deepflow/server/controller/recorder/pubsub/message/constraint"
	"github.com/deepflowio/deepflow/server/libs/logger"
)

const hookerDeletePage = 0

type deletePageHooker[MT metadbmodel.AssetResourceConstraint, MDT msgconstraint.Delete, MDPT msgconstraint.DeletePtr[MDT]] interface {
	beforeDeletePage([]*MT, MDPT) []*MT
}

var (
	subscriberManagerOnce sync.Once
	subscriberManager     *SubscriberManager
)

type SubscriberManager struct {
	cfg                  config.ControllerConfig
	domainLcuuidToIconID map[string]int
	resourceTypeToIconID map[IconKey]int

	subscribers []Subscriber
}

func GetSubscriberManager() *SubscriberManager {
	subscriberManagerOnce.Do(func() {
		subscriberManager = &SubscriberManager{}
	})
	return subscriberManager
}

func (c *SubscriberManager) Init(cfg config.ControllerConfig) {
	c.cfg = cfg
}

func (c *SubscriberManager) Start() (err error) {
	log.Info("tagrecorder subscriber manager started")
	c.domainLcuuidToIconID, c.resourceTypeToIconID, err = GetIconInfo(c.cfg)
	if err != nil {
		return err
	}
	c.subscribers = c.getSubscribers()
	log.Infof("tagrecorder run start")
	for _, subscriber := range c.subscribers {
		subscriber.SetConfig(c.cfg)
		subscriber.Subscribe()
	}
	return nil
}

func (m *SubscriberManager) GetSubscribers(subResourceType string) []Subscriber {
	ss := make([]Subscriber, 0)
	if subResourceType == pubsub.PubSubTypeDomain {
		return m.subscribers
	} else if subResourceType == pubsub.PubSubTypeSubDomain {
		for _, s := range m.subscribers {
			if slices.Contains(SUB_DOMAIN_RESOURCE_TYPES, s.GetSubResourceType()) {
				ss = append(ss, s)
			}
		}
	} else {
		for _, s := range m.subscribers {
			if s.GetSubResourceType() == subResourceType {
				ss = append(ss, s)
			}
		}
	}
	return ss
}

func (m *SubscriberManager) GetSubscriber(subResourceType, resourceType string) Subscriber {
	for _, s := range m.subscribers {
		if s.GetResourceType() == resourceType && s.GetSubResourceType() == subResourceType {
			return s
		}
	}
	return nil
}

func (c *SubscriberManager) getSubscribers() []Subscriber {
	subscribers := []Subscriber{
		NewChVMDevice(c.resourceTypeToIconID),
		NewChHostDevice(c.resourceTypeToIconID),
		NewChVRouterDevice(c.resourceTypeToIconID),
		NewChDHCPPortDevice(c.resourceTypeToIconID),
		NewChNATGatewayDevice(c.resourceTypeToIconID),
		NewChLBDevice(c.resourceTypeToIconID),
		NewChRDSInstanceDevice(c.resourceTypeToIconID),
		NewChRedisInstanceDevice(c.resourceTypeToIconID),
		NewChPodServiceDevice(c.resourceTypeToIconID),
		NewChPodDevice(c.resourceTypeToIconID),
		NewChPodGroupDevice(c.resourceTypeToIconID),
		NewChPodNodeDevice(c.resourceTypeToIconID),
		NewChPodClusterDevice(c.resourceTypeToIconID),
		NewChProcessDevice(c.resourceTypeToIconID),
		NewChCustomServiceDevice(c.resourceTypeToIconID),
		NewChBizService(c.resourceTypeToIconID),

		NewChAZ(c.domainLcuuidToIconID, c.resourceTypeToIconID),
		NewChChost(),
		NewChVPC(c.resourceTypeToIconID),
		NewChNetwork(c.resourceTypeToIconID),
		NewChPodCluster(c.resourceTypeToIconID),
		NewChPodNode(c.resourceTypeToIconID),
		NewChPodNamespace(c.resourceTypeToIconID),
		NewChPodIngress(),
		NewChPodService(),
		NewChPodGroup(c.resourceTypeToIconID),
		NewChPod(c.resourceTypeToIconID),
		NewChGProcess(c.resourceTypeToIconID),

		NewChChostCloudTag(),
		NewChChostCloudTags(),
		NewChPodNSCloudTag(),
		NewChPodNSCloudTags(),
		NewChPodServiceK8sLabel(),
		NewChPodServiceK8sLabels(),
		NewChPodServiceK8sAnnotation(),
		NewChPodServiceK8sAnnotations(),
		NewChPodK8sEnv(),
		NewChPodK8sEnvs(),
		NewChPodK8sLabel(),
		NewChPodK8sLabels(),
		NewChPodK8sAnnotation(),
		NewChPodK8sAnnotations(),
	}
	return subscribers
}

type Subscriber interface {
	pubsub.ResourceBatchAddedSubscriber
	pubsub.ResourceUpdatedSubscriber
	pubsub.ResourceBatchDeletedSubscriber

	Subscribe()
	SetConfig(config.ControllerConfig)
	GetSubResourceType() string
	GetResourceType() string // 获取CH表资源类型
	OnDomainDeleted(md *message.Metadata)
	OnSubDomainDeleted(md *message.Metadata)
	OnSubDomainTeamIDUpdated(md *message.Metadata)
}

type SubscriberDataGenerator[
	MAPT msgconstraint.AddPtr[MAT],
	MAT msgconstraint.Add,
	MUPT msgconstraint.UpdatePtr[MUT],
	MUT msgconstraint.Update,
	MDPT msgconstraint.DeletePtr[MDT],
	MDT msgconstraint.Delete,
	MT metadbmodel.AssetResourceConstraint,
	CT SubscriberMetaDBChModel,
	KT SubscriberChModelKey,
] interface {
	sourceToTarget(md *message.Metadata, resourceMySQLItem *MT) (chKeys []KT, chItems []CT) // 将源表数据转换为CH表数据
	onResourceUpdated(*message.Metadata, MUPT)
	softDeletedTargetsUpdated([]CT, *metadb.DB)
}

type SubscriberComponent[
	MAPT msgconstraint.AddPtr[MAT],
	MAT msgconstraint.Add,
	MUPT msgconstraint.UpdatePtr[MUT],
	MUT msgconstraint.Update,
	MDPT msgconstraint.DeletePtr[MDT],
	MDT msgconstraint.Delete,
	MT metadbmodel.AssetResourceConstraint,
	CT SubscriberMetaDBChModel,
	KT SubscriberChModelKey,
] struct {
	cfg config.ControllerConfig

	subResourceTypeName string // 订阅表资源类型，即源表资源类型
	resourceTypeName    string // CH表资源类型
	dbOperator          operator[CT, KT]
	subscriberDG        SubscriberDataGenerator[MAPT, MAT, MUPT, MUT, MDPT, MDT, MT, CT, KT]
	hookers             map[int]interface{}
	softDelete          bool
	subscribeRecorder   bool // Whether to subscribe to recorder messages, default is true
}

func newSubscriberComponent[
	MAPT msgconstraint.AddPtr[MAT],
	MAT msgconstraint.Add,
	MUPT msgconstraint.UpdatePtr[MUT],
	MUT msgconstraint.Update,
	MDPT msgconstraint.DeletePtr[MDT],
	MDT msgconstraint.Delete,
	MT metadbmodel.AssetResourceConstraint,
	CT SubscriberMetaDBChModel,
	KT SubscriberChModelKey,
](
	sourceResourceTypeName, resourceTypeName string,
) SubscriberComponent[MAPT, MAT, MUPT, MUT, MDPT, MDT, MT, CT, KT] {
	s := SubscriberComponent[MAPT, MAT, MUPT, MUT, MDPT, MDT, MT, CT, KT]{
		subResourceTypeName: sourceResourceTypeName,
		resourceTypeName:    resourceTypeName,
		hookers:             make(map[int]interface{}),
		softDelete:          false,
		subscribeRecorder:   true,
	}
	s.initDBOperator()
	return s
}

func (s *SubscriberComponent[MAPT, MAT, MUPT, MUT, MDPT, MDT, MT, CT, KT]) GetSubResourceType() string {
	return s.subResourceTypeName
}

func (s *SubscriberComponent[MAPT, MAT, MUPT, MUT, MDPT, MDT, MT, CT, KT]) GetResourceType() string {
	return s.resourceTypeName
}

func (s *SubscriberComponent[MAPT, MAT, MUPT, MUT, MDPT, MDT, MT, CT, KT]) initDBOperator() {
	s.dbOperator = newOperator[CT, KT](s.resourceTypeName)
}

func (s *SubscriberComponent[MAPT, MAT, MUPT, MUT, MDPT, MDT, MT, CT, KT]) generateKeyTargets(md *message.Metadata, sources []*MT) ([]KT, []CT) {
	keys := []KT{}
	targets := []CT{}
	seenKeys := map[KT]bool{}
	for _, item := range sources {
		if item == nil {
			log.Errorf("subscriber resource is nil")
			continue
		}
		ks, ts := s.subscriberDG.sourceToTarget(md, item)
		if len(ks) == 0 || len(ts) == 0 {
			continue
		}
		if len(ks) != len(ts) {
			log.Errorf("sourceToTarget returned mismatched lengths: keys=%d, targets=%d", len(ks), len(ts))
			continue
		}
		// deduplicate
		for i, k := range ks {
			if !seenKeys[k] {
				keys = append(keys, k)
				targets = append(targets, ts[i])
				seenKeys[k] = true
			}
		}
	}
	return keys, targets
}

func (s *SubscriberComponent[MAPT, MAT, MUPT, MUT, MDPT, MDT, MT, CT, KT]) SetConfig(cfg config.ControllerConfig) {
	s.cfg = cfg
	s.dbOperator.setConfig(cfg)
}

func (s *SubscriberComponent[MAPT, MAT, MUPT, MUT, MDPT, MDT, MT, CT, KT]) setSubscribeRecorder(subscribeRecorder bool) {
	s.subscribeRecorder = subscribeRecorder
}

func (s *SubscriberComponent[MAPT, MAT, MUPT, MUT, MDPT, MDT, MT, CT, KT]) Subscribe() {
	if !s.subscribeRecorder {
		return
	}
	pubsub.Subscribe(
		s,
		pubsub.NewSubscriptionSpec(s.subResourceTypeName, pubsub.TopicResourceBatchAddedFull),
		pubsub.NewSubscriptionSpec(s.subResourceTypeName, pubsub.TopicResourceUpdatedFull),
		pubsub.NewSubscriptionSpec(s.subResourceTypeName, pubsub.TopicResourceBatchDeletedFull),
	)
}

// OnResourceBatchAdded implements interface Subscriber in recorder/pubsub/subscriber.go
func (s *SubscriberComponent[MAPT, MAT, MUPT, MUT, MDPT, MDT, MT, CT, KT]) OnResourceBatchAdded(md *message.Metadata, msg interface{}) { // TODO handle org
	m := msg.(MAPT)
	dbItems := m.GetMetadbItems().([]*MT)
	db, err := metadb.GetDB(md.GetORGID())
	if err != nil {
		log.Error("get org dbinfo fail", logger.NewORGPrefix(md.GetORGID()))
	}
	keys, chItems := s.generateKeyTargets(md, dbItems)
	s.dbOperator.batchPage(keys, chItems, s.dbOperator.add, db)
}

// OnResourceBatchUpdated implements interface Subscriber in recorder/pubsub/subscriber.go
func (s *SubscriberComponent[MAPT, MAT, MUPT, MUT, MDPT, MDT, MT, CT, KT]) OnResourceUpdated(md *message.Metadata, msg interface{}) {
	updateMessage := msg.(MUPT)
	dbItem := updateMessage.GetNewMetadbItem().(*MT)
	dbItems := []*MT{dbItem}
	db := md.GetDB()
	// use add to complete addition and update of resource in ch table
	keys, chItems := s.generateKeyTargets(md, dbItems)
	s.dbOperator.batchPage(keys, chItems, s.dbOperator.add, db)
	// delete resource from ch table
	// such as ch_chost_cloud_tag, ch_pod_ns_cloud_tag, ch_pod_k8s_label,
	// ch_pod_k8s_annotation, ch_pod_k8s_env, ch_pod_service_k8s_label, ch_pod_service_k8s_annotation
	s.subscriberDG.onResourceUpdated(md, updateMessage)
}

// OnResourceBatchDeleted implements interface Subscriber in recorder/pubsub/subscriber.go
func (s *SubscriberComponent[MAPT, MAT, MUPT, MUT, MDPT, MDT, MT, CT, KT]) OnResourceBatchDeleted(md *message.Metadata, msg interface{}) {
	m := msg.(MDPT)
	items := m.GetMetadbItems().([]*MT)
	newItems := items
	if hasHooker, ok := s.hookers[hookerDeletePage]; ok {
		if hooker, ok := hasHooker.(deletePageHooker[MT, MDT, MDPT]); ok {
			newItems = hooker.beforeDeletePage(items, m)
		} else {
			log.Errorf("hooker type error", logger.NewORGPrefix(md.GetORGID()))
		}
	}

	db, err := metadb.GetDB(md.GetORGID()) // TODO use md.GetDB() instead
	if err != nil {
		log.Error("get org dbinfo fail", logger.NewORGPrefix(md.GetORGID()))
	}
	keys, chItems := s.generateKeyTargets(md, newItems)
	if len(chItems) == 0 {
		return
	}
	if md.SoftDelete && s.softDelete {
		s.subscriberDG.softDeletedTargetsUpdated(chItems, db)
		log.Infof("soft delete (values: %#v) success", chItems, db.LogPrefixORGID)
	} else {
		s.dbOperator.batchPage(keys, chItems, s.dbOperator.delete, db)
	}
}

// Delete resource by domain
func (s *SubscriberComponent[MAPT, MAT, MUPT, MUT, MDPT, MDT, MT, CT, KT]) OnDomainDeleted(md *message.Metadata) {
	var chModel CT
	db, err := metadb.GetDB(md.GetORGID())
	if err != nil {
		log.Error("get org dbinfo fail", logger.NewORGPrefix(md.GetORGID()))
	}
	if err := db.Where("domain_id = ?", md.GetDomainID()).Delete(&chModel).Error; err != nil {
		log.Error(err, logger.NewORGPrefix(md.GetORGID()))
	}
}

// Delete resource by sub domain
func (s *SubscriberComponent[MAPT, MAT, MUPT, MUT, MDPT, MDT, MT, CT, KT]) OnSubDomainDeleted(md *message.Metadata) {
	var chModel CT
	db, err := metadb.GetDB(md.GetORGID())
	if err != nil {
		log.Error("get org dbinfo fail", logger.NewORGPrefix(md.GetORGID()))
	}
	if err := db.Where("sub_domain_id = ?", md.GetSubDomainID()).Delete(&chModel).Error; err != nil {
		log.Error(err, logger.NewORGPrefix(md.GetORGID()))
	}
}

// Update team_id of resource by sub domain
func (s *SubscriberComponent[MAPT, MAT, MUPT, MUT, MDPT, MDT, MT, CT, KT]) OnSubDomainTeamIDUpdated(md *message.Metadata) {
	var chModel CT
	db, err := metadb.GetDB(md.GetORGID())
	if err != nil {
		log.Error("get org dbinfo fail", logger.NewORGPrefix(md.GetORGID()))
	}
	if err := db.Model(&chModel).Where("sub_domain_id = ?", md.GetSubDomainID()).Update("team_id", md.GetTeamID()).Error; err != nil {
		log.Error(err, db.LogPrefixORGID)
	}
}
