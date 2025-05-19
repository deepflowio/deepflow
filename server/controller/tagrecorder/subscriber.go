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
	"time"

	"github.com/deepflowio/deepflow/server/controller/config"
	"github.com/deepflowio/deepflow/server/controller/db/metadb"
	metadbModel "github.com/deepflowio/deepflow/server/controller/db/metadb/model"
	"github.com/deepflowio/deepflow/server/controller/recorder/constraint"
	"github.com/deepflowio/deepflow/server/controller/recorder/pubsub"
	"github.com/deepflowio/deepflow/server/controller/recorder/pubsub/message"
	msgconstraint "github.com/deepflowio/deepflow/server/controller/recorder/pubsub/message/constraint"
	"github.com/deepflowio/deepflow/server/libs/logger"
)

const hookerDeletePage = 0

type deletePageHooker[MT constraint.MySQLModel, MDT msgconstraint.Delete, MDPT msgconstraint.DeletePtr[MDT]] interface {
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
		NewChOSAppTag(),
		NewChOSAppTags(),
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
	OnDomainDeleted(md *message.Metadata)
	OnSubDomainDeleted(md *message.Metadata)
	OnSubDomainTeamIDUpdated(md *message.Metadata)
	updateChTagLastUpdatedAt(md *message.Metadata, db *metadb.DB)
}

type SubscriberDataGenerator[
	MAPT msgconstraint.AddPtr[MAT],
	MAT msgconstraint.Add,
	MUPT msgconstraint.FieldsUpdatePtr[MUT],
	MUT msgconstraint.FieldsUpdate,
	MDPT msgconstraint.DeletePtr[MDT],
	MDT msgconstraint.Delete,
	MT constraint.MySQLModel,
	CT MySQLChModel,
	KT ChModelKey,
] interface {
	sourceToTarget(md *message.Metadata, resourceMySQLItem *MT) (chKeys []KT, chItems []CT) // 将源表数据转换为CH表数据
	onResourceUpdated(int, MUPT, *metadb.DB)
	softDeletedTargetsUpdated([]CT, *metadb.DB)
}

type SubscriberComponent[
	MAPT msgconstraint.AddPtr[MAT],
	MAT msgconstraint.Add,
	MUPT msgconstraint.FieldsUpdatePtr[MUT],
	MUT msgconstraint.FieldsUpdate,
	MDPT msgconstraint.DeletePtr[MDT],
	MDT msgconstraint.Delete,
	MT constraint.MySQLModel,
	CT MySQLChModel,
	KT ChModelKey,
] struct {
	cfg config.ControllerConfig

	subResourceTypeName string // 订阅表资源类型，即源表资源类型
	resourceTypeName    string // CH表资源类型
	dbOperator          operator[CT, KT]
	subscriberDG        SubscriberDataGenerator[MAPT, MAT, MUPT, MUT, MDPT, MDT, MT, CT, KT]
	hookers             map[int]interface{}
}

func newSubscriberComponent[
	MAPT msgconstraint.AddPtr[MAT],
	MAT msgconstraint.Add,
	MUPT msgconstraint.FieldsUpdatePtr[MUT],
	MUT msgconstraint.FieldsUpdate,
	MDPT msgconstraint.DeletePtr[MDT],
	MDT msgconstraint.Delete,
	MT constraint.MySQLModel,
	CT MySQLChModel,
	KT ChModelKey,
](
	sourceResourceTypeName, resourceTypeName string,
) SubscriberComponent[MAPT, MAT, MUPT, MUT, MDPT, MDT, MT, CT, KT] {
	s := SubscriberComponent[MAPT, MAT, MUPT, MUT, MDPT, MDT, MT, CT, KT]{
		subResourceTypeName: sourceResourceTypeName,
		resourceTypeName:    resourceTypeName,
		hookers:             make(map[int]interface{}),
	}
	s.initDBOperator()
	return s
}

func (s *SubscriberComponent[MAPT, MAT, MUPT, MUT, MDPT, MDT, MT, CT, KT]) GetSubResourceType() string {
	return s.subResourceTypeName
}

func (s *SubscriberComponent[MAPT, MAT, MUPT, MUT, MDPT, MDT, MT, CT, KT]) initDBOperator() {
	s.dbOperator = newOperator[CT, KT](s.resourceTypeName)
}

func (s *SubscriberComponent[MAPT, MAT, MUPT, MUT, MDPT, MDT, MT, CT, KT]) generateKeyTargets(md *message.Metadata, sources []*MT) ([]KT, []CT) {
	keys := []KT{}
	targets := []CT{}
	for _, item := range sources {
		ks, ts := s.subscriberDG.sourceToTarget(md, item)
		keys = append(keys, ks...)
		targets = append(targets, ts...)
	}
	return keys, targets
}

func (s *SubscriberComponent[MAPT, MAT, MUPT, MUT, MDPT, MDT, MT, CT, KT]) SetConfig(cfg config.ControllerConfig) {
	s.cfg = cfg
	s.dbOperator.setConfig(cfg)
}

func (s *SubscriberComponent[MAPT, MAT, MUPT, MUT, MDPT, MDT, MT, CT, KT]) Subscribe() {
	pubsub.Subscribe(s.subResourceTypeName, pubsub.TopicResourceBatchAddedMessage, s)
	pubsub.Subscribe(s.subResourceTypeName, pubsub.TopicResourceUpdatedFields, s)
	pubsub.Subscribe(s.subResourceTypeName, pubsub.TopicResourceBatchDeletedMessage, s)
}

// OnResourceBatchAdded implements interface Subscriber in recorder/pubsub/subscriber.go
func (s *SubscriberComponent[MAPT, MAT, MUPT, MUT, MDPT, MDT, MT, CT, KT]) OnResourceBatchAdded(md *message.Metadata, msg interface{}) { // TODO handle org
	m := msg.(MAPT)
	dbItems := m.GetMySQLItems().([]*MT)
	db, err := metadb.GetDB(md.ORGID)
	if err != nil {
		log.Error("get org dbinfo fail", logger.NewORGPrefix(md.ORGID))
	}
	keys, chItems := s.generateKeyTargets(md, dbItems)
	s.dbOperator.batchPage(keys, chItems, s.dbOperator.add, db)
	s.updateChTagLastUpdatedAt(md, db)
}

// OnResourceBatchUpdated implements interface Subscriber in recorder/pubsub/subscriber.go
func (s *SubscriberComponent[MAPT, MAT, MUPT, MUT, MDPT, MDT, MT, CT, KT]) OnResourceUpdated(md *message.Metadata, msg interface{}) {
	updateFields := msg.(MUPT)
	db, err := metadb.GetDB(md.ORGID)
	if err != nil {
		log.Error("get org dbinfo fail", logger.NewORGPrefix(md.ORGID))
	}
	s.subscriberDG.onResourceUpdated(updateFields.GetID(), updateFields, db)
	s.updateChTagLastUpdatedAt(md, db)
}

// OnResourceBatchDeleted implements interface Subscriber in recorder/pubsub/subscriber.go
func (s *SubscriberComponent[MAPT, MAT, MUPT, MUT, MDPT, MDT, MT, CT, KT]) OnResourceBatchDeleted(md *message.Metadata, msg interface{}) {
	m := msg.(MDPT)
	items := m.GetMySQLItems().([]*MT)
	newItems := items
	if hasHooker, ok := s.hookers[hookerDeletePage]; ok {
		if hooker, ok := hasHooker.(deletePageHooker[MT, MDT, MDPT]); ok {
			newItems = hooker.beforeDeletePage(items, m)
		} else {
			log.Errorf("hooker type error", logger.NewORGPrefix(md.ORGID))
		}
	}

	db, err := metadb.GetDB(md.ORGID)
	if err != nil {
		log.Error("get org dbinfo fail", logger.NewORGPrefix(md.ORGID))
	}
	keys, chItems := s.generateKeyTargets(md, newItems)
	if len(chItems) == 0 {
		return
	}
	if md.SoftDelete {
		s.subscriberDG.softDeletedTargetsUpdated(chItems, db)
		log.Infof("soft delete (values: %#v) success", chItems, db.LogPrefixORGID)
	} else {
		s.dbOperator.batchPage(keys, chItems, s.dbOperator.delete, db)
	}
	s.updateChTagLastUpdatedAt(md, db)
}

// Delete resource by domain
func (s *SubscriberComponent[MAPT, MAT, MUPT, MUT, MDPT, MDT, MT, CT, KT]) OnDomainDeleted(md *message.Metadata) {
	var chModel CT
	db, err := metadb.GetDB(md.ORGID)
	if err != nil {
		log.Error("get org dbinfo fail", logger.NewORGPrefix(md.ORGID))
	}
	if err := db.Where("domain_id = ?", md.DomainID).Delete(&chModel).Error; err != nil {
		log.Error(err, logger.NewORGPrefix(md.ORGID))
	}
	s.updateChTagLastUpdatedAt(md, db)
}

// Delete resource by sub domain
func (s *SubscriberComponent[MAPT, MAT, MUPT, MUT, MDPT, MDT, MT, CT, KT]) OnSubDomainDeleted(md *message.Metadata) {
	var chModel CT
	db, err := metadb.GetDB(md.ORGID)
	if err != nil {
		log.Error("get org dbinfo fail", logger.NewORGPrefix(md.ORGID))
	}
	if err := db.Where("sub_domain_id = ?", md.SubDomainID).Delete(&chModel).Error; err != nil {
		log.Error(err, logger.NewORGPrefix(md.ORGID))
	}
	s.updateChTagLastUpdatedAt(md, db)
}

// Update team_id of resource by sub domain
func (s *SubscriberComponent[MAPT, MAT, MUPT, MUT, MDPT, MDT, MT, CT, KT]) OnSubDomainTeamIDUpdated(md *message.Metadata) {
	var chModel CT
	db, err := metadb.GetDB(md.ORGID)
	if err != nil {
		log.Error("get org dbinfo fail", logger.NewORGPrefix(md.ORGID))
	}
	if err := db.Model(&chModel).Where("sub_domain_id = ?", md.SubDomainID).Update("team_id", md.TeamID).Error; err != nil {
		log.Error(err, db.LogPrefixORGID)
	}
}

// updateChTagLastUpdatedAt updates the updated_at field of self resource type to trigger clickhouse synchronization
func (s *SubscriberComponent[MAPT, MAT, MUPT, MUT, MDPT, MDT, MT, CT, KT]) updateChTagLastUpdatedAt(md *message.Metadata, db *metadb.DB) {
	err := db.Model(&metadbModel.ChTagLastUpdatedAt{}).Where("table_name = ?", s.resourceTypeName).
		Updates(map[string]interface{}{"updated_at": time.Now()}).Error
	if err != nil {
		log.Errorf("update %s updated_at error: %v", s.resourceTypeName, err, db.LogPrefixORGID)
	}
}
