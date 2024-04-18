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
	"sync"
	"time"

	"github.com/deepflowio/deepflow/server/controller/config"
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	"github.com/deepflowio/deepflow/server/controller/recorder/constraint"
	"github.com/deepflowio/deepflow/server/controller/recorder/pubsub"
	"github.com/deepflowio/deepflow/server/controller/recorder/pubsub/message"
	msgconstraint "github.com/deepflowio/deepflow/server/controller/recorder/pubsub/message/constraint"
)

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
	for _, s := range m.subscribers {
		if s.GetSubResourceType() == subResourceType {
			ss = append(ss, s)
		}
	}
	return ss
}

func (c *SubscriberManager) getSubscribers() []Subscriber {
	subscribers := []Subscriber{
		NewChAZ(c.domainLcuuidToIconID, c.resourceTypeToIconID),
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
		NewChProcessDevice(c.resourceTypeToIconID),
		NewChOSAppTag(),
		NewChOSAppTags(),
		NewChPodK8sLabel(),
		NewChPodK8sLabels(),
		NewChPodK8sAnnotation(),
		NewChPodK8sAnnotations(),
		NewChPodK8sEnv(),
		NewChPodK8sEnvs(),
		NewChChostCloudTag(),
		NewChChostCloudTags(),
		NewChNetwork(c.resourceTypeToIconID),
		NewChChost(),
		NewChGProcess(c.resourceTypeToIconID),
		NewChVPC(c.resourceTypeToIconID),
		NewChPodCluster(c.resourceTypeToIconID),
		NewChPod(c.resourceTypeToIconID),
		NewChPodGroup(c.resourceTypeToIconID),
		NewChPodIngress(),
		NewChPodNode(c.resourceTypeToIconID),
		NewChPodNamespace(c.resourceTypeToIconID),
		NewChPodService(),

		NewChPodServiceK8sAnnotation(),
		NewChPodServiceK8sAnnotations(),
		NewChPodNSCloudTag(),
		NewChPodNSCloudTags(),
		NewChPodServiceK8sLabel(),
		NewChPodServiceK8sLabels(),
	}
	return subscribers
}

func (c *SubscriberManager) HealthCheck() {
	go func() {
		log.Info("tagrecorder health check data run")
		t := time.Now()
		for _, subscriber := range c.subscribers {
			if err := subscriber.Check(); err != nil {
				log.Error(err)
			}
		}
		log.Infof("tagrecorder health check data end, time since: %v", time.Since(t))
	}()
}

type Subscriber interface {
	Subscribe()
	SetConfig(config.ControllerConfig)
	Check() error
	GetSubResourceType() string
	pubsub.ResourceBatchAddedSubscriber
	pubsub.ResourceUpdatedSubscriber
	pubsub.ResourceBatchDeletedSubscriber
}

type SubscriberDataGenerator[MUPT msgconstraint.FieldsUpdatePtr[MUT], MUT msgconstraint.FieldsUpdate, MT constraint.MySQLModel, CT MySQLChModel, KT ChModelKey] interface {
	sourceToTarget(md *message.Metadata, resourceMySQLItem *MT) (chKeys []KT, chItems []CT) // 将源表数据转换为CH表数据
	onResourceUpdated(int, MUPT, *mysql.DB)
	softDeletedTargetsUpdated([]CT, *mysql.DB)
}

type SubscriberComponent[MUPT msgconstraint.FieldsUpdatePtr[MUT], MUT msgconstraint.FieldsUpdate, MT constraint.MySQLModel, CT MySQLChModel, KT ChModelKey] struct {
	cfg config.ControllerConfig

	subResourceTypeName string // 订阅表资源类型，即源表资源类型
	resourceTypeName    string // CH表资源类型
	dbOperator          operator[CT, KT]
	subscriberDG        SubscriberDataGenerator[MUPT, MUT, MT, CT, KT]
}

func newSubscriberComponent[MUPT msgconstraint.FieldsUpdatePtr[MUT], MUT msgconstraint.FieldsUpdate, MT constraint.MySQLModel, CT MySQLChModel, KT ChModelKey](
	sourceResourceTypeName, resourceTypeName string,
) SubscriberComponent[MUPT, MUT, MT, CT, KT] {
	s := SubscriberComponent[MUPT, MUT, MT, CT, KT]{
		subResourceTypeName: sourceResourceTypeName,
		resourceTypeName:    resourceTypeName,
	}
	s.initDBOperator()
	return s
}

func (s *SubscriberComponent[MUPT, MUT, MT, CT, KT]) GetSubResourceType() string {
	return s.subResourceTypeName
}

func (s *SubscriberComponent[MUPT, MUT, MT, CT, KT]) initDBOperator() {
	s.dbOperator = newOperator[CT, KT](s.resourceTypeName)
}

func (s *SubscriberComponent[MUPT, MUT, MT, CT, KT]) generateKeyTargets(md *message.Metadata, sources []*MT) ([]KT, []CT) {
	keys := []KT{}
	targets := []CT{}
	for _, item := range sources {
		ks, ts := s.subscriberDG.sourceToTarget(md, item)
		keys = append(keys, ks...)
		targets = append(targets, ts...)
	}
	return keys, targets
}

func (s *SubscriberComponent[MUPT, MUT, MT, CT, KT]) SetConfig(cfg config.ControllerConfig) {
	s.cfg = cfg
	s.dbOperator.setConfig(cfg)
}

func (s *SubscriberComponent[MUPT, MUT, MT, CT, KT]) SetIconInfo(domainLcuuidToIconID map[string]int, resourceTypeToIconID map[IconKey]int) {

}

func (s *SubscriberComponent[MUPT, MUT, MT, CT, KT]) Subscribe() {
	pubsub.Subscribe(s.subResourceTypeName, pubsub.TopicResourceBatchAddedMySQL, s)
	pubsub.Subscribe(s.subResourceTypeName, pubsub.TopicResourceUpdatedFields, s)
	pubsub.Subscribe(s.subResourceTypeName, pubsub.TopicResourceBatchDeletedMySQL, s)
}

func (s *SubscriberComponent[MUPT, MUT, MT, CT, KT]) Check() error {
	return check(s)
}

// OnResourceBatchAdded implements interface Subscriber in recorder/pubsub/subscriber.go
func (s *SubscriberComponent[MUPT, MUT, MT, CT, KT]) OnResourceBatchAdded(md *message.Metadata, msg interface{}) { // TODO handle org
	log.Infof("metadata: %#v", md)
	items := msg.([]*MT)
	db, err := mysql.GetDB(md.ORGID)
	if err != nil {
		log.Errorf("get org dbinfo fail : %d", md.ORGID)
	}
	keys, chItems := s.generateKeyTargets(md, items)
	s.dbOperator.batchPage(keys, chItems, s.dbOperator.add, db)
}

// OnResourceBatchUpdated implements interface Subscriber in recorder/pubsub/subscriber.go
func (s *SubscriberComponent[MUPT, MUT, MT, CT, KT]) OnResourceUpdated(md *message.Metadata, msg interface{}) {
	log.Infof("metadata: %#v", md)
	updateFields := msg.(MUPT)
	db, err := mysql.GetDB(md.ORGID)
	if err != nil {
		log.Errorf("get org dbinfo fail : %d", md.ORGID)
	}
	s.subscriberDG.onResourceUpdated(updateFields.GetID(), updateFields, db)
}

// OnResourceBatchDeleted implements interface Subscriber in recorder/pubsub/subscriber.go
func (s *SubscriberComponent[MUPT, MUT, MT, CT, KT]) OnResourceBatchDeleted(md *message.Metadata, msg interface{}, softDelete bool) {
	log.Infof("metadata: %#v", md)
	items := msg.([]*MT)
	db, err := mysql.GetDB(md.ORGID)
	if err != nil {
		log.Errorf("get org dbinfo fail : %d", md.ORGID)
	}
	keys, chItems := s.generateKeyTargets(md, items)
	if softDelete {
		s.subscriberDG.softDeletedTargetsUpdated(chItems, db)
	} else {
		s.dbOperator.batchPage(keys, chItems, s.dbOperator.delete, db)
	}
}
