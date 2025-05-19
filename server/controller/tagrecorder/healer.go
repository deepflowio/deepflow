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

package tagrecorder

import (
	// "context"
	// "slices"
	// "sync"
	"fmt"
	"time"

	"github.com/deepflowio/deepflow/server/controller/common"
	metadbModel "github.com/deepflowio/deepflow/server/controller/db/metadb/model"
	recorderCommon "github.com/deepflowio/deepflow/server/controller/recorder/common"
	"github.com/deepflowio/deepflow/server/controller/recorder/constraint"
	"github.com/deepflowio/deepflow/server/controller/recorder/pubsub/message"
)

const (
	keyConditionID     = "id = ?"
	keyConditionGID    = "gid = ?"
	keyConditionPID    = "pid"
	keyConditionDevice = "deviceid = ? AND devicetype = ?"
)

// var (
// 	healerManagerOnce     sync.Once
// 	healerManagerInstance *HealerManager
// )

// func GetHealerManager() *HealerManager {
// 	healerManagerOnce.Do(func() {
// 		healerManagerInstance = &HealerManager{}
// 	})
// 	return healerManagerInstance
// }

// type HealerManager struct {
// 	ctx    context.Context
// 	cancel context.CancelFunc

// 	inUse        bool
// 	mux          sync.Mutex
// 	orgIDToHealer map[int]*ORGHealer
// }

// func (m *HealerManager) Init(ctx context.Context) {
// 	m.ctx, m.cancel = context.WithCancel(ctx)
// 	m.orgIDToHealer = make(map[int]*ORGHealer)
// }

// func (m *HealerManager) Start(ctx context.Context) error {
// 	if m.inUse {
// 		return nil
// 	}
// 	m.inUse = true
// 	m.ctx, m.cancel = context.WithCancel(ctx)

// 	orgIDs, err := metadb.GetORGIDs()
// 	if err != nil {
// 		return fmt.Errorf("failed to get org IDs: %w", err)
// 	}
// 	for _, orgID := range orgIDs {
// 		if _, err := m.lazyCreate(orgID); err != nil {
// 			return fmt.Errorf("failed to create healer for org ID %d: %w", orgID, err)
// 		}
// 	}

// 	m.timedRefresh()
// 	return nil
// }

// func (m *HealerManager) timedRefresh() {
// 	go func() {
// 		ticker := time.NewTicker(1 * time.Minute)
// 		defer ticker.Stop()

// 		LOOP:
// 		for {
// 			select {
// 			case <-m.ctx.Done():
// 				break LOOP
// 			case <-ticker.C:
// 				m.refresh()
// 			}
// 		}
// 	}()
// }

// func (m *HealerManager) refresh() error {
// 	if err := m.checkORGs(); err != nil {
// 		return err
// 	}
// 	for _, healer := range m.orgIDToHealer {
// 		healer.Heal()
// 	}
// 	return nil
// }

// func (m *HealerManager) checkORGs() error {
// 	orgIDs, err := metadb.GetORGIDs()
// 	if err != nil {
// 		return fmt.Errorf("failed to get org IDs: %w", err)
// 	}
// 	m.mux.Lock()
// 	defer m.mux.Unlock()
// 	for orgID := range m.orgIDToHealer {
// 		if !slices.Contains(orgIDs, orgID) {
// 			delete(m.orgIDToHealer, orgID)
// 		}
// 	}
// 	for _, orgID := range orgIDs {
// 		if _, ok := m.orgIDToHealer[orgID]; !ok {
// 			m.orgIDToHealer[orgID] = newORGHealer(orgID)
// 		}
// 	}
// 	return nil
// }

// func (m *HealerManager) GetHealer(md *recorderCommon.MetadataBase) (*ORGHealer, error) {
// 	m.mux.Lock()
// 	defer m.mux.Unlock()
// 	// TODO add domain/subdomain filter
// 	if healer, ok := m.orgIDToHealer[md.GetORGID()]; ok {
// 		return healer, nil
// 	}
// 	healer := &ORGHealer{
// 		orgID: md.GetORGID(),
// 		sourceResourceTypeToHeader: make(map[string]healer),
// 	}
// 	m.orgIDToHealer[md.GetORGID()] = healer
// 	return healer, nil
// }

type Healers struct {
	recorderCommon.MetadataBase

	sourceResourceTypeToData map[string]dataGenerator
	targetResourceTypeToData map[string]dataGenerator

	healers []Healer
}

func NewHealers(md *recorderCommon.MetadataBase) *Healers {
	h := &Healers{
		MetadataBase: *md,
	}
	h.sourceResourceTypeToData = map[string]dataGenerator{
		common.RESOURCE_TYPE_AZ_EN:             newDataGeneratorComponent[metadbModel.AZ](common.RESOURCE_TYPE_AZ_EN, keyConditionID),
		common.RESOURCE_TYPE_VM_EN:             newDataGeneratorComponent[metadbModel.VM](common.RESOURCE_TYPE_VM_EN, keyConditionID),
		common.RESOURCE_TYPE_HOST_EN:           newDataGeneratorComponent[metadbModel.Host](common.RESOURCE_TYPE_HOST_EN, keyConditionID),
		common.RESOURCE_TYPE_VPC_EN:            newDataGeneratorComponent[metadbModel.VPC](common.RESOURCE_TYPE_VPC_EN, keyConditionID),
		common.RESOURCE_TYPE_VROUTER_EN:        newDataGeneratorComponent[metadbModel.VRouter](common.RESOURCE_TYPE_VROUTER_EN, keyConditionID),
		common.RESOURCE_TYPE_NETWORK_EN:        newDataGeneratorComponent[metadbModel.Network](common.RESOURCE_TYPE_NETWORK_EN, keyConditionID),
		common.RESOURCE_TYPE_DHCP_PORT_EN:      newDataGeneratorComponent[metadbModel.DHCPPort](common.RESOURCE_TYPE_DHCP_PORT_EN, keyConditionID),
		common.RESOURCE_TYPE_NAT_GATEWAY_EN:    newDataGeneratorComponent[metadbModel.NATGateway](common.RESOURCE_TYPE_NAT_GATEWAY_EN, keyConditionID),
		common.RESOURCE_TYPE_LB_EN:             newDataGeneratorComponent[metadbModel.LB](common.RESOURCE_TYPE_LB_EN, keyConditionID),
		common.RESOURCE_TYPE_RDS_INSTANCE_EN:   newDataGeneratorComponent[metadbModel.RDSInstance](common.RESOURCE_TYPE_RDS_INSTANCE_EN, keyConditionID),
		common.RESOURCE_TYPE_REDIS_INSTANCE_EN: newDataGeneratorComponent[metadbModel.RedisInstance](common.RESOURCE_TYPE_REDIS_INSTANCE_EN, keyConditionID),
		common.RESOURCE_TYPE_POD_CLUSTER_EN:    newDataGeneratorComponent[metadbModel.PodCluster](common.RESOURCE_TYPE_POD_CLUSTER_EN, keyConditionID),
		common.RESOURCE_TYPE_POD_NODE_EN:       newDataGeneratorComponent[metadbModel.PodNode](common.RESOURCE_TYPE_POD_NODE_EN, keyConditionID),
		common.RESOURCE_TYPE_POD_NAMESPACE_EN:  newDataGeneratorComponent[metadbModel.PodNamespace](common.RESOURCE_TYPE_POD_NAMESPACE_EN, keyConditionID),
		common.RESOURCE_TYPE_POD_SERVICE_EN:    newDataGeneratorComponent[metadbModel.PodService](common.RESOURCE_TYPE_POD_SERVICE_EN, keyConditionID),
		common.RESOURCE_TYPE_POD_INGRESS_EN:    newDataGeneratorComponent[metadbModel.PodIngress](common.RESOURCE_TYPE_POD_INGRESS_EN, keyConditionID),
		common.RESOURCE_TYPE_POD_GROUP_EN:      newDataGeneratorComponent[metadbModel.PodGroup](common.RESOURCE_TYPE_POD_GROUP_EN, keyConditionID),
		common.RESOURCE_TYPE_POD_EN:            newDataGeneratorComponent[metadbModel.Pod](common.RESOURCE_TYPE_POD_EN, keyConditionID),
		common.RESOURCE_TYPE_PROCESS_EN:        newDataGeneratorComponent[metadbModel.Process](common.RESOURCE_TYPE_PROCESS_EN, keyConditionGID),
		common.RESOURCE_TYPE_CUSTOM_SERVICE_EN: newDataGeneratorComponent[metadbModel.CustomService](common.RESOURCE_TYPE_CUSTOM_SERVICE_EN, keyConditionID),
	}
	h.targetResourceTypeToData = map[string]dataGenerator{
		RESOURCE_TYPE_CH_DEVICE:                      newDataGeneratorComponent[metadbModel.ChDevice](RESOURCE_TYPE_CH_DEVICE, keyConditionDevice),
		RESOURCE_TYPE_CH_AZ:                          newDataGeneratorComponent[metadbModel.ChAZ](RESOURCE_TYPE_CH_AZ, keyConditionID),
		RESOURCE_TYPE_CH_CHOST:                       newDataGeneratorComponent[metadbModel.ChChost](RESOURCE_TYPE_CH_CHOST, keyConditionID),
		RESOURCE_TYPE_CH_VPC:                         newDataGeneratorComponent[metadbModel.ChVPC](RESOURCE_TYPE_CH_VPC, keyConditionID),
		RESOURCE_TYPE_CH_NETWORK:                     newDataGeneratorComponent[metadbModel.ChNetwork](RESOURCE_TYPE_CH_NETWORK, keyConditionID),
		RESOURCE_TYPE_CH_POD_CLUSTER:                 newDataGeneratorComponent[metadbModel.ChPodCluster](RESOURCE_TYPE_CH_POD_CLUSTER, keyConditionID),
		RESOURCE_TYPE_CH_POD_NAMESPACE:               newDataGeneratorComponent[metadbModel.ChPodNamespace](RESOURCE_TYPE_CH_POD_NAMESPACE, keyConditionID),
		RESOURCE_TYPE_CH_POD_NODE:                    newDataGeneratorComponent[metadbModel.ChPodNode](RESOURCE_TYPE_CH_POD_NODE, keyConditionID),
		RESOURCE_TYPE_CH_POD_SERVICE:                 newDataGeneratorComponent[metadbModel.ChPodService](RESOURCE_TYPE_CH_POD_SERVICE, keyConditionID),
		RESOURCE_TYPE_CH_POD_INGRESS:                 newDataGeneratorComponent[metadbModel.ChPodIngress](RESOURCE_TYPE_CH_POD_INGRESS, keyConditionID),
		RESOURCE_TYPE_CH_POD_GROUP:                   newDataGeneratorComponent[metadbModel.ChPodGroup](RESOURCE_TYPE_CH_POD_GROUP, keyConditionID),
		RESOURCE_TYPE_CH_POD:                         newDataGeneratorComponent[metadbModel.ChPod](RESOURCE_TYPE_CH_POD, keyConditionID),
		RESOURCE_TYPE_CH_GPROCESS:                    newDataGeneratorComponent[metadbModel.ChGProcess](RESOURCE_TYPE_CH_GPROCESS, keyConditionGID),
		RESOURCE_TYPE_CH_CHOST_CLOUD_TAG:             newDataGeneratorComponent[metadbModel.ChChostCloudTag](RESOURCE_TYPE_CH_CHOST_CLOUD_TAG, keyConditionID),
		RESOURCE_TYPE_CH_CHOST_CLOUD_TAGS:            newDataGeneratorComponent[metadbModel.ChChostCloudTags](RESOURCE_TYPE_CH_CHOST_CLOUD_TAGS, keyConditionID),
		RESOURCE_TYPE_CH_POD_NS_CLOUD_TAG:            newDataGeneratorComponent[metadbModel.ChPodNSCloudTag](RESOURCE_TYPE_CH_POD_NS_CLOUD_TAG, keyConditionID),
		RESOURCE_TYPE_CH_POD_NS_CLOUD_TAGS:           newDataGeneratorComponent[metadbModel.ChPodNSCloudTags](RESOURCE_TYPE_CH_POD_NS_CLOUD_TAGS, keyConditionID),
		RESOURCE_TYPE_CH_POD_SERVICE_K8S_LABEL:       newDataGeneratorComponent[metadbModel.ChPodServiceK8sLabel](RESOURCE_TYPE_CH_POD_SERVICE_K8S_LABEL, keyConditionID),
		RESOURCE_TYPE_CH_POD_SERVICE_K8S_LABELS:      newDataGeneratorComponent[metadbModel.ChPodServiceK8sLabels](RESOURCE_TYPE_CH_POD_SERVICE_K8S_LABELS, keyConditionID),
		RESOURCE_TYPE_CH_POD_SERVICE_K8S_ANNOTATION:  newDataGeneratorComponent[metadbModel.ChPodServiceK8sAnnotation](RESOURCE_TYPE_CH_POD_SERVICE_K8S_ANNOTATION, keyConditionID),
		RESOURCE_TYPE_CH_POD_SERVICE_K8S_ANNOTATIONS: newDataGeneratorComponent[metadbModel.ChPodServiceK8sAnnotations](RESOURCE_TYPE_CH_POD_SERVICE_K8S_ANNOTATIONS, keyConditionID),
		RESOURCE_TYPE_CH_POD_K8S_ENV:                 newDataGeneratorComponent[metadbModel.ChPodK8sEnv](RESOURCE_TYPE_CH_POD_K8S_ENV, keyConditionID),
		RESOURCE_TYPE_CH_POD_K8S_ENVS:                newDataGeneratorComponent[metadbModel.ChPodK8sEnvs](RESOURCE_TYPE_CH_POD_K8S_ENVS, keyConditionID),
		RESOURCE_TYPE_CH_POD_K8S_LABEL:               newDataGeneratorComponent[metadbModel.ChPodK8sLabel](RESOURCE_TYPE_CH_POD_K8S_LABEL, keyConditionID),
		RESOURCE_TYPE_CH_POD_K8S_LABELS:              newDataGeneratorComponent[metadbModel.ChPodK8sLabels](RESOURCE_TYPE_CH_POD_K8S_LABELS, keyConditionID),
		RESOURCE_TYPE_CH_OS_APP_TAG:                  newDataGeneratorComponent[metadbModel.ChOSAppTag](RESOURCE_TYPE_CH_OS_APP_TAG, keyConditionID),
		RESOURCE_TYPE_CH_OS_APP_TAGS:                 newDataGeneratorComponent[metadbModel.ChOSAppTags](RESOURCE_TYPE_CH_OS_APP_TAGS, keyConditionID),
	}
	// h.healers = []Healer{
	// 	NewHealer
	return h
}

type Healer interface {
	Heal()
}

type healerComponent[MT constraint.MySQLModel, CT SubscriberMetaDBChModel] struct {
	recorderCommon.MetadataBase
	msgMetadata *message.Metadata

	sourceDataGen dataGenerator
	targetDataGen dataGenerator
}

func NewHealer[MT constraint.MySQLModel, CT SubscriberMetaDBChModel](md *recorderCommon.MetadataBase, sourceDataGen, targetDataGen dataGenerator) Healer {
	return &healerComponent[MT, CT]{
		MetadataBase: *md,
		msgMetadata: message.NewMetadata(
			md.GetORGID(),
			message.MetadataTeamID(md.GetTeamID()),
			message.MetadataDomainID(md.Domain.ID),
			message.MetadataSubDomainID(md.SubDomain.ID),
			message.MetadataSoftDelete(false), // no soft delete in healer
			message.MetadataDB(md.GetDB()),
		),

		sourceDataGen: sourceDataGen,
		targetDataGen: targetDataGen,
	}
}

func (h *healerComponent[MT, CT]) Heal() {
	log.Infof("tagrecorder healer: %s start", h.targetDataGen.getResourceType(), h.LogPrefixes)
	err := h.sourceDataGen.generate()
	if err != nil {
		log.Errorf("failed to generate source data: %s", err.Error())
		return
	}
	err = h.targetDataGen.generate()
	if err != nil {
		log.Errorf("failed to generate target data: %s", err.Error())
		return
	}

	sourceIDsToAdd := make([]int, 0)
	targetIDsToForceDelete := make([]int, 0)
	for sourceID, updatedAt := range h.sourceDataGen.getIDToUpdatedAt() {
		if targetUpdatedAt, ok := h.targetDataGen.getIDToUpdatedAt()[sourceID]; ok {
			if updatedAt.After(targetUpdatedAt) {
				targetIDsToForceDelete = append(targetIDsToForceDelete, sourceID)
				sourceIDsToAdd = append(sourceIDsToAdd, sourceID)
			}
		} else {
			sourceIDsToAdd = append(sourceIDsToAdd, sourceID)
		}
	}
	for targetID, _ := range h.targetDataGen.getIDToUpdatedAt() {
		if _, ok := h.sourceDataGen.getIDToUpdatedAt()[targetID]; !ok {
			targetIDsToForceDelete = append(targetIDsToForceDelete, targetID)
		}
	}

	err = h.forceDelete(targetIDsToForceDelete)
	if err != nil {
		log.Errorf("failed to force delete target data: %s", err.Error())
		return
	}
	err = h.publishAdd(sourceIDsToAdd)
	if err != nil {
		log.Errorf("failed to publish add source data: %s", err.Error())
		return
	}
}

func (h *healerComponent[MT, CT]) publishAdd(sourceIDs []int) error {
	if len(sourceIDs) == 0 {
		return nil
	}
	log.Infof("tagrecorder healer: %s publish add: %v", h.targetDataGen.getResourceType(), sourceIDs, h.LogPrefixes)
	var dbItems []*CT
	if err := h.DB.Where(fmt.Sprintf("%s IN ?", h.sourceDataGen.getKeyConditionQuery()), sourceIDs).Find(&dbItems).Error; err != nil {
		log.Errorf("failed to find %s: %v", h.targetDataGen.getResourceType(), err, h.LogPrefixes)
		return err
	}
	targetSubscriber := GetSubscriberManager().GetSubscriber(h.targetDataGen.getResourceType())
	if targetSubscriber == nil {
		log.Errorf("failed to get target subscriber: %s", h.targetDataGen.getResourceType(), h.LogPrefixes)
		return fmt.Errorf("failed to get target subscriber: %s", h.targetDataGen.getResourceType())
	}
	targetSubscriber.OnResourceBatchAdded(h.msgMetadata, dbItems)
	return nil
}

func (h *healerComponent[MT, CT]) forceDelete(sourceIDs []int) error {
	if len(sourceIDs) == 0 {
		return nil
	}
	log.Infof("tagrecorder healer: %s force delete data, ids: %v", h.targetDataGen.getResourceType(), sourceIDs, h.LogPrefixes)
	var dbItems []*CT
	if err := h.DB.Where(fmt.Sprintf("%s IN ?", h.targetDataGen.getKeyConditionQuery()), sourceIDs).Delete(&dbItems).Error; err != nil {
		log.Errorf("failed to delete %s: %v", h.targetDataGen.getResourceType(), err, h.LogPrefixes)
		return err
	}
	return nil
}

type dataGenerator interface {
	generate() error
	getResourceType() string
	getKeyConditionQuery() string
	getIDToUpdatedAt() map[int]time.Time
}

type healerChDevice struct {
	metadbModel.ChDevice
}

type dataGeneratorModel interface {
	metadbModel.AZ | metadbModel.Host | metadbModel.VM | metadbModel.VPC | metadbModel.Network | metadbModel.VRouter |
		metadbModel.DHCPPort | metadbModel.NATGateway | metadbModel.LB | metadbModel.RDSInstance | metadbModel.RedisInstance |
		metadbModel.PodCluster | metadbModel.PodNode | metadbModel.PodNamespace | metadbModel.PodIngress | metadbModel.PodService |
		metadbModel.PodGroup | metadbModel.PodReplicaSet | metadbModel.Pod | metadbModel.Process | metadbModel.CustomService |

		metadbModel.ChDevice | metadbModel.ChAZ | metadbModel.ChChost | metadbModel.ChVPC | metadbModel.ChNetwork | metadbModel.ChLBListener |
		metadbModel.ChPodCluster | metadbModel.ChPodNode | metadbModel.ChPodNamespace | metadbModel.ChPodIngress | metadbModel.ChPodService |
		metadbModel.ChPodGroup | metadbModel.ChPod | metadbModel.ChGProcess |
		metadbModel.ChPodServiceK8sLabels | metadbModel.ChPodServiceK8sLabel | metadbModel.ChPodServiceK8sAnnotation | metadbModel.ChPodServiceK8sAnnotations |
		metadbModel.ChPodNSCloudTags | metadbModel.ChChostCloudTags | metadbModel.ChPodNSCloudTag | metadbModel.ChChostCloudTag |
		metadbModel.ChPodK8sAnnotation | metadbModel.ChPodK8sAnnotations | metadbModel.ChPodK8sEnv | metadbModel.ChPodK8sEnvs | metadbModel.ChPodK8sLabel |
		metadbModel.ChPodK8sLabels | metadbModel.ChOSAppTag | metadbModel.ChOSAppTags

	GetID() int
	GetUpdatedAt() time.Time
}

func newDataGeneratorComponent[T dataGeneratorModel](resourceType, realIDField string) dataGenerator {
	return &dataGeneratorComponent[T]{
		resourceType:  resourceType,
		realIDField:   realIDField,
		idToUpdatedAt: make(map[int]time.Time),
	}
}

type dataGeneratorComponent[T dataGeneratorModel] struct {
	md *recorderCommon.MetadataBase

	resourceType string
	realIDField  string
	// realIDGetter sourceIDGetter[T]

	idToUpdatedAt map[int]time.Time
}

func (s *dataGeneratorComponent[T]) getResourceType() string {
	return s.resourceType
}

func (s *dataGeneratorComponent[T]) getKeyConditionQuery() string {
	return s.realIDField
}

func (s *dataGeneratorComponent[T]) getIDToUpdatedAt() map[int]time.Time {
	return s.idToUpdatedAt
}

func (s *dataGeneratorComponent[T]) generate() error {
	var data []*T
	query := s.md.DB.Select(s.realIDField, "updated_at").Where("domain = ?", s.md.Domain.Lcuuid)
	if s.md.SubDomain != nil {
		query = query.Where("sub_domain = ?", s.md.SubDomain.Lcuuid)
	}
	if err := query.Find(&data).Error; err != nil {
		log.Errorf("failed to find %s: %v", s.resourceType, err, s.md.LogPrefixes)
	}
	for _, item := range data {
		s.idToUpdatedAt[(*item).GetID()] = (*item).GetUpdatedAt()
	}
	return nil
}

// func (s *dataGeneratorComponent[T]) getRealID(item *T) int {
// 	if s.realIDGetter == nil {
// 		return (*item).GetID()
// 	}
// 	return s.realIDGetter.getRealID(item)
// }

// type sourceIDGetter[T constraint.MySQLModel] interface {
// 	getRealID(*T) int
// }
