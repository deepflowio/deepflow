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

package healer

import (
	"fmt"
	"strings"
	"time"

	"gorm.io/gorm"

	"github.com/deepflowio/deepflow/server/controller/common"
	mysqlmodel "github.com/deepflowio/deepflow/server/controller/db/mysql/model"
	recorderCommon "github.com/deepflowio/deepflow/server/controller/recorder/common"
	"github.com/deepflowio/deepflow/server/controller/tagrecorder"
)

type dataGenerator interface {
	generate() error
	getResourceType() string
	getRealIDField() string
	getIDToUpdatedAt() map[int]time.Time
	getChDeviceTypes() []int

	setRealIDField(realIDField string) dataGenerator
	setHasDuplicateID(bool) dataGenerator
	setTableName(tableName string) dataGenerator
	setGroupSortOrder(order string) dataGenerator
	setInSubDomain(bool) dataGenerator
	setChDeviceTypes(...int) dataGenerator
	setAdditionalSelectField(string) dataGenerator
	setUnscoped(bool) dataGenerator
}

func newDataGenerator(md *recorderCommon.MetadataBase, resourceType string) dataGenerator {
	var dg dataGenerator
	realID := "id"
	inSubDomain := true
	hasDuplicateID := false
	tableName := ""
	useLatestUpdatedAt := "ASC"
	switch resourceType {
	case common.RESOURCE_TYPE_AZ_EN:
		dg = newDataGeneratorComponent[mysqlmodel.AZ](md, resourceType)
		inSubDomain = false

	case common.RESOURCE_TYPE_VM_EN:
		dg = newDataGeneratorComponent[mysqlmodel.VM](md, resourceType)
		inSubDomain = false
	case common.RESOURCE_TYPE_HOST_EN:
		dg = newDataGeneratorComponent[mysqlmodel.Host](md, resourceType)
		inSubDomain = false

	case common.RESOURCE_TYPE_VPC_EN:
		dg = newDataGeneratorComponent[mysqlmodel.VPC](md, resourceType)
		inSubDomain = false
	case common.RESOURCE_TYPE_NETWORK_EN:
		dg = newDataGeneratorComponent[mysqlmodel.Network](md, resourceType)
		inSubDomain = false
	case common.RESOURCE_TYPE_VROUTER_EN:
		dg = newDataGeneratorComponent[mysqlmodel.VRouter](md, resourceType)
		inSubDomain = false
	case common.RESOURCE_TYPE_DHCP_PORT_EN:
		dg = newDataGeneratorComponent[mysqlmodel.DHCPPort](md, resourceType)
		inSubDomain = false

	case common.RESOURCE_TYPE_NAT_GATEWAY_EN:
		dg = newDataGeneratorComponent[mysqlmodel.NATGateway](md, resourceType)
		inSubDomain = false
	case common.RESOURCE_TYPE_LB_EN:
		dg = newDataGeneratorComponent[mysqlmodel.LB](md, resourceType)
		inSubDomain = false

	case common.RESOURCE_TYPE_RDS_INSTANCE_EN:
		dg = newDataGeneratorComponent[mysqlmodel.RDSInstance](md, resourceType)
		inSubDomain = false
	case common.RESOURCE_TYPE_REDIS_INSTANCE_EN:
		dg = newDataGeneratorComponent[mysqlmodel.RedisInstance](md, resourceType)
		inSubDomain = false

	case common.RESOURCE_TYPE_POD_CLUSTER_EN:
		dg = newDataGeneratorComponent[mysqlmodel.PodCluster](md, resourceType)
	case common.RESOURCE_TYPE_POD_NODE_EN:
		dg = newDataGeneratorComponent[mysqlmodel.PodNode](md, resourceType)
	case common.RESOURCE_TYPE_POD_NAMESPACE_EN:
		dg = newDataGeneratorComponent[mysqlmodel.PodNamespace](md, resourceType)
	case common.RESOURCE_TYPE_POD_INGRESS_EN:
		dg = newDataGeneratorComponent[mysqlmodel.PodIngress](md, resourceType)
	case common.RESOURCE_TYPE_POD_SERVICE_EN:
		dg = newDataGeneratorComponent[mysqlmodel.PodService](md, resourceType)
	case common.RESOURCE_TYPE_POD_GROUP_EN:
		dg = newDataGeneratorComponent[mysqlmodel.PodGroup](md, resourceType)
	case common.RESOURCE_TYPE_POD_EN:
		dg = newDataGeneratorComponent[mysqlmodel.Pod](md, resourceType)

	case common.RESOURCE_TYPE_PROCESS_EN:
		dg = newDataGeneratorComponent[healerProcess](md, resourceType)
		realID = "gid" // process uses gid as the real id field
		hasDuplicateID = true
		tableName = "process"
		useLatestUpdatedAt = "DESC"

	case common.RESOURCE_TYPE_CUSTOM_SERVICE_EN:
		dg = newDataGeneratorComponent[mysqlmodel.CustomService](md, resourceType)
		inSubDomain = false

	case tagrecorder.RESOURCE_TYPE_CH_DEVICE:
		dg = newDataGeneratorComponent[healerChDevice](md, resourceType)
		realID = "deviceid" // ch_device uses deviceid as the real id field
	case tagrecorder.RESOURCE_TYPE_CH_AZ:
		dg = newDataGeneratorComponent[mysqlmodel.ChAZ](md, resourceType)
		inSubDomain = false

	case tagrecorder.RESOURCE_TYPE_CH_CHOST:
		dg = newDataGeneratorComponent[mysqlmodel.ChChost](md, resourceType)
		inSubDomain = false

	case tagrecorder.RESOURCE_TYPE_CH_VPC:
		dg = newDataGeneratorComponent[mysqlmodel.ChVPC](md, resourceType)
		inSubDomain = false
	case tagrecorder.RESOURCE_TYPE_CH_NETWORK:
		dg = newDataGeneratorComponent[mysqlmodel.ChNetwork](md, resourceType)

	case tagrecorder.RESOURCE_TYPE_CH_POD_CLUSTER:
		dg = newDataGeneratorComponent[mysqlmodel.ChPodCluster](md, resourceType)
	case tagrecorder.RESOURCE_TYPE_CH_POD_NODE:
		dg = newDataGeneratorComponent[mysqlmodel.ChPodNode](md, resourceType)
	case tagrecorder.RESOURCE_TYPE_CH_POD_NAMESPACE:
		dg = newDataGeneratorComponent[mysqlmodel.ChPodNamespace](md, resourceType)
	case tagrecorder.RESOURCE_TYPE_CH_POD_INGRESS:
		dg = newDataGeneratorComponent[mysqlmodel.ChPodIngress](md, resourceType)
	case tagrecorder.RESOURCE_TYPE_CH_POD_SERVICE:
		dg = newDataGeneratorComponent[mysqlmodel.ChPodService](md, resourceType)
	case tagrecorder.RESOURCE_TYPE_CH_POD_GROUP:
		dg = newDataGeneratorComponent[mysqlmodel.ChPodGroup](md, resourceType)
	case tagrecorder.RESOURCE_TYPE_CH_POD:
		dg = newDataGeneratorComponent[mysqlmodel.ChPod](md, resourceType)

	case tagrecorder.RESOURCE_TYPE_CH_GPROCESS:
		dg = newDataGeneratorComponent[mysqlmodel.ChGProcess](md, resourceType)

	case tagrecorder.RESOURCE_TYPE_CH_CHOST_CLOUD_TAG:
		dg = newDataGeneratorComponent[mysqlmodel.ChChostCloudTag](md, resourceType)
		inSubDomain = false
		hasDuplicateID = true
		tableName = "ch_chost_cloud_tag"
	case tagrecorder.RESOURCE_TYPE_CH_CHOST_CLOUD_TAGS:
		dg = newDataGeneratorComponent[mysqlmodel.ChChostCloudTags](md, resourceType)
		inSubDomain = false
	case tagrecorder.RESOURCE_TYPE_CH_POD_NS_CLOUD_TAG:
		dg = newDataGeneratorComponent[mysqlmodel.ChPodNSCloudTag](md, resourceType)
		hasDuplicateID = true
		tableName = "ch_pod_ns_cloud_tag"
	case tagrecorder.RESOURCE_TYPE_CH_POD_NS_CLOUD_TAGS:
		dg = newDataGeneratorComponent[mysqlmodel.ChPodNSCloudTags](md, resourceType)
	case tagrecorder.RESOURCE_TYPE_CH_POD_SERVICE_K8S_LABEL:
		dg = newDataGeneratorComponent[mysqlmodel.ChPodServiceK8sLabel](md, resourceType)
		hasDuplicateID = true
		tableName = "ch_pod_service_k8s_label"
	case tagrecorder.RESOURCE_TYPE_CH_POD_SERVICE_K8S_LABELS:
		dg = newDataGeneratorComponent[mysqlmodel.ChPodServiceK8sLabels](md, resourceType)
	case tagrecorder.RESOURCE_TYPE_CH_POD_SERVICE_K8S_ANNOTATION:
		dg = newDataGeneratorComponent[mysqlmodel.ChPodServiceK8sAnnotation](md, resourceType)
		hasDuplicateID = true
		tableName = "ch_pod_service_k8s_annotation"
	case tagrecorder.RESOURCE_TYPE_CH_POD_SERVICE_K8S_ANNOTATIONS:
		dg = newDataGeneratorComponent[mysqlmodel.ChPodServiceK8sAnnotations](md, resourceType)
	case tagrecorder.RESOURCE_TYPE_CH_POD_K8S_ENV:
		dg = newDataGeneratorComponent[mysqlmodel.ChPodK8sEnv](md, resourceType)
		hasDuplicateID = true
		tableName = "ch_pod_k8s_env"
	case tagrecorder.RESOURCE_TYPE_CH_POD_K8S_ENVS:
		dg = newDataGeneratorComponent[mysqlmodel.ChPodK8sEnvs](md, resourceType)
	case tagrecorder.RESOURCE_TYPE_CH_POD_K8S_LABEL:
		dg = newDataGeneratorComponent[mysqlmodel.ChPodK8sLabel](md, resourceType)
		hasDuplicateID = true
		tableName = "ch_pod_k8s_label"
	case tagrecorder.RESOURCE_TYPE_CH_POD_K8S_LABELS:
		dg = newDataGeneratorComponent[mysqlmodel.ChPodK8sLabels](md, resourceType)
	case tagrecorder.RESOURCE_TYPE_CH_POD_K8S_ANNOTATION:
		dg = newDataGeneratorComponent[mysqlmodel.ChPodK8sAnnotation](md, resourceType)
		hasDuplicateID = true
		tableName = "ch_pod_k8s_annotation"
	case tagrecorder.RESOURCE_TYPE_CH_POD_K8S_ANNOTATIONS:
		dg = newDataGeneratorComponent[mysqlmodel.ChPodK8sAnnotations](md, resourceType)
	default:
		log.Errorf("unknown resource type: %s", resourceType, md.LogPrefixes)
		return nil
	}
	return dg.setRealIDField(realID).
		setInSubDomain(inSubDomain).
		setHasDuplicateID(hasDuplicateID).
		setTableName(tableName).
		setGroupSortOrder(useLatestUpdatedAt)
}

func newDataGeneratorComponent[GT dataGeneratorModel](md *recorderCommon.MetadataBase, resourceType string) dataGenerator {
	dataGeneratorComponent := &dataGeneratorComponent[GT]{
		md:            md,
		resourceType:  resourceType,
		realIDField:   "id",
		inSubDomain:   true, // default is true, used for query
		idToUpdatedAt: make(map[int]time.Time),
		unscoped:      true, // default is true, used for query
	}
	return dataGeneratorComponent
}

type dataGeneratorComponent[GT dataGeneratorModel] struct {
	md *recorderCommon.MetadataBase

	resourceType  string
	inSubDomain   bool // whether the resource may be in sub domain, used for query
	idToUpdatedAt map[int]time.Time
	// the field used to query the resource, usually the id field, but can be other fields like gid, deviceid.
	realIDField string
	// whether the resource has duplicate id, if true, we need to use the latest updated_at to determine which one to use. Default is false.
	hasDuplicateID bool
	// set when hasDuplicateID is true.
	// table name of the resource, used for query.
	tableName string
	// set when hasDuplicateID is true.
	// whether to use the latest updated_at, if true, we will use the latest updated_at to determine which one to use.
	groupSortOrder string // "ASC" or "DESC", default is "ASC"

	// TODO refactor
	chDeviceTypes         []int  // additional query conditions, only used for ch_device query
	additionalSelectField string // additional fields to select, used for label, env... query
	unscoped              bool   // whether to use Unscoped() in the query, default is true
}

func (s *dataGeneratorComponent[GT]) getResourceType() string {
	return s.resourceType
}

func (s *dataGeneratorComponent[GT]) getRealIDField() string {
	return s.realIDField
}

func (s *dataGeneratorComponent[GT]) getIDToUpdatedAt() map[int]time.Time {
	return s.idToUpdatedAt
}

func (s *dataGeneratorComponent[GT]) getChDeviceTypes() []int {
	return s.chDeviceTypes
}

func (s *dataGeneratorComponent[GT]) setHasDuplicateID(has bool) dataGenerator {
	s.hasDuplicateID = has
	return s
}

func (s *dataGeneratorComponent[GT]) setRealIDField(realIDField string) dataGenerator {
	s.realIDField = realIDField
	return s
}

func (s *dataGeneratorComponent[GT]) setTableName(tableName string) dataGenerator {
	s.tableName = tableName
	return s
}

func (s *dataGeneratorComponent[GT]) setGroupSortOrder(groupSortOrder string) dataGenerator {
	s.groupSortOrder = groupSortOrder
	return s
}

func (s *dataGeneratorComponent[GT]) setInSubDomain(inSubDomain bool) dataGenerator {
	s.inSubDomain = inSubDomain
	return s
}

func (s *dataGeneratorComponent[GT]) setChDeviceTypes(deviceTypes ...int) dataGenerator {
	s.chDeviceTypes = deviceTypes
	return s
}

func (s *dataGeneratorComponent[GT]) setAdditionalSelectField(fields string) dataGenerator {
	s.additionalSelectField = fields
	return s
}

func (s *dataGeneratorComponent[GT]) setUnscoped(unscoped bool) dataGenerator {
	s.unscoped = unscoped
	return s
}

func (s *dataGeneratorComponent[GT]) generate() error {
	log.Infof("gen %s data started", s.resourceType, s.md.LogPrefixes)
	// reset idToUpdatedAt map
	s.idToUpdatedAt = make(map[int]time.Time)

	var data []*GT
	item := new(GT)
	query := s.md.DB.Model(&item)

	selectFieldsStr := s.realIDField + ", updated_at"
	if len(s.additionalSelectField) > 0 {
		selectFieldsStr += ", " + s.additionalSelectField
	}
	query = query.Select(selectFieldsStr)

	if len(s.chDeviceTypes) != 0 {
		query.Where("devicetype IN (?)", s.chDeviceTypes)
	}

	appendDomainCond := func(q *gorm.DB) *gorm.DB {
		if strings.HasPrefix(s.resourceType, "ch_") {
			q = q.Where("domain_id = ?", s.md.Domain.ID)
			if s.inSubDomain {
				q = q.Where("sub_domain_id = ?", s.md.SubDomain.ID)
			}
		} else {
			q = q.Where("domain = ?", s.md.Domain.Lcuuid)
			if s.inSubDomain {
				q = q.Where("sub_domain = ?", s.md.SubDomain.Lcuuid)
			}
		}
		return q
	}
	appendUnscoped := func(q *gorm.DB) *gorm.DB {
		if !s.unscoped {
			q = q.Where("deleted_at IS NULL")
		}
		return q
	}

	// if hasDuplicateID is true, we need to use ROW_NUMBER() to get the latest updated_at for each id
	if s.hasDuplicateID {
		selectFieldsStr += ", " + fmt.Sprintf("ROW_NUMBER() OVER (PARTITION BY %s ORDER BY updated_at %s) as rn", s.realIDField, s.groupSortOrder)
		subQuery := s.md.DB.Table(s.tableName).Select(selectFieldsStr)
		subQuery = appendUnscoped(appendDomainCond(subQuery))
		query = query.Table("(?) as t", subQuery).Where("t.rn = 1")
	} else {
		query = appendUnscoped(appendDomainCond(query))
	}

	if err := query.Debug().Unscoped().Find(&data).Error; err != nil {
		log.Errorf("failed to get %s: %v", s.resourceType, err, s.md.LogPrefixes)
		return err
	}

	if s.additionalSelectField == "" {
		for _, item := range data {
			s.idToUpdatedAt[(*item).GetID()] = (*item).GetUpdatedAt()
		}
	} else {
		s.idToUpdatedAt = idToUpdatedAt(s.resourceType, s.additionalSelectField, data)
	}
	log.Infof("gen %s data finished, count: %d", s.resourceType, len(s.idToUpdatedAt), s.md.LogPrefixes)
	return nil
}

func idToUpdatedAt(resourceType, checkField string, data interface{}) map[int]time.Time {
	idToUpdatedAt := make(map[int]time.Time)
	switch resourceType {
	case common.RESOURCE_TYPE_VM_EN:
		for _, item := range data.([]*mysqlmodel.VM) {
			if len(item.CloudTags) == 0 {
				continue
			}
			idToUpdatedAt[item.GetID()] = item.GetUpdatedAt()
		}
	case common.RESOURCE_TYPE_POD_NAMESPACE_EN:
		for _, item := range data.([]*mysqlmodel.PodNamespace) {
			if len(item.CloudTags) == 0 {
				continue
			}
			idToUpdatedAt[item.GetID()] = item.GetUpdatedAt()
		}
	case common.RESOURCE_TYPE_POD_SERVICE_EN:
		for _, item := range data.([]*mysqlmodel.PodService) {
			if checkField == "label" && item.Label == "" {
				continue
			}
			if checkField == "annotation" && item.Annotation == "" {
				continue
			}
			idToUpdatedAt[item.GetID()] = item.GetUpdatedAt()
		}
	case common.RESOURCE_TYPE_POD_EN:
		for _, item := range data.([]*mysqlmodel.Pod) {
			if checkField == "env" && item.ENV == "" {
				continue
			}
			if checkField == "label" && item.Label == "" {
				continue
			}
			if checkField == "annotation" && item.Annotation == "" {
				continue
			}
			idToUpdatedAt[item.GetID()] = item.GetUpdatedAt()
		}
	}
	return idToUpdatedAt
}
