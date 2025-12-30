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
	"github.com/deepflowio/deepflow/server/controller/common/metadata"
	metadbModel "github.com/deepflowio/deepflow/server/controller/db/metadb/model"
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
	setFilterSubDomain(bool) dataGenerator
	setChDeviceTypes(...int) dataGenerator
	setAdditionalSelectField(...string) dataGenerator
	setUnscoped(bool) dataGenerator
}

func newDataGenerator(md metadata.Platform, resourceType string) dataGenerator {
	var dg dataGenerator
	realID := "id"
	filterSubDomain := true
	hasDuplicateID := false
	tableName := ""
	useLatestUpdatedAt := "ASC"
	switch resourceType {
	case common.RESOURCE_TYPE_AZ_EN:
		dg = newDataGeneratorComponent[metadbModel.AZ](md, resourceType)
		filterSubDomain = false

	case common.RESOURCE_TYPE_VM_EN:
		dg = newDataGeneratorComponent[metadbModel.VM](md, resourceType)
		filterSubDomain = false
	case common.RESOURCE_TYPE_HOST_EN:
		dg = newDataGeneratorComponent[metadbModel.Host](md, resourceType)
		filterSubDomain = false

	case common.RESOURCE_TYPE_VPC_EN:
		dg = newDataGeneratorComponent[metadbModel.VPC](md, resourceType)
		filterSubDomain = false
	case common.RESOURCE_TYPE_NETWORK_EN:
		dg = newDataGeneratorComponent[metadbModel.Network](md, resourceType)
	case common.RESOURCE_TYPE_VROUTER_EN:
		dg = newDataGeneratorComponent[metadbModel.VRouter](md, resourceType)
		filterSubDomain = false
	case common.RESOURCE_TYPE_DHCP_PORT_EN:
		dg = newDataGeneratorComponent[metadbModel.DHCPPort](md, resourceType)
		filterSubDomain = false

	case common.RESOURCE_TYPE_NAT_GATEWAY_EN:
		dg = newDataGeneratorComponent[metadbModel.NATGateway](md, resourceType)
		filterSubDomain = false
	case common.RESOURCE_TYPE_LB_EN:
		dg = newDataGeneratorComponent[metadbModel.LB](md, resourceType)
		filterSubDomain = false

	case common.RESOURCE_TYPE_RDS_INSTANCE_EN:
		dg = newDataGeneratorComponent[metadbModel.RDSInstance](md, resourceType)
		filterSubDomain = false
	case common.RESOURCE_TYPE_REDIS_INSTANCE_EN:
		dg = newDataGeneratorComponent[metadbModel.RedisInstance](md, resourceType)
		filterSubDomain = false

	case common.RESOURCE_TYPE_POD_CLUSTER_EN:
		dg = newDataGeneratorComponent[metadbModel.PodCluster](md, resourceType)
	case common.RESOURCE_TYPE_POD_NODE_EN:
		dg = newDataGeneratorComponent[metadbModel.PodNode](md, resourceType)
	case common.RESOURCE_TYPE_POD_NAMESPACE_EN:
		dg = newDataGeneratorComponent[metadbModel.PodNamespace](md, resourceType)
	case common.RESOURCE_TYPE_POD_INGRESS_EN:
		dg = newDataGeneratorComponent[metadbModel.PodIngress](md, resourceType)
	case common.RESOURCE_TYPE_POD_SERVICE_EN:
		dg = newDataGeneratorComponent[metadbModel.PodService](md, resourceType)
	case common.RESOURCE_TYPE_POD_GROUP_EN:
		dg = newDataGeneratorComponent[metadbModel.PodGroup](md, resourceType)
	case common.RESOURCE_TYPE_POD_EN:
		dg = newDataGeneratorComponent[metadbModel.Pod](md, resourceType)

	case common.RESOURCE_TYPE_PROCESS_EN:
		dg = newDataGeneratorComponent[healerProcess](md, resourceType)
		realID = "gid" // process uses gid as the real id field
		hasDuplicateID = true
		tableName = "process"
		useLatestUpdatedAt = "DESC"

	case common.RESOURCE_TYPE_CUSTOM_SERVICE_EN:
		dg = newDataGeneratorComponent[metadbModel.CustomService](md, resourceType)
		filterSubDomain = false

	case tagrecorder.RESOURCE_TYPE_CH_DEVICE:
		dg = newDataGeneratorComponent[healerChDevice](md, resourceType)
		realID = "deviceid" // ch_device uses deviceid as the real id field
		filterSubDomain = false
	case tagrecorder.RESOURCE_TYPE_CH_AZ:
		dg = newDataGeneratorComponent[metadbModel.ChAZ](md, resourceType)
		filterSubDomain = false

	case tagrecorder.RESOURCE_TYPE_CH_CHOST:
		dg = newDataGeneratorComponent[metadbModel.ChChost](md, resourceType)
		filterSubDomain = false

	case tagrecorder.RESOURCE_TYPE_CH_BIZ_SERVICE:
		dg = newDataGeneratorComponent[metadbModel.ChBizService](md, resourceType)
		filterSubDomain = false

	case tagrecorder.RESOURCE_TYPE_CH_VPC:
		dg = newDataGeneratorComponent[metadbModel.ChVPC](md, resourceType)
		filterSubDomain = false
	case tagrecorder.RESOURCE_TYPE_CH_NETWORK:
		dg = newDataGeneratorComponent[metadbModel.ChNetwork](md, resourceType)

	case tagrecorder.RESOURCE_TYPE_CH_POD_CLUSTER:
		dg = newDataGeneratorComponent[metadbModel.ChPodCluster](md, resourceType)
	case tagrecorder.RESOURCE_TYPE_CH_POD_NODE:
		dg = newDataGeneratorComponent[metadbModel.ChPodNode](md, resourceType)
	case tagrecorder.RESOURCE_TYPE_CH_POD_NAMESPACE:
		dg = newDataGeneratorComponent[metadbModel.ChPodNamespace](md, resourceType)
	case tagrecorder.RESOURCE_TYPE_CH_POD_INGRESS:
		dg = newDataGeneratorComponent[metadbModel.ChPodIngress](md, resourceType)
	case tagrecorder.RESOURCE_TYPE_CH_POD_SERVICE:
		dg = newDataGeneratorComponent[metadbModel.ChPodService](md, resourceType)
	case tagrecorder.RESOURCE_TYPE_CH_POD_GROUP:
		dg = newDataGeneratorComponent[metadbModel.ChPodGroup](md, resourceType)
	case tagrecorder.RESOURCE_TYPE_CH_POD:
		dg = newDataGeneratorComponent[metadbModel.ChPod](md, resourceType)

	case tagrecorder.RESOURCE_TYPE_CH_GPROCESS:
		dg = newDataGeneratorComponent[metadbModel.ChGProcess](md, resourceType)

	case tagrecorder.RESOURCE_TYPE_CH_CHOST_CLOUD_TAG:
		dg = newDataGeneratorComponent[metadbModel.ChChostCloudTag](md, resourceType)
		filterSubDomain = false
		hasDuplicateID = true
		tableName = "ch_chost_cloud_tag"
	case tagrecorder.RESOURCE_TYPE_CH_CHOST_CLOUD_TAGS:
		dg = newDataGeneratorComponent[metadbModel.ChChostCloudTags](md, resourceType)
		filterSubDomain = false
	case tagrecorder.RESOURCE_TYPE_CH_POD_NS_CLOUD_TAG:
		dg = newDataGeneratorComponent[metadbModel.ChPodNSCloudTag](md, resourceType)
		hasDuplicateID = true
		tableName = "ch_pod_ns_cloud_tag"
	case tagrecorder.RESOURCE_TYPE_CH_POD_NS_CLOUD_TAGS:
		dg = newDataGeneratorComponent[metadbModel.ChPodNSCloudTags](md, resourceType)
	case tagrecorder.RESOURCE_TYPE_CH_POD_SERVICE_K8S_LABEL:
		dg = newDataGeneratorComponent[metadbModel.ChPodServiceK8sLabel](md, resourceType)
		hasDuplicateID = true
		tableName = "ch_pod_service_k8s_label"
	case tagrecorder.RESOURCE_TYPE_CH_POD_SERVICE_K8S_LABELS:
		dg = newDataGeneratorComponent[metadbModel.ChPodServiceK8sLabels](md, resourceType)
	case tagrecorder.RESOURCE_TYPE_CH_POD_SERVICE_K8S_ANNOTATION:
		dg = newDataGeneratorComponent[metadbModel.ChPodServiceK8sAnnotation](md, resourceType)
		hasDuplicateID = true
		tableName = "ch_pod_service_k8s_annotation"
	case tagrecorder.RESOURCE_TYPE_CH_POD_SERVICE_K8S_ANNOTATIONS:
		dg = newDataGeneratorComponent[metadbModel.ChPodServiceK8sAnnotations](md, resourceType)
	case tagrecorder.RESOURCE_TYPE_CH_POD_K8S_ENV:
		dg = newDataGeneratorComponent[metadbModel.ChPodK8sEnv](md, resourceType)
		hasDuplicateID = true
		tableName = "ch_pod_k8s_env"
	case tagrecorder.RESOURCE_TYPE_CH_POD_K8S_ENVS:
		dg = newDataGeneratorComponent[metadbModel.ChPodK8sEnvs](md, resourceType)
	case tagrecorder.RESOURCE_TYPE_CH_POD_K8S_LABEL:
		dg = newDataGeneratorComponent[metadbModel.ChPodK8sLabel](md, resourceType)
		hasDuplicateID = true
		tableName = "ch_pod_k8s_label"
	case tagrecorder.RESOURCE_TYPE_CH_POD_K8S_LABELS:
		dg = newDataGeneratorComponent[metadbModel.ChPodK8sLabels](md, resourceType)
	case tagrecorder.RESOURCE_TYPE_CH_POD_K8S_ANNOTATION:
		dg = newDataGeneratorComponent[metadbModel.ChPodK8sAnnotation](md, resourceType)
		hasDuplicateID = true
		tableName = "ch_pod_k8s_annotation"
	case tagrecorder.RESOURCE_TYPE_CH_POD_K8S_ANNOTATIONS:
		dg = newDataGeneratorComponent[metadbModel.ChPodK8sAnnotations](md, resourceType)
	default:
		log.Errorf("unknown resource type: %s", resourceType, md.LogPrefixes)
		return nil
	}
	return dg.setRealIDField(realID).
		setFilterSubDomain(filterSubDomain).
		setHasDuplicateID(hasDuplicateID).
		setTableName(tableName).
		setGroupSortOrder(useLatestUpdatedAt)
}

func newDataGeneratorComponent[GT dataGeneratorModel](md metadata.Platform, resourceType string) dataGenerator {
	dataGeneratorComponent := &dataGeneratorComponent[GT]{
		md:              md,
		resourceType:    resourceType,
		realIDField:     "id",
		filterSubDomain: true, // default is true, used for query
		idToUpdatedAt:   make(map[int]time.Time),
		unscoped:        true, // default is true, used for query
	}
	return dataGeneratorComponent
}

type dataGeneratorComponent[GT dataGeneratorModel] struct {
	md metadata.Platform

	resourceType  string
	idToUpdatedAt map[int]time.Time

	// The following fields are used in query conditions
	// filterSubDomain indicates whether to add a sub_domain filter condition. The assignment logic is:
	// For source resources, if they may be sub_domain resources, set to true;
	// For ch resources, also set based on whether the source resource may be a sub_domain.
	filterSubDomain bool
	// realIDField specifies the resource key value, default is id, but can be other fields like gid, deviceid.
	realIDField string
	// Whether the resource has duplicate id, if true (for example, the gid field in the process table),
	// We need to use the latest updated_at to determine which one to use. Default is false.
	hasDuplicateID bool
	// Set when hasDuplicateID is true.
	// Table name of the resource, used for query.
	tableName string
	// Set when hasDuplicateID is true.
	// Whether to use the latest updated_at, if true, we will use the latest updated_at to determine which one to use.
	groupSortOrder string // "ASC" or "DESC", default is "ASC"

	// TODO refactor
	chDeviceTypes          []int    // additional query conditions, only used for ch_device query
	additionalSelectFields []string // additional fields to select, used for label, env... query
	unscoped               bool     // whether to use Unscoped() in the query, default is true
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

func (s *dataGeneratorComponent[GT]) setFilterSubDomain(filterSubDomain bool) dataGenerator {
	s.filterSubDomain = filterSubDomain
	return s
}

func (s *dataGeneratorComponent[GT]) setChDeviceTypes(deviceTypes ...int) dataGenerator {
	s.chDeviceTypes = deviceTypes
	return s
}

func (s *dataGeneratorComponent[GT]) setAdditionalSelectField(fields ...string) dataGenerator {
	s.additionalSelectFields = append(s.additionalSelectFields, fields...)
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

	// selectFieldsStr is used to select the fields in the query,
	// it contains the updated_at field, andthe realIDField which may not be id field in source table but is used as id in ch tables.
	selectFieldsStr := s.realIDField + ", updated_at"
	if len(s.additionalSelectFields) > 0 {
		selectFieldsStr += ", " + strings.Join(s.additionalSelectFields, ", ")
	}
	query = query.Select(selectFieldsStr)

	if len(s.chDeviceTypes) != 0 {
		query.Where("devicetype IN (?)", s.chDeviceTypes)
	}

	appendDomainCond := func(q *gorm.DB) *gorm.DB {
		if strings.HasPrefix(s.resourceType, "ch_") {
			q = q.Where("domain_id = ?", s.md.GetDomainID())
			if s.filterSubDomain {
				q = q.Where("sub_domain_id = ?", s.md.GetSubDomainID())
			}
		} else {
			q = q.Where(map[string]interface{}{"domain": s.md.GetDomainLcuuid()})
			if s.filterSubDomain {
				subDomainLcuuid := s.md.GetSubDomainLcuuid()
				if subDomainLcuuid != "" {
					q = q.Where("sub_domain = ?", subDomainLcuuid)
				} else {
					q = q.Where("(sub_domain = '' or sub_domain is null)")
				}
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

	if len(s.additionalSelectFields) == 0 {
		for _, item := range data {
			s.idToUpdatedAt[(*item).GetID()] = (*item).GetUpdatedAt()
		}
	} else {
		s.idToUpdatedAt = idToUpdatedAt(s.resourceType, s.additionalSelectFields, data)
	}
	log.Infof("gen %s data finished, count: %d", s.resourceType, len(s.idToUpdatedAt), s.md.LogPrefixes)
	return nil
}

func idToUpdatedAt(resourceType string, checkFields []string, data interface{}) map[int]time.Time {
	idToUpdatedAt := make(map[int]time.Time)
	switch resourceType {
	case common.RESOURCE_TYPE_VM_EN:
		for _, item := range data.([]*metadbModel.VM) {
			if len(item.LearnedCloudTags) == 0 && len(item.CustomCloudTags) == 0 {
				continue
			}
			idToUpdatedAt[item.GetID()] = item.GetUpdatedAt()
		}
	case common.RESOURCE_TYPE_POD_NAMESPACE_EN:
		for _, item := range data.([]*metadbModel.PodNamespace) {
			if len(item.LearnedCloudTags) == 0 && len(item.CustomCloudTags) == 0 {
				continue
			}
			idToUpdatedAt[item.GetID()] = item.GetUpdatedAt()
		}

	// 仅有 cloud.tag 需要支持多个字段检查，其他情况只会赋值一个字段，使用 checkFields[0] 即可
	case common.RESOURCE_TYPE_POD_SERVICE_EN:
		for _, item := range data.([]*metadbModel.PodService) {
			if checkFields[0] == "label" && item.Label == "" {
				continue
			}
			if checkFields[0] == "annotation" && item.Annotation == "" {
				continue
			}
			idToUpdatedAt[item.GetID()] = item.GetUpdatedAt()
		}
	case common.RESOURCE_TYPE_POD_EN:
		for _, item := range data.([]*metadbModel.Pod) {
			if checkFields[0] == "env" && item.ENV == "" {
				continue
			}
			if checkFields[0] == "label" && item.Label == "" {
				continue
			}
			if checkFields[0] == "annotation" && item.Annotation == "" {
				continue
			}
			idToUpdatedAt[item.GetID()] = item.GetUpdatedAt()
		}
	}
	return idToUpdatedAt
}
