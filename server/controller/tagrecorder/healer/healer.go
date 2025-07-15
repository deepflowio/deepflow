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
	"time"

	"github.com/deepflowio/deepflow/server/controller/common"
	mysqlmodel "github.com/deepflowio/deepflow/server/controller/db/mysql/model"
	recorderCommon "github.com/deepflowio/deepflow/server/controller/recorder/common"
	"github.com/deepflowio/deepflow/server/controller/recorder/constraint"
	"github.com/deepflowio/deepflow/server/controller/recorder/pubsub/message"
	msgConstraint "github.com/deepflowio/deepflow/server/controller/recorder/pubsub/message/constraint"
	"github.com/deepflowio/deepflow/server/controller/tagrecorder"
	"github.com/deepflowio/deepflow/server/libs/logger"
)

var log = logger.MustGetLogger("tagrecorder.healer")

func NewHealers(md *recorderCommon.MetadataBase) *Healers {
	h := &Healers{
		MetadataBase:             *md,
		sourceResourceTypeToData: make(map[string]dataGenerator),
		targetResourceTypeToData: make(map[string]dataGenerator),
	}

	msgMetadata := message.NewMetadata(
		md.GetORGID(),
		message.MetadataTeamID(md.GetTeamID()),
		message.MetadataDomainID(md.Domain.ID),
		message.MetadataSubDomainID(md.SubDomain.ID),
		message.MetadataSoftDelete(false), // no soft delete in healer
		message.MetadataDB(md.GetDB()),
	)
	h.healers = []Healer{
		newHealer[mysqlmodel.Host, mysqlmodel.ChDevice, *message.HostAdd](
			msgMetadata,
			newDataGenerator(md, common.RESOURCE_TYPE_HOST_EN),
			newDataGenerator(md, tagrecorder.RESOURCE_TYPE_CH_DEVICE).setChDeviceTypes(common.VIF_DEVICE_TYPE_HOST)),
		newHealer[mysqlmodel.VM, mysqlmodel.ChDevice, *message.VMAdd](
			msgMetadata,
			newDataGenerator(md, common.RESOURCE_TYPE_VM_EN),
			newDataGenerator(md, tagrecorder.RESOURCE_TYPE_CH_DEVICE).setChDeviceTypes(common.VIF_DEVICE_TYPE_VM)),
		newHealer[mysqlmodel.VRouter, mysqlmodel.ChDevice, *message.VRouterAdd](
			msgMetadata,
			newDataGenerator(md, common.RESOURCE_TYPE_VROUTER_EN),
			newDataGenerator(md, tagrecorder.RESOURCE_TYPE_CH_DEVICE).setChDeviceTypes(common.VIF_DEVICE_TYPE_VROUTER)),
		newHealer[mysqlmodel.DHCPPort, mysqlmodel.ChDevice, *message.DHCPPortAdd](
			msgMetadata,
			newDataGenerator(md, common.RESOURCE_TYPE_DHCP_PORT_EN),
			newDataGenerator(md, tagrecorder.RESOURCE_TYPE_CH_DEVICE).setChDeviceTypes(common.VIF_DEVICE_TYPE_DHCP_PORT)),
		newHealer[mysqlmodel.NATGateway, mysqlmodel.ChDevice, *message.NATGatewayAdd](
			msgMetadata,
			newDataGenerator(md, common.RESOURCE_TYPE_NAT_GATEWAY_EN),
			newDataGenerator(md, tagrecorder.RESOURCE_TYPE_CH_DEVICE).setChDeviceTypes(common.VIF_DEVICE_TYPE_NAT_GATEWAY)),
		newHealer[mysqlmodel.LB, mysqlmodel.ChDevice, *message.LBAdd](
			msgMetadata,
			newDataGenerator(md, common.RESOURCE_TYPE_LB_EN),
			newDataGenerator(md, tagrecorder.RESOURCE_TYPE_CH_DEVICE).setChDeviceTypes(common.VIF_DEVICE_TYPE_LB)),
		newHealer[mysqlmodel.RDSInstance, mysqlmodel.ChDevice, *message.RDSInstanceAdd](
			msgMetadata,
			newDataGenerator(md, common.RESOURCE_TYPE_RDS_INSTANCE_EN),
			newDataGenerator(md, tagrecorder.RESOURCE_TYPE_CH_DEVICE).setChDeviceTypes(common.VIF_DEVICE_TYPE_RDS_INSTANCE)),
		newHealer[mysqlmodel.RedisInstance, mysqlmodel.ChDevice, *message.RedisInstanceAdd](
			msgMetadata,
			newDataGenerator(md, common.RESOURCE_TYPE_REDIS_INSTANCE_EN),
			newDataGenerator(md, tagrecorder.RESOURCE_TYPE_CH_DEVICE).setChDeviceTypes(common.VIF_DEVICE_TYPE_REDIS_INSTANCE)),
		newHealer[mysqlmodel.PodNode, mysqlmodel.ChDevice, *message.PodNodeAdd](
			msgMetadata,
			newDataGenerator(md, common.RESOURCE_TYPE_POD_NODE_EN),
			newDataGenerator(md, tagrecorder.RESOURCE_TYPE_CH_DEVICE).setChDeviceTypes(common.VIF_DEVICE_TYPE_POD_NODE)),
		newHealer[mysqlmodel.PodService, mysqlmodel.ChDevice, *message.PodServiceAdd](
			msgMetadata,
			newDataGenerator(md, common.RESOURCE_TYPE_POD_SERVICE_EN),
			newDataGenerator(md, tagrecorder.RESOURCE_TYPE_CH_DEVICE).setChDeviceTypes(common.VIF_DEVICE_TYPE_POD_SERVICE)),
		newHealer[mysqlmodel.Pod, mysqlmodel.ChDevice, *message.PodAdd](
			msgMetadata,
			newDataGenerator(md, common.RESOURCE_TYPE_POD_EN),
			newDataGenerator(md, tagrecorder.RESOURCE_TYPE_CH_DEVICE).setChDeviceTypes(common.VIF_DEVICE_TYPE_POD)),
		newHealer[mysqlmodel.PodCluster, mysqlmodel.ChDevice, *message.PodClusterAdd](
			msgMetadata,
			newDataGenerator(md, common.RESOURCE_TYPE_POD_CLUSTER_EN),
			newDataGenerator(md, tagrecorder.RESOURCE_TYPE_CH_DEVICE).setChDeviceTypes(common.VIF_DEVICE_TYPE_POD_CLUSTER)),
		newHealer[mysqlmodel.PodGroup, mysqlmodel.ChDevice, *message.PodGroupAdd](
			msgMetadata,
			newDataGenerator(md, common.RESOURCE_TYPE_POD_GROUP_EN),
			newDataGenerator(md, tagrecorder.RESOURCE_TYPE_CH_DEVICE).setChDeviceTypes(
				common.VIF_DEVICE_TYPE_POD_GROUP_CLONESET,
				common.VIF_DEVICE_TYPE_POD_GROUP_DAEMON_SET,
				common.VIF_DEVICE_TYPE_POD_GROUP_RC,
				common.VIF_DEVICE_TYPE_POD_GROUP_REPLICASET_CONTROLLER,
				common.VIF_DEVICE_TYPE_POD_GROUP_DEPLOYMENT,
				common.VIF_DEVICE_TYPE_POD_GROUP_STATEFULSET,
			),
		),
		newHealer[mysqlmodel.Process, mysqlmodel.ChDevice, *message.ProcessAdd](
			msgMetadata,
			newDataGenerator(md, common.RESOURCE_TYPE_PROCESS_EN),
			newDataGenerator(md, tagrecorder.RESOURCE_TYPE_CH_DEVICE).setChDeviceTypes(common.VIF_DEVICE_TYPE_GPROCESS)),
		newHealer[mysqlmodel.CustomService, mysqlmodel.ChDevice, *message.CustomServiceAdd](
			msgMetadata,
			newDataGenerator(md, common.RESOURCE_TYPE_CUSTOM_SERVICE_EN),
			newDataGenerator(md, tagrecorder.RESOURCE_TYPE_CH_DEVICE).setChDeviceTypes(common.VIF_DEVICE_TYPE_CUSTOM_SERVICE)),

		newHealer[mysqlmodel.AZ, mysqlmodel.ChAZ, *message.AZAdd](
			msgMetadata,
			newDataGenerator(md, common.RESOURCE_TYPE_AZ_EN),
			newDataGenerator(md, tagrecorder.RESOURCE_TYPE_CH_AZ)),

		newHealer[mysqlmodel.VM, mysqlmodel.ChChost, *message.VMAdd](
			msgMetadata,
			newDataGenerator(md, common.RESOURCE_TYPE_VM_EN),
			newDataGenerator(md, tagrecorder.RESOURCE_TYPE_CH_CHOST)),

		newHealer[mysqlmodel.VPC, mysqlmodel.ChVPC, *message.VPCAdd](
			msgMetadata,
			newDataGenerator(md, common.RESOURCE_TYPE_VPC_EN),
			newDataGenerator(md, tagrecorder.RESOURCE_TYPE_CH_VPC)),
		newHealer[mysqlmodel.Network, mysqlmodel.ChNetwork, *message.NetworkAdd](
			msgMetadata,
			newDataGenerator(md, common.RESOURCE_TYPE_NETWORK_EN),
			newDataGenerator(md, tagrecorder.RESOURCE_TYPE_CH_NETWORK)),

		newHealer[mysqlmodel.PodCluster, mysqlmodel.ChPodCluster, *message.PodClusterAdd](
			msgMetadata,
			newDataGenerator(md, common.RESOURCE_TYPE_POD_CLUSTER_EN),
			newDataGenerator(md, tagrecorder.RESOURCE_TYPE_CH_POD_CLUSTER)),
		newHealer[mysqlmodel.PodNamespace, mysqlmodel.ChPodNamespace, *message.PodNamespaceAdd](
			msgMetadata,
			newDataGenerator(md, common.RESOURCE_TYPE_POD_NAMESPACE_EN),
			newDataGenerator(md, tagrecorder.RESOURCE_TYPE_CH_POD_NAMESPACE)),
		newHealer[mysqlmodel.PodNode, mysqlmodel.ChPodNode, *message.PodNodeAdd](
			msgMetadata,
			newDataGenerator(md, common.RESOURCE_TYPE_POD_NODE_EN),
			newDataGenerator(md, tagrecorder.RESOURCE_TYPE_CH_POD_NODE)),
		newHealer[mysqlmodel.PodIngress, mysqlmodel.ChPodIngress, *message.PodIngressAdd](
			msgMetadata,
			newDataGenerator(md, common.RESOURCE_TYPE_POD_INGRESS_EN),
			newDataGenerator(md, tagrecorder.RESOURCE_TYPE_CH_POD_INGRESS)),
		newHealer[mysqlmodel.PodService, mysqlmodel.ChPodService, *message.PodServiceAdd](
			msgMetadata,
			newDataGenerator(md, common.RESOURCE_TYPE_POD_SERVICE_EN),
			newDataGenerator(md, tagrecorder.RESOURCE_TYPE_CH_POD_SERVICE)),
		newHealer[mysqlmodel.PodGroup, mysqlmodel.ChPodGroup, *message.PodGroupAdd](
			msgMetadata,
			newDataGenerator(md, common.RESOURCE_TYPE_POD_GROUP_EN),
			newDataGenerator(md, tagrecorder.RESOURCE_TYPE_CH_POD_GROUP)),
		newHealer[mysqlmodel.Pod, mysqlmodel.ChPod, *message.PodAdd](
			msgMetadata,
			newDataGenerator(md, common.RESOURCE_TYPE_POD_EN),
			newDataGenerator(md, tagrecorder.RESOURCE_TYPE_CH_POD)),

		newHealer[mysqlmodel.Process, mysqlmodel.ChGProcess, *message.ProcessAdd](
			msgMetadata,
			newDataGenerator(md, common.RESOURCE_TYPE_PROCESS_EN),
			newDataGenerator(md, tagrecorder.RESOURCE_TYPE_CH_GPROCESS)),

		newHealer[mysqlmodel.VM, mysqlmodel.ChChostCloudTag, *message.VMAdd](
			msgMetadata,
			newDataGenerator(md, common.RESOURCE_TYPE_VM_EN).setAdditionalSelectField("cloud_tags").setUnscoped(false),
			newDataGenerator(md, tagrecorder.RESOURCE_TYPE_CH_CHOST_CLOUD_TAG)),
		newHealer[mysqlmodel.VM, mysqlmodel.ChChostCloudTags, *message.VMAdd](
			msgMetadata,
			newDataGenerator(md, common.RESOURCE_TYPE_VM_EN).setAdditionalSelectField("cloud_tags").setUnscoped(false),
			newDataGenerator(md, tagrecorder.RESOURCE_TYPE_CH_CHOST_CLOUD_TAGS)),
		newHealer[mysqlmodel.PodNamespace, mysqlmodel.ChPodNSCloudTag, *message.PodNamespaceAdd](
			msgMetadata,
			newDataGenerator(md, common.RESOURCE_TYPE_POD_NAMESPACE_EN).setAdditionalSelectField("cloud_tags").setUnscoped(false),
			newDataGenerator(md, tagrecorder.RESOURCE_TYPE_CH_POD_NS_CLOUD_TAG)),
		newHealer[mysqlmodel.PodNamespace, mysqlmodel.ChPodNSCloudTags, *message.PodNamespaceAdd](
			msgMetadata,
			newDataGenerator(md, common.RESOURCE_TYPE_POD_NAMESPACE_EN).setAdditionalSelectField("cloud_tags").setUnscoped(false),
			newDataGenerator(md, tagrecorder.RESOURCE_TYPE_CH_POD_NS_CLOUD_TAGS)),
		newHealer[mysqlmodel.PodService, mysqlmodel.ChPodServiceK8sLabel, *message.PodServiceAdd](
			msgMetadata,
			newDataGenerator(md, common.RESOURCE_TYPE_POD_SERVICE_EN).setAdditionalSelectField("label").setUnscoped(false),
			newDataGenerator(md, tagrecorder.RESOURCE_TYPE_CH_POD_SERVICE_K8S_LABEL)),
		newHealer[mysqlmodel.PodService, mysqlmodel.ChPodServiceK8sLabels, *message.PodServiceAdd](
			msgMetadata,
			newDataGenerator(md, common.RESOURCE_TYPE_POD_SERVICE_EN).setAdditionalSelectField("label").setUnscoped(false),
			newDataGenerator(md, tagrecorder.RESOURCE_TYPE_CH_POD_SERVICE_K8S_LABELS)),
		newHealer[mysqlmodel.PodService, mysqlmodel.ChPodServiceK8sAnnotation, *message.PodServiceAdd](
			msgMetadata,
			newDataGenerator(md, common.RESOURCE_TYPE_POD_SERVICE_EN).setAdditionalSelectField("annotation").setUnscoped(false),
			newDataGenerator(md, tagrecorder.RESOURCE_TYPE_CH_POD_SERVICE_K8S_ANNOTATION)),
		newHealer[mysqlmodel.PodService, mysqlmodel.ChPodServiceK8sAnnotations, *message.PodServiceAdd](
			msgMetadata,
			newDataGenerator(md, common.RESOURCE_TYPE_POD_SERVICE_EN).setAdditionalSelectField("annotation").setUnscoped(false),
			newDataGenerator(md, tagrecorder.RESOURCE_TYPE_CH_POD_SERVICE_K8S_ANNOTATIONS)),
		newHealer[mysqlmodel.Pod, mysqlmodel.ChPodK8sEnv, *message.PodAdd](
			msgMetadata,
			newDataGenerator(md, common.RESOURCE_TYPE_POD_EN).setAdditionalSelectField("env").setUnscoped(false),
			newDataGenerator(md, tagrecorder.RESOURCE_TYPE_CH_POD_K8S_ENV)),
		newHealer[mysqlmodel.Pod, mysqlmodel.ChPodK8sEnvs, *message.PodAdd](
			msgMetadata,
			newDataGenerator(md, common.RESOURCE_TYPE_POD_EN).setAdditionalSelectField("env").setUnscoped(false),
			newDataGenerator(md, tagrecorder.RESOURCE_TYPE_CH_POD_K8S_ENVS)),
		newHealer[mysqlmodel.Pod, mysqlmodel.ChPodK8sLabel, *message.PodAdd](
			msgMetadata,
			newDataGenerator(md, common.RESOURCE_TYPE_POD_EN).setAdditionalSelectField("label").setUnscoped(false),
			newDataGenerator(md, tagrecorder.RESOURCE_TYPE_CH_POD_K8S_LABEL)),
		newHealer[mysqlmodel.Pod, mysqlmodel.ChPodK8sLabels, *message.PodAdd](
			msgMetadata,
			newDataGenerator(md, common.RESOURCE_TYPE_POD_EN).setAdditionalSelectField("label").setUnscoped(false),
			newDataGenerator(md, tagrecorder.RESOURCE_TYPE_CH_POD_K8S_LABELS)),
		newHealer[mysqlmodel.Pod, mysqlmodel.ChPodK8sAnnotation, *message.PodAdd](
			msgMetadata,
			newDataGenerator(md, common.RESOURCE_TYPE_POD_EN).setAdditionalSelectField("annotation").setUnscoped(false),
			newDataGenerator(md, tagrecorder.RESOURCE_TYPE_CH_POD_K8S_ANNOTATION)),
		newHealer[mysqlmodel.Pod, mysqlmodel.ChPodK8sAnnotations, *message.PodAdd](
			msgMetadata,
			newDataGenerator(md, common.RESOURCE_TYPE_POD_EN).setAdditionalSelectField("annotation").setUnscoped(false),
			newDataGenerator(md, tagrecorder.RESOURCE_TYPE_CH_POD_K8S_ANNOTATIONS)),
	}
	return h
}

type Healers struct {
	recorderCommon.MetadataBase

	sourceResourceTypeToData map[string]dataGenerator
	targetResourceTypeToData map[string]dataGenerator

	healers []Healer
}

func (h *Healers) Run() {
	log.Info("tagrecorder healers started", h.LogPrefixes)
	for _, healer := range h.healers {
		healer.Heal()
	}
	log.Info("tagrecorder healers finished", h.LogPrefixes)
}

type Healer interface {
	Heal()
}

func newHealer[
	MT constraint.MySQLModel,
	CT tagrecorder.SubscriberMetaDBChModel,
	MAPT msgConstraint.AddPtr[MAT],
	MAT msgConstraint.Add,
](md *message.Metadata, sourceDataGen, targetDataGen dataGenerator) Healer {
	return &healerComponent[MT, CT, MAPT, MAT]{
		msgMetadata: md,

		sourceDataGen: sourceDataGen,
		targetDataGen: targetDataGen,
	}
}

type healerComponent[
	MT constraint.MySQLModel,
	CT tagrecorder.SubscriberMetaDBChModel,
	MAPT msgConstraint.AddPtr[MAT],
	MAT msgConstraint.Add,
] struct {
	msgMetadata *message.Metadata

	sourceDataGen dataGenerator
	targetDataGen dataGenerator
}

func (h *healerComponent[MT, CT, MAPT, MAT]) Heal() {
	log.Infof("tagrecorder %s healer (source: %s) started", h.targetDataGen.getResourceType(), h.sourceDataGen.getResourceType(), h.msgMetadata.LogPrefixes)
	err := h.sourceDataGen.generate()
	if err != nil {
		log.Errorf("failed to generate %s data: %s", h.sourceDataGen.getResourceType(), err.Error(), h.msgMetadata.LogPrefixes)
		return
	}
	err = h.targetDataGen.generate()
	if err != nil {
		log.Errorf("failed to generate %s data: %s", h.targetDataGen.getResourceType(), err.Error(), h.msgMetadata.LogPrefixes)
		return
	}

	sourceIDsToAdd := make([]int, 0)
	targetIDsToForceDelete := make([]int, 0)
	for sourceID, sourceUpdatedAt := range h.sourceDataGen.getIDToUpdatedAt() {
		// check if the source ID exists in the target data
		// if it exists, compare the updated_at timestamps, if the source is newer, means target data is stale, need to refresh it by force deleting it and adding.
		// yf it does not exist, means target data is missing, need to add it.
		if targetUpdatedAt, ok := h.targetDataGen.getIDToUpdatedAt()[sourceID]; ok {
			if sourceUpdatedAt.After(targetUpdatedAt) {
				targetIDsToForceDelete = append(targetIDsToForceDelete, sourceID)
				sourceIDsToAdd = append(sourceIDsToAdd, sourceID)
			}
			continue
		}
		sourceIDsToAdd = append(sourceIDsToAdd, sourceID)
	}
	for targetID, _ := range h.targetDataGen.getIDToUpdatedAt() {
		// check if the target ID exists in the source data
		// if it does not exist, means target data is stale, need to force delete it.
		if _, ok := h.sourceDataGen.getIDToUpdatedAt()[targetID]; !ok {
			targetIDsToForceDelete = append(targetIDsToForceDelete, targetID)
		}
	}

	err = h.forceDelete(targetIDsToForceDelete)
	if err != nil {
		log.Errorf("failed to force delete %s data: %s", h.targetDataGen.getResourceType(), err.Error(), h.msgMetadata.LogPrefixes)
		return
	}
	err = h.republishAdd(sourceIDsToAdd)
	if err != nil {
		log.Errorf("failed to publish %s add data: %s", h.targetDataGen.getResourceType(), err.Error(), h.msgMetadata.LogPrefixes)
		return
	}
}

func (h *healerComponent[MT, CT, MAPT, MAT]) republishAdd(sourceIDs []int) error {
	if len(sourceIDs) == 0 {
		return nil
	}
	log.Infof("tagrecorder %s healer (source: %s) republish add (ids: %v)", h.targetDataGen.getResourceType(), h.sourceDataGen.getResourceType(), sourceIDs, h.msgMetadata.LogPrefixes)
	var dbItems []*MT
	if err := h.msgMetadata.DB.Where(fmt.Sprintf("%s IN ?", h.sourceDataGen.getRealIDField()), sourceIDs).Find(&dbItems).Error; err != nil {
		log.Errorf("failed to find %s: %v", h.targetDataGen.getResourceType(), err, h.msgMetadata.LogPrefixes)
		return err
	}
	targetSubscriber := tagrecorder.GetSubscriberManager().GetSubscriber(h.sourceDataGen.getResourceType(), h.targetDataGen.getResourceType())
	if targetSubscriber == nil {
		log.Errorf("failed to get target subscriber: %s", h.targetDataGen.getResourceType(), h.msgMetadata.LogPrefixes)
		return fmt.Errorf("failed to get target subscriber: %s", h.targetDataGen.getResourceType())
	}

	msgData := MAPT(new(MAT))
	msgData.SetMySQLItems(dbItems)
	targetSubscriber.OnResourceBatchAdded(h.msgMetadata, msgData)
	return nil
}

func (h *healerComponent[MT, CT, MAPT, MAT]) forceDelete(targetIDs []int) error {
	if len(targetIDs) == 0 {
		return nil
	}
	log.Infof("tagrecorder %s healer (source: %s) force delete data, ids: %v", h.targetDataGen.getResourceType(), h.sourceDataGen.getResourceType(), targetIDs, h.msgMetadata.LogPrefixes)
	var dbItems []*CT
	delExec := h.msgMetadata.DB.Where(fmt.Sprintf("%s IN ?", h.targetDataGen.getRealIDField()), targetIDs)
	if h.targetDataGen.getResourceType() == tagrecorder.RESOURCE_TYPE_CH_DEVICE {
		delExec = delExec.Where("devicetype IN ?", h.targetDataGen.getChDeviceTypes())
	}
	if err := delExec.Delete(&dbItems).Error; err != nil {
		log.Errorf("failed to delete %s: %v", h.targetDataGen.getResourceType(), err, h.msgMetadata.LogPrefixes)
		return err
	}
	err := h.msgMetadata.DB.Model(&mysqlmodel.ChTagLastUpdatedAt{}).Where("table_name = ?", h.targetDataGen.getResourceType()).
		Updates(map[string]interface{}{"updated_at": time.Now()}).Error
	if err != nil {
		log.Errorf("update %s updated_at error: %v", h.targetDataGen.getResourceType(), err, h.msgMetadata.LogPrefixes)
	}
	return nil
}
