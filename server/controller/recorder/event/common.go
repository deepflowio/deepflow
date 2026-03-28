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

package event

import (
	"fmt"

	"github.com/pmezard/go-difflib/difflib"
	"gopkg.in/yaml.v2"

	ctrlrcommon "github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/db/metadb"
	metadbmodel "github.com/deepflowio/deepflow/server/controller/db/metadb/model"
	"github.com/deepflowio/deepflow/server/controller/recorder/cache/tool"
	"github.com/deepflowio/deepflow/server/controller/recorder/constraint"
	"github.com/deepflowio/deepflow/server/controller/recorder/pubsub/message"
	"github.com/deepflowio/deepflow/server/controller/trisolaris/metadata"
	"github.com/deepflowio/deepflow/server/libs/eventapi"
)

var (
	DESCMigrateFormat     = "%s migrate from %s to %s."
	DESCStateChangeFormat = "%s state changes from %s to %s."
	DESCRecreateFormat    = "%s recreate from %s to %s."
	DESCAddIPFormat       = "%s add ip %s(mac: %s) in subnet %s."
	DESCRemoveIPFormat    = "%s remove ip %s(mac: %s) in subnet %s."
)

type IPTool struct{}

func newTool() *IPTool {
	return &IPTool{}
}

func (i *IPTool) GetDeviceOptionsByDeviceID(md *message.Metadata, deviceType, deviceID int) ([]eventapi.TagFieldOption, error) {
	switch deviceType {
	case ctrlrcommon.VIF_DEVICE_TYPE_HOST:
		return i.getHostOptionsByID(md, deviceID)
	case ctrlrcommon.VIF_DEVICE_TYPE_VM:
		return i.getVMOptionsByID(md, deviceID)
	case ctrlrcommon.VIF_DEVICE_TYPE_VROUTER:
		return i.getVRouterOptionsByID(md, deviceID)
	case ctrlrcommon.VIF_DEVICE_TYPE_DHCP_PORT:
		return i.getDHCPPortOptionsByID(md, deviceID)
	case ctrlrcommon.VIF_DEVICE_TYPE_NAT_GATEWAY:
		return i.getNatGateWayOptionsByID(md, deviceID)
	case ctrlrcommon.VIF_DEVICE_TYPE_LB:
		return i.getLBOptionsByID(md, deviceID)
	case ctrlrcommon.VIF_DEVICE_TYPE_RDS_INSTANCE:
		return i.getRDSInstanceOptionsByID(md, deviceID)
	case ctrlrcommon.VIF_DEVICE_TYPE_REDIS_INSTANCE:
		return i.getRedisInstanceOptionsByID(md, deviceID)
	case ctrlrcommon.VIF_DEVICE_TYPE_POD_NODE:
		return i.getPodNodeOptionsByID(md, deviceID)
	case ctrlrcommon.VIF_DEVICE_TYPE_POD_SERVICE:
		return i.getPodServiceOptionsByID(md, deviceID)
	case ctrlrcommon.VIF_DEVICE_TYPE_POD:
		return i.getPodOptionsByID(md, deviceID)
	default:
		log.Errorf("device type %d not supported", deviceType, md.LogPrefixes)
		return nil, fmt.Errorf("device type %d not supported", deviceType)
	}
}

func (i *IPTool) getHostOptionsByID(md *message.Metadata, id int) ([]eventapi.TagFieldOption, error) {
	item := md.GetToolDataSet().Host().GetById(id)
	if !item.IsValid() {
		return nil, fmt.Errorf("host(id=%d) not found", id)
	}

	var opts []eventapi.TagFieldOption
	opts = append(opts, []eventapi.TagFieldOption{
		eventapi.TagRegionID(item.RegionId()),
		eventapi.TagAZID(item.AzId()),
	}...)
	return opts, nil
}

func (i *IPTool) getVMOptionsByID(md *message.Metadata, id int) ([]eventapi.TagFieldOption, error) {
	item := md.GetToolDataSet().Vm().GetById(id)
	if !item.IsValid() {
		return nil, fmt.Errorf("vm(id=%d) not found", id)
	}

	var opts []eventapi.TagFieldOption
	opts = append(opts, []eventapi.TagFieldOption{
		eventapi.TagRegionID(item.RegionId()),
		eventapi.TagAZID(item.AzId()),
		eventapi.TagVPCID(item.VpcId()),
		eventapi.TagHostID(item.HostId()),
		eventapi.TagL3DeviceType(ctrlrcommon.VIF_DEVICE_TYPE_VM),
		eventapi.TagL3DeviceID(id),
	}...)
	return opts, nil
}

func (i *IPTool) getVRouterOptionsByID(md *message.Metadata, id int) ([]eventapi.TagFieldOption, error) {
	item := md.GetToolDataSet().Vrouter().GetById(id)
	if !item.IsValid() {
		return nil, fmt.Errorf("vrouter(id=%d) not found", id)
	}

	var opts []eventapi.TagFieldOption
	opts = append(opts, []eventapi.TagFieldOption{
		eventapi.TagRegionID(item.RegionId()),
		eventapi.TagVPCID(item.VpcId()),
		eventapi.TagL3DeviceType(ctrlrcommon.VIF_DEVICE_TYPE_VROUTER),
		eventapi.TagL3DeviceID(id),
	}...)

	host := md.GetToolDataSet().Host().GetByIp(item.GwLaunchServer())
	if !host.IsValid() {
		log.Error(idByIPNotFound(ctrlrcommon.RESOURCE_TYPE_HOST_EN, item.GwLaunchServer()))
	} else {
		opts = append(opts, []eventapi.TagFieldOption{
			eventapi.TagHostID(host.Id()),
		}...)
	}

	return opts, nil
}

func (i *IPTool) getDHCPPortOptionsByID(md *message.Metadata, id int) ([]eventapi.TagFieldOption, error) {
	item := md.GetToolDataSet().DhcpPort().GetById(id)
	if !item.IsValid() {
		return nil, fmt.Errorf("dhcp_port(id=%d) not found", id)
	}

	var opts []eventapi.TagFieldOption
	opts = append(opts, []eventapi.TagFieldOption{
		eventapi.TagRegionID(item.RegionId()),
		eventapi.TagAZID(item.AzId()),
		eventapi.TagVPCID(item.VpcId()),
		eventapi.TagL3DeviceType(ctrlrcommon.VIF_DEVICE_TYPE_DHCP_PORT),
		eventapi.TagL3DeviceID(id),
	}...)
	return opts, nil
}

func (i *IPTool) getNatGateWayOptionsByID(md *message.Metadata, id int) ([]eventapi.TagFieldOption, error) {
	item := md.GetToolDataSet().NatGateway().GetById(id)
	if !item.IsValid() {
		return nil, fmt.Errorf("nat_gateway(id=%d) not found", id)
	}

	var opts []eventapi.TagFieldOption
	opts = append(opts, []eventapi.TagFieldOption{
		eventapi.TagRegionID(item.RegionId()),
		eventapi.TagAZID(item.AzId()),
		eventapi.TagVPCID(item.VpcId()),
		eventapi.TagL3DeviceType(ctrlrcommon.VIF_DEVICE_TYPE_NAT_GATEWAY),
		eventapi.TagL3DeviceID(id),
	}...)
	return opts, nil
}

func (i *IPTool) getLBOptionsByID(md *message.Metadata, id int) ([]eventapi.TagFieldOption, error) {
	item := md.GetToolDataSet().Lb().GetById(id)
	if !item.IsValid() {
		return nil, fmt.Errorf("lb(id=%d) not found", id)
	}

	var opts []eventapi.TagFieldOption
	opts = append(opts, []eventapi.TagFieldOption{
		eventapi.TagRegionID(item.RegionId()),
		eventapi.TagVPCID(item.VpcId()),
		eventapi.TagL3DeviceType(ctrlrcommon.VIF_DEVICE_TYPE_LB),
		eventapi.TagL3DeviceID(id),
	}...)
	return opts, nil
}

func (i *IPTool) getRDSInstanceOptionsByID(md *message.Metadata, id int) ([]eventapi.TagFieldOption, error) {
	item := md.GetToolDataSet().RdsInstance().GetById(id)
	if !item.IsValid() {
		return nil, fmt.Errorf("rds_instance(id=%d) not found", id)
	}

	var opts []eventapi.TagFieldOption
	opts = append(opts, []eventapi.TagFieldOption{
		eventapi.TagRegionID(item.RegionId()),
		eventapi.TagAZID(item.AzId()),
		eventapi.TagVPCID(item.VpcId()),
		eventapi.TagL3DeviceType(ctrlrcommon.VIF_DEVICE_TYPE_RDS_INSTANCE),
		eventapi.TagL3DeviceID(id),
	}...)
	return opts, nil
}

func (i *IPTool) getRedisInstanceOptionsByID(md *message.Metadata, id int) ([]eventapi.TagFieldOption, error) {
	item := md.GetToolDataSet().RedisInstance().GetById(id)
	if !item.IsValid() {
		return nil, fmt.Errorf("redis_instance(id=%d) not found", id)
	}

	var opts []eventapi.TagFieldOption
	opts = append(opts, []eventapi.TagFieldOption{
		eventapi.TagRegionID(item.RegionId()),
		eventapi.TagAZID(item.AzId()),
		eventapi.TagVPCID(item.VpcId()),
		eventapi.TagL3DeviceType(ctrlrcommon.VIF_DEVICE_TYPE_REDIS_INSTANCE),
		eventapi.TagL3DeviceID(id),
	}...)
	return opts, nil
}

func (i *IPTool) getPodNodeOptionsByID(md *message.Metadata, id int) ([]eventapi.TagFieldOption, error) {
	item := md.GetToolDataSet().PodNode().GetById(id)
	if !item.IsValid() {
		return nil, fmt.Errorf("pod_node(id=%d) not found", id)
	}

	var opts []eventapi.TagFieldOption
	opts = append(opts, []eventapi.TagFieldOption{
		eventapi.TagRegionID(item.RegionId()),
		eventapi.TagAZID(item.AzId()),
		eventapi.TagVPCID(item.VpcId()),
		eventapi.TagPodClusterID(item.PodClusterId()),
		eventapi.TagPodNodeID(id),
	}...)
	return opts, nil
}

func (i *IPTool) getPodServiceOptionsByID(md *message.Metadata, id int) ([]eventapi.TagFieldOption, error) {
	item := md.GetToolDataSet().PodService().GetById(id)
	if !item.IsValid() {
		return nil, fmt.Errorf("pod_service(id=%d) not found", id)
	}

	var opts []eventapi.TagFieldOption
	opts = append(opts, []eventapi.TagFieldOption{
		eventapi.TagRegionID(item.RegionId()),
		eventapi.TagAZID(item.AzId()),
		eventapi.TagVPCID(item.VpcId()),
		eventapi.TagL3DeviceType(ctrlrcommon.VIF_DEVICE_TYPE_POD_SERVICE),
		eventapi.TagL3DeviceID(id),
		eventapi.TagPodClusterID(item.PodClusterId()),
		eventapi.TagPodNSID(item.PodNamespaceId()),
		eventapi.TagPodServiceID(id), // TODO 此字段在 ingester 中并未被使用，待删除
	}...)
	return opts, nil
}

func (i *IPTool) getPodOptionsByID(md *message.Metadata, id int) ([]eventapi.TagFieldOption, error) {
	item := md.GetToolDataSet().Pod().GetById(id)
	if !item.IsValid() {
		return nil, fmt.Errorf("pod(id=%d) not found", id)
	}
	podGroup := md.GetToolDataSet().PodGroup().GetById(item.PodGroupId())
	if !podGroup.IsValid() {
		log.Errorf("db pod_group type(id: %d) not found", item.PodGroupId(), md.LogPrefixes)
	}

	var opts []eventapi.TagFieldOption
	opts = append(opts, []eventapi.TagFieldOption{
		eventapi.TagRegionID(item.RegionId()),
		eventapi.TagAZID(item.AzId()),
		eventapi.TagVPCID(item.VpcId()),
		eventapi.TagPodClusterID(item.PodClusterId()),
		eventapi.TagPodNSID(item.PodNamespaceId()),
		eventapi.TagPodGroupID(item.PodGroupId()),
		eventapi.TagPodGroupType(metadata.PodGroupTypeMap[podGroup.GType()]),
		eventapi.TagPodNodeID(item.PodNodeId()),
		eventapi.TagPodID(id),
	}...)
	return opts, nil
}

func (i *IPTool) getL3DeviceOptionsByPodNodeID(md *message.Metadata, id int) (opts []eventapi.TagFieldOption, ok bool) {
	vmID := md.GetToolDataSet().PodNode().GetById(id).VmId()
	ok = vmID != 0
	if ok {
		opts = append(opts, []eventapi.TagFieldOption{eventapi.TagL3DeviceType(ctrlrcommon.VIF_DEVICE_TYPE_VM), eventapi.TagL3DeviceID(vmID)}...)
		vmItem := md.GetToolDataSet().Vm().GetById(vmID)
		if !vmItem.IsValid() {
			log.Errorf("vm(id=%d) not found", vmID)
		} else {
			opts = append(opts, eventapi.TagHostID(vmItem.HostId()))
		}
	}
	return
}

func (i *IPTool) getDeviceNameFromAllByID(md *message.Metadata, deviceType, deviceID int) string {
	switch deviceType {
	case ctrlrcommon.VIF_DEVICE_TYPE_HOST:
		device := findFromAllByID[metadbmodel.Host](md.GetDB(), deviceID)
		if device == nil {
			log.Error(dbSoftDeletedResourceByIDNotFound(ctrlrcommon.RESOURCE_TYPE_HOST_EN, deviceID), md.LogPrefixes)
		} else {
			return device.Name
		}
	case ctrlrcommon.VIF_DEVICE_TYPE_VM:
		device := findFromAllByID[metadbmodel.VM](md.GetDB(), deviceID)
		if device == nil {
			log.Error(dbSoftDeletedResourceByIDNotFound(ctrlrcommon.RESOURCE_TYPE_VM_EN, deviceID), md.LogPrefixes)
		} else {
			return device.Name
		}
	case ctrlrcommon.VIF_DEVICE_TYPE_VROUTER:
		device := findFromAllByID[metadbmodel.VRouter](md.GetDB(), deviceID)
		if device == nil {
			log.Error(dbSoftDeletedResourceByIDNotFound(ctrlrcommon.RESOURCE_TYPE_VROUTER_EN, deviceID), md.LogPrefixes)
		} else {
			return device.Name
		}
	case ctrlrcommon.VIF_DEVICE_TYPE_DHCP_PORT:
		device := findFromAllByID[metadbmodel.DHCPPort](md.GetDB(), deviceID)
		if device == nil {
			log.Error(dbSoftDeletedResourceByIDNotFound(ctrlrcommon.RESOURCE_TYPE_DHCP_PORT_EN, deviceID), md.LogPrefixes)
		} else {
			return device.Name
		}
	case ctrlrcommon.VIF_DEVICE_TYPE_NAT_GATEWAY:
		device := findFromAllByID[metadbmodel.NATGateway](md.GetDB(), deviceID)
		if device == nil {
			log.Error(dbSoftDeletedResourceByIDNotFound(ctrlrcommon.RESOURCE_TYPE_NAT_GATEWAY_EN, deviceID), md.LogPrefixes)
		} else {
			return device.Name
		}
	case ctrlrcommon.VIF_DEVICE_TYPE_LB:
		device := findFromAllByID[metadbmodel.LB](md.GetDB(), deviceID)
		if device == nil {
			log.Error(dbSoftDeletedResourceByIDNotFound(ctrlrcommon.RESOURCE_TYPE_LB_EN, deviceID), md.LogPrefixes)
		} else {
			return device.Name
		}
	case ctrlrcommon.VIF_DEVICE_TYPE_RDS_INSTANCE:
		device := findFromAllByID[metadbmodel.RDSInstance](md.GetDB(), deviceID)
		if device == nil {
			log.Error(dbSoftDeletedResourceByIDNotFound(ctrlrcommon.RESOURCE_TYPE_RDS_INSTANCE_EN, deviceID), md.LogPrefixes)
		} else {
			return device.Name
		}
	case ctrlrcommon.VIF_DEVICE_TYPE_REDIS_INSTANCE:
		device := findFromAllByID[metadbmodel.RedisInstance](md.GetDB(), deviceID)
		if device == nil {
			log.Error(dbSoftDeletedResourceByIDNotFound(ctrlrcommon.RESOURCE_TYPE_REDIS_INSTANCE_EN, deviceID), md.LogPrefixes)
		} else {
			return device.Name
		}
	case ctrlrcommon.VIF_DEVICE_TYPE_POD_NODE:
		device := findFromAllByID[metadbmodel.PodNode](md.GetDB(), deviceID)
		if device == nil {
			log.Error(dbSoftDeletedResourceByIDNotFound(ctrlrcommon.RESOURCE_TYPE_POD_NODE_EN, deviceID), md.LogPrefixes)
		} else {
			return device.Name
		}
	case ctrlrcommon.VIF_DEVICE_TYPE_POD_SERVICE:
		device := findFromAllByID[metadbmodel.PodService](md.GetDB(), deviceID)
		if device == nil {
			log.Error(dbSoftDeletedResourceByIDNotFound(ctrlrcommon.RESOURCE_TYPE_POD_SERVICE_EN, deviceID), md.LogPrefixes)
		} else {
			return device.Name
		}
	case ctrlrcommon.VIF_DEVICE_TYPE_POD:
		device := findFromAllByID[metadbmodel.Pod](md.GetDB(), deviceID)
		if device == nil {
			log.Error(dbSoftDeletedResourceByIDNotFound(ctrlrcommon.RESOURCE_TYPE_POD_EN, deviceID), md.LogPrefixes)
		} else {
			return device.Name
		}
	default:
		log.Errorf("device type: %d is not supported", deviceType, md.LogPrefixes)
		return ""
	}
	return ""
}

// getDeviceIPNetworks returns all IPs and their network IDs for a device (VM or Pod).
func getDeviceIPNetworks(t *tool.Tool, deviceType, deviceID int) (networkIDs []uint32, ips []string) {
	vifs := t.Vinterface().GetByDeviceKey(deviceType, deviceID)
	for _, vif := range vifs {
		nID := vif.NetworkId()
		for _, lanIP := range t.LanIP().GetByVInterfaceID(vif.Id()) {
			networkIDs = append(networkIDs, uint32(nID))
			ips = append(ips, lanIP.Ip())
		}
		for _, wanIP := range t.WanIP().GetByVInterfaceID(vif.Id()) {
			networkIDs = append(networkIDs, uint32(nID))
			ips = append(ips, wanIP.Ip())
		}
	}
	return
}

func findFromAllByID[MT constraint.MetadbSoftDeleteModel](db *metadb.DB, id int) *MT {
	var item *MT
	res := db.Unscoped().Where("id = ?", id).Find(&item)
	if res.Error != nil {
		log.Error(dbQueryFailed(res.Error))
		return nil
	}
	if res.RowsAffected != 1 {
		return nil
	}
	return item
}

func CompareConfig(old, new string, context int) string {
	diff := difflib.UnifiedDiff{
		A:        difflib.SplitLines(old),
		B:        difflib.SplitLines(new),
		FromFile: "old",
		ToFile:   "new",
		Context:  context,
	}

	result, err := difflib.GetUnifiedDiffString(diff)
	if err != nil {
		log.Errorf("compare config error: %v, new: %s, old: %s", err, new, old)
	}
	return result
}

func JoinMetadataAndSpec(metadata, spec string) string {
	if metadata == "" && spec == "" {
		return ""
	}
	if metadata == "" {
		return spec
	}
	if spec == "" {
		return metadata
	}

	metadataYAML := metadata
	specYAML := spec

	var jsonMetadata, jsonSpec map[string]interface{}
	err := yaml.Unmarshal([]byte(metadata), &jsonMetadata)
	if err != nil {
		log.Errorf("failed to convert metadata YAML to JSON: %s, error: %v", metadata, err)
	}
	newMetadata, err := yaml.Marshal(map[string]interface{}{"metadata": jsonMetadata})
	if err != nil {
		log.Errorf("failed to convert metadata JSON to YAML: %s, error: %v", metadata, err)
	} else {
		metadataYAML = string(newMetadata)
	}
	err = yaml.Unmarshal([]byte(spec), &jsonSpec)
	if err != nil {
		log.Errorf("failed to convert spec YAML to JSON: %s, error: %v", spec, err)
	}
	newSpec, err := yaml.Marshal(map[string]interface{}{"spec": jsonSpec})
	if err != nil {
		log.Errorf("failed to convert spec JSON to YAML: %s, error: %v", spec, err)
	} else {
		specYAML = string(newSpec)
	}
	return metadataYAML + specYAML
}
