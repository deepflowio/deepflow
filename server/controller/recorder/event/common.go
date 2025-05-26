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

	ctrlrcommon "github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/db/metadb"
	metadbmodel "github.com/deepflowio/deepflow/server/controller/db/metadb/model"
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
	info, err := md.GetToolDataSet().GetHostInfoByID(id)
	if err != nil {
		return nil, err
	}

	var opts []eventapi.TagFieldOption
	opts = append(opts, []eventapi.TagFieldOption{
		eventapi.TagRegionID(info.RegionID),
		eventapi.TagAZID(info.AZID),
	}...)
	return opts, nil
}

func (i *IPTool) getVMOptionsByID(md *message.Metadata, id int) ([]eventapi.TagFieldOption, error) {
	info, err := md.GetToolDataSet().GetVMInfoByID(id)
	if err != nil {
		return nil, err
	}

	var opts []eventapi.TagFieldOption
	opts = append(opts, []eventapi.TagFieldOption{
		eventapi.TagRegionID(info.RegionID),
		eventapi.TagAZID(info.AZID),
		eventapi.TagVPCID(info.VPCID),
		eventapi.TagHostID(info.HostID),
		eventapi.TagL3DeviceType(ctrlrcommon.VIF_DEVICE_TYPE_VM),
		eventapi.TagL3DeviceID(id),
	}...)
	return opts, nil
}

func (i *IPTool) getVRouterOptionsByID(md *message.Metadata, id int) ([]eventapi.TagFieldOption, error) {
	info, err := md.GetToolDataSet().GetVRouterInfoByID(id)
	if err != nil {
		return nil, err
	}

	var opts []eventapi.TagFieldOption
	opts = append(opts, []eventapi.TagFieldOption{
		eventapi.TagRegionID(info.RegionID),
		eventapi.TagVPCID(info.VPCID),
		eventapi.TagL3DeviceType(ctrlrcommon.VIF_DEVICE_TYPE_VROUTER),
		eventapi.TagL3DeviceID(id),
	}...)

	hostID, ok := md.GetToolDataSet().GetHostIDByIP(info.GWLaunchServer)
	if !ok {
		log.Error(idByIPNotFound(ctrlrcommon.RESOURCE_TYPE_HOST_EN, info.GWLaunchServer))
	} else {
		opts = append(opts, []eventapi.TagFieldOption{
			eventapi.TagHostID(hostID),
		}...)
	}

	return opts, nil
}

func (i *IPTool) getDHCPPortOptionsByID(md *message.Metadata, id int) ([]eventapi.TagFieldOption, error) {
	info, err := md.GetToolDataSet().GetDHCPPortInfoByID(id)
	if err != nil {
		return nil, err
	}

	var opts []eventapi.TagFieldOption
	opts = append(opts, []eventapi.TagFieldOption{
		eventapi.TagRegionID(info.RegionID),
		eventapi.TagAZID(info.AZID),
		eventapi.TagVPCID(info.VPCID),
		eventapi.TagL3DeviceType(ctrlrcommon.VIF_DEVICE_TYPE_DHCP_PORT),
		eventapi.TagL3DeviceID(id),
	}...)
	return opts, nil
}

func (i *IPTool) getNatGateWayOptionsByID(md *message.Metadata, id int) ([]eventapi.TagFieldOption, error) {
	info, err := md.GetToolDataSet().GetNATGatewayInfoByID(id)
	if err != nil {
		return nil, err
	}

	var opts []eventapi.TagFieldOption
	opts = append(opts, []eventapi.TagFieldOption{
		eventapi.TagRegionID(info.RegionID),
		eventapi.TagAZID(info.AZID),
		eventapi.TagVPCID(info.VPCID),
		eventapi.TagL3DeviceType(ctrlrcommon.VIF_DEVICE_TYPE_NAT_GATEWAY),
		eventapi.TagL3DeviceID(id),
	}...)
	return opts, nil
}

func (i *IPTool) getLBOptionsByID(md *message.Metadata, id int) ([]eventapi.TagFieldOption, error) {
	info, err := md.GetToolDataSet().GetLBInfoByID(id)
	if err != nil {
		return nil, err
	}

	var opts []eventapi.TagFieldOption
	opts = append(opts, []eventapi.TagFieldOption{
		eventapi.TagRegionID(info.RegionID),
		eventapi.TagVPCID(info.VPCID),
		eventapi.TagL3DeviceType(ctrlrcommon.VIF_DEVICE_TYPE_LB),
		eventapi.TagL3DeviceID(id),
	}...)
	return opts, nil
}

func (i *IPTool) getRDSInstanceOptionsByID(md *message.Metadata, id int) ([]eventapi.TagFieldOption, error) {
	info, err := md.GetToolDataSet().GetRDSInstanceInfoByID(id)
	if err != nil {
		return nil, err
	}

	var opts []eventapi.TagFieldOption
	opts = append(opts, []eventapi.TagFieldOption{
		eventapi.TagRegionID(info.RegionID),
		eventapi.TagAZID(info.AZID),
		eventapi.TagVPCID(info.VPCID),
		eventapi.TagL3DeviceType(ctrlrcommon.VIF_DEVICE_TYPE_RDS_INSTANCE),
		eventapi.TagL3DeviceID(id),
	}...)
	return opts, nil
}

func (i *IPTool) getRedisInstanceOptionsByID(md *message.Metadata, id int) ([]eventapi.TagFieldOption, error) {
	info, err := md.GetToolDataSet().GetRedisInstanceInfoByID(id)
	if err != nil {
		return nil, err
	}

	var opts []eventapi.TagFieldOption
	opts = append(opts, []eventapi.TagFieldOption{
		eventapi.TagRegionID(info.RegionID),
		eventapi.TagAZID(info.AZID),
		eventapi.TagVPCID(info.VPCID),
		eventapi.TagL3DeviceType(ctrlrcommon.VIF_DEVICE_TYPE_REDIS_INSTANCE),
		eventapi.TagL3DeviceID(id),
	}...)
	return opts, nil
}

func (i *IPTool) getPodNodeOptionsByID(md *message.Metadata, id int) ([]eventapi.TagFieldOption, error) {
	info, err := md.GetToolDataSet().GetPodNodeInfoByID(id)
	if err != nil {
		return nil, err
	}

	var opts []eventapi.TagFieldOption
	opts = append(opts, []eventapi.TagFieldOption{
		eventapi.TagRegionID(info.RegionID),
		eventapi.TagAZID(info.AZID),
		eventapi.TagVPCID(info.VPCID),
		eventapi.TagPodClusterID(info.PodClusterID),
		eventapi.TagPodNodeID(id),
	}...)
	return opts, nil
}

func (i *IPTool) getPodServiceOptionsByID(md *message.Metadata, id int) ([]eventapi.TagFieldOption, error) {
	info, err := md.GetToolDataSet().GetPodServiceInfoByID(id)
	if err != nil {
		return nil, err
	}

	var opts []eventapi.TagFieldOption
	opts = append(opts, []eventapi.TagFieldOption{
		eventapi.TagRegionID(info.RegionID),
		eventapi.TagAZID(info.AZID),
		eventapi.TagVPCID(info.VPCID),
		eventapi.TagL3DeviceType(ctrlrcommon.VIF_DEVICE_TYPE_POD_SERVICE),
		eventapi.TagL3DeviceID(id),
		eventapi.TagPodClusterID(info.PodClusterID),
		eventapi.TagPodNSID(info.PodNamespaceID),
		eventapi.TagPodServiceID(id),
	}...)
	return opts, nil
}

func (i *IPTool) getPodOptionsByID(md *message.Metadata, id int) ([]eventapi.TagFieldOption, error) {
	info, err := md.GetToolDataSet().GetPodInfoByID(id)
	if err != nil {
		return nil, err
	}
	podGroupType, ok := md.GetToolDataSet().GetPodGroupTypeByID(info.PodGroupID)
	if !ok {
		log.Errorf("db pod_group type(id: %d) not found", info.PodGroupID, md.LogPrefixes)
	}

	var opts []eventapi.TagFieldOption
	opts = append(opts, []eventapi.TagFieldOption{
		eventapi.TagRegionID(info.RegionID),
		eventapi.TagAZID(info.AZID),
		eventapi.TagVPCID(info.VPCID),
		eventapi.TagPodClusterID(info.PodClusterID),
		eventapi.TagPodNSID(info.PodNamespaceID),
		eventapi.TagPodGroupID(info.PodGroupID),
		eventapi.TagPodGroupType(metadata.PodGroupTypeMap[podGroupType]),
		eventapi.TagPodNodeID(info.PodNodeID),
		eventapi.TagPodID(id),
	}...)
	return opts, nil
}

func (i *IPTool) getL3DeviceOptionsByPodNodeID(md *message.Metadata, id int) (opts []eventapi.TagFieldOption, ok bool) {
	vmID, ok := md.GetToolDataSet().GetVMIDByPodNodeID(id)
	if ok {
		opts = append(opts, []eventapi.TagFieldOption{eventapi.TagL3DeviceType(ctrlrcommon.VIF_DEVICE_TYPE_VM), eventapi.TagL3DeviceID(vmID)}...)
		vmInfo, err := md.GetToolDataSet().GetVMInfoByID(vmID)
		if err != nil {
			log.Error(err)
		} else {
			opts = append(opts, eventapi.TagHostID(vmInfo.HostID))
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

func findFromAllByID[MT constraint.MySQLSoftDeleteModel](db *metadb.DB, id int) *MT {
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
