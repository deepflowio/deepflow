/*
 * Copyright (c) 2022 Yunshan Networks
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

	"github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	"github.com/deepflowio/deepflow/server/controller/recorder/cache"
	. "github.com/deepflowio/deepflow/server/controller/recorder/common"
	"github.com/deepflowio/deepflow/server/controller/recorder/constraint"
	"github.com/deepflowio/deepflow/server/libs/eventapi"
)

var (
	DESCMigrateFormat     = "%s migrate from %s to %s."
	DESCStateChangeFormat = "%s state changes from %s to %s."
	DESCRecreateFormat    = "%s recreate from %s to %s."
	DESCAddIPFormat       = "%s add ip %s in subnet %s."
	DESCRemoveIPFormat    = "%s remove ip %s in subnet %s."
)

func GetDeviceOptionsByDeviceID(t *cache.ToolDataSet, deviceType, deviceID int) ([]eventapi.TagFieldOption, error) {
	switch deviceType {
	case common.VIF_DEVICE_TYPE_HOST:
		return getHostOptionsByID(t, deviceID)
	case common.VIF_DEVICE_TYPE_VM:
		return getVMOptionsByID(t, deviceID)
	case common.VIF_DEVICE_TYPE_VROUTER:
		return getVRouterOptionsByID(t, deviceID)
	case common.VIF_DEVICE_TYPE_DHCP_PORT:
		return getDHCPPortOptionsByID(t, deviceID)
	case common.VIF_DEVICE_TYPE_NAT_GATEWAY:
		return getNatGateWayOptionsByID(t, deviceID)
	case common.VIF_DEVICE_TYPE_LB:
		return getLBOptionsByID(t, deviceID)
	case common.VIF_DEVICE_TYPE_RDS_INSTANCE:
		return getRDSInstanceOptionsByID(t, deviceID)
	case common.VIF_DEVICE_TYPE_REDIS_INSTANCE:
		return getRedisInstanceOptionsByID(t, deviceID)
	case common.VIF_DEVICE_TYPE_POD_NODE:
		return getPodNodeOptionsByID(t, deviceID)
	case common.VIF_DEVICE_TYPE_POD_SERVICE:
		return getPodServiceOptionsByID(t, deviceID)
	case common.VIF_DEVICE_TYPE_POD:
		return getPodOptionsByID(t, deviceID)
	default:
		return nil, fmt.Errorf("device type %d not supported", deviceType)
	}
}

func getHostOptionsByID(t *cache.ToolDataSet, id int) ([]eventapi.TagFieldOption, error) {
	info, err := t.GetHostInfoByID(id)
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

func getVMOptionsByID(t *cache.ToolDataSet, id int) ([]eventapi.TagFieldOption, error) {
	info, err := t.GetVMInfoByID(id)
	if err != nil {
		return nil, err
	}

	var opts []eventapi.TagFieldOption
	opts = append(opts, []eventapi.TagFieldOption{
		eventapi.TagRegionID(info.RegionID),
		eventapi.TagAZID(info.AZID),
		eventapi.TagVPCID(info.VPCID),
		eventapi.TagHostID(info.HostID),
		eventapi.TagL3DeviceType(common.VIF_DEVICE_TYPE_VM),
		eventapi.TagL3DeviceID(id),
	}...)
	return opts, nil
}

func getVRouterOptionsByID(t *cache.ToolDataSet, id int) ([]eventapi.TagFieldOption, error) {
	info, err := t.GetVRouterInfoByID(id)
	if err != nil {
		return nil, err
	}

	var opts []eventapi.TagFieldOption
	opts = append(opts, []eventapi.TagFieldOption{
		eventapi.TagRegionID(info.RegionID),
		eventapi.TagVPCID(info.VPCID),
		eventapi.TagL3DeviceType(common.VIF_DEVICE_TYPE_VROUTER),
		eventapi.TagL3DeviceID(id),
	}...)

	hostID, ok := t.GetHostIDByIP(info.GWLaunchServer)
	if !ok {
		log.Error(idByIPNotFound(RESOURCE_TYPE_HOST_EN, info.GWLaunchServer))
	} else {
		opts = append(opts, []eventapi.TagFieldOption{
			eventapi.TagHostID(hostID),
		}...)
	}

	return opts, nil
}

func getDHCPPortOptionsByID(t *cache.ToolDataSet, id int) ([]eventapi.TagFieldOption, error) {
	info, err := t.GetDHCPPortInfoByID(id)
	if err != nil {
		return nil, err
	}

	var opts []eventapi.TagFieldOption
	opts = append(opts, []eventapi.TagFieldOption{
		eventapi.TagRegionID(info.RegionID),
		eventapi.TagAZID(info.AZID),
		eventapi.TagVPCID(info.VPCID),
		eventapi.TagL3DeviceType(common.VIF_DEVICE_TYPE_DHCP_PORT),
		eventapi.TagL3DeviceID(id),
	}...)
	return opts, nil
}

func getNatGateWayOptionsByID(t *cache.ToolDataSet, id int) ([]eventapi.TagFieldOption, error) {
	info, err := t.GetNATGatewayInfoByID(id)
	if err != nil {
		return nil, err
	}

	var opts []eventapi.TagFieldOption
	opts = append(opts, []eventapi.TagFieldOption{
		eventapi.TagRegionID(info.RegionID),
		eventapi.TagAZID(info.AZID),
		eventapi.TagVPCID(info.VPCID),
		eventapi.TagL3DeviceType(common.VIF_DEVICE_TYPE_NAT_GATEWAY),
		eventapi.TagL3DeviceID(id),
	}...)
	return opts, nil
}

func getLBOptionsByID(t *cache.ToolDataSet, id int) ([]eventapi.TagFieldOption, error) {
	info, err := t.GetLBInfoByID(id)
	if err != nil {
		return nil, err
	}

	var opts []eventapi.TagFieldOption
	opts = append(opts, []eventapi.TagFieldOption{
		eventapi.TagRegionID(info.RegionID),
		eventapi.TagVPCID(info.VPCID),
		eventapi.TagL3DeviceType(common.VIF_DEVICE_TYPE_LB),
		eventapi.TagL3DeviceID(id),
	}...)
	return opts, nil
}

func getRDSInstanceOptionsByID(t *cache.ToolDataSet, id int) ([]eventapi.TagFieldOption, error) {
	info, err := t.GetRDSInstanceInfoByID(id)
	if err != nil {
		return nil, err
	}

	var opts []eventapi.TagFieldOption
	opts = append(opts, []eventapi.TagFieldOption{
		eventapi.TagRegionID(info.RegionID),
		eventapi.TagAZID(info.AZID),
		eventapi.TagVPCID(info.VPCID),
		eventapi.TagL3DeviceType(common.VIF_DEVICE_TYPE_RDS_INSTANCE),
		eventapi.TagL3DeviceID(id),
	}...)
	return opts, nil
}

func getRedisInstanceOptionsByID(t *cache.ToolDataSet, id int) ([]eventapi.TagFieldOption, error) {
	info, err := t.GetRedisInstanceInfoByID(id)
	if err != nil {
		return nil, err
	}

	var opts []eventapi.TagFieldOption
	opts = append(opts, []eventapi.TagFieldOption{
		eventapi.TagRegionID(info.RegionID),
		eventapi.TagAZID(info.AZID),
		eventapi.TagVPCID(info.VPCID),
		eventapi.TagL3DeviceType(common.VIF_DEVICE_TYPE_REDIS_INSTANCE),
		eventapi.TagL3DeviceID(id),
	}...)
	return opts, nil
}

func getPodNodeOptionsByID(t *cache.ToolDataSet, id int) ([]eventapi.TagFieldOption, error) {
	info, err := t.GetPodNodeInfoByID(id)
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

func getPodServiceOptionsByID(t *cache.ToolDataSet, id int) ([]eventapi.TagFieldOption, error) {
	info, err := t.GetPodServiceInfoByID(id)
	if err != nil {
		return nil, err
	}

	var opts []eventapi.TagFieldOption
	opts = append(opts, []eventapi.TagFieldOption{
		eventapi.TagRegionID(info.RegionID),
		eventapi.TagAZID(info.AZID),
		eventapi.TagVPCID(info.VPCID),
		eventapi.TagL3DeviceType(common.VIF_DEVICE_TYPE_POD_SERVICE),
		eventapi.TagL3DeviceID(id),
		eventapi.TagPodClusterID(info.PodClusterID),
		eventapi.TagPodNSID(info.PodNamespaceID),
		eventapi.TagPodServiceID(id),
	}...)
	return opts, nil
}

func getPodOptionsByID(t *cache.ToolDataSet, id int) ([]eventapi.TagFieldOption, error) {
	info, err := t.GetPodInfoByID(id)
	if err != nil {
		return nil, err
	}

	var opts []eventapi.TagFieldOption
	opts = append(opts, []eventapi.TagFieldOption{
		eventapi.TagRegionID(info.RegionID),
		eventapi.TagAZID(info.AZID),
		eventapi.TagVPCID(info.VPCID),
		eventapi.TagPodClusterID(info.PodClusterID),
		eventapi.TagPodNSID(info.PodNamespaceID),
		eventapi.TagPodGroupID(info.PodGroupID),
		eventapi.TagPodNodeID(info.PodNodeID),
		eventapi.TagPodID(id),
	}...)
	return opts, nil
}

func getL3DeviceOptionsByPodNodeID(t *cache.ToolDataSet, id int) (opts []eventapi.TagFieldOption, ok bool) {
	vmID, ok := t.GetVMIDByPodNodeID(id)
	if ok {
		opts = append(opts, []eventapi.TagFieldOption{eventapi.TagL3DeviceType(common.VIF_DEVICE_TYPE_VM), eventapi.TagL3DeviceID(vmID)}...)
		vmInfo, err := t.GetVMInfoByID(vmID)
		if err != nil {
			log.Error(err)
		} else {
			opts = append(opts, eventapi.TagHostID(vmInfo.HostID))
		}
	}
	return
}

func findFromAllByID[MT constraint.MySQLSoftDeleteModel](id int) *MT {
	var item *MT
	res := mysql.Db.Unscoped().Where("id = ?", id).Find(&item)
	if res.Error != nil {
		log.Error(dbQueryFailed(res.Error))
		return nil
	}
	if res.RowsAffected != 1 {
		return nil
	}
	return item
}

func getDeviceNameFromAllByID(deviceType, deviceID int) string {
	switch deviceType {
	case common.VIF_DEVICE_TYPE_HOST:
		device := findFromAllByID[mysql.Host](deviceID)
		if device == nil {
			log.Errorf(dbSoftDeletedResourceByIDNotFound(RESOURCE_TYPE_HOST_EN, deviceID))
		} else {
			return device.Name
		}
	case common.VIF_DEVICE_TYPE_VM:
		device := findFromAllByID[mysql.VM](deviceID)
		if device == nil {
			log.Errorf(dbSoftDeletedResourceByIDNotFound(RESOURCE_TYPE_VM_EN, deviceID))
		} else {
			return device.Name
		}
	case common.VIF_DEVICE_TYPE_VROUTER:
		device := findFromAllByID[mysql.VRouter](deviceID)
		if device == nil {
			log.Errorf(dbSoftDeletedResourceByIDNotFound(RESOURCE_TYPE_VROUTER_EN, deviceID))
		} else {
			return device.Name
		}
	case common.VIF_DEVICE_TYPE_DHCP_PORT:
		device := findFromAllByID[mysql.DHCPPort](deviceID)
		if device == nil {
			log.Errorf(dbSoftDeletedResourceByIDNotFound(RESOURCE_TYPE_DHCP_PORT_EN, deviceID))
		} else {
			return device.Name
		}
	case common.VIF_DEVICE_TYPE_NAT_GATEWAY:
		device := findFromAllByID[mysql.NATGateway](deviceID)
		if device == nil {
			log.Errorf(dbSoftDeletedResourceByIDNotFound(RESOURCE_TYPE_NAT_GATEWAY_EN, deviceID))
		} else {
			return device.Name
		}
	case common.VIF_DEVICE_TYPE_LB:
		device := findFromAllByID[mysql.LB](deviceID)
		if device == nil {
			log.Errorf(dbSoftDeletedResourceByIDNotFound(RESOURCE_TYPE_LB_EN, deviceID))
		} else {
			return device.Name
		}
	case common.VIF_DEVICE_TYPE_RDS_INSTANCE:
		device := findFromAllByID[mysql.RDSInstance](deviceID)
		if device == nil {
			log.Errorf(dbSoftDeletedResourceByIDNotFound(RESOURCE_TYPE_RDS_INSTANCE_EN, deviceID))
		} else {
			return device.Name
		}
	case common.VIF_DEVICE_TYPE_REDIS_INSTANCE:
		device := findFromAllByID[mysql.RedisInstance](deviceID)
		if device == nil {
			log.Errorf(dbSoftDeletedResourceByIDNotFound(RESOURCE_TYPE_REDIS_INSTANCE_EN, deviceID))
		} else {
			return device.Name
		}
	case common.VIF_DEVICE_TYPE_POD_NODE:
		device := findFromAllByID[mysql.PodNode](deviceID)
		if device == nil {
			log.Errorf(dbSoftDeletedResourceByIDNotFound(RESOURCE_TYPE_POD_NODE_EN, deviceID))
		} else {
			return device.Name
		}
	case common.VIF_DEVICE_TYPE_POD_SERVICE:
		device := findFromAllByID[mysql.PodService](deviceID)
		if device == nil {
			log.Errorf(dbSoftDeletedResourceByIDNotFound(RESOURCE_TYPE_POD_SERVICE_EN, deviceID))
		} else {
			return device.Name
		}
	case common.VIF_DEVICE_TYPE_POD:
		device := findFromAllByID[mysql.Pod](deviceID)
		if device == nil {
			log.Errorf(dbSoftDeletedResourceByIDNotFound(RESOURCE_TYPE_POD_EN, deviceID))
		} else {
			return device.Name
		}
	default:
		log.Errorf("device type: %d is not supported", deviceType)
		return ""
	}
	return ""
}
