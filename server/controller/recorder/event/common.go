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

	"github.com/deepflowys/deepflow/server/controller/common"
	"github.com/deepflowys/deepflow/server/controller/recorder/cache"
	"github.com/deepflowys/deepflow/server/libs/eventapi"
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
		eventapi.TagPodNSID(info.PodNSID),
		eventapi.TagPodServiceID(id),
	}...)
	return opts, nil
}

func getPodOptionsByID(t *cache.ToolDataSet, id int) ([]eventapi.TagFieldOption, error) {
	info, err := t.GetPodInfoeByID(id)
	if err != nil {
		return nil, err
	}

	var opts []eventapi.TagFieldOption
	opts = append(opts, []eventapi.TagFieldOption{
		eventapi.TagRegionID(info.RegionID),
		eventapi.TagAZID(info.AZID),
		eventapi.TagVPCID(info.VPCID),
		eventapi.TagPodClusterID(info.PodClusterID),
		eventapi.TagPodNSID(info.PodNSID),
		eventapi.TagPodGroupID(info.PodGroupID),
		eventapi.TagPodNodeID(info.PodNodeID),
		eventapi.TagPodID(id),
	}...)
	return opts, nil
}
