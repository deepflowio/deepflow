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
	"errors"
	"fmt"

	"github.com/deepflowys/deepflow/server/controller/common"
	"github.com/deepflowys/deepflow/server/controller/recorder/cache"
	. "github.com/deepflowys/deepflow/server/controller/recorder/common"
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

func addErrMessage(err error, message string) error {
	if err == nil {
		return errors.New(message)
	}
	if message == "" {
		return err
	}
	return fmt.Errorf("%w, %s", err, message)
}

func getHostOptionsByID(t *cache.ToolDataSet, id int) ([]eventapi.TagFieldOption, error) {
	info, err := t.GetHostInfoByID(id)
	if err != nil {
		return nil, err
	}
	var resultErr error
	regionID, azID, err := getRegionIDAndAZIDByLcuuid(t, info.RegionLcuuid, info.AZLcuuid)
	if err != nil {
		resultErr = addErrMessage(resultErr, err.Error())
	}
	var opts []eventapi.TagFieldOption
	opts = append(opts, []eventapi.TagFieldOption{
		eventapi.TagRegionID(regionID),
		eventapi.TagAZID(azID),
	}...)
	return opts, resultErr
}

func getVMOptionsByID(t *cache.ToolDataSet, id int) ([]eventapi.TagFieldOption, error) {
	info, err := t.GetVMInfoByID(id)
	if err != nil {
		return nil, err
	}
	var resultErr error
	regionID, azID, err := getRegionIDAndAZIDByLcuuid(t, info.RegionLcuuid, info.AZLcuuid)
	if err != nil {
		resultErr = addErrMessage(resultErr, err.Error())
	}
	hostID, exists := t.GetHostIDByIP(info.LaunchServer)
	if !exists {
		resultErr = addErrMessage(resultErr, fmt.Sprintf("host id for %s (ip: %d) not found", RESOURCE_TYPE_HOST_EN, id))
	}

	var opts []eventapi.TagFieldOption
	opts = append(opts, []eventapi.TagFieldOption{
		eventapi.TagRegionID(regionID),
		eventapi.TagAZID(azID),
		eventapi.TagVPCID(info.VPCID),
		eventapi.TagHostID(hostID),
		eventapi.TagL3DeviceType(common.VIF_DEVICE_TYPE_VM),
		eventapi.TagL3DeviceID(id),
	}...)
	return opts, resultErr
}

func getVRouterOptionsByID(t *cache.ToolDataSet, id int) ([]eventapi.TagFieldOption, error) {
	info, err := t.GetVRouterInfoByID(id)
	if err != nil {
		return nil, err
	}
	var resultErr error
	regionID, azID, err := getRegionIDAndAZIDByLcuuid(t, info.RegionLcuuid, info.AZLcuuid)
	if err != nil {
		resultErr = addErrMessage(resultErr, err.Error())
	}

	var opts []eventapi.TagFieldOption
	opts = append(opts, []eventapi.TagFieldOption{
		eventapi.TagRegionID(regionID),
		eventapi.TagAZID(azID),
		eventapi.TagVPCID(info.VPCID),
		eventapi.TagL3DeviceType(common.VIF_DEVICE_TYPE_VROUTER),
		eventapi.TagL3DeviceID(id),
	}...)
	return opts, nil
}

func getDHCPPortOptionsByID(t *cache.ToolDataSet, id int) ([]eventapi.TagFieldOption, error) {
	info, err := t.GetVRouterInfoByID(id)
	if err != nil {
		return nil, err
	}
	var resultErr error
	regionID, azID, err := getRegionIDAndAZIDByLcuuid(t, info.RegionLcuuid, info.AZLcuuid)
	if err != nil {
		resultErr = addErrMessage(resultErr, err.Error())
	}

	var opts []eventapi.TagFieldOption
	opts = append(opts, []eventapi.TagFieldOption{
		eventapi.TagRegionID(regionID),
		eventapi.TagAZID(azID),
		eventapi.TagVPCID(info.VPCID),
		eventapi.TagL3DeviceType(common.VIF_DEVICE_TYPE_DHCP_PORT),
		eventapi.TagL3DeviceID(id),
	}...)
	return opts, resultErr
}

func getNatGateWayOptionsByID(t *cache.ToolDataSet, id int) ([]eventapi.TagFieldOption, error) {
	info, err := t.GetNATGatewayInfoByID(id)
	if err != nil {
		return nil, err
	}
	var resultErr error
	regionID, azID, err := getRegionIDAndAZIDByLcuuid(t, info.RegionLcuuid, info.AZLcuuid)
	if err != nil {
		resultErr = addErrMessage(resultErr, err.Error())
	}

	var opts []eventapi.TagFieldOption
	opts = append(opts, []eventapi.TagFieldOption{
		eventapi.TagRegionID(regionID),
		eventapi.TagAZID(azID),
		eventapi.TagVPCID(info.VPCID),
		eventapi.TagL3DeviceType(common.VIF_DEVICE_TYPE_NAT_GATEWAY),
		eventapi.TagL3DeviceID(id),
	}...)
	return opts, resultErr
}

func getLBOptionsByID(t *cache.ToolDataSet, id int) ([]eventapi.TagFieldOption, error) {
	info, err := t.GetLBInfoByID(id)
	if err != nil {
		return nil, err
	}
	var resultErr error
	regionID, azID, err := getRegionIDAndAZIDByLcuuid(t, info.RegionLcuuid, info.AZLcuuid)
	if err != nil {
		resultErr = addErrMessage(resultErr, err.Error())
	}

	var opts []eventapi.TagFieldOption
	opts = append(opts, []eventapi.TagFieldOption{
		eventapi.TagRegionID(regionID),
		eventapi.TagAZID(azID),
		eventapi.TagVPCID(info.VPCID),
		eventapi.TagL3DeviceType(common.VIF_DEVICE_TYPE_LB),
		eventapi.TagL3DeviceID(id),
	}...)
	return opts, resultErr
}

func getRDSInstanceOptionsByID(t *cache.ToolDataSet, id int) ([]eventapi.TagFieldOption, error) {
	info, err := t.GetRDSInstanceInfoByID(id)
	if err != nil {
		return nil, err
	}
	var resultErr error
	regionID, azID, err := getRegionIDAndAZIDByLcuuid(t, info.RegionLcuuid, info.AZLcuuid)
	if err != nil {
		resultErr = addErrMessage(resultErr, err.Error())
	}

	var opts []eventapi.TagFieldOption
	opts = append(opts, []eventapi.TagFieldOption{
		eventapi.TagRegionID(regionID),
		eventapi.TagAZID(azID),
		eventapi.TagVPCID(info.VPCID),
		eventapi.TagL3DeviceType(common.VIF_DEVICE_TYPE_RDS_INSTANCE),
		eventapi.TagL3DeviceID(id),
	}...)
	return opts, resultErr
}

func getRedisInstanceOptionsByID(t *cache.ToolDataSet, id int) ([]eventapi.TagFieldOption, error) {
	info, err := t.GetRedisInstanceInfoByID(id)
	if err != nil {
		return nil, err
	}
	var resultErr error
	regionID, azID, err := getRegionIDAndAZIDByLcuuid(t, info.RegionLcuuid, info.AZLcuuid)
	if err != nil {
		resultErr = addErrMessage(resultErr, err.Error())
	}

	var opts []eventapi.TagFieldOption
	opts = append(opts, []eventapi.TagFieldOption{
		eventapi.TagRegionID(regionID),
		eventapi.TagAZID(azID),
		eventapi.TagVPCID(info.VPCID),
		eventapi.TagL3DeviceType(common.VIF_DEVICE_TYPE_REDIS_INSTANCE),
		eventapi.TagL3DeviceID(id),
	}...)
	return opts, resultErr
}

func getPodNodeOptionsByID(t *cache.ToolDataSet, id int) ([]eventapi.TagFieldOption, error) {
	info, err := t.GetPodNodeInfoByID(id)
	if err != nil {
		return nil, err
	}
	var resultErr error
	regionID, azID, err := getRegionIDAndAZIDByLcuuid(t, info.RegionLcuuid, info.AZLcuuid)
	if err != nil {
		resultErr = addErrMessage(resultErr, err.Error())
	}

	var opts []eventapi.TagFieldOption
	opts = append(opts, []eventapi.TagFieldOption{
		eventapi.TagRegionID(regionID),
		eventapi.TagAZID(azID),
		eventapi.TagVPCID(info.VPCID),
		eventapi.TagPodClusterID(info.PodClusterID),
	}...)
	return opts, resultErr
}

func getPodServiceOptionsByID(t *cache.ToolDataSet, id int) ([]eventapi.TagFieldOption, error) {
	info, err := t.GetPodServiceInfoByID(id)
	if err != nil {
		return nil, err
	}
	var resultErr error
	regionID, azID, err := getRegionIDAndAZIDByLcuuid(t, info.RegionLcuuid, info.AZLcuuid)
	if err != nil {
		resultErr = addErrMessage(resultErr, err.Error())
	}

	var opts []eventapi.TagFieldOption
	opts = append(opts, []eventapi.TagFieldOption{
		eventapi.TagRegionID(regionID),
		eventapi.TagAZID(azID),
		eventapi.TagVPCID(info.VPCID),
		eventapi.TagL3DeviceType(common.VIF_DEVICE_TYPE_POD_SERVICE),
		eventapi.TagL3DeviceID(id),
		eventapi.TagPodClusterID(info.PodClusterID),
		eventapi.TagPodNSID(info.PodNSID),
	}...)
	return opts, resultErr
}

func getPodOptionsByID(t *cache.ToolDataSet, id int) ([]eventapi.TagFieldOption, error) {
	info, err := t.GetPodInfoeByID(id)
	if err != nil {
		return nil, err
	}
	var resultErr error
	regionID, azID, err := getRegionIDAndAZIDByLcuuid(t, info.RegionLcuuid, info.AZLcuuid)
	if err != nil {
		resultErr = addErrMessage(resultErr, err.Error())
	}

	var opts []eventapi.TagFieldOption
	opts = append(opts, []eventapi.TagFieldOption{
		eventapi.TagRegionID(regionID),
		eventapi.TagAZID(azID),
		eventapi.TagVPCID(info.VPCID),
		eventapi.TagPodClusterID(info.PodClusterID),
		eventapi.TagPodNSID(info.PodNSID),
		eventapi.TagPodGroupID(info.PodGroupID),
		eventapi.TagPodNodeID(info.PodNodeID),
	}...)
	return opts, resultErr
}

func getRegionIDAndAZIDByLcuuid(t *cache.ToolDataSet, regionLcuuid, azLcuuid string) (regionID, azID int, err error) {
	regionID, ok := t.GetRegionIDByLcuuid(regionLcuuid)
	if !ok {
		return 0, 0, fmt.Errorf("%s (lcuuid: %s) id not found", RESOURCE_TYPE_REGION_EN, regionLcuuid)
	}
	azID, ok = t.GetAZIDByLcuuid(azLcuuid)
	if !ok {
		return 0, 0, fmt.Errorf("%s (lcuuid: %s) id not found", RESOURCE_TYPE_AZ_EN, azLcuuid)
	}
	return
}
