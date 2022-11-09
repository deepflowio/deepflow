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
	case common.VIF_DEVICE_TYPE_DHCP_PORT:
	case common.VIF_DEVICE_TYPE_NAT_GATEWAY:
	case common.VIF_DEVICE_TYPE_LB:
	case common.VIF_DEVICE_TYPE_RDS_INSTANCE:
	case common.VIF_DEVICE_TYPE_REDIS_INSTANCE:
	case common.VIF_DEVICE_TYPE_POD_NODE:
	case common.VIF_DEVICE_TYPE_POD_SERVICE:
	case common.VIF_DEVICE_TYPE_POD:
	default:
		return nil, fmt.Errorf("device type %d not supported", deviceType)
	}
	return nil, nil
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
	regionLcuuid, exists := t.GetHostRegionLcuuidByID(id)
	var resultErr error
	if !exists {
		resultErr = addErrMessage(resultErr, cacheRegionLcuuidByIDNotFound(RESOURCE_TYPE_HOST_EN, id))
	}
	azLcuuid, exists := t.GetHostAZLcuuidByID(id)
	if !exists {
		resultErr = addErrMessage(resultErr, cacheAZLcuuidByIDNotFound(RESOURCE_TYPE_AZ_EN, id))
	}

	regionID, azID, err := getRegionIDAndAZIDByLcuuid(t, regionLcuuid, azLcuuid)
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
	regionLcuuid, exists := t.GetVMRegionLcuuidByID(id)
	var resultErr error
	if !exists {
		resultErr = addErrMessage(resultErr, cacheRegionLcuuidByIDNotFound(RESOURCE_TYPE_VM_EN, id))
	}
	azLcuuid, exists := t.GetVMAZLcuuidByID(id)
	if !exists {
		resultErr = addErrMessage(resultErr, cacheAZLcuuidByIDNotFound(RESOURCE_TYPE_AZ_EN, id))
	}
	regionID, azID, err := getRegionIDAndAZIDByLcuuid(t, regionLcuuid, azLcuuid)
	if err != nil {
		resultErr = addErrMessage(resultErr, err.Error())
	}

	vpcID, exists := t.GetVMVPCIDByID(id)
	if !exists {
		resultErr = addErrMessage(resultErr, cacheVPCIDByIDNotFound(RESOURCE_TYPE_VM_EN, id))
	}

	launchServer, exists := t.GetVMLaunchServerByID(id)
	if !exists {
		resultErr = addErrMessage(resultErr, cacheLaunchServerByIDNotFound(RESOURCE_TYPE_VM_EN, id))
	}
	hostID, exists := t.GetHostIDByIP(launchServer)
	if !exists {
		resultErr = addErrMessage(resultErr, fmt.Sprintf("host id for %s (ip: %d) not found", RESOURCE_TYPE_HOST_EN, id))
	}

	var opts []eventapi.TagFieldOption
	opts = append(opts, []eventapi.TagFieldOption{
		eventapi.TagRegionID(regionID),
		eventapi.TagAZID(azID),
		eventapi.TagVPCID(vpcID),
		eventapi.TagHostID(hostID),
		eventapi.TagL3DeviceType(common.VIF_DEVICE_TYPE_VM),
		eventapi.TagL3DeviceID(id),
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
