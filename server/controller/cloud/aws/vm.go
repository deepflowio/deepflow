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

package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/deepflowio/deepflow/server/controller/cloud/model"
	"github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/libs/logger"
)

func (a *Aws) getVMs(client *ec2.Client) ([]model.VM, error) {
	log.Debug("get vms starting", logger.NewORGPrefix(a.orgID))
	a.vmIDToPrivateIP = map[string]string{}
	var vms []model.VM
	states := map[string]int{
		"running": common.VM_STATE_RUNNING,
		"stopped": common.VM_STATE_STOPPED,
	}

	var retVMs []types.Reservation
	var nextToken string
	var maxResults int32 = 100
	for {
		var input *ec2.DescribeInstancesInput
		if nextToken == "" {
			input = &ec2.DescribeInstancesInput{MaxResults: &maxResults}
		} else {
			input = &ec2.DescribeInstancesInput{MaxResults: &maxResults, NextToken: &nextToken}
		}
		result, err := client.DescribeInstances(context.TODO(), input)
		if err != nil {
			log.Errorf("vm request aws api error: (%s)", err.Error(), logger.NewORGPrefix(a.orgID))
			return []model.VM{}, err
		}
		retVMs = append(retVMs, result.Reservations...)
		if result.NextToken == nil {
			break
		}
		nextToken = *result.NextToken
	}

	for _, reserve := range retVMs {
		for _, ins := range reserve.Instances {
			if ins.Placement == nil {
				log.Debug("placement is nil", logger.NewORGPrefix(a.orgID))
				continue
			}
			azLcuuid := common.GetUUIDByOrgID(a.orgID, a.getStringPointerValue(ins.Placement.AvailabilityZone))
			instanceID := a.getStringPointerValue(ins.InstanceId)
			vmName := a.getResultTagName(ins.Tags)
			if vmName == "" {
				vmName = instanceID
			}
			vmLcuuid := common.GetUUIDByOrgID(a.orgID, instanceID)
			vmState, ok := states[string(ins.State.Name)]
			if !ok {
				vmState = common.VM_STATE_EXCEPTION
			}
			vms = append(vms, model.VM{
				Lcuuid:       vmLcuuid,
				Name:         vmName,
				Label:        instanceID,
				VPCLcuuid:    common.GetUUIDByOrgID(a.orgID, a.getStringPointerValue(ins.VpcId)),
				State:        vmState,
				HType:        common.VM_HTYPE_VM_C,
				IP:           a.instanceIDToPrimaryIP[instanceID],
				CreatedAt:    a.getTimePointerValue(ins.LaunchTime),
				AZLcuuid:     azLcuuid,
				RegionLcuuid: a.regionLcuuid,
			})
			a.azLcuuidMap[azLcuuid] = 0
			a.vmIDToPrivateIP[instanceID] = a.getStringPointerValue(ins.PrivateIpAddress)
		}
	}
	log.Debug("get vms complete", logger.NewORGPrefix(a.orgID))
	return vms, nil
}
