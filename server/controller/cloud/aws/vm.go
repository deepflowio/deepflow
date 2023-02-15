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

package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/deepflowio/deepflow/server/controller/cloud/model"
	"github.com/deepflowio/deepflow/server/controller/common"
	uuid "github.com/satori/go.uuid"
)

func (a *Aws) getVMs(region awsRegion) ([]model.VM, []model.VMSecurityGroup, error) {
	log.Debug("get vms starting")
	a.vmIDToPrivateIP = map[string]string{}
	var vms []model.VM
	var vmSGs []model.VMSecurityGroup
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
		result, err := a.ec2Client.DescribeInstances(context.TODO(), input)
		if err != nil {
			log.Errorf("vm request aws api error: (%s)", err.Error())
			return []model.VM{}, []model.VMSecurityGroup{}, err
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
				log.Debug("placement is nil")
				continue
			}
			azLcuuid := common.GetUUID(a.getStringPointerValue(ins.Placement.AvailabilityZone), uuid.Nil)
			instanceID := a.getStringPointerValue(ins.InstanceId)
			vmName := a.getResultTagName(ins.Tags)
			if vmName == "" {
				vmName = instanceID
			}
			vmLcuuid := common.GetUUID(instanceID, uuid.Nil)
			vmState, ok := states[string(ins.State.Name)]
			if !ok {
				vmState = common.VM_STATE_EXCEPTION
			}
			vms = append(vms, model.VM{
				Lcuuid:       vmLcuuid,
				Name:         vmName,
				Label:        instanceID,
				VPCLcuuid:    common.GetUUID(a.getStringPointerValue(ins.VpcId), uuid.Nil),
				State:        vmState,
				HType:        common.VM_HTYPE_VM_C,
				CreatedAt:    a.getTimePointerValue(ins.LaunchTime),
				AZLcuuid:     azLcuuid,
				RegionLcuuid: a.getRegionLcuuid(region.lcuuid),
			})
			a.azLcuuidMap[azLcuuid] = 0
			a.vmIDToPrivateIP[instanceID] = a.getStringPointerValue(ins.PrivateIpAddress)

			for priority, sg := range ins.SecurityGroups {
				vmSGs = append(vmSGs, model.VMSecurityGroup{
					Lcuuid:              common.GetUUID(vmLcuuid+a.getStringPointerValue(sg.GroupId), uuid.Nil),
					SecurityGroupLcuuid: common.GetUUID(a.getStringPointerValue(sg.GroupId), uuid.Nil),
					VMLcuuid:            vmLcuuid,
					Priority:            priority,
				})
			}
		}
	}
	log.Debug("get vms complete")
	return vms, vmSGs, nil
}
