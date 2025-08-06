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
	"errors"
	"fmt"

	ctrlrcommon "github.com/deepflowio/deepflow/server/controller/common"
	metadbmodel "github.com/deepflowio/deepflow/server/controller/db/metadb/model"
	"github.com/deepflowio/deepflow/server/controller/recorder/pubsub"
	"github.com/deepflowio/deepflow/server/controller/recorder/pubsub/message"
	"github.com/deepflowio/deepflow/server/libs/eventapi"
	"github.com/deepflowio/deepflow/server/libs/queue"
)

var (
	VMStateToString = map[int]string{
		ctrlrcommon.VM_STATE_RUNNING:   "running",
		ctrlrcommon.VM_STATE_STOPPED:   "stopped",
		ctrlrcommon.VM_STATE_EXCEPTION: "exception",
	}
)

type VM struct {
	ManagerComponent
	CUDSubscriberComponent
	deviceType int
}

func NewVM(q *queue.OverwriteQueue) *VM {
	mng := &VM{
		newManagerComponent(ctrlrcommon.RESOURCE_TYPE_VM_EN, q),
		newCUDSubscriberComponent(ctrlrcommon.RESOURCE_TYPE_VM_EN, SubTopic(pubsub.TopicResourceUpdatedMessage)),
		ctrlrcommon.VIF_DEVICE_TYPE_VM,
	}
	mng.SetSubscriberSelf(mng)
	return mng
}

func (v *VM) OnResourceBatchAdded(md *message.Metadata, msg interface{}) {
	for _, item := range msg.([]*metadbmodel.VM) {
		var opts []eventapi.TagFieldOption
		info, err := md.GetToolDataSet().GetVMInfoByID(item.ID)
		if err != nil {
			log.Error(err)
		} else {
			opts = append(opts, []eventapi.TagFieldOption{
				eventapi.TagAZID(info.AZID),
				eventapi.TagRegionID(info.RegionID),
				eventapi.TagHostID(info.HostID),
			}...)
		}
		opts = append(opts, []eventapi.TagFieldOption{
			eventapi.TagL3DeviceType(v.deviceType),
			eventapi.TagL3DeviceID(item.ID),
			eventapi.TagVPCID(item.VPCID),
		}...)

		v.createInstanceAndEnqueue(md,
			item.Lcuuid,
			eventapi.RESOURCE_EVENT_TYPE_CREATE,
			item.Name,
			v.deviceType,
			item.ID,
			opts...,
		)
	}
}

func (v *VM) OnResourceUpdated(md *message.Metadata, msg interface{}) {
	updateMsg := msg.(*message.UpdatedVM)
	dbItemNew := updateMsg.GetNewMetadbItem().(*metadbmodel.VM)
	updatedFields := updateMsg.GetFields().(*message.UpdatedVMFields)
	id := updatedFields.GetID()

	var eType string
	var description string
	if updatedFields.LaunchServer.IsDifferent() {
		eType = eventapi.RESOURCE_EVENT_TYPE_MIGRATE
		description = fmt.Sprintf(DESCMigrateFormat, dbItemNew.Name, updatedFields.LaunchServer.GetOld(), updatedFields.LaunchServer.GetNew())
	}
	if updatedFields.State.IsDifferent() {
		eType = eventapi.RESOURCE_EVENT_TYPE_UPDATE_STATE
		description = fmt.Sprintf(DESCStateChangeFormat, dbItemNew.Name,
			VMStateToString[updatedFields.State.GetOld()], VMStateToString[updatedFields.State.GetNew()])
	}
	if eType == "" {
		return
	}

	nIDs, ips := v.getIPNetworksByID(md, id)
	opts := []eventapi.TagFieldOption{
		eventapi.TagDescription(description),
		eventapi.TagAttributeSubnetIDs(nIDs),
		eventapi.TagAttributeIPs(ips),
	}
	if len(nIDs) > 0 {
		opts = append(opts, eventapi.TagSubnetID(nIDs[0]))
	}
	if len(ips) > 0 {
		opts = append(opts, eventapi.TagIP(ips[0]))
	}
	v.createInstanceAndEnqueue(
		md,
		updatedFields.GetLcuuid(),
		eType,
		dbItemNew.Name,
		ctrlrcommon.VIF_DEVICE_TYPE_VM,
		id,
		opts...,
	)
}

func (v *VM) OnResourceBatchDeleted(md *message.Metadata, msg interface{}) {
	for _, item := range msg.([]*metadbmodel.VM) {
		v.createInstanceAndEnqueue(md, item.Lcuuid, eventapi.RESOURCE_EVENT_TYPE_DELETE, item.Name, v.deviceType, item.ID)
	}
}

func (v *VM) getIPNetworksByID(md *message.Metadata, id int) (networkIDs []uint32, ips []string) {
	ipNetworkMap, _ := md.GetToolDataSet().EventDataSet.GetVMIPNetworkMapByID(id)
	for ip, nID := range ipNetworkMap {
		networkIDs = append(networkIDs, uint32(nID))
		ips = append(ips, ip.IP)
	}
	return
}

func (v *VM) getVMIDAndNameByLcuuid(md *message.Metadata, lcuuid string) (int, string, error) {
	id, ok := md.GetToolDataSet().GetVMIDByLcuuid(lcuuid)
	if !ok {
		return 0, "", errors.New(nameByIDNotFound(v.resourceType, id))
	}
	name, err := md.GetToolDataSet().GetVMNameByID(id)
	if !ok {
		return 0, "", err
	}

	return id, name, nil
}
