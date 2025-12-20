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

package tool

import (
	ctrlrcommon "github.com/deepflowio/deepflow/server/controller/common"
	metadbmodel "github.com/deepflowio/deepflow/server/controller/db/metadb/model"
)

// VInterface defines cache data structure.
type VInterface struct {
	lcuuid     string
	id         int
	name       string
	ifType     int
	index      int
	mac        string
	regionID   int
	networkID  int
	vpcID      int
	deviceType int
	deviceID   int
	deviceName string
}

func (t *VInterface) IsValid() bool {
	return t.lcuuid != ""
}

func (t *VInterface) Lcuuid() string {
	return t.lcuuid
}

func (t *VInterface) ID() int {
	return t.id
}

func (t *VInterface) Name() string {
	return t.name
}

func (t *VInterface) Type() int {
	return t.ifType
}

func (t *VInterface) Index() int {
	return t.index
}

func (t *VInterface) Mac() string {
	return t.mac
}

func (t *VInterface) RegionID() int {
	return t.regionID
}

func (t *VInterface) NetworkID() int {
	return t.networkID
}

func (t *VInterface) VPCID() int {
	return t.vpcID
}

func (t *VInterface) DeviceType() int {
	return t.deviceType
}

func (t *VInterface) DeviceID() int {
	return t.deviceID
}

func (t *VInterface) DeviceName() string {
	return t.deviceName
}

func (t *VInterface) reset(dbItem *metadbmodel.VInterface, tool *Tool) {
	t.lcuuid = dbItem.Lcuuid
	t.id = dbItem.ID
	t.name = dbItem.Name
	t.ifType = dbItem.Type
	t.index = dbItem.Index
	t.mac = dbItem.Mac
	t.regionID = tool.Region().GetByLcuuid(dbItem.Region).ID()
	t.networkID = dbItem.NetworkID
	t.vpcID = dbItem.VPCID
	t.deviceType = dbItem.DeviceType
	t.deviceID = dbItem.DeviceID
	t.resetCustom(dbItem, tool)
}

func NewVInterfaceCollection(t *Tool) *VInterfaceCollection {
	c := new(VInterfaceCollection)
	c.resetExt()
	c.collection = newCollectionBuilder[*VInterface]().
		withResourceType(ctrlrcommon.RESOURCE_TYPE_VINTERFACE_EN).
		withTool(t).
		withDBItemFactory(func() *metadbmodel.VInterface { return new(metadbmodel.VInterface) }).
		withCacheItemFactory(func() *VInterface { return new(VInterface) }).
		withExtender(c).
		build()
	return c
}

// VInterfaceCollection defines a collection that maps individual fields to the VInterface cache data structure.
type VInterfaceCollection struct {
	collection[*VInterface, *metadbmodel.VInterface]
	VInterfaceCollectionExt
}
