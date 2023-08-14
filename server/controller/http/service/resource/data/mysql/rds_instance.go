/**
 * Copyright (c) 2023 Yunshan Networks
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

package mysql

import (
	"golang.org/x/exp/slices"

	ctrlrcommon "github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	"github.com/deepflowio/deepflow/server/controller/http/service/resource/common"
)

type RDSInstance struct {
	DataProvider
	dataTool *rdsInstanceToolData
}

func NewRDSInstance() *RDSInstance {
	dp := &RDSInstance{newDataProvider(ctrlrcommon.RESOURCE_TYPE_RDS_INSTANCE_EN), new(rdsInstanceToolData)}
	dp.setGenerator(dp)
	return dp
}

func (v *RDSInstance) generate() (data []common.ResponseElem, err error) {
	err = v.dataTool.Init().Load()
	for _, item := range v.dataTool.rdsInstances {
		data = append(data, v.generateOne(item))
	}
	return
}

func (v *RDSInstance) generateOne(item mysql.RDSInstance) common.ResponseElem {
	d := MySQLModelToMap(item)
	d["DOMAIN_NAME"] = v.dataTool.domainLcuuidToName[item.Domain]
	d["REGION_NAME"] = v.dataTool.regionLcuuidToName[item.Region]
	d["AZ_NAME"] = v.dataTool.azLcuuidToName[item.AZ]
	d["EPC_NAME"] = v.dataTool.vpcIDToName[item.VPCID]
	d["NETS"] = v.dataTool.rdsInsIDToNetworkInfos[item.ID]
	d["WAN_IPS"] = v.dataTool.rdsInsIDToWANIPs[item.ID]
	d["LAN_IPS"] = v.dataTool.rdsInsIDToLANIPs[item.ID]
	d["ALL_IPS"] = append(v.dataTool.rdsInsIDToWANIPs[item.ID], v.dataTool.rdsInsIDToLANIPs[item.ID]...)

	d["CREATED_AT"] = item.CreatedAt.Format(ctrlrcommon.GO_BIRTHDAY)
	d["UPDATED_AT"] = item.UpdatedAt.Format(ctrlrcommon.GO_BIRTHDAY)
	return d
}

type rdsInstanceToolData struct {
	rdsInstances []mysql.RDSInstance

	domainLcuuidToName map[string]string
	regionLcuuidToName map[string]string
	azLcuuidToName     map[string]string
	vpcIDToName        map[int]string

	rdsInsIDToNetworkInfos map[int][]map[string]interface{}
	rdsInsIDToWANIPs       map[int][]string
	rdsInsIDToLANIPs       map[int][]string
}

func (td *rdsInstanceToolData) Init() *rdsInstanceToolData {
	td.domainLcuuidToName = make(map[string]string)
	td.regionLcuuidToName = make(map[string]string)
	td.azLcuuidToName = make(map[string]string)
	td.vpcIDToName = make(map[int]string)

	td.rdsInsIDToNetworkInfos = make(map[int][]map[string]interface{})
	td.rdsInsIDToWANIPs = make(map[int][]string)
	td.rdsInsIDToLANIPs = make(map[int][]string)
	return td
}

func (td *rdsInstanceToolData) Load() (err error) {
	td.rdsInstances, err = UnscopedOrderFind[mysql.RDSInstance]("created_at DESC")
	if err != nil {
		return err
	}

	domains, err := Select[mysql.Domain]([]string{"lcuuid", "name"})
	if err != nil {
		return err
	}
	for _, item := range domains {
		td.domainLcuuidToName[item.Lcuuid] = item.Name
	}

	regions, err := Select[mysql.Region]([]string{"lcuuid", "name"})
	if err != nil {
		return err
	}
	for _, item := range regions {
		td.regionLcuuidToName[item.Lcuuid] = item.Name
	}

	azs, err := Select[mysql.AZ]([]string{"lcuuid", "name"})
	if err != nil {
		return err
	}
	for _, item := range azs {
		td.azLcuuidToName[item.Lcuuid] = item.Name
	}

	vpcs, err := Select[mysql.VPC]([]string{"id", "name"})
	if err != nil {
		return err
	}
	for _, item := range vpcs {
		td.vpcIDToName[item.ID] = item.Name
	}

	networks, err := Select[mysql.Network]([]string{"id", "name"})
	if err != nil {
		return err
	}
	idToNetwork := make(map[int]mysql.Network)
	for _, item := range networks {
		idToNetwork[item.ID] = item
	}

	vifs, err := SelectWithQuery[mysql.VInterface]([]string{"id", "subnetid", "deviceid"}, "devicetype = ?", ctrlrcommon.VIF_DEVICE_TYPE_RDS_INSTANCE)
	if err != nil {
		return err
	}
	vifIDs := make([]int, 0, len(vifs))
	for _, item := range vifs {
		vifIDs = append(vifIDs, item.ID)
	}
	wanIPs, err := SelectWithQuery[mysql.WANIP]([]string{"vifid", "ip"}, "vifid in (?)", vifIDs)
	if err != nil {
		return err
	}
	vifIDToWANIPs := make(map[int][]string)
	for _, item := range wanIPs {
		vifIDToWANIPs[item.VInterfaceID] = append(vifIDToWANIPs[item.VInterfaceID], item.IP)
	}
	lanIPs, err := SelectWithQuery[mysql.LANIP]([]string{"vifid", "ip"}, "vifid in (?)", vifIDs)
	if err != nil {
		return err
	}
	vifIDToLANIPs := make(map[int][]string)
	for _, item := range lanIPs {
		vifIDToLANIPs[item.VInterfaceID] = append(vifIDToLANIPs[item.VInterfaceID], item.IP)
	}
	rdsInsIDToNetworkIDs := make(map[int][]int)
	for _, item := range vifs {
		if slices.Contains(rdsInsIDToNetworkIDs[item.DeviceID], item.NetworkID) {
			rdsInsIDToNetworkIDs[item.DeviceID] = append(rdsInsIDToNetworkIDs[item.DeviceID], item.NetworkID)
			td.rdsInsIDToNetworkInfos[item.DeviceID] = append(td.rdsInsIDToNetworkInfos[item.DeviceID], map[string]interface{}{"VL2_ID": item.NetworkID, "VL2_NAME": idToNetwork[item.NetworkID].Name})
		}
		td.rdsInsIDToWANIPs[item.DeviceID] = append(td.rdsInsIDToWANIPs[item.DeviceID], vifIDToWANIPs[item.ID]...)
		td.rdsInsIDToLANIPs[item.DeviceID] = append(td.rdsInsIDToLANIPs[item.DeviceID], vifIDToLANIPs[item.ID]...)
	}
	return nil
}
