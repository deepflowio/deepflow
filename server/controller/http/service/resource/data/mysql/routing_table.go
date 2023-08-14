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
	ctrlrcommon "github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	"github.com/deepflowio/deepflow/server/controller/http/service/resource/common"
)

const (
	ROUTING_TABLE_NEXTHOP_TYPE_VPC         = "VPC"
	ROUTING_TABLE_NEXTHOP_TYPE_NAT_GATEWAY = "nat-gateway"
)

type RoutingTable struct {
	DataProvider
	dataTool *routingTableToolData
}

func NewRoutingTable() *RoutingTable {
	dp := &RoutingTable{newDataProvider(ctrlrcommon.RESOURCE_TYPE_ROUTING_TABLE_EN), new(routingTableToolData)}
	dp.setGenerator(dp)
	return dp
}

func (v *RoutingTable) generate() (data []common.ResponseElem, err error) {
	err = v.dataTool.Init().Load()
	for _, item := range v.dataTool.routingTables {
		data = append(data, v.generateOne(item))
	}
	return
}

func (v *RoutingTable) generateOne(item mysql.RoutingTable) common.ResponseElem {
	d := MySQLModelToMap(item)
	d["ROUTE_NAME"] = v.dataTool.vrouterIDToInfo[item.VRouterID].name
	d["EPC_ID"] = v.dataTool.vrouterIDToInfo[item.VRouterID].vpcID
	var name string
	if item.NexthopType == ROUTING_TABLE_NEXTHOP_TYPE_VPC {
		name = v.dataTool.vpcLabelToName[item.Nexthop]
	} else if item.NexthopType == ROUTING_TABLE_NEXTHOP_TYPE_NAT_GATEWAY {
		name = v.dataTool.natGatewayLcuuidToName[item.Nexthop]
	}
	if name != "" {
		d["NEXTHOP"] = name
	}
	return d
}

type routingTableToolData struct {
	routingTables []mysql.RoutingTable

	vrouterIDToInfo        map[int]nameVPCID
	vpcLabelToName         map[string]string
	natGatewayLcuuidToName map[string]string
}

func (td *routingTableToolData) Init() *routingTableToolData {
	td.vrouterIDToInfo = make(map[int]nameVPCID)
	td.vpcLabelToName = make(map[string]string)
	td.natGatewayLcuuidToName = make(map[string]string)
	return td
}

func (td *routingTableToolData) Load() (err error) {
	td.routingTables, err = UnscopedFind[mysql.RoutingTable]()
	if err != nil {
		return err
	}

	vrouters, err := Select[mysql.VRouter]([]string{"id", "name", "epc_id"})
	if err != nil {
		return err
	}
	for _, item := range vrouters {
		td.vrouterIDToInfo[item.ID] = nameVPCID{name: item.Name, vpcID: item.VPCID}
	}

	vpcs, err := Select[mysql.VPC]([]string{"name", "label"})
	if err != nil {
		return err
	}
	for _, item := range vpcs {
		td.vpcLabelToName[item.Label] = item.Name
	}

	ngs, err := Select[mysql.NATGateway]([]string{"lcuuid", "name"})
	if err != nil {
		return err
	}
	for _, item := range ngs {
		td.natGatewayLcuuidToName[item.Lcuuid] = item.Name
	}
	return nil
}
