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
	"errors"
	"fmt"

	mapset "github.com/deckarep/golang-set/v2"

	ctrlrcommon "github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/config"
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	"github.com/deepflowio/deepflow/server/controller/http/service/resource/common"
)

const (
	DEFAULT_ICON_ID_REGION = -4
)

type Region struct {
	DataProvider
	toolData *regionToolData
}

func NewRegion(cfg config.DFWebService) *Region {
	dp := &Region{newDataProvider(ctrlrcommon.RESOURCE_TYPE_REGION_EN), &regionToolData{dfWebServiceCfg: cfg}}
	dp.setGenerator(dp)
	return dp
}

func (p *Region) generate() ([]common.ResponseElem, error) {
	data := make([]common.ResponseElem, 0)
	err := p.toolData.Init().Load()
	if err != nil {
		return data, err
	}
	for _, item := range p.toolData.regions {
		data = append(data, p.generateOne(item))
	}
	return data, nil
}

func (a *Region) generateOne(item mysql.Region) common.ResponseElem {
	d := MySQLModelToMap(item)
	if item.Latitude == 0 {
		d["LATITUDE"] = nil
	}
	if item.Longitude == 0 {
		d["LONGITUDE"] = nil
	}
	iconID := DEFAULT_ICON_ID_REGION
	domainIconIDs := mapset.NewSet[int]()
	for _, i := range a.toolData.regionLcuuidToDomainLcuuids[item.Lcuuid] {
		if id, ok := a.toolData.domainLcuuidToIconID[i]; ok {
			domainIconIDs.Add(id)
		}
	}
	if domainIconIDs.Cardinality() == 1 {
		iconID = domainIconIDs.ToSlice()[0]
	}
	d["ICON_ID"] = iconID

	d["AZ_COUNT"] = a.toolData.regionLcuuidToAZCount[item.Lcuuid]
	d["EPC_COUNT"] = a.toolData.regionLcuuidToVPCCount[item.Lcuuid]
	d["SUBNET_COUNT"] = a.toolData.regionLcuuidToNetworkCount[item.Lcuuid]
	d["VM_COUNT"] = a.toolData.regionLcuuidToVMCount[item.Lcuuid]
	d["POD_COUNT"] = a.toolData.regionLcuuidToPodCount[item.Lcuuid]

	d["CREATED_AT"] = item.CreatedAt.Format(ctrlrcommon.GO_BIRTHDAY)
	d["UPDATED_AT"] = item.UpdatedAt.Format(ctrlrcommon.GO_BIRTHDAY)
	return d
}

type regionToolData struct {
	dfWebServiceCfg config.DFWebService

	regions []mysql.Region

	regionLcuuidToAZCount      map[string]int
	regionLcuuidToVPCCount     map[string]int
	regionLcuuidToNetworkCount map[string]int
	regionLcuuidToVMCount      map[string]int
	regionLcuuidToPodCount     map[string]int

	domainLcuuidToIconID        map[string]int
	regionLcuuidToDomainLcuuids map[string][]string
}

func (td *regionToolData) Init() *regionToolData {
	td.regionLcuuidToAZCount = make(map[string]int)
	td.regionLcuuidToVPCCount = make(map[string]int)
	td.regionLcuuidToNetworkCount = make(map[string]int)
	td.regionLcuuidToVMCount = make(map[string]int)
	td.regionLcuuidToPodCount = make(map[string]int)

	td.domainLcuuidToIconID = make(map[string]int)
	td.regionLcuuidToDomainLcuuids = make(map[string][]string)
	return td
}

func (td *regionToolData) Load() error {
	var err error
	td.regions, err = UnscopedFind[mysql.Region]()
	if err != nil {
		return err
	}

	azs, err := Select[mysql.AZ]([]string{"region", "domain"})
	if err != nil {
		return err
	}
	for _, item := range azs {
		td.regionLcuuidToAZCount[item.Region]++
		if item.Domain != ctrlrcommon.DEFAULT_DOMAIN && item.Domain != "" && item.Region != "" {
			td.regionLcuuidToDomainLcuuids[item.Region] = append(td.regionLcuuidToDomainLcuuids[item.Region], item.Domain)
		}
	}

	vpcs, err := UnscopedSelect[mysql.VPC]([]string{"region"})
	if err != nil {
		return err
	}
	for _, item := range vpcs {
		td.regionLcuuidToVPCCount[item.Region]++
	}

	nets, err := UnscopedSelect[mysql.Network]([]string{"region"})
	if err != nil {
		return err
	}
	for _, item := range nets {
		td.regionLcuuidToNetworkCount[item.Region]++
	}

	vms, err := UnscopedSelect[mysql.VM]([]string{"region"})
	if err != nil {
		return err
	}
	for _, item := range vms {
		td.regionLcuuidToVMCount[item.Region]++
	}

	pods, err := UnscopedSelect[mysql.Pod]([]string{"region"})
	if err != nil {
		return err
	}
	for _, item := range pods {
		td.regionLcuuidToPodCount[item.Region]++
	}

	td.domainLcuuidToIconID, err = getDomainLcuuidToIconID(td.dfWebServiceCfg)
	if err != nil {
		return err
	}
	return nil
}

func getDomainLcuuidToIconID(dfWebServiceCfg config.DFWebService) (map[string]int, error) {
	domainLcuuidToIconID := make(map[string]int)
	if !dfWebServiceCfg.Enabled {
		return nil, nil
	}
	body := make(map[string]interface{})
	response, err := ctrlrcommon.CURLPerform("GET", fmt.Sprintf("http://%s:%d/v1/icons", dfWebServiceCfg.Host, dfWebServiceCfg.Port), body)
	if err != nil {
		return nil, err
	}
	if len(response.Get("DATA").MustArray()) == 0 {
		return nil, errors.New("no data in get icons response")
	}
	domainTypeToDefaultIconID := make(map[int]int)
	for i := range response.Get("DATA").MustArray() {
		icon := response.Get("DATA").GetIndex(i)
		for k := range ctrlrcommon.IconNameToDomainTypes[icon.Get("NAME").MustString()] {
			domainTypeToDefaultIconID[k] = icon.Get("ID").MustInt()
		}
	}

	domains, err := GetAll[mysql.Domain]()
	if err != nil {
		return nil, err
	}
	for _, item := range domains {
		if item.IconID != 0 {
			domainLcuuidToIconID[item.Lcuuid] = item.IconID
		} else {
			if defaultIconID, ok := domainTypeToDefaultIconID[item.Type]; ok {
				domainLcuuidToIconID[item.Lcuuid] = defaultIconID
			} else {
				domainLcuuidToIconID[item.Lcuuid] = ctrlrcommon.DEFAULT_DOMAIN_ICON
			}
		}
	}
	return domainLcuuidToIconID, nil
}
