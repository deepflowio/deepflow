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
	"github.com/deepflowio/deepflow/server/controller/config"
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	"github.com/deepflowio/deepflow/server/controller/http/service/resource/common"
	"golang.org/x/exp/slices"
)

const (
	DEFAULT_ICON_ID_AZ = -5
)

type AZ struct {
	DataProvider
	toolData *azToolData
}

func NewAZ(cfg config.DFWebService) *AZ {
	dp := &AZ{newDataProvider(ctrlrcommon.RESOURCE_TYPE_AZ_EN), &azToolData{dfWebServiceCfg: cfg}}
	dp.setGenerator(dp)
	return dp
}

func (p *AZ) generate() ([]common.ResponseElem, error) {
	data := make([]common.ResponseElem, 0)
	err := p.toolData.Init().Load()
	if err != nil {
		return data, err
	}
	for _, item := range p.toolData.azs {
		data = append(data, p.generateOne(item))
	}
	return data, nil
}

func (a *AZ) generateOne(item mysql.AZ) common.ResponseElem {
	d := MySQLModelToMap(item)
	d["DOMAIN_NAME"] = a.toolData.domainLcuuidToName[item.Domain]
	d["REGION_NAME"] = a.toolData.regionLcuuidToName[item.Region]
	iconID := DEFAULT_ICON_ID_AZ
	if domainIconID, ok := a.toolData.domainLcuuidToIconID[item.Domain]; ok {
		iconID = domainIconID
	}
	d["ICON_ID"] = iconID
	d["VM_COUNT"] = a.toolData.azLcuuidToVMCount[item.Lcuuid]
	d["POD_COUNT"] = a.toolData.azLcuuidToPodCount[item.Lcuuid]
	d["ANALYZER_IPS"] = a.toolData.azLcuuidToAnalyzerIPs[item.Lcuuid]
	d["CONTROLLER_IPS"] = a.toolData.azLcuuidToControllerIPs[item.Lcuuid]

	// TODO extract common
	d["CREATED_AT"] = item.CreatedAt.Format(ctrlrcommon.GO_BIRTHDAY)
	d["UPDATED_AT"] = item.UpdatedAt.Format(ctrlrcommon.GO_BIRTHDAY)
	return d
}

type azToolData struct {
	dfWebServiceCfg config.DFWebService

	azs []mysql.AZ

	domainLcuuidToName map[string]string
	regionLcuuidToName map[string]string

	azLcuuidToVMCount  map[string]int
	azLcuuidToPodCount map[string]int

	azLcuuidToAnalyzerIPs   map[string][]string
	azLcuuidToControllerIPs map[string][]string

	domainLcuuidToIconID map[string]int
}

func (td *azToolData) Init() *azToolData {
	td.domainLcuuidToName = make(map[string]string)
	td.regionLcuuidToName = make(map[string]string)

	td.azLcuuidToVMCount = make(map[string]int)
	td.azLcuuidToPodCount = make(map[string]int)

	td.azLcuuidToAnalyzerIPs = make(map[string][]string)
	td.azLcuuidToControllerIPs = make(map[string][]string)

	td.domainLcuuidToIconID = make(map[string]int)
	return td
}

func (td *azToolData) Load() error {
	var err error
	td.azs, err = UnscopedFind[mysql.AZ]()
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

	vms, err := UnscopedSelect[mysql.VM]([]string{"az"})
	if err != nil {
		return err
	}
	for _, item := range vms {
		td.azLcuuidToVMCount[item.AZ]++
	}

	pods, err := UnscopedSelect[mysql.Pod]([]string{"az"})
	if err != nil {
		return err
	}
	for _, item := range pods {
		td.azLcuuidToPodCount[item.AZ]++
	}

	regionLcuuidToAZLcuuids := make(map[string][]string)
	for _, item := range td.azs {
		regionLcuuidToAZLcuuids[item.Region] = append(regionLcuuidToAZLcuuids[item.Region], item.Lcuuid)
	}

	analyzerConns, err := GetAll[mysql.AZAnalyzerConnection]()
	if err != nil {
		return err
	}
	analyzerIPToAZLcuuids := make(map[string][]string)
	analyzerIPToRegionLcuuid := make(map[string]string)
	for _, item := range analyzerConns {
		analyzerIPToRegionLcuuid[item.AnalyzerIP] = item.Region
		if !slices.Contains(analyzerIPToAZLcuuids[item.AnalyzerIP], item.AZ) {
			analyzerIPToAZLcuuids[item.AnalyzerIP] = append(analyzerIPToAZLcuuids[item.AnalyzerIP], item.AZ)
		}
	}
	td.azLcuuidToAnalyzerIPs = td.getAZIPMap(regionLcuuidToAZLcuuids, analyzerIPToAZLcuuids, analyzerIPToRegionLcuuid)

	controllerConns, err := GetAll[mysql.AZControllerConnection]()
	if err != nil {
		return err
	}
	controllerIPToAZLcuuids := make(map[string][]string)
	controllerIPToRegionLcuuid := make(map[string]string)
	for _, item := range controllerConns {
		controllerIPToRegionLcuuid[item.ControllerIP] = item.Region
		if !slices.Contains(controllerIPToAZLcuuids[item.ControllerIP], item.AZ) {
			controllerIPToAZLcuuids[item.ControllerIP] = append(controllerIPToAZLcuuids[item.ControllerIP], item.AZ)
		}
	}
	td.azLcuuidToControllerIPs = td.getAZIPMap(regionLcuuidToAZLcuuids, controllerIPToAZLcuuids, controllerIPToRegionLcuuid)

	td.domainLcuuidToIconID, err = getDomainLcuuidToIconID(td.dfWebServiceCfg)
	if err != nil {
		return err
	}
	return nil
}

func (td *azToolData) getAZIPMap(regionLcuuidToAZLcuuids, ipToAZLcuuids map[string][]string, ipToRegionLcuuid map[string]string) map[string][]string {
	azLcuuidToIPs := make(map[string][]string)
	for k, v := range ipToAZLcuuids {
		if !slices.Contains(v, "ALL") {
			continue
		}
		if len(v) == 1 {
			ipToAZLcuuids[k] = regionLcuuidToAZLcuuids[ipToRegionLcuuid[k]]
		} else {
			ipToAZLcuuids[k] = func(s []string) []string {
				r := make([]string, 0)
				for _, i := range s {
					if i != "ALL" {
						r = append(r, i)
					}
				}
				return r
			}(v)
		}
	}
	for ip, uids := range ipToAZLcuuids {
		for _, uid := range uids {
			azLcuuidToIPs[uid] = append(azLcuuidToIPs[uid], ip)
		}
	}
	return azLcuuidToIPs
}
