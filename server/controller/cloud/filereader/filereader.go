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

package filereader

import (
	"errors"
	"fmt"
	"os"

	"gopkg.in/yaml.v2"

	simplejson "github.com/bitly/go-simplejson"
	logging "github.com/op/go-logging"

	"github.com/deepflowio/deepflow/server/controller/cloud/model"
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
)

var log = logging.MustGetLogger("cloud.filereader")

type FileReader struct {
	orgID        int
	Uuid         string
	UuidGenerate string
	Name         string
	RegionUuid   string
	filePath     string

	regionNameToLcuuid        map[string]string
	azNameToLcuuid            map[string]string
	vpcNameToLcuuid           map[string]string
	networkNameToLcuuid       map[string]string
	networkLcuuidToVPCLcuuid  map[string]string
	networkLcuuidToNetType    map[string]int
	subnetNameToNetworkLcuuid map[string]string
	subnetNameToLcuuid        map[string]string
}

func NewFileReader(orgID int, domain mysql.Domain) (*FileReader, error) {
	config, err := simplejson.NewJson([]byte(domain.Config))
	if err != nil {
		log.Error(err)
		return nil, err
	}

	filePath, err := config.Get("path").String()
	if err != nil {
		log.Error("path must be specified")
		return nil, err
	}

	return &FileReader{
		orgID: orgID,
		Uuid:  domain.Lcuuid,
		// TODO: display_name replace to uuid_generate
		UuidGenerate: domain.DisplayName,
		Name:         domain.Name,
		RegionUuid:   config.Get("region_uuid").MustString(),
		filePath:     filePath,

		regionNameToLcuuid:        make(map[string]string),
		azNameToLcuuid:            make(map[string]string),
		vpcNameToLcuuid:           make(map[string]string),
		networkNameToLcuuid:       make(map[string]string),
		networkLcuuidToVPCLcuuid:  make(map[string]string),
		networkLcuuidToNetType:    make(map[string]int),
		subnetNameToNetworkLcuuid: make(map[string]string),
		subnetNameToLcuuid:        make(map[string]string),
	}, nil
}

func (f *FileReader) getRegionLcuuid(regionName string) (string, error) {
	if f.RegionUuid != "" {
		return f.RegionUuid, nil
	}

	regionLcuuid, ok := f.regionNameToLcuuid[regionName]
	if !ok {
		err := errors.New(fmt.Sprintf("region (%s) not in file", regionName))
		log.Error(err)
		return "", err
	}
	return regionLcuuid, nil
}

func (f *FileReader) ClearDebugLog() {
	return
}

func (f *FileReader) CheckAuth() error {
	return nil
}

func (f *FileReader) GetCloudData() (model.Resource, error) {
	var resource model.Resource

	fileBytes, err := os.ReadFile(f.filePath)
	if err != nil {
		log.Error(err)
		return resource, err
	}

	var fileInfo FileInfo
	if err = yaml.Unmarshal(fileBytes, &fileInfo); err != nil {
		log.Errorf("Unmarshal yaml error: %v", err)
		return resource, err
	}

	// region
	regions, err := f.getRegions(&fileInfo)
	if err != nil {
		log.Error("get region data failed")
		return resource, err
	}

	// az
	azs, err := f.getAZs(&fileInfo)
	if err != nil {
		log.Error("get az data failed")
		return resource, err
	}

	hosts, err := f.getHosts(&fileInfo)
	if err != nil {
		log.Error("get host data failed")
		return resource, err
	}

	// VPC
	vpcs, err := f.getVPCs(&fileInfo)
	if err != nil {
		log.Error("get vpc data failed")
		return resource, err
	}

	// network
	networks, err := f.getNetworks(&fileInfo)
	if err != nil {
		log.Error("get network data failed")
		return resource, err
	}

	// subnet
	subnets, err := f.getSubnets(&fileInfo)
	if err != nil {
		log.Error("get subnet data failed")
		return resource, err
	}

	// vm, vinterface and ip
	vms, vinterfaces, ips, err := f.getVMs(&fileInfo)
	if err != nil {
		log.Error("get vm data failed")
		return resource, err
	}

	// vrouter, vinterface and ip
	vrouters, tmpVInterfaces, tmpIPs, err := f.getRouters(&fileInfo)
	if err != nil {
		log.Error("get router data failed")
		return resource, err
	}
	vinterfaces = append(vinterfaces, tmpVInterfaces...)
	ips = append(ips, tmpIPs...)

	resource.Regions = regions
	resource.AZs = azs
	resource.Hosts = hosts
	resource.VPCs = vpcs
	resource.Networks = networks
	resource.Subnets = subnets
	resource.VMs = vms
	resource.VRouters = vrouters
	resource.VInterfaces = vinterfaces
	resource.IPs = ips
	return resource, nil
}
