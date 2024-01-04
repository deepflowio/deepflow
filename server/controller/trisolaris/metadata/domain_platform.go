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

package metadata

type DomainPlatformData map[string]*PlatformData

type DomainToPlatformData struct {
	// domain包含所有平台数据 包含sub_domain数据
	domainToAllPlatformData DomainPlatformData
	// domainn内所有数据除去pod数据(包含subdomain数据)
	domainToPlatformDataExceptPod DomainPlatformData
	// domainn内所有数据只有pod数据
	domainToPlatformDataOnlyPod DomainPlatformData
	// 所有简化vinterface数据vtap使用
	allSimplePlatformData *PlatformData
	// 所有简化vinterface数据vtap使用，不包含POD/容器服务接口
	allSimplePlatformDataExceptPod *PlatformData
	//noDomain platformData
	noDomainPlatfromData *PlatformData

	// droplet data
	// 所有完整vinterface数据除了pod， droplet使用
	allCompletePlatformDataExceptPod *PlatformData
	// region内所有数据只有pod数据 完整vinterface
	regionToPlatformDataOnlyPod DomainPlatformData
	// az内所有数据只有pod数据 完整vinterface
	azToPlatformDataOnlyPod DomainPlatformData
}

func newDomainToPlatformData() *DomainToPlatformData {
	return &DomainToPlatformData{
		domainToAllPlatformData:       make(DomainPlatformData),
		domainToPlatformDataExceptPod: make(DomainPlatformData),
		domainToPlatformDataOnlyPod:   make(DomainPlatformData),
		regionToPlatformDataOnlyPod:   make(DomainPlatformData),
		azToPlatformDataOnlyPod:       make(DomainPlatformData),
	}
}

func (s DomainPlatformData) checkVersion(t DomainPlatformData) bool {
	flag := true
	for lcuuid, newDomainData := range t {
		oldDomainData, ok := s[lcuuid]
		if ok == false {
			flag = false
			newDomainData.initVersion()
			log.Debug("add domain data. ", newDomainData)
			continue
		}

		if !oldDomainData.equal(newDomainData) {
			flag = false
			newDomainData.setVersion(oldDomainData.GetVersion() + 1)
			log.Infof("domain data changed, (%s) to (%s)", oldDomainData, newDomainData)
		} else {
			newDomainData.setVersion(oldDomainData.GetVersion())
		}
	}
	return flag
}

func (d *DomainToPlatformData) updateDomainToAllPlatformData(data DomainPlatformData) {
	d.domainToAllPlatformData = data
}

func (d *DomainToPlatformData) updateDomainToPlatformDataExceptPod(data DomainPlatformData) {
	d.domainToPlatformDataExceptPod = data
}

func (d *DomainToPlatformData) updateDomainToPlatformDataOnlyPod(data DomainPlatformData) {
	d.domainToPlatformDataOnlyPod = data
}

func (d *DomainToPlatformData) updateAllsimpleplatformdata(data *PlatformData) {
	d.allSimplePlatformData = data
}

func (d *DomainToPlatformData) updateAllSimplePlatformDataExceptPod(data *PlatformData) {
	d.allSimplePlatformDataExceptPod = data
}

func (d *DomainToPlatformData) GetAllSimplePlatformData() *PlatformData {
	return d.allSimplePlatformData
}

func (d *DomainToPlatformData) GetAllSimplePlatformDataExceptPod() *PlatformData {
	return d.allSimplePlatformDataExceptPod
}

func (d *DomainToPlatformData) GetDomainToAllPlatformData() DomainPlatformData {
	return d.domainToAllPlatformData
}

func (d *DomainToPlatformData) GetDomainToPlatformDataExceptPod() DomainPlatformData {
	return d.domainToPlatformDataExceptPod
}

func (d *DomainToPlatformData) GetDomainToPlatformDataOnlyPod() DomainPlatformData {
	return d.domainToPlatformDataOnlyPod
}

func (d *DomainToPlatformData) GetRegionToPlatformDataOnlyPod() DomainPlatformData {
	return d.regionToPlatformDataOnlyPod
}

func (d *DomainToPlatformData) updateRegionToPlatformDataOnlyPod(data DomainPlatformData) {
	d.regionToPlatformDataOnlyPod = data
}

func (d *DomainToPlatformData) GetAllCompletePlatformDataExceptPod() *PlatformData {
	return d.allCompletePlatformDataExceptPod
}

func (d *DomainToPlatformData) updateAllCompletePlatformDataExceptPod(data *PlatformData) {
	d.allCompletePlatformDataExceptPod = data
}

func (d *DomainToPlatformData) GetAZToPlatformDataOnlyPod() DomainPlatformData {
	return d.azToPlatformDataOnlyPod
}

func (d *DomainToPlatformData) updateAZToPlatformDataOnlyPod(data DomainPlatformData) {
	d.azToPlatformDataOnlyPod = data
}

func (d *DomainToPlatformData) GetNoDomainPlatformData() *PlatformData {
	return d.noDomainPlatfromData
}

func (d *DomainToPlatformData) updateNoDomainPlatformData(data *PlatformData) {
	d.noDomainPlatfromData = data
}
