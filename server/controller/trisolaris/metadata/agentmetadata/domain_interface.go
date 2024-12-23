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

package agentmetadata

import (
	"github.com/deepflowio/deepflow/message/agent"
	. "github.com/deepflowio/deepflow/server/controller/common"
	models "github.com/deepflowio/deepflow/server/controller/db/metadb/model"
	. "github.com/deepflowio/deepflow/server/controller/trisolaris/utils"
)

type TInterfaces []*agent.Interface

type DomainInterfaceData map[string]TInterfaces

type DomainInterfaceProto struct {
	domainToInterfacesExceptPod          DomainInterfaceData
	domainToAllInterfaces                DomainInterfaceData
	domainOrSubdomainToInterfacesOnlyPod DomainInterfaceData
	allSimpleInterfacesExceptPod         TInterfaces
	allSimpleInterfaces                  TInterfaces
	allCompleteInterfacesExceptPod       TInterfaces
	ORGID
}

func NewDomainInterfaceProto(orgID ORGID) *DomainInterfaceProto {
	return &DomainInterfaceProto{
		domainToInterfacesExceptPod:          make(DomainInterfaceData),
		domainToAllInterfaces:                make(DomainInterfaceData),
		domainOrSubdomainToInterfacesOnlyPod: make(DomainInterfaceData),
		allSimpleInterfacesExceptPod:         make(TInterfaces, 0),
		allSimpleInterfaces:                  make(TInterfaces, 0),
		ORGID:                                orgID,
	}
}

func (d *DomainInterfaceProto) addInterfaceProto(vif *models.VInterface, ifpd *InterfaceProto, rawData *PlatformRawData) {
	if _, ok := d.domainToAllInterfaces[vif.Domain]; ok {
		d.domainToAllInterfaces[vif.Domain] = append(
			d.domainToAllInterfaces[vif.Domain], ifpd.sInterface)
	} else {
		d.domainToAllInterfaces[vif.Domain] = []*agent.Interface{ifpd.sInterface}
	}

	vifDomain := ""
	if vif.SubDomain == "" || vif.Domain == vif.SubDomain {
		vifDomain = vif.Domain
	} else {
		vifDomain = vif.SubDomain
	}
	if vif.DeviceType != VIF_DEVICE_TYPE_POD && vif.DeviceType != VIF_DEVICE_TYPE_POD_SERVICE {
		if _, ok := d.domainToInterfacesExceptPod[vif.Domain]; ok {
			d.domainToInterfacesExceptPod[vif.Domain] = append(
				d.domainToInterfacesExceptPod[vif.Domain], ifpd.sInterface)
		} else {
			d.domainToInterfacesExceptPod[vif.Domain] = []*agent.Interface{ifpd.sInterface}
		}
		d.allSimpleInterfacesExceptPod = append(
			d.allSimpleInterfacesExceptPod, ifpd.sInterface)
	} else {
		if _, ok := d.domainOrSubdomainToInterfacesOnlyPod[vifDomain]; ok {
			d.domainOrSubdomainToInterfacesOnlyPod[vifDomain] = append(
				d.domainOrSubdomainToInterfacesOnlyPod[vifDomain], ifpd.sInterface)
		} else {
			d.domainOrSubdomainToInterfacesOnlyPod[vifDomain] = []*agent.Interface{ifpd.sInterface}
		}
	}
}

func (d *DomainInterfaceProto) addFloatingIPProto(domain string, data *agent.Interface) {
	d.allSimpleInterfacesExceptPod = append(
		d.allSimpleInterfacesExceptPod, data)
	if _, ok := d.domainToAllInterfaces[domain]; ok {
		d.domainToAllInterfaces[domain] = append(
			d.domainToAllInterfaces[domain], data)
	} else {
		d.domainToAllInterfaces[domain] = []*agent.Interface{data}
	}
	if _, ok := d.domainToInterfacesExceptPod[domain]; ok {
		d.domainToInterfacesExceptPod[domain] = append(
			d.domainToInterfacesExceptPod[domain], data)
	} else {
		d.domainToInterfacesExceptPod[domain] = []*agent.Interface{data}
	}
}

func (d *DomainInterfaceProto) addNoVIfIDProto(domain string, data *agent.Interface) {
	if _, ok := d.domainToAllInterfaces[domain]; ok {
		d.domainToAllInterfaces[domain] = append(
			d.domainToAllInterfaces[domain], data)
	} else {
		d.domainToAllInterfaces[domain] = []*agent.Interface{data}
	}
	if _, ok := d.domainToInterfacesExceptPod[domain]; ok {
		d.domainToInterfacesExceptPod[domain] = append(
			d.domainToInterfacesExceptPod[domain], data)
	} else {
		d.domainToInterfacesExceptPod[domain] = []*agent.Interface{data}
	}
}

func (d *DomainInterfaceProto) addWanIPsProto(data *agent.Interface) {
	d.allSimpleInterfacesExceptPod = append(d.allSimpleInterfacesExceptPod, data)
}

func (d *DomainInterfaceProto) updateAllSimpleInterfaces(data TInterfaces) {
	d.allSimpleInterfaces = data
}
