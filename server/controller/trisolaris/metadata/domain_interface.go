package metadata

import (
	"gitlab.yunshan.net/yunshan/metaflow/message/trident"
	. "server/controller/common"
	models "server/controller/db/mysql"
)

type TInterfaces []*trident.Interface

type DomainInterfaceData map[string]TInterfaces

type DomainInterfaceProto struct {
	domainToInterfacesExceptPod          DomainInterfaceData
	domainToAllInterfaces                DomainInterfaceData
	domainOrSubdomainToInterfacesOnlyPod DomainInterfaceData
	allSimpleInterfacesExceptPod         TInterfaces
	allSimpleInterfaces                  TInterfaces
	allCompleteInterfaces                TInterfaces
}

func NewDomainInterfaceProto() *DomainInterfaceProto {
	return &DomainInterfaceProto{
		domainToInterfacesExceptPod:          make(DomainInterfaceData),
		domainToAllInterfaces:                make(DomainInterfaceData),
		domainOrSubdomainToInterfacesOnlyPod: make(DomainInterfaceData),
		allSimpleInterfacesExceptPod:         make(TInterfaces, 0),
		allSimpleInterfaces:                  make(TInterfaces, 0),
		allCompleteInterfaces:                make(TInterfaces, 0),
	}
}

func (d *DomainInterfaceProto) addInterfaceProto(vif *models.VInterface, ifpd *InterfaceProto) {
	if _, ok := d.domainToAllInterfaces[vif.Domain]; ok {
		d.domainToAllInterfaces[vif.Domain] = append(
			d.domainToAllInterfaces[vif.Domain], ifpd.sInterface)
	} else {
		d.domainToAllInterfaces[vif.Domain] = []*trident.Interface{ifpd.sInterface}
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
			d.domainToInterfacesExceptPod[vif.Domain] = []*trident.Interface{ifpd.sInterface}
		}
		d.allSimpleInterfacesExceptPod = append(
			d.allSimpleInterfacesExceptPod, ifpd.sInterface)
	} else {
		if _, ok := d.domainOrSubdomainToInterfacesOnlyPod[vifDomain]; ok {
			d.domainOrSubdomainToInterfacesOnlyPod[vifDomain] = append(
				d.domainOrSubdomainToInterfacesOnlyPod[vifDomain], ifpd.sInterface)
		} else {
			d.domainOrSubdomainToInterfacesOnlyPod[vifDomain] = []*trident.Interface{ifpd.sInterface}
		}
	}
}

func (d *DomainInterfaceProto) addFloatingIPProto(domain string, data *trident.Interface) {
	d.allSimpleInterfacesExceptPod = append(
		d.allSimpleInterfacesExceptPod, data)
	if _, ok := d.domainToAllInterfaces[domain]; ok {
		d.domainToAllInterfaces[domain] = append(
			d.domainToAllInterfaces[domain], data)
	} else {
		d.domainToAllInterfaces[domain] = []*trident.Interface{data}
	}
	if _, ok := d.domainToInterfacesExceptPod[domain]; ok {
		d.domainToInterfacesExceptPod[domain] = append(
			d.domainToInterfacesExceptPod[domain], data)
	} else {
		d.domainToInterfacesExceptPod[domain] = []*trident.Interface{data}
	}
}

func (d *DomainInterfaceProto) addNoVIfIDProto(domain string, data *trident.Interface) {
	if _, ok := d.domainToAllInterfaces[domain]; ok {
		d.domainToAllInterfaces[domain] = append(
			d.domainToAllInterfaces[domain], data)
	} else {
		d.domainToAllInterfaces[domain] = []*trident.Interface{data}
	}
	if _, ok := d.domainToInterfacesExceptPod[domain]; ok {
		d.domainToInterfacesExceptPod[domain] = append(
			d.domainToInterfacesExceptPod[domain], data)
	} else {
		d.domainToInterfacesExceptPod[domain] = []*trident.Interface{data}
	}
}
