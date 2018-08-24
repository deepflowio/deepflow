package droplet

import (
	"net"
	"strconv"
	"strings"

	"gitlab.x.lan/yunshan/droplet-libs/datatype"
	"gitlab.x.lan/yunshan/droplet-libs/policy"
	. "gitlab.x.lan/yunshan/droplet-libs/utils"

	"gitlab.x.lan/yunshan/droplet/protobuf"
)

func newServicedata(service *protobuf.Service) *policy.ServiceData {
	if service == nil {
		return nil
	}
	splitPorts := strings.Split(service.GetPorts(), ",")
	ports := make([]uint32, 0, len(splitPorts))
	for _, port := range splitPorts {
		portInt, err := strconv.Atoi(port)
		if err == nil {
			ports = append(ports, uint32(portInt))
		}
	}

	return &policy.ServiceData{
		Id:      service.GetId(),
		GroupId: service.GetGroupId(),
		Proto:   uint16(service.GetProtocol()),
		Ports:   ports,
	}
}

func convert2ServiceData(response *protobuf.SyncResponse) []*policy.ServiceData {
	services := response.GetPlatformData().GetServices()
	serviceDatas := make([]*policy.ServiceData, 0, len(services))
	for _, service := range response.GetPlatformData().GetServices() {
		if newData := newServicedata(service); newData != nil {
			serviceDatas = append(serviceDatas, newData)
		}
	}
	return serviceDatas
}

func newPlatformData(vifData *protobuf.Interface) *datatype.PlatformData {
	macInt := uint64(0)
	if mac, err := net.ParseMAC(vifData.GetMac()); err == nil {
		macInt = Mac2Uint64(mac)
	}

	hostIp := uint32(0)
	ip := net.ParseIP(vifData.GetLaunchServer())
	if ip != nil {
		hostIp = IpToUint32(ip)
	}

	var ips []*datatype.IpNet
	for _, ipResource := range vifData.IpResources {
		fixIp := net.ParseIP(ipResource.GetIp())
		if fixIp == nil {
			continue
		}
		netmask := ipResource.GetMasklen()
		if netmask == 0 || netmask > datatype.MAX_MASK_LEN || netmask < datatype.MIN_MASK_LEN {
			netmask = datatype.MAX_MASK_LEN
		}
		var ipinfo = &datatype.IpNet{
			Ip:       IpToUint32(fixIp),
			Netmask:  netmask,
			SubnetId: ipResource.GetSubnetId(),
		}
		ips = append(ips, ipinfo)
	}
	return &datatype.PlatformData{
		Mac:        macInt,
		Ips:        ips,
		EpcId:      int32(vifData.GetEpcId()),
		DeviceType: vifData.GetDeviceType(),
		DeviceId:   vifData.GetDeviceId(),
		IfIndex:    vifData.GetIfIndex(),
		IfType:     vifData.GetIfType(),
		HostIp:     hostIp,
		GroupIds:   vifData.GetGroupIds(),
	}
}

func convert2PlatformData(response *protobuf.SyncResponse) []*datatype.PlatformData {
	interfaces := response.GetPlatformData().GetInterfaces()
	platformDatas := make([]*datatype.PlatformData, 0, len(interfaces))
	for _, data := range interfaces {
		if newData := newPlatformData(data); newData != nil {
			platformDatas = append(platformDatas, newData)
		}
	}
	return platformDatas
}

func newIpGroupData(ipGroup *protobuf.Group) *policy.IpGroupData {
	if ipGroup == nil || ipGroup.GetIps == nil {
		return nil
	}
	return &policy.IpGroupData{
		Id:    ipGroup.GetId(),
		EpcId: int32(ipGroup.GetEpcId()),
		Type:  uint8(ipGroup.GetType()),
		Ips:   ipGroup.GetIps(),
	}
}

func convert2IpGroupdata(response *protobuf.SyncResponse) []*policy.IpGroupData {
	ipGroups := response.GetPlatformData().GetIpGroups()
	ipGroupDatas := make([]*policy.IpGroupData, 0, len(ipGroups))
	for _, group := range ipGroups {
		if newData := newIpGroupData(group); newData != nil {
			ipGroupDatas = append(ipGroupDatas, newData)
		}
	}

	return ipGroupDatas
}
