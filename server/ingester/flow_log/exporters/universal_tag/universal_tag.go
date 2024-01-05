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

package universal_tag

import (
	"fmt"
	"net"
	"regexp"
	"strings"

	logging "github.com/op/go-logging"
	"golang.org/x/net/context"

	"github.com/deepflowio/deepflow/message/trident"
	"github.com/deepflowio/deepflow/server/ingester/config"
	"github.com/deepflowio/deepflow/server/ingester/flow_log/log_data"
	"github.com/deepflowio/deepflow/server/ingester/ingesterctl"
	"github.com/deepflowio/deepflow/server/libs/debug"
	"github.com/deepflowio/deepflow/server/libs/grpc"
	"github.com/deepflowio/deepflow/server/libs/utils"
)

var log = logging.MustGetLogger("universal_tag")

type UniversalTags struct {
	Region       string
	AZ           string
	Host         string
	L3DeviceType string
	L3Device     string
	PodNode      string
	PodNS        string
	PodGroup     string
	Pod          string
	PodCluster   string
	L3Epc        string
	Subnet       string
	Service      string
	GProcess     string
	Vtap         string

	CHost      string
	Router     string
	DhcpGW     string
	PodService string
	Redis      string
	RDS        string
	LB         string
	NatGW      string

	TapPortName string

	AutoInstanceType string
	AutoInstance     string
	AutoServiceType  string
	AutoService      string
}

type DeviceType uint8

const (
	TYPE_INTERNET       DeviceType = 0
	TYPE_VM             DeviceType = 1
	TYPE_VROUTER        DeviceType = 5
	TYPE_HOST           DeviceType = 6
	TYPE_DHCP_GW        DeviceType = 9
	TYPE_POD            DeviceType = 10
	TYPE_POD_SERVICE    DeviceType = 11
	TYPE_REDIS_INSTANCE DeviceType = 12
	TYPE_RDS_INSTANCE   DeviceType = 13
	TYPE_POD_NODE       DeviceType = 14
	TYPE_LB             DeviceType = 15
	TYPE_NAT_GATEWAY    DeviceType = 16
	TYPE_POD_GROUP      DeviceType = 101
	TYPE_SERVICE        DeviceType = 102
	TYPE_GPROCESS       DeviceType = 120
	TYPE_IP             DeviceType = 255
)

// from clickhouse flow_tag.node_type_map
var deviceTypeStrings = []string{
	TYPE_INTERNET:       "internet_ip",
	TYPE_VM:             "chost",
	TYPE_VROUTER:        "router",
	TYPE_HOST:           "host",
	TYPE_DHCP_GW:        "dhcpgw",
	TYPE_POD:            "pod",
	TYPE_POD_SERVICE:    "pod_service",
	TYPE_REDIS_INSTANCE: "redis",
	TYPE_RDS_INSTANCE:   "rds",
	TYPE_POD_NODE:       "pod_node",
	TYPE_LB:             "lb",
	TYPE_NAT_GATEWAY:    "natgw",
	TYPE_POD_GROUP:      "pod_group",
	TYPE_SERVICE:        "service",
	TYPE_GPROCESS:       "gprocess",
	TYPE_IP:             "ip",
}

func (t DeviceType) String() string {
	return deviceTypeStrings[t]
}

type Labels map[string]string

type UniversalTagMaps struct {
	podK8SLabelMap map[uint32]Labels
	regionMap      map[uint16]string
	azMap          map[uint16]string
	deviceMap      map[uint64]string //deviceId+deviceType -> deviceName
	podNodeMap     map[uint32]string
	podNsMap       map[uint16]string
	podGroupMap    map[uint32]string
	podMap         map[uint32]string
	podClusterMap  map[uint16]string
	l3EpcMap       map[uint32]string
	subnetMap      map[uint16]string
	gprocessMap    map[uint32]string
	vtapMap        map[uint16]string
}

func (u *UniversalTagsManager) QueryUniversalTags(l7FlowLog *log_data.L7FlowLog) (*UniversalTags, *UniversalTags) {
	tagMaps := u.universalTagMaps
	tags0, tags1 := &UniversalTags{
		Region:       tagMaps.regionMap[l7FlowLog.RegionID0],
		AZ:           tagMaps.azMap[l7FlowLog.AZID0],
		Host:         tagMaps.deviceMap[uint64(TYPE_HOST)<<32|uint64(l7FlowLog.HostID0)],
		L3DeviceType: DeviceType(l7FlowLog.L3DeviceType0).String(),
		L3Device:     tagMaps.deviceMap[uint64(l7FlowLog.L3DeviceType0)<<32|uint64(l7FlowLog.L3DeviceID0)],
		PodNode:      tagMaps.podNodeMap[l7FlowLog.PodNodeID0],
		PodNS:        tagMaps.podNsMap[l7FlowLog.PodNSID0],
		PodGroup:     tagMaps.podGroupMap[l7FlowLog.PodGroupID0],
		Pod:          tagMaps.podMap[l7FlowLog.PodID0],
		PodCluster:   tagMaps.podClusterMap[l7FlowLog.PodClusterID0],
		L3Epc:        tagMaps.l3EpcMap[uint32(l7FlowLog.L3EpcID0)],
		Subnet:       tagMaps.subnetMap[l7FlowLog.SubnetID0],
		Service:      tagMaps.deviceMap[uint64(TYPE_SERVICE)<<32|uint64(l7FlowLog.ServiceID0)],
		GProcess:     tagMaps.gprocessMap[l7FlowLog.GPID0],
		Vtap:         tagMaps.vtapMap[l7FlowLog.VtapID],
	}, &UniversalTags{
		Region:       tagMaps.regionMap[l7FlowLog.RegionID1],
		AZ:           tagMaps.azMap[l7FlowLog.AZID1],
		Host:         tagMaps.deviceMap[uint64(TYPE_HOST)<<32|uint64(l7FlowLog.HostID1)],
		L3DeviceType: DeviceType(l7FlowLog.L3DeviceType1).String(),
		L3Device:     tagMaps.deviceMap[uint64(l7FlowLog.L3DeviceType1)<<32|uint64(l7FlowLog.L3DeviceID1)],
		PodNode:      tagMaps.podNodeMap[l7FlowLog.PodNodeID1],
		PodNS:        tagMaps.podNsMap[l7FlowLog.PodNSID1],
		PodGroup:     tagMaps.podGroupMap[l7FlowLog.PodGroupID1],
		Pod:          tagMaps.podMap[l7FlowLog.PodID1],
		PodCluster:   tagMaps.podClusterMap[l7FlowLog.PodClusterID1],
		L3Epc:        tagMaps.l3EpcMap[uint32(l7FlowLog.L3EpcID1)],
		Subnet:       tagMaps.subnetMap[l7FlowLog.SubnetID1],
		Service:      tagMaps.deviceMap[uint64(TYPE_SERVICE)<<32|uint64(l7FlowLog.ServiceID1)],
		GProcess:     tagMaps.gprocessMap[l7FlowLog.GPID1],
		Vtap:         tagMaps.vtapMap[l7FlowLog.VtapID],
	}

	l3Device0 := tagMaps.deviceMap[uint64(l7FlowLog.L3DeviceType0)<<32|uint64(l7FlowLog.L3DeviceID0)]
	fillDevice(tags0, DeviceType(l7FlowLog.L3DeviceType0), l3Device0)

	l3Device1 := tagMaps.deviceMap[uint64(l7FlowLog.L3DeviceType1)<<32|uint64(l7FlowLog.L3DeviceID1)]
	fillDevice(tags1, DeviceType(l7FlowLog.L3DeviceType1), l3Device1)

	tags0.AutoServiceType = DeviceType(l7FlowLog.AutoServiceType0).String()
	tags0.AutoService = u.getAuto(DeviceType(l7FlowLog.AutoServiceType0), l7FlowLog.AutoServiceID0, l7FlowLog.IsIPv4, l7FlowLog.IP40, l7FlowLog.IP60)
	tags0.AutoInstanceType = DeviceType(l7FlowLog.AutoInstanceType0).String()
	tags0.AutoInstance = u.getAuto(DeviceType(l7FlowLog.AutoInstanceType0), l7FlowLog.AutoInstanceID0, l7FlowLog.IsIPv4, l7FlowLog.IP40, l7FlowLog.IP60)

	tags1.AutoServiceType = DeviceType(l7FlowLog.AutoServiceType1).String()
	tags1.AutoService = u.getAuto(DeviceType(l7FlowLog.AutoServiceType1), l7FlowLog.AutoServiceID1, l7FlowLog.IsIPv4, l7FlowLog.IP41, l7FlowLog.IP61)
	tags1.AutoInstanceType = DeviceType(l7FlowLog.AutoInstanceType1).String()
	tags1.AutoInstance = u.getAuto(DeviceType(l7FlowLog.AutoInstanceType1), l7FlowLog.AutoInstanceID1, l7FlowLog.IsIPv4, l7FlowLog.IP41, l7FlowLog.IP61)

	return tags0, tags1
}

func fillDevice(tags *UniversalTags, deviceType DeviceType, device string) {
	switch deviceType {
	case TYPE_VM:
		tags.CHost = device
	case TYPE_VROUTER:
		tags.Router = device
	case TYPE_DHCP_GW:
		tags.DhcpGW = device
	case TYPE_POD_SERVICE:
		tags.PodService = device
	case TYPE_REDIS_INSTANCE:
		tags.Redis = device
	case TYPE_RDS_INSTANCE:
		tags.RDS = device
	case TYPE_LB:
		tags.LB = device
	}
}

func (u *UniversalTagsManager) getAuto(autoType DeviceType, autoID uint32, isIPv4 bool, ip4 uint32, ip6 net.IP) string {
	if autoType == TYPE_IP || autoType == TYPE_INTERNET {
		if isIPv4 {
			return utils.IpFromUint32(ip4).String()
		} else {
			return ip6.String()
		}
	}
	return u.universalTagMaps.deviceMap[uint64(autoType)<<32|uint64(autoID)]
}

func (u *UniversalTagsManager) QueryCustomK8sLabels(podID uint32) Labels {
	return u.universalTagMaps.podK8SLabelMap[podID]
}

type UniversalTagsManager struct {
	universalTagMaps *UniversalTagMaps
	tapPortNameMap   map[uint64]string

	customK8sLabelsRegexp string
	k8sLabelsRegexp       *regexp.Regexp

	grpcSession             *grpc.GrpcSession
	versionUniversalTagMaps uint32
}

func NewUniversalTagsManager(customK8sLabelsRegexp string, baseCfg *config.Config) *UniversalTagsManager {
	universalTagMaps := &UniversalTagMaps{}
	var k8sLabelsRegexp *regexp.Regexp
	if customK8sLabelsRegexp != "" {
		var err error
		k8sLabelsRegexp, err = regexp.Compile(customK8sLabelsRegexp)
		if err != nil {
			log.Warningf("exporter compile k8s label regexp pattern failed: %s", err)
		}
	}
	m := &UniversalTagsManager{
		customK8sLabelsRegexp: customK8sLabelsRegexp,
		universalTagMaps:      universalTagMaps,
		tapPortNameMap:        make(map[uint64]string),
		k8sLabelsRegexp:       k8sLabelsRegexp,
		grpcSession:           &grpc.GrpcSession{},
	}

	runOnce := func() {
		if err := m.Reload(); err != nil {
			log.Warning(err)
		}
	}

	controllers := make([]net.IP, len(baseCfg.ControllerIPs))
	for i, ipString := range baseCfg.ControllerIPs {
		controllers[i] = net.ParseIP(ipString)
		if controllers[i].To4() != nil {
			controllers[i] = controllers[i].To4()
		}
	}
	m.grpcSession.Init(controllers, baseCfg.ControllerPort, grpc.DEFAULT_SYNC_INTERVAL, baseCfg.GrpcBufferSize, runOnce)
	debug.ServerRegisterSimple(ingesterctl.CMD_EXPORTER_PLATFORMDATA, m)

	return m
}

func (u *UniversalTagsManager) Start() {
	u.grpcSession.Start()
}

func (u *UniversalTagsManager) Close() {
	u.grpcSession.Close()
}

func (u *UniversalTagsManager) Reload() error {
	var response *trident.UniversalTagNameMapsResponse
	err := u.grpcSession.Request(func(ctx context.Context, remote net.IP) error {
		var err error
		c := u.grpcSession.GetClient()
		if c == nil {
			return fmt.Errorf("can't get grpc client to %s", remote)
		}
		client := trident.NewSynchronizerClient(c)
		response, err = client.GetUniversalTagNameMaps(ctx, &trident.UniversalTagNameMapsRequest{})
		return err
	})
	if err != nil {
		return err
	}

	newVersion := response.GetVersion()
	if newVersion == u.versionUniversalTagMaps {
		return nil
	}

	u.universalTagMaps = u.GetUniversalTagMaps(response)

	log.Infof("Event update rpc universalTagNames version %d -> %d", u.versionUniversalTagMaps, newVersion)
	u.versionUniversalTagMaps = newVersion

	return nil
}

func (u *UniversalTagsManager) genU16KeyMap(idNames []*trident.IdNameMap) map[uint16]string {
	m := make(map[uint16]string)
	for i := range idNames {
		m[uint16(idNames[i].GetId())] = idNames[i].GetName()
	}
	return m
}

func (u *UniversalTagsManager) genU32KeyMap(idNames []*trident.IdNameMap) map[uint32]string {
	m := make(map[uint32]string)
	for i := range idNames {
		m[idNames[i].GetId()] = idNames[i].GetName()
	}
	return m
}

func (u *UniversalTagsManager) GetUniversalTagMaps(response *trident.UniversalTagNameMapsResponse) *UniversalTagMaps {
	tagMaps := &UniversalTagMaps{
		podK8SLabelMap: make(map[uint32]Labels),
		deviceMap:      make(map[uint64]string),
	}

	for _, podK8sLabel := range response.GetPodK8SLabelMap() {
		labelMap := make(map[string]string)
		for i, name := range podK8sLabel.GetLabelName() {
			if u.isK8sLabelExport(name) {
				labelMap[name] = podK8sLabel.GetLabelValue()[i]
			}
		}
		tagMaps.podK8SLabelMap[podK8sLabel.GetPodId()] = labelMap
	}
	for _, device := range response.GetDeviceMap() {
		tagMaps.deviceMap[uint64(device.GetType())<<32|uint64(device.GetId())] = device.GetName()
	}

	tagMaps.regionMap = u.genU16KeyMap(response.GetRegionMap())
	tagMaps.azMap = u.genU16KeyMap(response.GetAzMap())
	tagMaps.podNodeMap = u.genU32KeyMap(response.GetPodNodeMap())
	tagMaps.podNsMap = u.genU16KeyMap(response.GetPodNsMap())
	tagMaps.podGroupMap = u.genU32KeyMap(response.GetPodGroupMap())
	tagMaps.podMap = u.genU32KeyMap(response.GetPodMap())
	tagMaps.podClusterMap = u.genU16KeyMap(response.GetPodClusterMap())
	tagMaps.l3EpcMap = u.genU32KeyMap(response.GetL3EpcMap())
	tagMaps.subnetMap = u.genU16KeyMap(response.GetSubnetMap())
	tagMaps.gprocessMap = u.genU32KeyMap(response.GetGprocessMap())
	tagMaps.vtapMap = u.genU16KeyMap(response.GetVtapMap())

	return tagMaps
}

func (u *UniversalTagsManager) isK8sLabelExport(name string) bool {
	// if not configured, all are not exported
	if len(u.customK8sLabelsRegexp) == 0 {
		return false
	}

	if u.k8sLabelsRegexp != nil && u.k8sLabelsRegexp.MatchString(name) {
		return true
	}

	return false
}

func (u *UniversalTagsManager) HandleSimpleCommand(operate uint16, arg string) string {
	sb := &strings.Builder{}
	sb.WriteString(fmt.Sprintf("podK8SLabelMap: %+v\n", u.universalTagMaps.podK8SLabelMap))
	sb.WriteString(fmt.Sprintf("regionMap: %+v\n", u.universalTagMaps.regionMap))

	sb.WriteString(fmt.Sprintf("azMap: %+v\n", u.universalTagMaps.azMap))
	sb.WriteString(fmt.Sprintf("deviceMap: %+v\n", u.universalTagMaps.deviceMap))
	sb.WriteString(fmt.Sprintf("podNodeMap: %+v\n", u.universalTagMaps.podNodeMap))
	sb.WriteString(fmt.Sprintf("podGroupMap: %+v\n", u.universalTagMaps.podGroupMap))
	sb.WriteString(fmt.Sprintf("podMap: %+v\n", u.universalTagMaps.podMap))
	sb.WriteString(fmt.Sprintf("podClusterMap: %+v\n", u.universalTagMaps.podClusterMap))
	sb.WriteString(fmt.Sprintf("l3EpcMap: %+v\n", u.universalTagMaps.l3EpcMap))
	sb.WriteString(fmt.Sprintf("subnetMap: %+v\n", u.universalTagMaps.subnetMap))
	sb.WriteString(fmt.Sprintf("gprocessMap: %+v\n", u.universalTagMaps.gprocessMap))
	sb.WriteString(fmt.Sprintf("vtapMap: %+v\n", u.universalTagMaps.vtapMap))
	return sb.String()
}
