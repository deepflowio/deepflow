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
	exportercfg "github.com/deepflowio/deepflow/server/ingester/exporters/config"
	"github.com/deepflowio/deepflow/server/ingester/ingesterctl"
	"github.com/deepflowio/deepflow/server/libs/debug"
	"github.com/deepflowio/deepflow/server/libs/grpc"
	"github.com/deepflowio/deepflow/server/libs/utils"
)

var log = logging.MustGetLogger("universal_tag")

const (
	Unknown = iota
	Region
	AZ
	Host
	L3DeviceType
	L3Device
	PodNode
	PodNS
	PodGroup
	Pod
	PodCluster
	L3Epc
	Subnet
	Service
	GProcess
	Vtap

	CHost
	Router
	DhcpGW
	PodService
	Redis
	RDS
	LB
	NatGW

	// TapPortName string

	AutoInstanceType
	AutoInstance
	AutoServiceType
	AutoService

	MAX_TAG_ID
)

var idStrings = []string{
	Unknown:      "unknown",
	Region:       "region",
	AZ:           "az",
	Host:         "host",
	L3DeviceType: "l3_device_type",
	L3Device:     "l3_device",
	PodNode:      "pod_node",
	PodNS:        "pod_ns",
	PodGroup:     "pod_group",
	Pod:          "pod",
	PodCluster:   "pod_cluster",
	L3Epc:        "l3_epc",
	Subnet:       "subnet",
	Service:      "service",
	GProcess:     "gprocess",
	Vtap:         "agent",

	CHost:      "chost",
	Router:     "router",
	DhcpGW:     "dhcpgw",
	PodService: "pod_service",
	Redis:      "redis",
	RDS:        "rds",
	LB:         "lb",
	NatGW:      "natgw",

	// TapPortName string

	AutoInstanceType: "auto_instance_type",
	AutoInstance:     "auto_instance",
	AutoServiceType:  "auto_service_type",
	AutoService:      "auto_service",
}

type UniversalTags [MAX_TAG_ID]string

func (u UniversalTags) GetTagValue(id uint8) string {
	return u[id]
}

func StringToUniversalTagID(str string) uint8 {
	for i, name := range idStrings {
		if name == str {
			return uint8(i)
		}
		l := len(str)
		if ((strings.HasSuffix(str, "_id_0") || strings.HasSuffix(str, "_id_1")) && str[:l-5] == name) ||
			((strings.HasSuffix(str, "_0") || strings.HasSuffix(str, "_1")) && str[:l-2] == name) ||
			(strings.HasSuffix(str, "_id") && str[:l-3] == name) {
			return uint8(i)
		}
	}
	return Unknown
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

func (u *UniversalTagsManager) QueryRegion(regionID uint16) string {
	return u.universalTagMaps.regionMap[regionID]
}

func (u *UniversalTagsManager) QueryAZ(azID uint16) string {
	return u.universalTagMaps.azMap[azID]
}

func (u *UniversalTagsManager) QueryHost(hostID uint16) string {
	return u.universalTagMaps.deviceMap[uint64(TYPE_HOST)<<32|uint64(hostID)]
}

func (u *UniversalTagsManager) QueryL3Device(l3DeviceType uint8, l3DeviceID uint32) (string, string) {
	return DeviceType(l3DeviceType).String(), u.universalTagMaps.deviceMap[uint64(l3DeviceType)<<32|uint64(l3DeviceID)]
}

func (u *UniversalTagsManager) QueryPodNode(podNodeID uint32) string {
	return u.universalTagMaps.podNodeMap[podNodeID]
}

func (u *UniversalTagsManager) QueryPodNs(podNsID uint16) string {
	return u.universalTagMaps.podNsMap[podNsID]
}

func (u *UniversalTagsManager) QueryPodGroup(podGroupID uint32) string {
	return u.universalTagMaps.podGroupMap[podGroupID]
}

func (u *UniversalTagsManager) QueryPod(podID uint32) string {
	return u.universalTagMaps.podMap[podID]
}

func (u *UniversalTagsManager) QueryPodCluster(podClusterID uint16) string {
	return u.universalTagMaps.podClusterMap[podClusterID]
}

func (u *UniversalTagsManager) QueryEpc(l3EpcID int32) string {
	return u.universalTagMaps.l3EpcMap[uint32(l3EpcID)]
}

func (u *UniversalTagsManager) QuerySubnet(subnetID uint16) string {
	return u.universalTagMaps.subnetMap[subnetID]
}

func (u *UniversalTagsManager) QueryGProcess(gprocessID uint32) string {
	return u.universalTagMaps.gprocessMap[gprocessID]
}

func (u *UniversalTagsManager) QueryVtap(agentID uint16) string {
	return u.universalTagMaps.vtapMap[agentID]
}

func (u *UniversalTagsManager) QueryAuto(autoType uint8, autoID uint32, isIPv4 bool, ip4 uint32, ip6 net.IP) (string, string) {
	return DeviceType(autoType).String(), u.getAuto(DeviceType(autoType), autoID, isIPv4, ip4, ip6)
}

func (u *UniversalTagsManager) QueryUniversalTags(
	regionID, azID, hostID, podNsID, podClusterID, subnetID, agentID uint16,
	l3DeviceType, autoServiceType, autoInstanceType uint8,
	l3DeviceID, autoServiceID, autoInstanceID, podNodeID, podGroupID, podID, l3EpcID, gprocessID, serviceID uint32,
	isIPv4 bool, ip4 uint32, ip6 net.IP,
) *UniversalTags {
	tagMaps := u.universalTagMaps
	tags := &UniversalTags{
		Region:       tagMaps.regionMap[regionID],
		AZ:           tagMaps.azMap[azID],
		Host:         tagMaps.deviceMap[uint64(TYPE_HOST)<<32|uint64(hostID)],
		L3DeviceType: DeviceType(l3DeviceType).String(),
		L3Device:     tagMaps.deviceMap[uint64(l3DeviceType)<<32|uint64(l3DeviceID)],
		PodNode:      tagMaps.podNodeMap[podNodeID],
		PodNS:        tagMaps.podNsMap[podNsID],
		PodGroup:     tagMaps.podGroupMap[podGroupID],
		Pod:          tagMaps.podMap[podID],
		PodCluster:   tagMaps.podClusterMap[podClusterID],
		L3Epc:        tagMaps.l3EpcMap[uint32(l3EpcID)],
		Subnet:       tagMaps.subnetMap[subnetID],
		Service:      tagMaps.deviceMap[uint64(TYPE_SERVICE)<<32|uint64(serviceID)],
		GProcess:     tagMaps.gprocessMap[gprocessID],
		Vtap:         tagMaps.vtapMap[agentID],
	}

	fillDevice(tags, DeviceType(l3DeviceType), tags[L3Device])

	tags[AutoServiceType] = DeviceType(autoServiceType).String()
	tags[AutoService] = u.getAuto(DeviceType(autoServiceType), autoServiceID, isIPv4, ip4, ip6)
	tags[AutoInstanceType] = DeviceType(autoInstanceType).String()
	tags[AutoInstance] = u.getAuto(DeviceType(autoInstanceType), autoInstanceID, isIPv4, ip4, ip6)

	return tags
}

func fillDevice(tags *UniversalTags, deviceType DeviceType, device string) {
	switch deviceType {
	case TYPE_VM:
		tags[CHost] = device
	case TYPE_VROUTER:
		tags[Router] = device
	case TYPE_DHCP_GW:
		tags[DhcpGW] = device
	case TYPE_POD_SERVICE:
		tags[PodService] = device
	case TYPE_REDIS_INSTANCE:
		tags[Redis] = device
	case TYPE_RDS_INSTANCE:
		tags[RDS] = device
	case TYPE_LB:
		tags[LB] = device
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

	k8sLabelFields  []string
	k8sLabelRegexps []*regexp.Regexp

	grpcSession             *grpc.GrpcSession
	versionUniversalTagMaps uint32
}

func NewUniversalTagsManager(k8sLabelConfig []string, baseCfg *config.Config) *UniversalTagsManager {
	universalTagMaps := &UniversalTagMaps{}
	var k8sLabelRegexps []*regexp.Regexp
	var k8sLabelFields []string
	for _, k8sLabel := range k8sLabelConfig {
		if strings.HasPrefix(k8sLabel, "~") {
			if k8sLabelRegexp, err := regexp.Compile(k8sLabel[1:]); err == nil {
				k8sLabelRegexps = append(k8sLabelRegexps, k8sLabelRegexp)
			} else {
				log.Warningf("exporter compile k8s label regexp pattern failed: %s", err)
			}
		} else {
			k8sLabelFields = append(k8sLabelFields, k8sLabel)
		}
	}
	m := &UniversalTagsManager{
		k8sLabelFields:   k8sLabelFields,
		k8sLabelRegexps:  k8sLabelRegexps,
		universalTagMaps: universalTagMaps,
		tapPortNameMap:   make(map[uint64]string),
		grpcSession:      &grpc.GrpcSession{},
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
	for _, field := range u.k8sLabelFields {
		// export `k8s.label` category  all
		if field == exportercfg.CATEGORY_K8S_LABEL {
			return true
		}
		if field == name {
			return true
		}
	}

	for _, reg := range u.k8sLabelRegexps {
		if reg != nil && reg.MatchString(name) {
			return true
		}
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
	sb.WriteString(fmt.Sprintf("agentMap: %+v\n", u.universalTagMaps.vtapMap))
	return sb.String()
}
