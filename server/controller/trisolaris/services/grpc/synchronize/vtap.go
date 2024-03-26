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

package synchronize

import (
	"fmt"
	"strings"
	"time"

	"github.com/golang/protobuf/proto"
	context "golang.org/x/net/context"

	"github.com/deepflowio/deepflow/message/common"
	api "github.com/deepflowio/deepflow/message/trident"
	. "github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/trisolaris"
	. "github.com/deepflowio/deepflow/server/controller/trisolaris/common"
	"github.com/deepflowio/deepflow/server/controller/trisolaris/pushmanager"
	"github.com/deepflowio/deepflow/server/controller/trisolaris/vtap"
)

var (
	RAW_UDP_SOCKET = api.SocketType_RAW_UDP
	TCP_SOCKET     = api.SocketType_TCP
	UDP_SOCKET     = api.SocketType_UDP
	FILE_SOCKET    = api.SocketType_FILE
)

var SOCKET_TYPE_TO_MESSAGE = map[string]api.SocketType{
	"RAW_UDP": RAW_UDP_SOCKET,
	"TCP":     TCP_SOCKET,
	"UDP":     UDP_SOCKET,
	"FILE":    FILE_SOCKET,
}

type VTapEvent struct{}

func NewVTapEvent() *VTapEvent {
	return &VTapEvent{}
}

func Int2Bool(i int) bool {
	if i == 0 {
		return false
	}

	return true
}

func (e *VTapEvent) getPlugins(vConfig *vtap.VTapConfig) *api.PluginConfig {
	if vConfig == nil || vConfig.PluginNewUpdateTime == 0 {
		return &api.PluginConfig{}
	}

	return &api.PluginConfig{
		UpdateTime:  proto.Uint32(vConfig.PluginNewUpdateTime),
		WasmPlugins: vConfig.ConvertedWasmPlugins,
		SoPlugins:   vConfig.ConvertedSoPlugins,
	}
}

func (e *VTapEvent) generateConfigInfo(c *vtap.VTapCache, clusterID string) *api.Config {
	gVTapInfo := trisolaris.GetGVTapInfo()
	vtapConfig := c.GetVTapConfig()
	if vtapConfig == nil {
		return &api.Config{}
	}

	collectorSocketType, ok := SOCKET_TYPE_TO_MESSAGE[vtapConfig.CollectorSocketType]
	if ok == false {
		collectorSocketType = UDP_SOCKET
	}
	npbSocketType, ok := SOCKET_TYPE_TO_MESSAGE[vtapConfig.NpbSocketType]
	if ok == false {
		npbSocketType = RAW_UDP_SOCKET
	}
	decapTypes := make([]api.DecapType, 0, len(vtapConfig.ConvertedDecapType))
	for _, decap := range vtapConfig.ConvertedDecapType {
		decapTypes = append(decapTypes, api.DecapType(decap))
	}
	npbVlanMode := api.VlanMode(vtapConfig.NpbVlanMode)
	ifMacSource := api.IfMacSource(vtapConfig.IfMacSource)
	captureSocketType := api.CaptureSocketType(vtapConfig.CaptureSocketType)
	vtapID := uint32(c.GetVTapID())

	tridentType := common.TridentType(0)
	if clusterID != "" { // if agent report cluster_id, force set tridentType = VTAP_TYPE_POD_VM
		tridentType = common.TridentType(VTAP_TYPE_POD_VM)
	} else {
		tridentType = common.TridentType(c.GetVTapType())
	}
	podClusterId := uint32(c.GetPodClusterID())
	vpcID := uint32(c.GetVPCID())
	tapMode := api.TapMode(vtapConfig.TapMode)
	breakerMetricStr := convertBreakerMetric(vtapConfig.SystemLoadCircuitBreakerMetric)
	loadMetric := api.SystemLoadMetric(api.SystemLoadMetric_value[breakerMetricStr])
	configure := &api.Config{
		CollectorEnabled:              proto.Bool(Int2Bool(vtapConfig.CollectorEnabled)),
		CollectorSocketType:           &collectorSocketType,
		PlatformEnabled:               proto.Bool(Int2Bool(vtapConfig.PlatformEnabled)),
		MaxCpus:                       proto.Uint32(uint32(vtapConfig.MaxCPUs)),
		MaxMemory:                     proto.Uint32(uint32(vtapConfig.MaxMemory)),
		StatsInterval:                 proto.Uint32(uint32(vtapConfig.StatsInterval)),
		SyncInterval:                  proto.Uint32(uint32(vtapConfig.SyncInterval)),
		PlatformSyncInterval:          proto.Uint32(uint32(vtapConfig.PlatformSyncInterval)),
		NpbBpsThreshold:               proto.Uint64(uint64(vtapConfig.MaxNpbBps)),
		GlobalPpsThreshold:            proto.Uint64(uint64(vtapConfig.MaxCollectPps)),
		Mtu:                           proto.Uint32(uint32(vtapConfig.Mtu)),
		OutputVlan:                    proto.Uint32(uint32(vtapConfig.OutputVlan)),
		RsyslogEnabled:                proto.Bool(Int2Bool(vtapConfig.RsyslogEnabled)),
		ServerTxBandwidthThreshold:    proto.Uint64(uint64(vtapConfig.MaxTxBandwidth)),
		BandwidthProbeInterval:        proto.Uint64(uint64(vtapConfig.BandwidthProbeInterval)),
		MaxEscapeSeconds:              proto.Uint32(uint32(vtapConfig.MaxEscapeSeconds)),
		NpbVlanMode:                   &npbVlanMode,
		NpbDedupEnabled:               proto.Bool(Int2Bool(vtapConfig.NpbDedupEnabled)),
		IfMacSource:                   &ifMacSource,
		NpbSocketType:                 &npbSocketType,
		VtapFlow_1SEnabled:            proto.Bool(Int2Bool(vtapConfig.VTapFlow1sEnabled)),
		CapturePacketSize:             proto.Uint32(uint32(vtapConfig.CapturePacketSize)),
		InactiveServerPortEnabled:     proto.Bool(Int2Bool(vtapConfig.InactiveServerPortEnabled)),
		InactiveIpEnabled:             proto.Bool(Int2Bool(vtapConfig.InactiveIPEnabled)),
		LibvirtXmlPath:                proto.String(vtapConfig.VMXMLPath),
		ExtraNetnsRegex:               proto.String(vtapConfig.ExtraNetnsRegex),
		LogThreshold:                  proto.Uint32(uint32(vtapConfig.LogThreshold)),
		LogLevel:                      proto.String(vtapConfig.LogLevel),
		LogRetention:                  proto.Uint32(uint32(vtapConfig.LogRetention)),
		L4LogCollectNpsThreshold:      proto.Uint64(uint64(vtapConfig.L4LogCollectNpsThreshold)),
		L7LogCollectNpsThreshold:      proto.Uint64(uint64(vtapConfig.L7LogCollectNpsThreshold)),
		L7MetricsEnabled:              proto.Bool(Int2Bool(vtapConfig.L7MetricsEnabled)),
		L7LogPacketSize:               proto.Uint32(uint32(vtapConfig.L7LogPacketSize)),
		DecapType:                     decapTypes,
		CaptureSocketType:             &captureSocketType,
		CaptureBpf:                    proto.String(vtapConfig.CaptureBpf),
		ThreadThreshold:               proto.Uint32(uint32(vtapConfig.ThreadThreshold)),
		ProcessThreshold:              proto.Uint32(uint32(vtapConfig.ProcessThreshold)),
		HttpLogProxyClient:            proto.String(vtapConfig.HTTPLogProxyClient),
		HttpLogTraceId:                proto.String(vtapConfig.HTTPLogTraceID),
		HttpLogSpanId:                 proto.String(vtapConfig.HTTPLogSpanID),
		HttpLogXRequestId:             proto.String(vtapConfig.HTTPLogXRequestID),
		NtpEnabled:                    proto.Bool(Int2Bool(vtapConfig.NtpEnabled)),
		L4PerformanceEnabled:          proto.Bool(Int2Bool(vtapConfig.L4PerformanceEnabled)),
		KubernetesApiEnabled:          proto.Bool(false),
		SysFreeMemoryLimit:            proto.Uint32(uint32(vtapConfig.SysFreeMemoryLimit)),
		LogFileSize:                   proto.Uint32(uint32(vtapConfig.LogFileSize)),
		ExternalAgentHttpProxyEnabled: proto.Bool(Int2Bool(c.GetExternalAgentHTTPProxyEnabledConfig(gVTapInfo))),
		ExternalAgentHttpProxyPort:    proto.Uint32(uint32(vtapConfig.ExternalAgentHTTPProxyPort)),
		PrometheusHttpApiAddresses:    strings.Split(vtapConfig.PrometheusHttpAPIAddresses, ","),
		AnalyzerPort:                  proto.Uint32(uint32(vtapConfig.AnalyzerPort)),
		ProxyControllerPort:           proto.Uint32(uint32(vtapConfig.ProxyControllerPort)),
		// 调整后采集器配置信息
		L7LogStoreTapTypes:  vtapConfig.ConvertedL7LogStoreTapTypes,
		L4LogTapTypes:       vtapConfig.ConvertedL4LogTapTypes,
		L4LogIgnoreTapSides: vtapConfig.ConvertedL4LogIgnoreTapSides,
		L7LogIgnoreTapSides: vtapConfig.ConvertedL7LogIgnoreTapSides,
		// 采集器其他配置
		Enabled:           proto.Bool(Int2Bool(c.GetVTapEnabled())),
		Host:              proto.String(c.GetVTapHost()),
		ProxyControllerIp: proto.String(c.GetControllerIP()),
		AnalyzerIp:        proto.String(c.GetTSDBIP()),
		VtapId:            &vtapID,
		TridentType:       &tridentType,
		EpcId:             &vpcID,
		TapMode:           &tapMode,
		RegionId:          proto.Uint32(uint32(c.GetRegionID())),
		// 容器采集器所在容器集群ID
		PodClusterId: &podClusterId,

		Plugins: e.getPlugins(vtapConfig),

		SystemLoadCircuitBreakerThreshold: proto.Float32((vtapConfig.SystemLoadCircuitBreakerThreshold)),
		SystemLoadCircuitBreakerRecover:   proto.Float32((vtapConfig.SystemLoadCircuitBreakerRecover)),
		SystemLoadCircuitBreakerMetric:    &loadMetric,
	}

	cacheTSBIP := c.GetTSDBIP()
	configTSDBIP := gVTapInfo.GetConfigTSDBIP()
	if configTSDBIP != "" {
		configure.AnalyzerIp = &configTSDBIP
		configure.AnalyzerPort = proto.Uint32(uint32(DefaultAnalyzerPort))
	} else if cacheTSBIP != "" {
		configure.AnalyzerIp = &cacheTSBIP
		configure.AnalyzerPort = proto.Uint32(uint32(DefaultAnalyzerPort))
	}

	if vtapConfig.NatIPEnabled == 1 {
		configure.ProxyControllerIp = proto.String(trisolaris.GetGNodeInfo().GetControllerNatIP(c.GetControllerIP()))
		configure.ProxyControllerPort = proto.Uint32(uint32(DefaultProxyControllerPort))

		configure.AnalyzerIp = proto.String(trisolaris.GetGNodeInfo().GetTSDBNatIP(c.GetTSDBIP()))
		configure.AnalyzerPort = proto.Uint32(uint32(DefaultAnalyzerPort))
	}

	if vtapConfig.ProxyControllerIP != "" {
		configure.ProxyControllerIp = proto.String(vtapConfig.ProxyControllerIP)
	}
	if vtapConfig.ProxyControllerPort != 0 {
		configure.ProxyControllerPort = proto.Uint32(uint32(vtapConfig.ProxyControllerPort))
	}
	if vtapConfig.AnalyzerIP != "" {
		configure.AnalyzerIp = proto.String(vtapConfig.AnalyzerIP)
	}
	if vtapConfig.AnalyzerPort != 0 {
		configure.AnalyzerPort = proto.Uint32(uint32(vtapConfig.AnalyzerPort))
	}

	if isPodVTap(c.GetVTapType()) && gVTapInfo.IsTheSameCluster(clusterID) {
		configure.AnalyzerIp = proto.String(trisolaris.GetGNodeInfo().GetTSDBPodIP(c.GetTSDBIP()))
		configure.AnalyzerPort = proto.Uint32(uint32(trisolaris.GetIngesterPort()))

		configure.ProxyControllerIp = proto.String(trisolaris.GetGNodeInfo().GetControllerPodIP(c.GetControllerIP()))
		configure.ProxyControllerPort = proto.Uint32(uint32(trisolaris.GetGrpcPort()))

	}

	if configure.GetProxyControllerIp() == "" {
		log.Errorf("vtap(%s) has no proxy_controller_ip", c.GetCtrlIP())
	}
	if configure.GetAnalyzerIp() == "" {
		configure.Enabled = proto.Bool(false)
		log.Errorf("vtap(%s) has no analyzer_ip", c.GetCtrlIP())
	}
	if vtapConfig.TapInterfaceRegex != "" {
		configure.TapInterfaceRegex = proto.String(vtapConfig.TapInterfaceRegex)
	}
	pcapDataRetention := trisolaris.GetGNodeInfo().GetPcapDataRetention()
	if pcapDataRetention != 0 {
		configure.PcapDataRetention = proto.Uint32(pcapDataRetention)
	}
	configure.LocalConfig = proto.String(c.GetLocalConfig())

	if c.GetVTapEnabled() == 0 {
		configure.KubernetesApiEnabled = proto.Bool(false)
		configure.PlatformEnabled = proto.Bool(false)
		configure.Enabled = proto.Bool(false)
	}

	return configure
}

// convertBreakerMetric make the first letter of a string uppercase, such as load1 to Load1.
func convertBreakerMetric(breakerMetric string) string {
	var breakerMetricStr string
	if len(breakerMetric) >= 2 {
		breakerMetricStr = strings.ToUpper(string(breakerMetric[0])) + breakerMetric[1:]
	}
	return breakerMetricStr
}

func isOpenK8sSyn(vtapType int) bool {
	switch vtapType {
	case VTAP_TYPE_POD_VM, VTAP_TYPE_POD_HOST, VTAP_TYPE_WORKLOAD_V, VTAP_TYPE_WORKLOAD_P,
		VTAP_TYPE_K8S_SIDECAR:
		return true
	default:
		return false
	}
}

func isPodVTap(vtapType int) bool {
	switch vtapType {
	case VTAP_TYPE_POD_VM, VTAP_TYPE_POD_HOST, VTAP_TYPE_K8S_SIDECAR:
		return true
	default:
		return false
	}
}

func getRealRevision(revision string) string {
	var realRevision string
	splitStr := strings.Split(revision, " ")
	if len(splitStr) == 2 {
		realRevision = splitStr[1]
	} else {
		realRevision = revision
	}

	return realRevision
}

func (e *VTapEvent) Sync(ctx context.Context, in *api.SyncRequest) (*api.SyncResponse, error) {
	if trisolaris.GetConfig().DomainAutoRegister && in.GetKubernetesClusterId() != "" {
		gKubernetesInfo := trisolaris.GetGKubernetesInfo()
		exists := gKubernetesInfo.CreateDomainIfClusterIDNotExists(in.GetKubernetesClusterId(), in.GetKubernetesClusterName())
		if !exists {
			log.Infof("call me from ip: %s with cluster_id: %s, cluster_name: %s", getRemote(ctx), in.GetKubernetesClusterId(), in.GetKubernetesClusterName())
		}
	}

	gVTapInfo := trisolaris.GetGVTapInfo()
	ctrlIP := in.GetCtrlIp()
	ctrlMac := in.GetCtrlMac()
	vtapCacheKey := ctrlIP + "-" + ctrlMac
	vtapCache, err := e.getVTapCache(in)
	if err != nil {
		log.Warningf("err:%s ctrlIp is %s, ctrlMac is %s, hostIps is %s, name:%s,  revision:%s,  bootTime:%d",
			err, ctrlIP, ctrlMac, in.GetHostIps(), in.GetProcessName(), in.GetRevision(), in.GetBootTime())
		return &api.SyncResponse{
			Status:        &STATUS_FAILED,
			Revision:      proto.String(in.GetRevision()),
			SelfUpdateUrl: proto.String(gVTapInfo.GetSelfUpdateUrl()),
		}, nil
	}
	if vtapCache == nil {
		log.Warningf("vtap (ctrl_ip: %s, ctrl_mac: %s, host_ips: %s, kubernetes_cluster_id: %s, kubernetes_force_watch: %t, group_id: %s) not found in cache. "+
			"NAME:%s  REVISION:%s  BOOT_TIME:%d",
			ctrlIP, ctrlMac, in.GetHostIps(), in.GetKubernetesClusterId(), in.GetKubernetesForceWatch(),
			in.GetVtapGroupIdRequest(), in.GetProcessName(), in.GetRevision(), in.GetBootTime())

		// If the kubernetes_force_watch field is true, the ctrl_ip and ctrl_mac of the vtap will not change,
		// resulting in unsuccessful registration and a large number of error logs.
		if !in.GetKubernetesForceWatch() {
			gVTapInfo.Register(
				int(in.GetTapMode()),
				in.GetCtrlIp(),
				in.GetCtrlMac(),
				in.GetHostIps(),
				in.GetHost(),
				in.GetVtapGroupIdRequest(),
				int(in.GetAgentUniqueIdentifier()))
		}
		return e.noVTapResponse(in), nil
	}

	vtapID := int(vtapCache.GetVTapID())
	functions := vtapCache.GetFunctions()
	versionPlatformData := vtapCache.GetSimplePlatformDataVersion()
	versionGroups := gVTapInfo.GetGroupDataVersion()
	versionPolicy := gVTapInfo.GetVTapPolicyVersion(vtapID, functions)
	if versionPlatformData != in.GetVersionPlatformData() || versionPlatformData == 0 ||
		versionGroups != in.GetVersionGroups() || versionPolicy != in.GetVersionAcls() {
		log.Infof("ctrl_ip is %s, ctrl_mac is %s, host_ips is %s, "+
			"(platform data version  %d -> %d), "+
			"(acls version %d -> %d), "+
			"(groups version %d -> %d), "+
			"NAME:%s  REVISION:%s  BOOT_TIME:%d",
			ctrlIP, ctrlMac, in.GetHostIps(),
			versionPlatformData, in.GetVersionPlatformData(),
			versionPolicy, in.GetVersionAcls(),
			versionGroups, in.GetVersionGroups(),
			in.GetProcessName(), in.GetRevision(), in.GetBootTime())
	} else {
		log.Debugf("ctrl_ip is %s, ctrl_mac is %s, host_ips is %s,"+
			"(platform data version  %d -> %d), "+
			"(acls version %d -> %d), "+
			"(groups version %d -> %d), "+
			"NAME:%s  REVISION:%s  BOOT_TIME:%d",
			ctrlIP, ctrlMac, in.GetHostIps(),
			versionPlatformData, in.GetVersionPlatformData(),
			versionPolicy, in.GetVersionAcls(),
			versionGroups, in.GetVersionGroups(),
			in.GetProcessName(), in.GetRevision(), in.GetBootTime())
	}

	// trident上报的revision与升级trident_revision一致后，则取消预期的`expected_revision`
	if vtapCache.GetExpectedRevision() == getRealRevision(in.GetRevision()) {
		vtapCache.UpdateUpgradeInfo("", "")
	}
	if uint32(vtapCache.GetBootTime()) != in.GetBootTime() {
		vtapCache.UpdateBootTime(in.GetBootTime())
	}
	if vtapCache.GetRevision() != in.GetRevision() {
		vtapCache.UpdateRevision(in.GetRevision())
	}
	tridentException := vtapCache.GetExceptions() & VTAP_TRIDENT_EXCEPTIONS_MASK
	if tridentException != int64(in.GetException()) {
		vtapCache.UpdateExceptions(int64(in.GetException()))
	}
	vtapCache.UpdateVTapRawHostname(in.GetHost())
	vtapCache.UpdateSyncedControllerAt(time.Now())
	vtapCache.UpdateSystemInfoFromGrpc(
		int(in.GetCpuNum()),
		int64(in.GetMemorySize()),
		in.GetArch(),
		in.GetOs(),
		in.GetKernelVersion(),
		in.GetProcessName())

	vtapCache.UpdateCtrlMacFromGrpc(in.GetCtrlMac())
	vtapCache.SetControllerSyncFlag()
	// 记录采集器版本号， push接口用
	if in.GetVersionPlatformData() != 0 {
		vtapCache.UpdatePushVersionPlatformData(in.GetVersionPlatformData())
	} else {
		vtapCache.UpdatePushVersionPlatformData(versionPlatformData)
	}
	if in.GetVersionGroups() != 0 {
		vtapCache.UpdatePushVersionGroups(in.GetVersionGroups())
	} else {
		vtapCache.UpdatePushVersionGroups(versionGroups)
	}
	if in.GetVersionAcls() != 0 {
		vtapCache.UpdatePushVersionPolicy(in.GetVersionAcls())
	} else {
		vtapCache.UpdatePushVersionPolicy(versionPolicy)
	}
	platformData := []byte{}
	if versionPlatformData != in.GetVersionPlatformData() {
		platformData = vtapCache.GetSimplePlatformDataStr()
	}
	groups := []byte{}
	if versionGroups != in.GetVersionGroups() {
		groups = gVTapInfo.GetGroupData()
	}
	acls := []byte{}
	if versionPolicy != in.GetVersionAcls() {
		acls = gVTapInfo.GetVTapPolicyData(vtapID, functions)
	}

	// 只有专属采集器下发tap_types
	tapTypes := []*api.TapType{}
	if vtapCache.GetVTapType() == VTAP_TYPE_DEDICATED {
		tapTypes = gVTapInfo.GetTapTypes()
	}

	configInfo := e.generateConfigInfo(vtapCache, in.GetKubernetesClusterId())
	// 携带信息有cluster_id时选择一个采集器开启云平台同步开关
	if in.GetKubernetesClusterId() != "" && isOpenK8sSyn(vtapCache.GetVTapType()) == true {
		value := gVTapInfo.GetKubernetesClusterID(in.GetKubernetesClusterId(), vtapCacheKey, in.GetKubernetesForceWatch())
		if value == vtapCacheKey {
			log.Infof(
				"open cluster(%s) kubernetes_api_enabled VTap(ctrl_ip: %s, ctrl_mac: %s, kubernetes_force_watch: %t)",
				in.GetKubernetesClusterId(), ctrlIP, ctrlMac, in.GetKubernetesForceWatch())
			configInfo.KubernetesApiEnabled = proto.Bool(true)
		}
	}
	localSegments := vtapCache.GetVTapLocalSegments()
	remoteSegments := vtapCache.GetVTapRemoteSegments()
	upgradeRevision := vtapCache.GetExpectedRevision()
	skipInterface := gVTapInfo.GetSkipInterface(vtapCache)
	Containers := gVTapInfo.GetContainers(int(vtapCache.GetVTapID()))
	return &api.SyncResponse{
		Status:              &STATUS_SUCCESS,
		LocalSegments:       localSegments,
		RemoteSegments:      remoteSegments,
		Config:              configInfo,
		PlatformData:        platformData,
		Groups:              groups,
		FlowAcls:            acls,
		VersionPlatformData: proto.Uint64(versionPlatformData),
		VersionGroups:       proto.Uint64(versionGroups),
		VersionAcls:         proto.Uint64(versionPolicy),
		TapTypes:            tapTypes,
		Containers:          Containers,
		SkipInterface:       skipInterface,
		SelfUpdateUrl:       proto.String(gVTapInfo.GetSelfUpdateUrl()),
		Revision:            proto.String(upgradeRevision),
	}, nil
}

func (e *VTapEvent) generateNoVTapCacheConfig(groupID string) *api.Config {
	vtapConfig := trisolaris.GetGVTapInfo().GetVTapConfigFromShortID(groupID)
	if vtapConfig == nil {
		return nil
	}
	collectorSocketType, ok := SOCKET_TYPE_TO_MESSAGE[vtapConfig.CollectorSocketType]
	if ok == false {
		collectorSocketType = UDP_SOCKET
	}
	npbSocketType, ok := SOCKET_TYPE_TO_MESSAGE[vtapConfig.NpbSocketType]
	if ok == false {
		npbSocketType = RAW_UDP_SOCKET
	}
	decapTypes := make([]api.DecapType, 0, len(vtapConfig.ConvertedDecapType))
	for _, decap := range vtapConfig.ConvertedDecapType {
		decapTypes = append(decapTypes, api.DecapType(decap))
	}
	npbVlanMode := api.VlanMode(vtapConfig.NpbVlanMode)
	ifMacSource := api.IfMacSource(vtapConfig.IfMacSource)
	captureSocketType := api.CaptureSocketType(vtapConfig.CaptureSocketType)
	tapMode := api.TapMode(vtapConfig.TapMode)
	breakerMetricStr := convertBreakerMetric(vtapConfig.SystemLoadCircuitBreakerMetric)
	loadMetric := api.SystemLoadMetric(api.SystemLoadMetric_value[breakerMetricStr])
	configure := &api.Config{
		CollectorEnabled:              proto.Bool(Int2Bool(vtapConfig.CollectorEnabled)),
		CollectorSocketType:           &collectorSocketType,
		PlatformEnabled:               proto.Bool(Int2Bool(vtapConfig.PlatformEnabled)),
		MaxCpus:                       proto.Uint32(uint32(vtapConfig.MaxCPUs)),
		MaxMemory:                     proto.Uint32(uint32(vtapConfig.MaxMemory)),
		StatsInterval:                 proto.Uint32(uint32(vtapConfig.StatsInterval)),
		SyncInterval:                  proto.Uint32(uint32(vtapConfig.SyncInterval)),
		PlatformSyncInterval:          proto.Uint32(uint32(vtapConfig.PlatformSyncInterval)),
		NpbBpsThreshold:               proto.Uint64(uint64(vtapConfig.MaxNpbBps)),
		GlobalPpsThreshold:            proto.Uint64(uint64(vtapConfig.MaxCollectPps)),
		Mtu:                           proto.Uint32(uint32(vtapConfig.Mtu)),
		OutputVlan:                    proto.Uint32(uint32(vtapConfig.OutputVlan)),
		RsyslogEnabled:                proto.Bool(Int2Bool(vtapConfig.RsyslogEnabled)),
		ServerTxBandwidthThreshold:    proto.Uint64(uint64(vtapConfig.MaxTxBandwidth)),
		BandwidthProbeInterval:        proto.Uint64(uint64(vtapConfig.BandwidthProbeInterval)),
		MaxEscapeSeconds:              proto.Uint32(uint32(vtapConfig.MaxEscapeSeconds)),
		NpbVlanMode:                   &npbVlanMode,
		NpbDedupEnabled:               proto.Bool(Int2Bool(vtapConfig.NpbDedupEnabled)),
		IfMacSource:                   &ifMacSource,
		NpbSocketType:                 &npbSocketType,
		VtapFlow_1SEnabled:            proto.Bool(Int2Bool(vtapConfig.VTapFlow1sEnabled)),
		CapturePacketSize:             proto.Uint32(uint32(vtapConfig.CapturePacketSize)),
		InactiveServerPortEnabled:     proto.Bool(Int2Bool(vtapConfig.InactiveServerPortEnabled)),
		InactiveIpEnabled:             proto.Bool(Int2Bool(vtapConfig.InactiveIPEnabled)),
		LibvirtXmlPath:                proto.String(vtapConfig.VMXMLPath),
		ExtraNetnsRegex:               proto.String(vtapConfig.ExtraNetnsRegex),
		LogThreshold:                  proto.Uint32(uint32(vtapConfig.LogThreshold)),
		LogLevel:                      proto.String(vtapConfig.LogLevel),
		LogRetention:                  proto.Uint32(uint32(vtapConfig.LogRetention)),
		L4LogCollectNpsThreshold:      proto.Uint64(uint64(vtapConfig.L4LogCollectNpsThreshold)),
		L7LogCollectNpsThreshold:      proto.Uint64(uint64(vtapConfig.L7LogCollectNpsThreshold)),
		L7MetricsEnabled:              proto.Bool(Int2Bool(vtapConfig.L7MetricsEnabled)),
		L7LogPacketSize:               proto.Uint32(uint32(vtapConfig.L7LogPacketSize)),
		DecapType:                     decapTypes,
		CaptureSocketType:             &captureSocketType,
		CaptureBpf:                    proto.String(vtapConfig.CaptureBpf),
		ThreadThreshold:               proto.Uint32(uint32(vtapConfig.ThreadThreshold)),
		ProcessThreshold:              proto.Uint32(uint32(vtapConfig.ProcessThreshold)),
		HttpLogProxyClient:            proto.String(vtapConfig.HTTPLogProxyClient),
		HttpLogTraceId:                proto.String(vtapConfig.HTTPLogTraceID),
		HttpLogSpanId:                 proto.String(vtapConfig.HTTPLogSpanID),
		HttpLogXRequestId:             proto.String(vtapConfig.HTTPLogXRequestID),
		NtpEnabled:                    proto.Bool(Int2Bool(vtapConfig.NtpEnabled)),
		L4PerformanceEnabled:          proto.Bool(Int2Bool(vtapConfig.L4PerformanceEnabled)),
		KubernetesApiEnabled:          proto.Bool(false),
		SysFreeMemoryLimit:            proto.Uint32(uint32(vtapConfig.SysFreeMemoryLimit)),
		LogFileSize:                   proto.Uint32(uint32(vtapConfig.LogFileSize)),
		ExternalAgentHttpProxyEnabled: proto.Bool(Int2Bool(vtapConfig.ExternalAgentHTTPProxyEnabled)),
		ExternalAgentHttpProxyPort:    proto.Uint32(uint32(vtapConfig.ExternalAgentHTTPProxyPort)),
		PrometheusHttpApiAddresses:    strings.Split(vtapConfig.PrometheusHttpAPIAddresses, ","),
		AnalyzerPort:                  proto.Uint32(uint32(vtapConfig.AnalyzerPort)),
		ProxyControllerPort:           proto.Uint32(uint32(vtapConfig.ProxyControllerPort)),
		TapMode:                       &tapMode,
		// 调整后采集器配置信息
		L7LogStoreTapTypes:  vtapConfig.ConvertedL7LogStoreTapTypes,
		L4LogTapTypes:       vtapConfig.ConvertedL4LogTapTypes,
		L4LogIgnoreTapSides: vtapConfig.ConvertedL4LogIgnoreTapSides,
		L7LogIgnoreTapSides: vtapConfig.ConvertedL7LogIgnoreTapSides,
		Plugins:             e.getPlugins(vtapConfig),

		SystemLoadCircuitBreakerThreshold: proto.Float32((vtapConfig.SystemLoadCircuitBreakerThreshold)),
		SystemLoadCircuitBreakerRecover:   proto.Float32((vtapConfig.SystemLoadCircuitBreakerRecover)),
		SystemLoadCircuitBreakerMetric:    &loadMetric,
	}
	if vtapConfig.TapInterfaceRegex != "" {
		configure.TapInterfaceRegex = proto.String(vtapConfig.TapInterfaceRegex)
	}
	configure.LocalConfig = proto.String(
		trisolaris.GetGVTapInfo().GetVTapLocalConfigByShortID(groupID))

	if vtapConfig.ProxyControllerIP != "" {
		configure.ProxyControllerIp = proto.String(vtapConfig.ProxyControllerIP)
	}
	if vtapConfig.AnalyzerIP != "" {
		configure.AnalyzerIp = proto.String(vtapConfig.AnalyzerIP)
	}

	return configure
}

func (e *VTapEvent) noVTapResponse(in *api.SyncRequest) *api.SyncResponse {
	ctrlIP := in.GetCtrlIp()
	ctrlMac := in.GetCtrlMac()
	vtapCacheKey := ctrlIP + "-" + ctrlMac

	configInfo := e.generateNoVTapCacheConfig(in.GetVtapGroupIdRequest())
	gVTapInfo := trisolaris.GetGVTapInfo()
	if in.GetKubernetesClusterId() != "" {
		tridentType := common.TridentType(VTAP_TYPE_POD_VM)
		if configInfo == nil {
			configInfo = &api.Config{
				KubernetesApiEnabled: proto.Bool(false),
				MaxEscapeSeconds:     proto.Uint32(uint32(gVTapInfo.GetDefaultMaxEscapeSeconds())),
				MaxMemory:            proto.Uint32(uint32(gVTapInfo.GetDefaultMaxMemory())),
			}
		}
		configInfo.TridentType = &tridentType
		configInfo.Enabled = proto.Bool(false)
		value := gVTapInfo.GetKubernetesClusterID(in.GetKubernetesClusterId(), vtapCacheKey, in.GetKubernetesForceWatch())
		if value == vtapCacheKey {
			configInfo.KubernetesApiEnabled = proto.Bool(true)
			log.Infof(
				"open cluster(%s) kubernetes_api_enabled VTap(ctrl_ip: %s, ctrl_mac: %s, kubernetes_force_watch: %t)",
				in.GetKubernetesClusterId(), ctrlIP, ctrlMac, in.GetKubernetesForceWatch())
		}
		return &api.SyncResponse{
			Status: &STATUS_SUCCESS,
			Config: configInfo,
		}
	}

	tridentTypeForUnkonwVTap := gVTapInfo.GetTridentTypeForUnkonwVTap()
	if tridentTypeForUnkonwVTap != 0 {
		tridentType := common.TridentType(tridentTypeForUnkonwVTap)
		if configInfo == nil {
			configInfo = &api.Config{
				MaxEscapeSeconds: proto.Uint32(uint32(gVTapInfo.GetDefaultMaxEscapeSeconds())),
				MaxMemory:        proto.Uint32(uint32(gVTapInfo.GetDefaultMaxMemory())),
				PlatformEnabled:  proto.Bool(true),
			}
		}
		configInfo.Enabled = proto.Bool(false)
		configInfo.TridentType = &tridentType

		return &api.SyncResponse{
			Status: &STATUS_SUCCESS,
			Config: configInfo,
		}
	}

	// if vtap not exist & not k8s/agent sync, set vtap disable
	if configInfo == nil {
		configInfo = &api.Config{
			Enabled: proto.Bool(false),
		}
	} else {
		configInfo.Enabled = proto.Bool(false)
	}

	return &api.SyncResponse{
		Status: &STATUS_SUCCESS,
		Config: configInfo,
	}
}

func (e *VTapEvent) getVTapCache(in *api.SyncRequest) (*vtap.VTapCache, error) {
	gVTapInfo := trisolaris.GetGVTapInfo()
	ctrlIP := in.GetCtrlIp()
	ctrlMac := in.GetCtrlMac()
	vtapCacheKey := ctrlIP + "-" + ctrlMac
	if !gVTapInfo.GetVTapCacheIsReady() {
		return nil, fmt.Errorf("VTap cache data not ready")
	}

	vtapCache := gVTapInfo.GetVTapCache(vtapCacheKey)
	if vtapCache == nil {
		vtapCache = gVTapInfo.GetVTapCache(ctrlIP)
		if vtapCache == nil {
			vtapCache = gVTapInfo.GetKvmVTapCache(ctrlIP)
			// ctrl_ip是kvm采集器的，但是ctrl_mac不属于tap_ports，需自动发现采集器
			if vtapCache != nil && gVTapInfo.IsCtrlMacInTapPorts(ctrlIP, ctrlMac) == false {
				vtapCache = nil
			}
		}
	}
	return vtapCache, nil
}

func (e *VTapEvent) pushResponse(in *api.SyncRequest) (*api.SyncResponse, error) {
	ctrlIP := in.GetCtrlIp()
	ctrlMac := in.GetCtrlMac()
	vtapCacheKey := ctrlIP + "-" + ctrlMac
	gVTapInfo := trisolaris.GetGVTapInfo()
	vtapCache, err := e.getVTapCache(in)
	if err != nil {
		return &api.SyncResponse{
			Status:        &STATUS_FAILED,
			Revision:      proto.String(in.GetRevision()),
			SelfUpdateUrl: proto.String(gVTapInfo.GetSelfUpdateUrl()),
		}, err
	}
	if vtapCache == nil {
		return e.noVTapResponse(in), fmt.Errorf("no find vtap(%s %s) cache", ctrlIP, ctrlMac)
	}
	vtapID := int(vtapCache.GetVTapID())
	functions := vtapCache.GetFunctions()
	versionPlatformData := vtapCache.GetSimplePlatformDataVersion()
	pushVersionPlatformData := vtapCache.GetPushVersionPlatformData()
	versionGroups := gVTapInfo.GetGroupDataVersion()
	pushVersionGroups := vtapCache.GetPushVersionGroups()
	versionPolicy := gVTapInfo.GetVTapPolicyVersion(vtapID, functions)
	pushVersionPolicy := vtapCache.GetPushVersionPolicy()
	newAcls := gVTapInfo.GetVTapPolicyData(vtapID, functions)
	if versionPlatformData != pushVersionPlatformData ||
		versionGroups != pushVersionGroups || versionPolicy != pushVersionPolicy {
		log.Infof("push data ctrl_ip is %s, ctrl_mac is %s, "+
			"(platform data version  %d -> %d), "+
			"(acls version %d -> %d datalen: %d), "+
			"(groups version %d -> %d), "+
			"NAME:%s  REVISION:%s  BOOT_TIME:%d",
			ctrlIP, ctrlMac,
			versionPlatformData, pushVersionPlatformData,
			versionPolicy, pushVersionPolicy, len(newAcls),
			versionGroups, pushVersionGroups,
			in.GetProcessName(), in.GetRevision(), in.GetBootTime())
	} else {
		log.Debugf("push data ctrl_ip is %s, ctrl_mac is %s, "+
			"(platform data version  %d -> %d), "+
			"(acls version %d -> %d), "+
			"(groups version %d -> %d), "+
			"NAME:%s  REVISION:%s  BOOT_TIME:%d",
			ctrlIP, ctrlMac,
			versionPlatformData, pushVersionPlatformData,
			versionPolicy, pushVersionPolicy,
			versionGroups, pushVersionGroups,
			in.GetProcessName(), in.GetRevision(), in.GetBootTime())
	}

	platformData := []byte{}
	if versionPlatformData != pushVersionPlatformData {
		platformData = vtapCache.GetSimplePlatformDataStr()
	}
	groups := []byte{}
	if versionGroups != pushVersionGroups {
		groups = gVTapInfo.GetGroupData()
	}
	acls := []byte{}
	if versionPolicy != pushVersionPolicy {
		acls = gVTapInfo.GetVTapPolicyData(vtapID, functions)
	}

	// 只有专属采集器下发tap_types
	tapTypes := []*api.TapType{}
	if vtapCache.GetVTapType() == VTAP_TYPE_DEDICATED {
		tapTypes = gVTapInfo.GetTapTypes()
	}

	configInfo := e.generateConfigInfo(vtapCache, in.GetKubernetesClusterId())
	// 携带信息有cluster_id时选择一个采集器开启云平台同步开关
	if in.GetKubernetesClusterId() != "" && isOpenK8sSyn(vtapCache.GetVTapType()) == true {
		value := gVTapInfo.GetKubernetesClusterID(in.GetKubernetesClusterId(), vtapCacheKey, in.GetKubernetesForceWatch())
		if value == vtapCacheKey {
			log.Infof(
				"open cluster(%s) kubernetes_api_enabled VTap(ctrl_ip: %s, ctrl_mac: %s, kubernetes_force_watch: %t)",
				in.GetKubernetesClusterId(), ctrlIP, ctrlMac, in.GetKubernetesForceWatch())
			configInfo.KubernetesApiEnabled = proto.Bool(true)
		}
	}
	localSegments := vtapCache.GetVTapLocalSegments()
	remoteSegments := vtapCache.GetVTapRemoteSegments()
	skipInterface := gVTapInfo.GetSkipInterface(vtapCache)
	Containers := gVTapInfo.GetContainers(int(vtapCache.GetVTapID()))
	return &api.SyncResponse{
		Status:              &STATUS_SUCCESS,
		LocalSegments:       localSegments,
		RemoteSegments:      remoteSegments,
		Config:              configInfo,
		PlatformData:        platformData,
		SkipInterface:       skipInterface,
		VersionPlatformData: proto.Uint64(versionPlatformData),
		Groups:              groups,
		VersionGroups:       proto.Uint64(versionGroups),
		FlowAcls:            acls,
		VersionAcls:         proto.Uint64(versionPolicy),
		TapTypes:            tapTypes,
		Containers:          Containers,
	}, nil
}

func (e *VTapEvent) Push(r *api.SyncRequest, in api.Synchronizer_PushServer) error {
	var err error
	for {
		response, err := e.pushResponse(r)
		if err != nil {
			log.Error(err)
		}
		err = in.Send(response)
		if err != nil {
			log.Error(err)
			break
		}
		pushmanager.Wait()
	}
	log.Info("exit push", r.GetCtrlIp(), r.GetCtrlMac())
	return err
}
