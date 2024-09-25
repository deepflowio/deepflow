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
	"github.com/deepflowio/deepflow/server/libs/logger"
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

func (e *VTapEvent) generateConfigInfo(c *vtap.VTapCache, clusterID string, gVTapInfo *vtap.VTapInfo, orgID int) *api.Config {
	vtapConfig := c.GetVTapConfig()
	if vtapConfig == nil {
		return &api.Config{}
	}

	collectorSocketType, ok := SOCKET_TYPE_TO_MESSAGE[*vtapConfig.CollectorSocketType]
	if ok == false {
		collectorSocketType = UDP_SOCKET
	}
	npbSocketType, ok := SOCKET_TYPE_TO_MESSAGE[*vtapConfig.NpbSocketType]
	if ok == false {
		npbSocketType = RAW_UDP_SOCKET
	}
	decapTypes := make([]api.DecapType, 0, len(vtapConfig.ConvertedDecapType))
	for _, decap := range vtapConfig.ConvertedDecapType {
		decapTypes = append(decapTypes, api.DecapType(decap))
	}
	npbVlanMode := api.VlanMode(*vtapConfig.NpbVlanMode)
	ifMacSource := api.IfMacSource(*vtapConfig.IfMacSource)
	captureSocketType := api.CaptureSocketType(*vtapConfig.CaptureSocketType)
	vtapID := uint32(c.GetVTapID())

	tridentType := common.TridentType(0)
	if clusterID != "" { // if agent report cluster_id, force set tridentType = VTAP_TYPE_POD_VM
		tridentType = common.TridentType(VTAP_TYPE_POD_VM)
	} else {
		tridentType = common.TridentType(c.GetVTapType())
	}
	podClusterId := uint32(c.GetPodClusterID())
	vpcID := uint32(c.GetVPCID())
	tapMode := api.TapMode(*vtapConfig.TapMode)
	breakerMetricStr := convertBreakerMetric(*vtapConfig.SystemLoadCircuitBreakerMetric)
	loadMetric := api.SystemLoadMetric(api.SystemLoadMetric_value[breakerMetricStr])
	configure := &api.Config{
		CollectorEnabled:              proto.Bool(Int2Bool(*vtapConfig.CollectorEnabled)),
		CollectorSocketType:           &collectorSocketType,
		PlatformEnabled:               proto.Bool(Int2Bool(*vtapConfig.PlatformEnabled)),
		MaxCpus:                       proto.Uint32(uint32(*vtapConfig.MaxCPUs)),
		MaxMillicpus:                  proto.Uint32(uint32(*vtapConfig.MaxMilliCPUs)),
		MaxMemory:                     proto.Uint32(uint32(*vtapConfig.MaxMemory)),
		StatsInterval:                 proto.Uint32(uint32(*vtapConfig.StatsInterval)),
		SyncInterval:                  proto.Uint32(uint32(*vtapConfig.SyncInterval)),
		PlatformSyncInterval:          proto.Uint32(uint32(*vtapConfig.PlatformSyncInterval)),
		NpbBpsThreshold:               proto.Uint64(uint64(*vtapConfig.MaxNpbBps)),
		GlobalPpsThreshold:            proto.Uint64(uint64(*vtapConfig.MaxCollectPps)),
		Mtu:                           proto.Uint32(uint32(*vtapConfig.Mtu)),
		OutputVlan:                    proto.Uint32(uint32(*vtapConfig.OutputVlan)),
		RsyslogEnabled:                proto.Bool(Int2Bool(*vtapConfig.RsyslogEnabled)),
		ServerTxBandwidthThreshold:    proto.Uint64(uint64(*vtapConfig.MaxTxBandwidth)),
		BandwidthProbeInterval:        proto.Uint64(uint64(*vtapConfig.BandwidthProbeInterval)),
		MaxEscapeSeconds:              proto.Uint32(uint32(*vtapConfig.MaxEscapeSeconds)),
		NpbVlanMode:                   &npbVlanMode,
		NpbDedupEnabled:               proto.Bool(Int2Bool(*vtapConfig.NpbDedupEnabled)),
		IfMacSource:                   &ifMacSource,
		NpbSocketType:                 &npbSocketType,
		VtapFlow_1SEnabled:            proto.Bool(Int2Bool(*vtapConfig.VTapFlow1sEnabled)),
		CapturePacketSize:             proto.Uint32(uint32(*vtapConfig.CapturePacketSize)),
		InactiveServerPortEnabled:     proto.Bool(Int2Bool(*vtapConfig.InactiveServerPortEnabled)),
		InactiveIpEnabled:             proto.Bool(Int2Bool(*vtapConfig.InactiveIPEnabled)),
		LibvirtXmlPath:                vtapConfig.VMXMLPath,
		ExtraNetnsRegex:               vtapConfig.ExtraNetnsRegex,
		LogThreshold:                  proto.Uint32(uint32(*vtapConfig.LogThreshold)),
		LogLevel:                      vtapConfig.LogLevel,
		LogRetention:                  proto.Uint32(uint32(*vtapConfig.LogRetention)),
		L4LogCollectNpsThreshold:      proto.Uint64(uint64(*vtapConfig.L4LogCollectNpsThreshold)),
		L7LogCollectNpsThreshold:      proto.Uint64(uint64(*vtapConfig.L7LogCollectNpsThreshold)),
		L7MetricsEnabled:              proto.Bool(Int2Bool(*vtapConfig.L7MetricsEnabled)),
		L7LogPacketSize:               proto.Uint32(uint32(*vtapConfig.L7LogPacketSize)),
		DecapType:                     decapTypes,
		CaptureSocketType:             &captureSocketType,
		CaptureBpf:                    vtapConfig.CaptureBpf,
		ThreadThreshold:               proto.Uint32(uint32(*vtapConfig.ThreadThreshold)),
		ProcessThreshold:              proto.Uint32(uint32(*vtapConfig.ProcessThreshold)),
		HttpLogProxyClient:            vtapConfig.HTTPLogProxyClient,
		HttpLogTraceId:                vtapConfig.HTTPLogTraceID,
		HttpLogSpanId:                 vtapConfig.HTTPLogSpanID,
		HttpLogXRequestId:             vtapConfig.HTTPLogXRequestID,
		NtpEnabled:                    proto.Bool(Int2Bool(*vtapConfig.NtpEnabled)),
		L4PerformanceEnabled:          proto.Bool(Int2Bool(*vtapConfig.L4PerformanceEnabled)),
		KubernetesApiEnabled:          proto.Bool(false),
		SysFreeMemoryLimit:            proto.Uint32(uint32(*vtapConfig.SysFreeMemoryLimit)),
		LogFileSize:                   proto.Uint32(uint32(*vtapConfig.LogFileSize)),
		ExternalAgentHttpProxyEnabled: proto.Bool(Int2Bool(c.GetExternalAgentHTTPProxyEnabledConfig())),
		ExternalAgentHttpProxyPort:    proto.Uint32(uint32(*vtapConfig.ExternalAgentHTTPProxyPort)),
		AnalyzerPort:                  proto.Uint32(uint32(*vtapConfig.AnalyzerPort)),
		ProxyControllerPort:           proto.Uint32(uint32(*vtapConfig.ProxyControllerPort)),
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

		SystemLoadCircuitBreakerThreshold: vtapConfig.SystemLoadCircuitBreakerThreshold,
		SystemLoadCircuitBreakerRecover:   vtapConfig.SystemLoadCircuitBreakerRecover,
		SystemLoadCircuitBreakerMetric:    &loadMetric,

		TeamId:     proto.Uint32(uint32(c.GetTeamID())),
		OrganizeId: proto.Uint32(uint32(c.GetOrganizeID())),
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

	if trisolaris.GetAllAgentConnectToNatIP() || (vtapConfig.NatIPEnabled != nil && *vtapConfig.NatIPEnabled == 1) {
		configure.ProxyControllerIp = proto.String(trisolaris.GetORGNodeInfo(orgID).GetControllerNatIP(c.GetControllerIP()))
		configure.ProxyControllerPort = proto.Uint32(uint32(DefaultProxyControllerPort))

		configure.AnalyzerIp = proto.String(trisolaris.GetORGNodeInfo(orgID).GetTSDBNatIP(c.GetTSDBIP()))
		configure.AnalyzerPort = proto.Uint32(uint32(DefaultAnalyzerPort))
	}

	if vtapConfig.ProxyControllerIP != nil && *vtapConfig.ProxyControllerIP != "" {
		configure.ProxyControllerIp = vtapConfig.ProxyControllerIP
	}
	if vtapConfig.ProxyControllerPort != nil && *vtapConfig.ProxyControllerPort != 0 {
		configure.ProxyControllerPort = proto.Uint32(uint32(*vtapConfig.ProxyControllerPort))
	}
	if vtapConfig.AnalyzerIP != nil && *vtapConfig.AnalyzerIP != "" {
		configure.AnalyzerIp = vtapConfig.AnalyzerIP
	}
	if vtapConfig.AnalyzerPort != nil && *vtapConfig.AnalyzerPort != 0 {
		configure.AnalyzerPort = proto.Uint32(uint32(*vtapConfig.AnalyzerPort))
	}

	if isPodVTap(c.GetVTapType()) && gVTapInfo.IsTheSameCluster(clusterID) {
		configure.AnalyzerIp = proto.String(trisolaris.GetORGNodeInfo(orgID).GetTSDBPodIP(c.GetTSDBIP()))
		configure.AnalyzerPort = proto.Uint32(uint32(trisolaris.GetIngesterPort()))

		configure.ProxyControllerIp = proto.String(trisolaris.GetORGNodeInfo(orgID).GetControllerPodIP(c.GetControllerIP()))
		configure.ProxyControllerPort = proto.Uint32(uint32(trisolaris.GetGrpcPort()))

	}

	if configure.GetProxyControllerIp() == "" {
		log.Errorf("agent(%s) has no proxy_controller_ip, "+
			"Please check whether the agent allocs controller IP or If nat-ip is enabled, whether the controller is configured with nat-ip", c.GetCtrlIP())
	}
	if configure.GetAnalyzerIp() == "" {
		configure.Enabled = proto.Bool(false)
		log.Errorf("agent(%s) has no tsdb_ip, "+
			"Please check whether the agent allocs tsdb IP or If nat-ip is enabled, whether the tsdb is configured with nat-ip", c.GetCtrlIP())
	}
	if vtapConfig.TapInterfaceRegex != nil && *vtapConfig.TapInterfaceRegex != "" {
		configure.TapInterfaceRegex = vtapConfig.TapInterfaceRegex
	}
	pcapDataRetention := trisolaris.GetORGNodeInfo(orgID).GetPcapDataRetention()
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

func (e *VTapEvent) GetFailedResponse(in *api.SyncRequest, gVTapInfo *vtap.VTapInfo) *api.SyncResponse {
	return &api.SyncResponse{
		Status:        &STATUS_FAILED,
		Revision:      proto.String(in.GetRevision()),
		SelfUpdateUrl: proto.String(gVTapInfo.GetSelfUpdateUrl()),
	}
}

func (e *VTapEvent) Sync(ctx context.Context, in *api.SyncRequest) (*api.SyncResponse, error) {
	if trisolaris.GetConfig().DomainAutoRegister && in.GetKubernetesClusterId() != "" {
		gKubernetesInfo := trisolaris.GetGKubernetesInfo(in.GetTeamId())
		if gKubernetesInfo != nil {
			exists := gKubernetesInfo.CreateDomainIfClusterIDNotExists(in.GetTeamId(), in.GetKubernetesClusterId(), in.GetKubernetesClusterName())
			if !exists {
				log.Infof("call me from ip: %s with team_id: %s, cluster_id: %s, cluster_name: %s", getRemote(ctx), in.GetTeamId(), in.GetKubernetesClusterId(), in.GetKubernetesClusterName())
			}
		}
	}

	ctrlIP := in.GetCtrlIp()
	ctrlMac := in.GetCtrlMac()
	teamIDStr := in.GetTeamId()
	orgID, teamIDInt := trisolaris.GetOrgInfoByTeamID(teamIDStr)
	if rOrgID := int(in.GetOrgId()); rOrgID != 0 && len(teamIDStr) == 0 {
		orgID = rOrgID
	}
	gVTapInfo := trisolaris.GetORGVTapInfo(orgID)
	if gVTapInfo == nil {
		log.Errorf("ctrlIp is %s, ctrlMac is %s, team_id is (str=%s,int=%d) not found vtapInfo", ctrlIP, ctrlMac, teamIDStr, teamIDInt, logger.NewORGPrefix(orgID))
		return e.GetFailedResponse(in, gVTapInfo), nil
	}
	vtapCacheKey := ctrlIP + "-" + ctrlMac
	vtapCache, err := e.getVTapCache(in, orgID)
	if err != nil {
		log.Warningf("err:%s ctrlIp is %s, ctrlMac is %s, team_id is (str=%s,int=%d), hostIps is %s, name:%s,  revision:%s,  bootTime:%d",
			err, ctrlIP, ctrlMac, teamIDStr, teamIDInt, in.GetHostIps(), in.GetProcessName(), in.GetRevision(), in.GetBootTime(), logger.NewORGPrefix(orgID))
		return e.GetFailedResponse(in, gVTapInfo), nil
	}
	if vtapCache == nil {
		if len(teamIDStr) == 0 && trisolaris.GetIsRefused() {
			log.Errorf("ctrlIp is %s, ctrlMac is %s, not team_id refuse(%v) register", ctrlIP, ctrlMac, trisolaris.GetIsRefused(), logger.NewORGPrefix(orgID))
			return e.GetFailedResponse(in, nil), nil
		}
		log.Warningf("vtap (ctrl_ip: %s, ctrl_mac: %s, team_id: (str=%s,int=%d), host_ips: %s, kubernetes_cluster_id: %s, kubernetes_force_watch: %t, kubernetes_watch_policy: %d, group_id: %s) not found in cache. "+
			"NAME:%s  REVISION:%s  BOOT_TIME:%d",
			ctrlIP, ctrlMac, teamIDStr, teamIDInt, in.GetHostIps(),
			in.GetKubernetesClusterId(), in.GetKubernetesForceWatch(), in.GetKubernetesWatchPolicy(),
			in.GetVtapGroupIdRequest(), in.GetProcessName(), in.GetRevision(), in.GetBootTime(), logger.NewORGPrefix(orgID))
		// kubernetes_force_watch field is compatibility for old version agent
		// If the kubernetes_force_watch field is true, the ctrl_ip and ctrl_mac of the vtap will not change,
		// If the kubernetes_watch_policy field is KWP_WATCH_ONLY, the ctrl_ip and ctrl_mac of the vtap will not change,
		// resulting in unsuccessful registration and a large number of error logs.
		if !in.GetKubernetesForceWatch() || in.GetKubernetesWatchPolicy() != KWP_WATCH_ONLY {
			gVTapInfo.Register(
				int(in.GetTapMode()),
				in.GetCtrlIp(),
				in.GetCtrlMac(),
				in.GetHostIps(),
				in.GetHost(),
				in.GetVtapGroupIdRequest(),
				int(in.GetAgentUniqueIdentifier()),
				teamIDInt)
		}
		return e.noVTapResponse(in, orgID), nil
	}

	vtapID := int(vtapCache.GetVTapID())
	functions := vtapCache.GetFunctions()
	versionPlatformData := vtapCache.GetSimplePlatformDataVersion()
	versionGroups := gVTapInfo.GetGroupDataVersion()
	versionPolicy := gVTapInfo.GetVTapPolicyVersion(vtapID, functions)
	changedInfo := fmt.Sprintf("ctrl_ip is %s, ctrl_mac is %s, team_id is (str=%s,int=%d), host_ips is %s, "+
		"(platform data version  %d -> %d), "+
		"(acls version %d -> %d), "+
		"(groups version %d -> %d), "+
		"NAME:%s  REVISION:%s  BOOT_TIME:%d",
		ctrlIP, ctrlMac, teamIDStr, teamIDInt, in.GetHostIps(),
		versionPlatformData, in.GetVersionPlatformData(),
		versionPolicy, in.GetVersionAcls(),
		versionGroups, in.GetVersionGroups(),
		in.GetProcessName(), in.GetRevision(), in.GetBootTime())

	if versionPlatformData != in.GetVersionPlatformData() || versionPlatformData == 0 ||
		versionGroups != in.GetVersionGroups() || versionPolicy != in.GetVersionAcls() {
		log.Info(changedInfo, logger.NewORGPrefix(orgID))
	} else {
		log.Debug(changedInfo, logger.NewORGPrefix(orgID))
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
		in.GetProcessName(),
		in.GetCurrentK8SImage())

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

	configInfo := e.generateConfigInfo(vtapCache, in.GetKubernetesClusterId(), gVTapInfo, orgID)
	// 携带信息有cluster_id && watch_policy != disabled 时选择一个采集器开启云平台同步开关
	if in.GetKubernetesClusterId() != "" &&
		in.GetKubernetesWatchPolicy() != KWP_WATCH_DISABLED &&
		isOpenK8sSyn(vtapCache.GetVTapType()) == true {
		value := gVTapInfo.GetKubernetesClusterID(
			in.GetKubernetesClusterId(),
			vtapCacheKey,
			in.GetKubernetesForceWatch(),
			int(in.GetKubernetesWatchPolicy()),
		)
		if value == vtapCacheKey {
			log.Infof(
				"open cluster(%s) kubernetes_api_enabled VTap(ctrl_ip: %s, ctrl_mac: %s, team_id: (str=%s,int=%d), kubernetes_force_watch: %t, kubernetes_watch_policy: %d)",
				in.GetKubernetesClusterId(), ctrlIP, ctrlMac,
				teamIDStr, teamIDInt, in.GetKubernetesForceWatch(), in.GetKubernetesWatchPolicy(), logger.NewORGPrefix(orgID))
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

func (e *VTapEvent) generateNoVTapCacheConfig(groupID string, orgID int) *api.Config {
	vtapConfig := trisolaris.GetORGVTapInfo(orgID).GetVTapConfigFromShortID(groupID)
	if vtapConfig == nil {
		return nil
	}
	collectorSocketType, ok := SOCKET_TYPE_TO_MESSAGE[*vtapConfig.CollectorSocketType]
	if ok == false {
		collectorSocketType = UDP_SOCKET
	}
	npbSocketType, ok := SOCKET_TYPE_TO_MESSAGE[*vtapConfig.NpbSocketType]
	if ok == false {
		npbSocketType = RAW_UDP_SOCKET
	}
	decapTypes := make([]api.DecapType, 0, len(vtapConfig.ConvertedDecapType))
	for _, decap := range vtapConfig.ConvertedDecapType {
		decapTypes = append(decapTypes, api.DecapType(decap))
	}
	npbVlanMode := api.VlanMode(*vtapConfig.NpbVlanMode)
	ifMacSource := api.IfMacSource(*vtapConfig.IfMacSource)
	captureSocketType := api.CaptureSocketType(*vtapConfig.CaptureSocketType)
	tapMode := api.TapMode(*vtapConfig.TapMode)
	breakerMetricStr := convertBreakerMetric(*vtapConfig.SystemLoadCircuitBreakerMetric)
	loadMetric := api.SystemLoadMetric(api.SystemLoadMetric_value[breakerMetricStr])
	configure := &api.Config{
		CollectorEnabled:              proto.Bool(Int2Bool(*vtapConfig.CollectorEnabled)),
		CollectorSocketType:           &collectorSocketType,
		PlatformEnabled:               proto.Bool(Int2Bool(*vtapConfig.PlatformEnabled)),
		MaxCpus:                       proto.Uint32(uint32(*vtapConfig.MaxCPUs)),
		MaxMillicpus:                  proto.Uint32(uint32(*vtapConfig.MaxMilliCPUs)),
		MaxMemory:                     proto.Uint32(uint32(*vtapConfig.MaxMemory)),
		StatsInterval:                 proto.Uint32(uint32(*vtapConfig.StatsInterval)),
		SyncInterval:                  proto.Uint32(uint32(*vtapConfig.SyncInterval)),
		PlatformSyncInterval:          proto.Uint32(uint32(*vtapConfig.PlatformSyncInterval)),
		NpbBpsThreshold:               proto.Uint64(uint64(*vtapConfig.MaxNpbBps)),
		GlobalPpsThreshold:            proto.Uint64(uint64(*vtapConfig.MaxCollectPps)),
		Mtu:                           proto.Uint32(uint32(*vtapConfig.Mtu)),
		OutputVlan:                    proto.Uint32(uint32(*vtapConfig.OutputVlan)),
		RsyslogEnabled:                proto.Bool(Int2Bool(*vtapConfig.RsyslogEnabled)),
		ServerTxBandwidthThreshold:    proto.Uint64(uint64(*vtapConfig.MaxTxBandwidth)),
		BandwidthProbeInterval:        proto.Uint64(uint64(*vtapConfig.BandwidthProbeInterval)),
		MaxEscapeSeconds:              proto.Uint32(uint32(*vtapConfig.MaxEscapeSeconds)),
		NpbVlanMode:                   &npbVlanMode,
		NpbDedupEnabled:               proto.Bool(Int2Bool(*vtapConfig.NpbDedupEnabled)),
		IfMacSource:                   &ifMacSource,
		NpbSocketType:                 &npbSocketType,
		VtapFlow_1SEnabled:            proto.Bool(Int2Bool(*vtapConfig.VTapFlow1sEnabled)),
		CapturePacketSize:             proto.Uint32(uint32(*vtapConfig.CapturePacketSize)),
		InactiveServerPortEnabled:     proto.Bool(Int2Bool(*vtapConfig.InactiveServerPortEnabled)),
		InactiveIpEnabled:             proto.Bool(Int2Bool(*vtapConfig.InactiveIPEnabled)),
		LibvirtXmlPath:                vtapConfig.VMXMLPath,
		ExtraNetnsRegex:               vtapConfig.ExtraNetnsRegex,
		LogThreshold:                  proto.Uint32(uint32(*vtapConfig.LogThreshold)),
		LogLevel:                      vtapConfig.LogLevel,
		LogRetention:                  proto.Uint32(uint32(*vtapConfig.LogRetention)),
		L4LogCollectNpsThreshold:      proto.Uint64(uint64(*vtapConfig.L4LogCollectNpsThreshold)),
		L7LogCollectNpsThreshold:      proto.Uint64(uint64(*vtapConfig.L7LogCollectNpsThreshold)),
		L7MetricsEnabled:              proto.Bool(Int2Bool(*vtapConfig.L7MetricsEnabled)),
		L7LogPacketSize:               proto.Uint32(uint32(*vtapConfig.L7LogPacketSize)),
		DecapType:                     decapTypes,
		CaptureSocketType:             &captureSocketType,
		CaptureBpf:                    vtapConfig.CaptureBpf,
		ThreadThreshold:               proto.Uint32(uint32(*vtapConfig.ThreadThreshold)),
		ProcessThreshold:              proto.Uint32(uint32(*vtapConfig.ProcessThreshold)),
		HttpLogProxyClient:            vtapConfig.HTTPLogProxyClient,
		HttpLogTraceId:                vtapConfig.HTTPLogTraceID,
		HttpLogSpanId:                 vtapConfig.HTTPLogSpanID,
		HttpLogXRequestId:             vtapConfig.HTTPLogXRequestID,
		NtpEnabled:                    proto.Bool(Int2Bool(*vtapConfig.NtpEnabled)),
		L4PerformanceEnabled:          proto.Bool(Int2Bool(*vtapConfig.L4PerformanceEnabled)),
		KubernetesApiEnabled:          proto.Bool(false),
		SysFreeMemoryLimit:            proto.Uint32(uint32(*vtapConfig.SysFreeMemoryLimit)),
		LogFileSize:                   proto.Uint32(uint32(*vtapConfig.LogFileSize)),
		ExternalAgentHttpProxyEnabled: proto.Bool(Int2Bool(*vtapConfig.ExternalAgentHTTPProxyEnabled)),
		ExternalAgentHttpProxyPort:    proto.Uint32(uint32(*vtapConfig.ExternalAgentHTTPProxyPort)),
		AnalyzerPort:                  proto.Uint32(uint32(*vtapConfig.AnalyzerPort)),
		ProxyControllerPort:           proto.Uint32(uint32(*vtapConfig.ProxyControllerPort)),
		TapMode:                       &tapMode,
		// 调整后采集器配置信息
		L7LogStoreTapTypes:  vtapConfig.ConvertedL7LogStoreTapTypes,
		L4LogTapTypes:       vtapConfig.ConvertedL4LogTapTypes,
		L4LogIgnoreTapSides: vtapConfig.ConvertedL4LogIgnoreTapSides,
		L7LogIgnoreTapSides: vtapConfig.ConvertedL7LogIgnoreTapSides,
		Plugins:             e.getPlugins(vtapConfig),

		SystemLoadCircuitBreakerThreshold: vtapConfig.SystemLoadCircuitBreakerThreshold,
		SystemLoadCircuitBreakerRecover:   vtapConfig.SystemLoadCircuitBreakerRecover,
		SystemLoadCircuitBreakerMetric:    &loadMetric,
	}
	if vtapConfig.TapInterfaceRegex != nil && *vtapConfig.TapInterfaceRegex != "" {
		configure.TapInterfaceRegex = vtapConfig.TapInterfaceRegex
	}
	configure.LocalConfig = proto.String(
		trisolaris.GetORGVTapInfo(orgID).GetVTapLocalConfigByShortID(groupID))

	if vtapConfig.ProxyControllerIP != nil && *vtapConfig.ProxyControllerIP != "" {
		configure.ProxyControllerIp = vtapConfig.ProxyControllerIP
	}
	if vtapConfig.AnalyzerIP != nil && *vtapConfig.AnalyzerIP != "" {
		configure.AnalyzerIp = vtapConfig.AnalyzerIP
	}

	return configure
}

func (e *VTapEvent) noVTapResponse(in *api.SyncRequest, orgID int) *api.SyncResponse {
	ctrlIP := in.GetCtrlIp()
	ctrlMac := in.GetCtrlMac()
	vtapCacheKey := ctrlIP + "-" + ctrlMac

	configInfo := e.generateNoVTapCacheConfig(in.GetVtapGroupIdRequest(), orgID)
	gVTapInfo := trisolaris.GetORGVTapInfo(orgID)
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
		if in.GetKubernetesWatchPolicy() != KWP_WATCH_DISABLED {
			value := gVTapInfo.GetKubernetesClusterID(
				in.GetKubernetesClusterId(),
				vtapCacheKey,
				in.GetKubernetesForceWatch(),
				int(in.GetKubernetesWatchPolicy()),
			)
			if value == vtapCacheKey {
				configInfo.KubernetesApiEnabled = proto.Bool(true)
				log.Infof(
					"open cluster(%s) kubernetes_api_enabled "+
						"VTap(ctrl_ip: %s, ctrl_mac: %s, kubernetes_force_watch: %t, kubernetes_watch_policy: %d)",
					in.GetKubernetesClusterId(), ctrlIP, ctrlMac,
					in.GetKubernetesForceWatch(), in.GetKubernetesWatchPolicy(), logger.NewORGPrefix(orgID))
			}
		}
		return &api.SyncResponse{
			Status: &STATUS_SUCCESS,
			Config: configInfo,
		}
	}

	tridentTypeForUnknowVTap := gVTapInfo.GetTridentTypeForUnknowVTap()
	if tridentTypeForUnknowVTap != 0 {
		tridentType := common.TridentType(tridentTypeForUnknowVTap)
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

func (e *VTapEvent) getVTapCache(in *api.SyncRequest, orgID int) (*vtap.VTapCache, error) {
	gVTapInfo := trisolaris.GetORGVTapInfo(orgID)
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

func (e *VTapEvent) pushResponse(in *api.SyncRequest, all bool) (*api.SyncResponse, error) {
	ctrlIP := in.GetCtrlIp()
	ctrlMac := in.GetCtrlMac()
	teamIDStr := in.GetTeamId()
	orgID, teamIDInt := trisolaris.GetOrgInfoByTeamID(teamIDStr)
	vtapCacheKey := ctrlIP + "-" + ctrlMac
	gVTapInfo := trisolaris.GetORGVTapInfo(orgID)
	if gVTapInfo == nil {
		log.Errorf("ctrlIp is %s, ctrlMac is %s, team_id is (str=%s,int=%d) not found  vtapinfo", ctrlIP, ctrlMac, teamIDStr, teamIDInt, logger.NewORGPrefix(orgID))
		return &api.SyncResponse{
			Status:        &STATUS_FAILED,
			Revision:      proto.String(in.GetRevision()),
			SelfUpdateUrl: proto.String(gVTapInfo.GetSelfUpdateUrl()),
		}, nil

	}
	vtapCache, err := e.getVTapCache(in, orgID)
	if err != nil {
		return &api.SyncResponse{
			Status:        &STATUS_FAILED,
			Revision:      proto.String(in.GetRevision()),
			SelfUpdateUrl: proto.String(gVTapInfo.GetSelfUpdateUrl()),
		}, err
	}
	if vtapCache == nil {
		return e.noVTapResponse(in, orgID), fmt.Errorf("no find vtap(%s %s) cache", ctrlIP, ctrlMac)
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
	changedInfo := fmt.Sprintf("push data ctrl_ip is %s, ctrl_mac is %s, "+
		"team_id is (str=%s,int=%d) "+
		"(platform data version  %d -> %d), "+
		"(acls version %d -> %d datalen: %d), "+
		"(groups version %d -> %d), "+
		"NAME:%s  REVISION:%s  BOOT_TIME:%d",
		ctrlIP, ctrlMac,
		teamIDStr, teamIDInt,
		versionPlatformData, pushVersionPlatformData,
		versionPolicy, pushVersionPolicy, len(newAcls),
		versionGroups, pushVersionGroups,
		in.GetProcessName(), in.GetRevision(), in.GetBootTime())
	if versionPlatformData != pushVersionPlatformData ||
		versionGroups != pushVersionGroups || versionPolicy != pushVersionPolicy {
		log.Infof(changedInfo, logger.NewORGPrefix(orgID))
	} else {
		log.Debugf(changedInfo, logger.NewORGPrefix(orgID))
	}

	platformData := []byte{}
	groups := []byte{}
	acls := []byte{}
	if all {
		log.Info("first: ", changedInfo)
		platformData = vtapCache.GetSimplePlatformDataStr()
		groups = gVTapInfo.GetGroupData()
		acls = gVTapInfo.GetVTapPolicyData(vtapID, functions)
	} else {
		if versionPlatformData != pushVersionPlatformData {
			platformData = vtapCache.GetSimplePlatformDataStr()
		}
		if versionGroups != pushVersionGroups {
			groups = gVTapInfo.GetGroupData()
		}
		if versionPolicy != pushVersionPolicy {
			acls = gVTapInfo.GetVTapPolicyData(vtapID, functions)
		}
	}

	// 只有专属采集器下发tap_types
	tapTypes := []*api.TapType{}
	if vtapCache.GetVTapType() == VTAP_TYPE_DEDICATED {
		tapTypes = gVTapInfo.GetTapTypes()
	}

	configInfo := e.generateConfigInfo(vtapCache, in.GetKubernetesClusterId(), gVTapInfo, orgID)
	// 携带信息有cluster_id && watch_policy != disabled 时选择一个采集器开启云平台同步开关
	if in.GetKubernetesClusterId() != "" &&
		in.GetKubernetesWatchPolicy() != KWP_WATCH_DISABLED &&
		isOpenK8sSyn(vtapCache.GetVTapType()) == true {
		value := gVTapInfo.GetKubernetesClusterID(
			in.GetKubernetesClusterId(),
			vtapCacheKey,
			in.GetKubernetesForceWatch(),
			int(in.GetKubernetesWatchPolicy()),
		)
		if value == vtapCacheKey {
			log.Infof(
				"open cluster(%s) kubernetes_api_enabled "+
					"VTap(ctrl_ip: %s, ctrl_mac: %s, team_id: (str=%s,int=%d), kubernetes_force_watch: %t, kubernetes_watch_policy %d)",
				in.GetKubernetesClusterId(), ctrlIP, ctrlMac, teamIDStr, teamIDInt,
				in.GetKubernetesForceWatch(), in.GetKubernetesWatchPolicy(), logger.NewORGPrefix(orgID))
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

// The first push link sends full data
func (e *VTapEvent) Push(r *api.SyncRequest, in api.Synchronizer_PushServer) error {
	var err error
	orgID := trisolaris.GetOrgIDByTeamID(r.GetTeamId())
	if orgID == 0 {
		log.Errorf("get orgid failed by team_id(%s)", r.GetTeamId(), logger.NewORGPrefix(orgID))
		response := &api.SyncResponse{
			Status: &STATUS_FAILED,
		}
		err = in.Send(response)
		if err != nil {
			log.Error(err)
		}

		return nil
	}
	response, err := e.pushResponse(r, true)
	if err != nil {
		log.Error(err)
	}
	err = in.Send(response)
	if err != nil {
		log.Error(err)
		return err
	}
	for {
		pushmanager.Wait(orgID)
		response, err := e.pushResponse(r, false)
		if err != nil {
			log.Error(err)
		}
		err = in.Send(response)
		if err != nil {
			log.Error(err)
			break
		}
	}
	log.Infof("exit agent push", r.GetCtrlIp(), r.GetCtrlMac(), logger.NewORGPrefix(orgID))
	return err
}
