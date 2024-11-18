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

package agentsynchronize

import (
	"bytes"
	"fmt"
	"strings"
	"time"

	"github.com/golang/protobuf/proto"
	"github.com/spf13/viper"
	context "golang.org/x/net/context"
	yaml "gopkg.in/yaml.v3"

	api "github.com/deepflowio/deepflow/message/agent"
	. "github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/trisolaris"
	. "github.com/deepflowio/deepflow/server/controller/trisolaris/common"
	"github.com/deepflowio/deepflow/server/controller/trisolaris/pushmanager"
	"github.com/deepflowio/deepflow/server/controller/trisolaris/utils"
	"github.com/deepflowio/deepflow/server/controller/trisolaris/vtap"
	"github.com/deepflowio/deepflow/server/libs/logger"
)

var log = logger.MustGetLogger("trisolaris.agentsynchronize")

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

type AgentEvent struct{}

func NewAgentEvent() *AgentEvent {
	return &AgentEvent{}
}

func (e *AgentEvent) generateUserConfig(c *vtap.VTapCache, clusterID string, gAgentInfo *vtap.VTapInfo, orgID int) *viper.Viper {
	userConfig := c.GetUserConfig()
	viperConfig := viper.New()
	viperConfig.SetConfigType("yaml")
	if err := viperConfig.ReadConfig(bytes.NewBufferString(userConfig)); err != nil {
		log.Errorf("viper read agent(%d) config yaml error: %v", c.GetVTapID(), err)
	}

	configTSDBIP := gAgentInfo.GetConfigTSDBIP()
	if configTSDBIP != "" {
		viperConfig.Set(CONFIG_KEY_INGESTER_IP, configTSDBIP)
	}

	natIPEnabled := viperConfig.GetBool("global.communication.request_via_nat_ip")
	if trisolaris.GetAllAgentConnectToNatIP() || natIPEnabled == true {
		viperConfig.Set(CONFIG_KEY_PROXY_CONTROLLER_IP, trisolaris.GetORGNodeInfo(orgID).GetControllerNatIP(c.GetControllerIP()))
		viperConfig.Set(CONFIG_KEY_INGESTER_IP, trisolaris.GetORGNodeInfo(orgID).GetTSDBNatIP(c.GetTSDBIP()))
	}

	if isPodVTap(c.GetVTapType()) && gAgentInfo.IsTheSameCluster(clusterID) {
		viperConfig.Set(CONFIG_KEY_PROXY_CONTROLLER_IP, trisolaris.GetORGNodeInfo(orgID).GetControllerPodIP(c.GetControllerIP()))
		viperConfig.Set(CONFIG_KEY_PROXY_CONTROLLER_PORT, trisolaris.GetGrpcPort())

		viperConfig.Set(CONFIG_KEY_INGESTER_IP, trisolaris.GetORGNodeInfo(orgID).GetTSDBPodIP(c.GetTSDBIP()))
		viperConfig.Set(CONFIG_KEY_INGESTER_PORT, trisolaris.GetIngesterPort())
	}
	if viperConfig.GetString(CONFIG_KEY_PROXY_CONTROLLER_IP) == "" {
		log.Errorf("agent(%s) has no proxy_controller_ip, "+
			"Please check whether the agent allocs controller IP or If nat-ip is enabled, whether the controller is configured with nat-ip", c.GetCtrlIP())
	}

	if c.GetVTapEnabled() == 0 {
		viperConfig.Set(CONFIG_KEY_HYPERVISOR_RESOURCE_ENABLED, false)
	}

	return viperConfig
}

func (e *AgentEvent) generateDynamicConfig(clusterID string, c *vtap.VTapCache) *api.DynamicConfig {
	agentType := c.GetVTapType()
	if clusterID != "" { // if agent report cluster_id, force set tridentType = VTAP_TYPE_POD_VM
		agentType = VTAP_TYPE_POD_VM
	}
	return &api.DynamicConfig{
		AgentType:            utils.Int2AgentTypePtr(agentType),
		Enabled:              proto.Bool(c.GetVTapEnabled() != 0),
		KubernetesApiEnabled: proto.Bool(false),
		Hostname:             proto.String(c.GetVTapHost()),
		RegionId:             proto.Uint32(uint32(c.GetRegionID())),
		PodClusterId:         proto.Uint32(uint32(c.GetPodClusterID())),
		VpcId:                proto.Uint32(uint32(c.GetVPCID())),
		AgentId:              proto.Uint32(uint32(c.GetVTapID())),
		TeamId:               proto.Uint32(uint32(c.GetTeamID())),
		OrganizeId:           proto.Uint32(uint32(c.GetOrganizeID())),
	}
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

func isPodAgent(vtapType int) bool {
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

func (e *AgentEvent) GetFailedResponse(in *api.SyncRequest, gAgentInfo *vtap.VTapInfo) *api.SyncResponse {
	return &api.SyncResponse{
		Status:        &STATUS_FAILED,
		Revision:      proto.String(in.GetRevision()),
		SelfUpdateUrl: proto.String(gAgentInfo.GetSelfUpdateUrl()),
	}
}

func (e *AgentEvent) Sync(ctx context.Context, in *api.SyncRequest) (*api.SyncResponse, error) {
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
	clusterID := in.GetKubernetesClusterId()
	k8sForceWatch := in.GetKubernetesForceWatch()
	k8sWatchPoilcy := in.GetKubernetesWatchPolicy()
	orgID, teamIDInt := trisolaris.GetOrgInfoByTeamID(teamIDStr)
	gAgentInfo := trisolaris.GetORGVTapInfo(orgID)
	if gAgentInfo == nil {
		log.Errorf("ctrlIp is %s, ctrlMac is %s, team_id is (str=%s,int=%d) not found vtapInfo", ctrlIP, ctrlMac, teamIDStr, teamIDInt, logger.NewORGPrefix(orgID))
		return e.GetFailedResponse(in, gAgentInfo), nil
	}
	vtapCacheKey := ctrlIP + "-" + ctrlMac
	vtapCache, err := e.getAgentCache(in, orgID)
	if err != nil {
		log.Warningf("err:%s ctrlIp is %s, ctrlMac is %s, team_id is (str=%s,int=%d), hostIps is %s, name:%s,  revision:%s,  bootTime:%d",
			err, ctrlIP, ctrlMac, teamIDStr, teamIDInt, in.GetHostIps(), in.GetProcessName(), in.GetRevision(), in.GetBootTime(), logger.NewORGPrefix(orgID))
		return e.GetFailedResponse(in, gAgentInfo), nil
	}
	if vtapCache == nil {
		if len(teamIDStr) == 0 && trisolaris.GetIsRefused() {
			log.Errorf("ctrlIp is %s, ctrlMac is %s, not team_id refuse(%v) register", ctrlIP, ctrlMac, trisolaris.GetIsRefused(), logger.NewORGPrefix(orgID))
			return e.GetFailedResponse(in, nil), nil
		}
		log.Warningf("vtap (ctrl_ip: %s, ctrl_mac: %s, team_id: (str=%s,int=%d), host_ips: %s, kubernetes_cluster_id: %s, kubernetes_force_watch: %t, kubernetes_watch_policy: %d, group_id: %s) not found in cache. "+
			"NAME:%s  REVISION:%s  BOOT_TIME:%d",
			ctrlIP, ctrlMac, teamIDStr, teamIDInt, in.GetHostIps(), clusterID, k8sForceWatch, k8sWatchPoilcy,
			in.GetAgentGroupIdRequest(), in.GetProcessName(), in.GetRevision(), in.GetBootTime(), logger.NewORGPrefix(orgID))
		// kubernetes_force_watch field is compatibility for old version agent
		// If the kubernetes_force_watch field is true, the ctrl_ip and ctrl_mac of the vtap will not change,
		// If the kubernetes_watch_policy field is KWP_WATCH_ONLY, the ctrl_ip and ctrl_mac of the vtap will not change,
		// resulting in unsuccessful registration and a large number of error logs.
		if !k8sForceWatch || k8sWatchPoilcy != AGENT_KWP_WATCH_ONLY {
			gAgentInfo.Register(
				int(in.GetPacketCaptureType()),
				in.GetCtrlIp(),
				in.GetCtrlMac(),
				in.GetHostIps(),
				in.GetHost(),
				in.GetAgentGroupIdRequest(),
				int(in.GetAgentUniqueIdentifier()),
				teamIDInt)
		}
		return e.noAgentResponse(in, orgID), nil
	}

	vtapID := int(vtapCache.GetVTapID())
	functions := vtapCache.GetFunctions()
	versionPlatformData := vtapCache.GetAgentPlatformDataVersion()
	versionGroups := gAgentInfo.GetAgentGroupDataVersion()
	versionPolicy := gAgentInfo.GetAgentPolicyVersion(vtapID, functions)
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
		platformData = vtapCache.GetAgentPlatformDataStr()
	}
	groups := []byte{}
	if versionGroups != in.GetVersionGroups() {
		groups = gAgentInfo.GetAgentGroupData()
	}
	acls := []byte{}
	if versionPolicy != in.GetVersionAcls() {
		acls = gAgentInfo.GetAgentPolicyData(vtapID, functions)
	}

	// 只有专属采集器下发tap_types
	tapTypes := []*api.CaptureNetworkType{}
	if vtapCache.GetVTapType() == VTAP_TYPE_DEDICATED {
		tapTypes = gAgentInfo.GetCaptureNetworkTypes()
	}

	dynamicConfig := e.generateDynamicConfig(clusterID, vtapCache)
	// 携带信息有cluster_id && watch_policy != disabled 时选择一个采集器开启云平台同步开关
	if clusterID != "" && k8sWatchPoilcy != AGENT_KWP_WATCH_DISABLED && isOpenK8sSyn(vtapCache.GetVTapType()) == true {
		value := gAgentInfo.GetKubernetesClusterID(clusterID, vtapCacheKey, k8sForceWatch, int(k8sWatchPoilcy))
		if value == vtapCacheKey {
			log.Infof(
				"open cluster(%s) kubernetes_api_enabled Agent(ctrl_ip: %s, ctrl_mac: %s, team_id: (str=%s,int=%d), kubernetes_force_watch: %t)",
				clusterID, ctrlIP, ctrlMac,
				teamIDStr, teamIDInt, k8sForceWatch, logger.NewORGPrefix(orgID))
			dynamicConfig.KubernetesApiEnabled = proto.Bool(true)
		}
	}
	userConfig := e.generateUserConfig(vtapCache, clusterID, gAgentInfo, orgID)
	if userConfig.GetString(CONFIG_KEY_INGESTER_IP) == "" {
		dynamicConfig.Enabled = proto.Bool(false)
		log.Errorf("agent(%s) has no ingester_ip, "+
			"Please check whether the agent allocs tsdb IP or If nat-ip is enabled, whether the tsdb is configured with nat-ip", vtapCache.GetCtrlIP())
	}
	localSegments := vtapCache.GetAgentLocalSegments()
	remoteSegments := vtapCache.GetAgentRemoteSegments()
	upgradeRevision := vtapCache.GetExpectedRevision()
	skipInterface := gAgentInfo.GetAgentSkipInterface(vtapCache)
	containers := gAgentInfo.GetAgentContainers(int(vtapCache.GetVTapID()))
	return &api.SyncResponse{
		Status:              &STATUS_SUCCESS,
		LocalSegments:       localSegments,
		RemoteSegments:      remoteSegments,
		UserConfig:          proto.String(e.formateViperConfigToString(userConfig)),
		DynamicConfig:       dynamicConfig,
		PlatformData:        platformData,
		Groups:              groups,
		FlowAcls:            acls,
		VersionPlatformData: proto.Uint64(versionPlatformData),
		VersionGroups:       proto.Uint64(versionGroups),
		VersionAcls:         proto.Uint64(versionPolicy),
		CaptureNetworkTypes: tapTypes,
		Containers:          containers,
		SkipInterface:       skipInterface,
		SelfUpdateUrl:       proto.String(gAgentInfo.GetSelfUpdateUrl()),
		Revision:            proto.String(upgradeRevision),
	}, nil
}

func (e *AgentEvent) generateNoAgentCacheDynamicConfig() *api.DynamicConfig {
	return &api.DynamicConfig{
		Enabled:              proto.Bool(false),
		KubernetesApiEnabled: proto.Bool(false),
	}
}

func (e *AgentEvent) generateNoAgentCacheUserViperConfig(groupID string, orgID int) *viper.Viper {
	vtapConfig := trisolaris.GetORGVTapInfo(orgID).GetVTapConfigFromShortID(groupID)
	v := viper.New()
	v.SetConfigType("yaml")
	if vtapConfig == nil {
		return v
	}
	if err := v.ReadConfig(bytes.NewBufferString(vtapConfig.GetUserConfig())); err != nil {
		log.Error(err)
	}
	return v
}

func (e *AgentEvent) formateViperConfigToString(userConfig *viper.Viper) string {
	b, err := yaml.Marshal(userConfig.AllSettings())
	if err != nil {
		log.Error(err)
		return ""
	}
	return string(b)
}

func (e *AgentEvent) noAgentResponse(in *api.SyncRequest, orgID int) *api.SyncResponse {
	ctrlIP := in.GetCtrlIp()
	ctrlMac := in.GetCtrlMac()
	vtapCacheKey := ctrlIP + "-" + ctrlMac

	clusterID := in.GetKubernetesClusterId()
	k8sForceWatch := in.GetKubernetesForceWatch()
	k8sWatchPoilcy := in.GetKubernetesWatchPolicy()
	dynamicConfigInfo := e.generateNoAgentCacheDynamicConfig()
	viperConfig := e.generateNoAgentCacheUserViperConfig(in.GetAgentGroupIdRequest(), orgID)
	gAgentInfo := trisolaris.GetORGVTapInfo(orgID)
	if clusterID != "" {
		dynamicConfigInfo.AgentType = utils.Int2AgentTypePtr(VTAP_TYPE_POD_VM)
		if k8sWatchPoilcy != AGENT_KWP_WATCH_DISABLED {
			value := gAgentInfo.GetKubernetesClusterID(clusterID, vtapCacheKey, k8sForceWatch, int(k8sWatchPoilcy))
			if value == vtapCacheKey {
				dynamicConfigInfo.KubernetesApiEnabled = proto.Bool(true)
				log.Infof(
					"open cluster(%s) kubernetes_api_enabled Agent(ctrl_ip: %s, ctrl_mac: %s, kubernetes_force_watch: %t, kubernetes_watch_policy: %d)",
					clusterID, ctrlIP, ctrlMac, k8sForceWatch, k8sWatchPoilcy, logger.NewORGPrefix(orgID))
			}
			viperConfig.Set(CONFIG_KEY_MAX_ESCAPE_DURATION, gAgentInfo.GetDefaultMaxEscapeSecondsStr())
			viperConfig.Set(CONFIG_KEY_MAX_MEMORY, gAgentInfo.GetDefaultMaxMemory())
		}

		return &api.SyncResponse{
			Status:        &STATUS_SUCCESS,
			UserConfig:    proto.String(e.formateViperConfigToString(viperConfig)),
			DynamicConfig: dynamicConfigInfo,
		}
	}

	agentTypeForUnknowAgent := gAgentInfo.GetTridentTypeForUnknowVTap()
	if agentTypeForUnknowAgent != 0 {
		dynamicConfigInfo.AgentType = utils.Int2AgentTypePtr(agentTypeForUnknowAgent)
		viperConfig.Set(CONFIG_KEY_MAX_ESCAPE_DURATION, gAgentInfo.GetDefaultMaxEscapeSecondsStr())
		viperConfig.Set(CONFIG_KEY_MAX_MEMORY, gAgentInfo.GetDefaultMaxMemory())
		viperConfig.Set(CONFIG_KEY_HYPERVISOR_RESOURCE_ENABLED, true)

		return &api.SyncResponse{
			Status:        &STATUS_SUCCESS,
			DynamicConfig: dynamicConfigInfo,
			UserConfig:    proto.String(e.formateViperConfigToString(viperConfig)),
		}
	}

	return &api.SyncResponse{
		Status:        &STATUS_SUCCESS,
		DynamicConfig: dynamicConfigInfo,
		UserConfig:    proto.String(e.formateViperConfigToString(viperConfig)),
	}
}

func (e *AgentEvent) getAgentCache(in *api.SyncRequest, orgID int) (*vtap.VTapCache, error) {
	gAgentInfo := trisolaris.GetORGVTapInfo(orgID)
	ctrlIP := in.GetCtrlIp()
	ctrlMac := in.GetCtrlMac()
	vtapCacheKey := ctrlIP + "-" + ctrlMac
	if !gAgentInfo.GetVTapCacheIsReady() {
		return nil, fmt.Errorf("Agent cache data not ready")
	}
	vtapCache := gAgentInfo.GetVTapCache(vtapCacheKey)
	if vtapCache == nil {
		vtapCache = gAgentInfo.GetVTapCache(ctrlIP)
		if vtapCache == nil {
			vtapCache = gAgentInfo.GetKvmVTapCache(ctrlIP)
			// ctrl_ip是kvm采集器的，但是ctrl_mac不属于tap_ports，需自动发现采集器
			if vtapCache != nil && gAgentInfo.IsCtrlMacInTapPorts(ctrlIP, ctrlMac) == false {
				vtapCache = nil
			}
		}
	}
	return vtapCache, nil
}

func (e *AgentEvent) pushResponse(in *api.SyncRequest, all bool) (*api.SyncResponse, error) {
	ctrlIP := in.GetCtrlIp()
	ctrlMac := in.GetCtrlMac()
	teamIDStr := in.GetTeamId()
	clusterID := in.GetKubernetesClusterId()
	k8sForceWatch := in.GetKubernetesForceWatch()
	k8sWatchPoilcy := in.GetKubernetesWatchPolicy()
	orgID, teamIDInt := trisolaris.GetOrgInfoByTeamID(teamIDStr)
	vtapCacheKey := ctrlIP + "-" + ctrlMac
	gAgentInfo := trisolaris.GetORGVTapInfo(orgID)
	if gAgentInfo == nil {
		log.Errorf("ctrlIp is %s, ctrlMac is %s, team_id is (str=%s,int=%d) not found  vtapinfo", ctrlIP, ctrlMac, teamIDStr, teamIDInt, logger.NewORGPrefix(orgID))
		return &api.SyncResponse{
			Status:        &STATUS_FAILED,
			Revision:      proto.String(in.GetRevision()),
			SelfUpdateUrl: proto.String(gAgentInfo.GetSelfUpdateUrl()),
		}, nil

	}
	vtapCache, err := e.getAgentCache(in, orgID)
	if err != nil {
		return &api.SyncResponse{
			Status:        &STATUS_FAILED,
			Revision:      proto.String(in.GetRevision()),
			SelfUpdateUrl: proto.String(gAgentInfo.GetSelfUpdateUrl()),
		}, err
	}
	if vtapCache == nil {
		return e.noAgentResponse(in, orgID), fmt.Errorf("no find vtap(%s %s) cache", ctrlIP, ctrlMac)
	}
	vtapID := int(vtapCache.GetVTapID())
	functions := vtapCache.GetFunctions()
	versionPlatformData := vtapCache.GetAgentPlatformDataVersion()
	pushVersionPlatformData := vtapCache.GetPushVersionPlatformData()
	versionGroups := gAgentInfo.GetAgentGroupDataVersion()
	pushVersionGroups := vtapCache.GetPushVersionGroups()
	versionPolicy := gAgentInfo.GetAgentPolicyVersion(vtapID, functions)
	pushVersionPolicy := vtapCache.GetPushVersionPolicy()
	newAcls := gAgentInfo.GetAgentPolicyData(vtapID, functions)
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
		platformData = vtapCache.GetAgentPlatformDataStr()
		groups = gAgentInfo.GetAgentGroupData()
		acls = gAgentInfo.GetAgentPolicyData(vtapID, functions)
	} else {
		if versionPlatformData != pushVersionPlatformData {
			platformData = vtapCache.GetAgentPlatformDataStr()
		}
		if versionGroups != pushVersionGroups {
			groups = gAgentInfo.GetAgentGroupData()
		}
		if versionPolicy != pushVersionPolicy {
			acls = gAgentInfo.GetAgentPolicyData(vtapID, functions)
		}
	}

	// 只有专属采集器下发tap_types
	tapTypes := []*api.CaptureNetworkType{}
	if vtapCache.GetVTapType() == VTAP_TYPE_DEDICATED {
		tapTypes = gAgentInfo.GetCaptureNetworkTypes()
	}

	dynamicConfig := e.generateDynamicConfig(clusterID, vtapCache)
	// 携带信息有cluster_id && watch_policy != disabled 时选择一个采集器开启云平台同步开关
	if clusterID != "" && k8sWatchPoilcy != AGENT_KWP_WATCH_DISABLED && isOpenK8sSyn(vtapCache.GetVTapType()) == true {
		value := gAgentInfo.GetKubernetesClusterID(clusterID, vtapCacheKey, k8sForceWatch, int(k8sWatchPoilcy))
		if value == vtapCacheKey {
			log.Infof(
				"open cluster(%s) kubernetes_api_enabled Agent(ctrl_ip: %s, ctrl_mac: %s, team_id: (str=%s,int=%d), kubernetes_force_watch: %t, kubernetes_watch_policy %d)",
				clusterID, ctrlIP, ctrlMac, teamIDStr, teamIDInt, k8sForceWatch, k8sWatchPoilcy, logger.NewORGPrefix(orgID))
			dynamicConfig.KubernetesApiEnabled = proto.Bool(true)
		}
	}

	userConfig := e.generateUserConfig(vtapCache, clusterID, gAgentInfo, orgID)
	if userConfig.GetString(CONFIG_KEY_INGESTER_IP) == "" {
		dynamicConfig.Enabled = proto.Bool(false)
		log.Errorf("agent(%s) has no ingester_ip, "+
			"Please check whether the agent allocs tsdb IP or If nat-ip is enabled, whether the tsdb is configured with nat-ip", vtapCache.GetCtrlIP())
	}
	localSegments := vtapCache.GetAgentLocalSegments()
	remoteSegments := vtapCache.GetAgentRemoteSegments()
	skipInterface := gAgentInfo.GetAgentSkipInterface(vtapCache)
	containers := gAgentInfo.GetAgentContainers(int(vtapCache.GetVTapID()))
	return &api.SyncResponse{
		Status:              &STATUS_SUCCESS,
		LocalSegments:       localSegments,
		RemoteSegments:      remoteSegments,
		DynamicConfig:       dynamicConfig,
		UserConfig:          proto.String(e.formateViperConfigToString(userConfig)),
		PlatformData:        platformData,
		SkipInterface:       skipInterface,
		VersionPlatformData: proto.Uint64(versionPlatformData),
		Groups:              groups,
		VersionGroups:       proto.Uint64(versionGroups),
		FlowAcls:            acls,
		VersionAcls:         proto.Uint64(versionPolicy),
		CaptureNetworkTypes: tapTypes,
		Containers:          containers,
	}, nil
}

// The first push link sends full data
func (e *AgentEvent) Push(r *api.SyncRequest, in api.Synchronizer_PushServer) error {
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
