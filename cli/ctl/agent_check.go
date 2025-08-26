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

package ctl

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"sort"
	"strconv"
	"time"

	"github.com/deepflowio/deepflow/message/agent"
	"github.com/deepflowio/deepflow/server/libs/utils"
	"github.com/golang/protobuf/proto"
	"github.com/spf13/cobra"
	_ "golang.org/x/net/context"
	"google.golang.org/grpc"

	"github.com/deepflowio/deepflow/cli/ctl/common"
)

type AgentParamData struct {
	K8SWatchPolicy int32
	OrgID          uint32
	GRPCBufferSize uint64
	CtrlIP         string
	CtrlMac        string
	GroupID        string
	ClusterID      string
	TeamID         string
	RpcIP          string
	RpcPort        string
	PluginType     string
	PluginName     string
}

type AgentSortedAcls []*agent.FlowAcl

var agentParamData AgentParamData

type AgentCmdExecute func(response *agent.SyncResponse)

func agentRegiterCommand() []*cobra.Command {
	agentCacheCmd := &cobra.Command{
		Use:   "agent-cache",
		Short: "get agent-cache from deepflow-server",
		Run: func(cmd *cobra.Command, args []string) {
			agentCache(agentParamData.TeamID, agentParamData.CtrlIP, agentParamData.CtrlMac, cmd)
		},
	}

	platformDataCmd := &cobra.Command{
		Use:   "platform-data",
		Short: "get platform-data from deepflow-server",
		Run: func(cmd *cobra.Command, args []string) {
			agentInitCmd(cmd, []AgentCmdExecute{AplatformData})
		},
	}
	ipGroupsCmd := &cobra.Command{
		Use:   "ip-groups",
		Short: "get ip groups from deepflow-servr",
		Run: func(cmd *cobra.Command, args []string) {
			agentInitCmd(cmd, []AgentCmdExecute{AipGroups})
		},
	}
	flowAclsCmd := &cobra.Command{
		Use:   "flow-acls",
		Short: "get flow-acls from deepflow-server",
		Run: func(cmd *cobra.Command, args []string) {
			agentInitCmd(cmd, []AgentCmdExecute{AflowAcls})
		},
	}
	tapTypesCmd := &cobra.Command{
		Use:   "capture-network-types",
		Short: "get capture-network-types from deepflow-server",
		Run: func(cmd *cobra.Command, args []string) {
			initCmd(cmd, []CmdExecute{tapTypes})
		},
	}
	segmentsCmd := &cobra.Command{
		Use:   "segments",
		Short: "get segments from deepflow-server",
		Run: func(cmd *cobra.Command, args []string) {
			agentInitCmd(cmd, []AgentCmdExecute{Asegments})
		},
	}
	containersCmd := &cobra.Command{
		Use:   "containers",
		Short: "get containers from deepflow-server",
		Run: func(cmd *cobra.Command, args []string) {
			agentInitCmd(cmd, []AgentCmdExecute{Acontainers})
		},
	}
	configCmd := &cobra.Command{
		Use:   "config",
		Short: "get config from deepflow-server",
		Run: func(cmd *cobra.Command, args []string) {
			agentInitCmd(cmd, []AgentCmdExecute{AconfigData})
		},
	}
	grpcBufferSizeCmd := &cobra.Command{
		Use:   "grpc-buffer-size",
		Short: "grpc request server with current-grpc-buffer-size",
		Run: func(cmd *cobra.Command, args []string) {
			agentInitCmd(cmd, []AgentCmdExecute{AGRPCBufferSize})
		},
	}
	skipInterfaceCmd := &cobra.Command{
		Use:   "skip-interface",
		Short: "get skip-interface from deepflow-server",
		Run: func(cmd *cobra.Command, args []string) {
			agentInitCmd(cmd, []AgentCmdExecute{AskipInterface})
		},
	}
	gpidAgentResponseCmd := &cobra.Command{
		Use:   "gpid-agent-response",
		Short: "get gpid-agent-response from deepflow-server",
		Run: func(cmd *cobra.Command, args []string) {
			AgpidAgentResponse(cmd)
		},
	}
	gpidGlobalTableCmd := &cobra.Command{
		Use:   "gpid-global-table",
		Short: "get gpid-global-table from deepflow-server",
		Run: func(cmd *cobra.Command, args []string) {
			AgpidGlobalTable(cmd)
		},
	}

	gpidAgentRequestCmd := &cobra.Command{
		Use:   "gpid-agent-request",
		Short: "get gpid-agent-request from deepflow-server",
		Run: func(cmd *cobra.Command, args []string) {
			AgpidAgentRequest(cmd)
		},
	}
	realGlobalCmd := &cobra.Command{
		Use:   "realclient-to-realserver",
		Short: "get realclient-to-realserver from deepflow-server",
		Run: func(cmd *cobra.Command, args []string) {
			ArealGlobal(cmd)
		},
	}

	ripToVipCmd := &cobra.Command{
		Use:   "rip-to-vip",
		Short: "get rip-to-vip from deepflow-server",
		Run: func(cmd *cobra.Command, args []string) {
			AripToVip(cmd)
		},
	}

	pluginCmd := &cobra.Command{
		Use:   "plugin",
		Short: "get plugin from deepflow-server",
		Run: func(cmd *cobra.Command, args []string) {
			Aplugin(cmd)
		},
	}

	allCmd := &cobra.Command{
		Use:   "all",
		Short: "get all data from deepflow-server",
		Run: func(cmd *cobra.Command, args []string) {
			agentInitCmd(cmd, []AgentCmdExecute{AplatformData, AipGroups, AflowAcls,
				Asegments, AtapTypes, Acontainers, AconfigData, AGRPCBufferSize, AskipInterface})
		},
	}

	commands := []*cobra.Command{agentCacheCmd, platformDataCmd, ipGroupsCmd,
		flowAclsCmd, configCmd, grpcBufferSizeCmd, tapTypesCmd, segmentsCmd, containersCmd,
		skipInterfaceCmd, gpidAgentResponseCmd, gpidGlobalTableCmd,
		gpidAgentRequestCmd, realGlobalCmd, ripToVipCmd, pluginCmd, allCmd}
	return commands
}

func AgentCheckRegisterCommand() *cobra.Command {
	trisolarisCmd := &cobra.Command{
		Use:   "trisolaris.agent-check",
		Short: "pull grpc data from deepflow-server",
	}
	trisolarisCmd.PersistentFlags().Int32VarP(&agentParamData.K8SWatchPolicy, "kwp", "", 0, "agent k8s watch policy: 0.normal 1.only 2.disabled")
	trisolarisCmd.PersistentFlags().Uint64VarP(&agentParamData.GRPCBufferSize, "size", "", 0, "agent current grpc buffer size, Unit: MB")
	trisolarisCmd.PersistentFlags().StringVarP(&agentParamData.CtrlIP, "cip", "", "", "agent ctrl ip")
	trisolarisCmd.PersistentFlags().StringVarP(&agentParamData.CtrlMac, "cmac", "", "", "agent ctrl mac")
	trisolarisCmd.PersistentFlags().StringVarP(&agentParamData.GroupID, "gid", "", "", "agent group ID")
	trisolarisCmd.PersistentFlags().StringVarP(&agentParamData.TeamID, "tid", "", "", "agent team ID")
	trisolarisCmd.PersistentFlags().StringVarP(&agentParamData.ClusterID, "cid", "", "", "agent k8s cluster ID")
	trisolarisCmd.PersistentFlags().StringVarP(&agentParamData.PluginType, "ptype", "", "wasm", "request plugin type")
	trisolarisCmd.PersistentFlags().StringVarP(&agentParamData.PluginName, "pname", "", "", "request plugin name")
	cmds := agentRegiterCommand()
	for _, handler := range cmds {
		trisolarisCmd.AddCommand(handler)
	}

	return trisolarisCmd
}

func agentGetConn(cmd *cobra.Command) *grpc.ClientConn {
	server := common.GetServerInfo(cmd)
	orgID := common.GetORGID(cmd)
	agentParamData.RpcIP = server.IP
	agentParamData.RpcPort = strconv.Itoa(int(server.RpcPort))
	agentParamData.OrgID = uint32(orgID)
	addr := net.JoinHostPort(agentParamData.RpcIP, agentParamData.RpcPort)
	conn, err := grpc.Dial(addr, grpc.WithInsecure(), grpc.WithMaxMsgSize(1024*1024*200))
	if err != nil {
		fmt.Println(err)
		return nil
	}

	return conn
}

func agentInitCmd(cmd *cobra.Command, cmds []AgentCmdExecute) {
	conn := agentGetConn(cmd)
	if conn == nil {
		return
	}
	defer conn.Close()
	name := "agent"
	groupID := agentParamData.GroupID
	clusterID := agentParamData.ClusterID
	teamID := agentParamData.TeamID
	k8sWatchPolicy := agent.KubernetesWatchPolicy(agentParamData.K8SWatchPolicy)
	grpcBufferSize := agentParamData.GRPCBufferSize * 1024 * 1024
	fmt.Printf("request trisolaris(%s), params(%+v)\n", conn.Target(), agentParamData)
	c := agent.NewSynchronizerClient(conn)
	reqData := &agent.SyncRequest{
		CtrlIp:                &agentParamData.CtrlIP,
		CtrlMac:               &agentParamData.CtrlMac,
		CurrentGrpcBufferSize: &grpcBufferSize,
		AgentGroupIdRequest:   &groupID,
		KubernetesClusterId:   &clusterID,
		KubernetesWatchPolicy: &k8sWatchPolicy,
		ProcessName:           &name,
		TeamId:                &teamID,
	}
	var response *agent.SyncResponse
	var err error
	response, err = c.Sync(context.Background(), reqData)
	if err != nil {
		fmt.Println(err)
		return
	}
	if agentParamData.GRPCBufferSize == 0 {
		fmt.Printf("revision: %s\n", response.GetRevision())
	} else {
		fmt.Printf("current grpc buffer size (byte): %d\n", grpcBufferSize)
	}

	for _, cmd := range cmds {
		cmd(response)
	}
}

func AgpidAgentResponse(cmd *cobra.Command) {
	conn := agentGetConn(cmd)
	if conn == nil {
		return
	}
	defer conn.Close()
	fmt.Printf("request trisolaris(%s), params(%+v)\n", conn.Target(), agentParamData)
	c := agent.NewSynchronizerClient(conn)
	reqData := &agent.GPIDSyncRequest{
		CtrlIp:  &agentParamData.CtrlIP,
		CtrlMac: &agentParamData.CtrlMac,
		TeamId:  &agentParamData.TeamID,
	}
	response, err := c.GPIDSync(context.Background(), reqData)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println("gpid:")
	for index, entry := range response.Entries {
		AJsonFormat(index+1, AformatEntries(entry))
	}
}

func AformatGlobalEntry(entry *agent.GlobalGPIDEntry) string {
	buffer := bytes.Buffer{}
	format := "{ protocol: %d, agent_id_1: %d, epc_id_1: %d, ipv4_1: %s, port_1: %d, pid_1: %d, gpid_1: %d " +
		"agent_id_0: %d, epc_id_0: %d, ipv4_0: %s, port_0: %d, pid_0: %d, gpid_0: %d, netns_idx: %d}"
	buffer.WriteString(fmt.Sprintf(format,
		entry.GetProtocol(),
		entry.GetAgentId_1(), entry.GetEpcId_1(), utils.IpFromUint32(entry.GetIpv4_1()).String(), entry.GetPort_1(), entry.GetPid_1(), entry.GetGpid_1(),
		entry.GetAgentId_0(), entry.GetEpcId_0(), utils.IpFromUint32(entry.GetIpv4_0()).String(), entry.GetPort_0(), entry.GetPid_0(), entry.GetGpid_0(),
		entry.GetNetnsIdx()))

	return buffer.String()
}

func AgpidGlobalTable(cmd *cobra.Command) {
	conn := agentGetConn(cmd)
	if conn == nil {
		return
	}
	defer conn.Close()
	fmt.Printf("request trisolaris(%s), params(%+v)\n", conn.Target(), agentParamData)
	c := agent.NewDebugClient(conn)
	reqData := &agent.GPIDSyncRequest{
		TeamId: &agentParamData.TeamID,
	}
	response, err := c.DebugGPIDGlobalData(context.Background(), reqData)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println("GPIDGlobalData:")
	for index, entry := range response.GetEntries() {
		AJsonFormat(index+1, AformatGlobalEntry(entry))
	}
}

func AformatEntries(entry *agent.GPIDSyncEntry) string {
	buffer := bytes.Buffer{}
	format := "{protocol: %d, epc_id_1: %d, ipv4_1: %s, port_1: %d, pid_1: %d, " +
		"epc_id_0: %d, ipv4_0: %s, port_0: %d, pid_0: %d, epc_id_real: %d, " +
		"ipv4_real: %s, port_real: %d, pid_real: %d, role_real: %d, netns_idx: %d}"
	buffer.WriteString(fmt.Sprintf(format,
		entry.GetProtocol(), entry.GetEpcId_1(), utils.IpFromUint32(entry.GetIpv4_1()).String(), entry.GetPort_1(), entry.GetPid_1(),
		entry.GetEpcId_0(), utils.IpFromUint32(entry.GetIpv4_0()).String(), entry.GetPort_0(), entry.GetPid_0(), entry.GetEpcIdReal(),
		utils.IpFromUint32(entry.GetIpv4Real()).String(), entry.GetPortReal(), entry.GetPidReal(), entry.GetRoleReal(), entry.GetNetnsIdx()),
	)
	return buffer.String()
}

func getAgentConn(cmd *cobra.Command) *grpc.ClientConn {
	server := common.GetServerInfo(cmd)
	orgID := common.GetORGID(cmd)
	agentParamData.RpcIP = server.IP
	agentParamData.RpcPort = strconv.Itoa(int(server.RpcPort))
	agentParamData.OrgID = uint32(orgID)
	addr := net.JoinHostPort(agentParamData.RpcIP, agentParamData.RpcPort)
	conn, err := grpc.Dial(addr, grpc.WithInsecure(), grpc.WithMaxMsgSize(1024*1024*200))
	if err != nil {
		fmt.Println(err)
		return nil
	}

	return conn
}

func AgpidAgentRequest(cmd *cobra.Command) {
	conn := getAgentConn(cmd)
	if conn == nil {
		return
	}
	defer conn.Close()
	fmt.Printf("request trisolaris(%s), params(%+v)\n", conn.Target(), agentParamData)
	c := agent.NewDebugClient(conn)
	reqData := &agent.GPIDSyncRequest{
		CtrlIp:  &agentParamData.CtrlIP,
		CtrlMac: &agentParamData.CtrlMac,
		TeamId:  &agentParamData.TeamID,
	}
	response, err := c.DebugGPIDAgentData(context.Background(), reqData)
	if err != nil {
		fmt.Println(err)
		return
	}
	req := response.GetSyncRequest()
	tm := time.Unix(int64(response.GetUpdateTime()), 0)
	fmt.Printf("response(ctrl_ip: %s ctrl_mac: %s agent_id: %d update_time: %s)\n", req.GetCtrlIp(), req.GetCtrlMac(), req.GetAgentId(), tm.Format("2006-01-02 15:04:05"))
	fmt.Println("Entries:")
	if req == nil {
		return
	}
	for index, entry := range req.GetEntries() {
		JsonFormat(index+1, AformatEntries(entry))
	}
}

func AformatRealEntry(entry *agent.RealClientToRealServer) string {
	buffer := bytes.Buffer{}
	format := "{epc_id_1: %d, ipv4_1: %s, port_1: %d, " +
		"epc_id_0: %d, ipv4_0: %s, port_0: %d, " +
		"epc_id_real: %d, ipv4_real: %s, port_real: %d, pid_real: %d, agent_id_real: %d}"
	buffer.WriteString(fmt.Sprintf(format,
		entry.GetEpcId_1(), utils.IpFromUint32(entry.GetIpv4_1()).String(), entry.GetPort_1(),
		entry.GetEpcId_0(), utils.IpFromUint32(entry.GetIpv4_0()).String(), entry.GetPort_0(),
		entry.GetEpcIdReal(), utils.IpFromUint32(entry.GetIpv4Real()).String(),
		entry.GetPortReal(), entry.GetPidReal(), entry.GetAgentIdReal()))
	return buffer.String()
}

func ArealGlobal(cmd *cobra.Command) {
	conn := agentGetConn(cmd)
	if conn == nil {
		return
	}
	defer conn.Close()
	fmt.Printf("request trisolaris(%s), params(%+v)\n", conn.Target(), agentParamData)
	c := agent.NewDebugClient(conn)
	reqData := &agent.GPIDSyncRequest{
		CtrlIp:  &agentParamData.CtrlIP,
		CtrlMac: &agentParamData.CtrlMac,
		TeamId:  &agentParamData.TeamID,
	}
	response, err := c.DebugRealGlobalData(context.Background(), reqData)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println("Entries:")
	for index, entry := range response.GetEntries() {
		AJsonFormat(index+1, AformatRealEntry(entry))
	}
}

func AformatRVEntry(entry *agent.RipToVip) string {
	buffer := bytes.Buffer{}
	format := "{protocol: %d, epc_id: %d, r_ipv4: %s, r_port: %d, " +
		" v_ipv4: %s, v_port: %d, }"
	buffer.WriteString(fmt.Sprintf(format,
		entry.GetProtocol(), entry.GetEpcId(),
		utils.IpFromUint32(entry.GetRIpv4()).String(), entry.GetRPort(),
		utils.IpFromUint32(entry.GetVIpv4()).String(), entry.GetVPort(),
	))
	return buffer.String()
}

func AripToVip(cmd *cobra.Command) {
	conn := agentGetConn(cmd)
	if conn == nil {
		return
	}
	defer conn.Close()
	fmt.Printf("request trisolaris(%s), params(%+v)\n", conn.Target(), agentParamData)
	c := agent.NewDebugClient(conn)
	reqData := &agent.GPIDSyncRequest{
		CtrlIp:  &agentParamData.CtrlIP,
		CtrlMac: &agentParamData.CtrlMac,
		TeamId:  &agentParamData.TeamID,
	}
	response, err := c.DebugRIPToVIP(context.Background(), reqData)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println("Entries:")
	for index, entry := range response.GetEntries() {
		AJsonFormat(index+1, AformatRVEntry(entry))
	}
}

func AJsonFormat(index int, v interface{}) {
	jsonBytes, err := json.Marshal(v)
	if err != nil {
		fmt.Println("json encode failed")
	}
	fmt.Printf("\t%v: %s\n", index, jsonBytes)
}

func (a AgentSortedAcls) Len() int {
	return len(a)
}

func (a AgentSortedAcls) Less(i, j int) bool {
	return a[i].GetId() < a[j].GetId()
}

func (a AgentSortedAcls) Swap(i, j int) {
	a[i], a[j] = a[j], a[i]
}

func AflowAcls(response *agent.SyncResponse) {
	flowAcls := agent.FlowAcls{}
	fmt.Println("flow Acls version:", response.GetVersionAcls())

	if flowAclsCompressed := response.GetFlowAcls(); flowAclsCompressed != nil {
		if err := flowAcls.Unmarshal(flowAclsCompressed); err == nil {
			sort.Sort(AgentSortedAcls(flowAcls.FlowAcl)) // sort by id
			fmt.Println("flow Acls:")
			for index, entry := range flowAcls.FlowAcl {
				AJsonFormat(index+1, entry)
			}
		}
	}
}

func AipGroups(response *agent.SyncResponse) {
	groups := agent.Groups{}
	fmt.Println("Groups version:", response.GetVersionGroups())

	if groupsCompressed := response.GetGroups(); groupsCompressed != nil {
		if err := groups.Unmarshal(groupsCompressed); err == nil {
			fmt.Println("Groups data:")
			for index, entry := range groups.Groups {
				AJsonFormat(index+1, entry)
			}
		}
	}
}

func AformatString(data *agent.Interface) string {
	buffer := bytes.Buffer{}
	format := "Id: %d Mac: %s EpcId: %d DeviceType: %d IfType: %d" +
		" RegionId: %d " +
		" PodClusterId: %d, IsVipInterface: %t "
	buffer.WriteString(fmt.Sprintf(format, data.GetId(), Uint64ToMac(data.GetMac()),
		data.GetEpcId(), data.GetDeviceType(), data.GetIfType(), data.GetRegionId(),
		data.GetPodClusterId(),
		data.GetIsVipInterface()))
	if data.GetPodNodeId() > 0 {
		buffer.WriteString(fmt.Sprintf("PodNodeId: %d ", data.GetPodNodeId()))
	}
	if len(data.GetIpResources()) > 0 {
		buffer.WriteString(fmt.Sprintf("IpResources: %s", data.GetIpResources()))
	}
	return buffer.String()
}

func AplatformData(response *agent.SyncResponse) {
	platform := agent.PlatformData{}
	fmt.Println("PlatformData version:", response.GetVersionPlatformData())

	if plarformCompressed := response.GetPlatformData(); plarformCompressed != nil {
		if err := platform.Unmarshal(plarformCompressed); err == nil {
			fmt.Println("interfaces:")
			for index, entry := range platform.Interfaces {
				AJsonFormat(index+1, AformatString(entry))
			}
			fmt.Println("peer connections:")
			for index, entry := range platform.PeerConnections {
				AJsonFormat(index+1, entry)
			}
			fmt.Println("cidrs:")
			for index, entry := range platform.Cidrs {
				AJsonFormat(index+1, entry)
			}
		}
	}
}

func AconfigData(response *agent.SyncResponse) {
	fmt.Println("config:")
	config := response.GetUserConfig()
	fmt.Println(config)
	dynamicConfig := response.GetDynamicConfig()
	fmt.Println("DynamicConfig:")
	fmt.Println(proto.MarshalTextString(dynamicConfig))
}

func AGRPCBufferSize(response *agent.SyncResponse) {
	fmt.Printf("only partial fields: %t\n", response.GetOnlyPartialFields())
	fmt.Printf("new grpc buffer size (byte): %d\n", response.GetNewGrpcBufferSize())
}

func AskipInterface(response *agent.SyncResponse) {
	fmt.Println("SkipInterface:")
	for index, skipInterface := range response.GetSkipInterface() {
		AJsonFormat(index+1, fmt.Sprintf("mac: %s", Uint64ToMac(skipInterface.GetMac())))
	}
}

func AtapTypes(response *agent.SyncResponse) {
	fmt.Println("taptypes:")
	tapTypes := response.GetCaptureNetworkTypes()
	for index, tapType := range tapTypes {
		JsonFormat(index+1, tapType)
	}
}

func Asegments(response *agent.SyncResponse) {
	fmt.Println("local_segments:")
	localSegments := response.GetLocalSegments()
	for index, localSegment := range localSegments {
		AJsonFormat(index+1, localSegment)
	}
	fmt.Println("remote_segments:")
	remoteSegments := response.GetRemoteSegments()
	for index, remoteSegment := range remoteSegments {
		AJsonFormat(index+1, remoteSegment)
	}
}

func Acontainers(response *agent.SyncResponse) {
	fmt.Println("containers:")
	containers := response.GetContainers()
	for index, container := range containers {
		AJsonFormat(index+1, container)
	}
}

func Aplugin(cmd *cobra.Command) {
	conn := agentGetConn(cmd)
	if conn == nil {
		return
	}
	defer conn.Close()
	fmt.Printf("request trisolaris(%s), params(%+v)\n", conn.Target(), agentParamData)
	var pluginType agent.PluginType
	switch agentParamData.PluginType {
	case "wasm":
		pluginType = agent.PluginType_WASM
	default:
		fmt.Printf("request pluginType(%s) not supported, pluginType must be in %s\n",
			agentParamData.PluginType, []string{"wasm"})
		return
	}
	c := agent.NewSynchronizerClient(conn)
	reqData := &agent.PluginRequest{
		CtrlIp:     &agentParamData.CtrlIP,
		CtrlMac:    &agentParamData.CtrlMac,
		TeamId:     &agentParamData.TeamID,
		PluginType: &pluginType,
		PluginName: &agentParamData.PluginName,
	}
	stream, err := c.Plugin(context.Background(), reqData)
	if err != nil {
		fmt.Println(err)
		return
	}
	var (
		data []byte
		md5  string
	)
	for {
		if res, err := stream.Recv(); err == nil {
			data = append(data, res.GetContent()...)
			md5 = res.GetMd5()
		} else {
			if errors.Is(err, io.EOF) {
				break
			}
			fmt.Println(res, err)
			return
		}
	}
	fileName := agentParamData.PluginType + "-" + agentParamData.PluginName
	err = ioutil.WriteFile(fileName, data, 0666)
	if err != nil {
		fmt.Printf("save plugin(%s) fail %s\n", fileName, err)
		return
	}
	fmt.Printf("save plugin(%s) success, md5=%s\n", fileName, md5)
}
