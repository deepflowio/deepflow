/*
 * Copyright (c) 2022 Yunshan Networks
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
	. "encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"sort"
	"strconv"

	"github.com/golang/protobuf/proto"
	"github.com/spf13/cobra"
	_ "golang.org/x/net/context"
	"google.golang.org/grpc"

	"github.com/deepflowio/deepflow/cli/ctl/common"
	"github.com/deepflowio/deepflow/message/trident"
)

type ParamData struct {
	CtrlIP    string
	CtrlMac   string
	GroupID   string
	ClusterID string
	RpcIP     string
	RpcPort   string
	Type      string
}

type SortedAcls []*trident.FlowAcl

var paramData ParamData

type CmdExecute func(response *trident.SyncResponse)

func regiterCommand() []*cobra.Command {
	platformDataCmd := &cobra.Command{
		Use:   "platformData",
		Short: "get platformData from deepflow-server",
		Run: func(cmd *cobra.Command, args []string) {
			initCmd(cmd, []CmdExecute{platformData})
		},
	}
	ipGroupsCmd := &cobra.Command{
		Use:   "ipGroups",
		Short: "get ipGroups from deepflow-servr",
		Run: func(cmd *cobra.Command, args []string) {
			initCmd(cmd, []CmdExecute{ipGroups})
		},
	}
	flowAclsCmd := &cobra.Command{
		Use:   "flowAcls",
		Short: "get flowAcls from deepflow-server",
		Run: func(cmd *cobra.Command, args []string) {
			initCmd(cmd, []CmdExecute{flowAcls})
		},
	}
	tapTypesCmd := &cobra.Command{
		Use:   "tapTypes",
		Short: "get tapTypes from deepflow-server",
		Run: func(cmd *cobra.Command, args []string) {
			initCmd(cmd, []CmdExecute{tapTypes})
		},
	}
	segmentsCmd := &cobra.Command{
		Use:   "segments",
		Short: "get segments from deepflow-server",
		Run: func(cmd *cobra.Command, args []string) {
			initCmd(cmd, []CmdExecute{segments})
		},
	}
	vpcIPCmd := &cobra.Command{
		Use:   "vpcIP",
		Short: "get vpcIP from deepflow-server",
		Run: func(cmd *cobra.Command, args []string) {
			initCmd(cmd, []CmdExecute{vpcIP})
		},
	}
	configCmd := &cobra.Command{
		Use:   "config",
		Short: "get config from deepflow-server",
		Run: func(cmd *cobra.Command, args []string) {
			initCmd(cmd, []CmdExecute{configData})
		},
	}
	skipInterfaceCmd := &cobra.Command{
		Use:   "skipInterface",
		Short: "get skipInterface from deepflow-server",
		Run: func(cmd *cobra.Command, args []string) {
			initCmd(cmd, []CmdExecute{skipInterface})
		},
	}
	localServersCmd := &cobra.Command{
		Use:   "localServers",
		Short: "get localServers from deepflow-server",
		Run: func(cmd *cobra.Command, args []string) {
			initCmd(cmd, []CmdExecute{localServers})
		},
	}
	allCmd := &cobra.Command{
		Use:   "all",
		Short: "get all data from deepflow-server",
		Run: func(cmd *cobra.Command, args []string) {
			initCmd(cmd, []CmdExecute{platformData, ipGroups, flowAcls, tapTypes,
				segments, vpcIP, configData, skipInterface, localServers})
		},
	}

	commands := []*cobra.Command{platformDataCmd, ipGroupsCmd, flowAclsCmd,
		tapTypesCmd, configCmd, segmentsCmd, vpcIPCmd, skipInterfaceCmd, localServersCmd, allCmd}
	return commands
}

func RegisterTrisolarisCommand() *cobra.Command {
	trisolarisCmd := &cobra.Command{
		Use:   "trisolaris.check",
		Short: "pull grpc data from deepflow-server",
	}
	trisolarisCmd.PersistentFlags().StringVarP(&paramData.CtrlIP, "cip", "", "", "vtap ctrl ip")
	trisolarisCmd.PersistentFlags().StringVarP(&paramData.CtrlMac, "cmac", "", "", "vtap ctrl mac")
	trisolarisCmd.PersistentFlags().StringVarP(&paramData.GroupID, "gid", "", "", "vtap group ID")
	trisolarisCmd.PersistentFlags().StringVarP(&paramData.ClusterID, "cid", "", "", "vtap k8s cluster ID")
	trisolarisCmd.PersistentFlags().StringVarP(&paramData.Type, "type", "", "trident", "request type trdient/analyzer")
	cmds := regiterCommand()
	for _, handler := range cmds {
		trisolarisCmd.AddCommand(handler)
	}

	return trisolarisCmd
}

func initCmd(cmd *cobra.Command, cmds []CmdExecute) {
	server := common.GetServerInfo(cmd)
	paramData.RpcIP = server.IP
	paramData.RpcPort = strconv.Itoa(int(server.RpcPort))
	addr := net.JoinHostPort(paramData.RpcIP, paramData.RpcPort)
	conn, err := grpc.Dial(addr, grpc.WithInsecure(), grpc.WithMaxMsgSize(1024*1024*200))
	if err != nil {
		fmt.Println(err)
		return
	}
	defer conn.Close()
	var name, groupID, clusterID string
	switch paramData.Type {
	case "trident":
		name = paramData.Type
		groupID = paramData.GroupID
		clusterID = paramData.ClusterID
	case "analyzer":
		name = paramData.Type
	default:
		fmt.Printf("type(%s) muste be in [trident, analyzer]", paramData.Type)
		return
	}
	fmt.Printf("request trisolaris(%s), params(%+v)\n", addr, paramData)
	c := trident.NewSynchronizerClient(conn)
	reqData := &trident.SyncRequest{
		CtrlIp:              &paramData.CtrlIP,
		CtrlMac:             &paramData.CtrlMac,
		VtapGroupIdRequest:  &groupID,
		KubernetesClusterId: &clusterID,
		ProcessName:         &name,
	}
	var response *trident.SyncResponse
	if paramData.Type == "trident" {
		response, err = c.Sync(context.Background(), reqData)
	} else {
		response, err = c.AnalyzerSync(context.Background(), reqData)
	}
	if err != nil {
		fmt.Println(err)
		return
	}
	for _, cmd := range cmds {
		cmd(response)
	}
}

func JsonFormat(index int, v interface{}) {
	jsonBytes, err := json.Marshal(v)
	if err != nil {
		fmt.Println("json encode failed")
	}
	fmt.Printf("\t%v: %s\n", index, jsonBytes)
}

func (a SortedAcls) Len() int {
	return len(a)
}

func (a SortedAcls) Less(i, j int) bool {
	return a[i].GetId() < a[j].GetId()
}

func (a SortedAcls) Swap(i, j int) {
	a[i], a[j] = a[j], a[i]
}

func flowAcls(response *trident.SyncResponse) {
	flowAcls := trident.FlowAcls{}
	fmt.Println("flow Acls version:", response.GetVersionAcls())

	if flowAclsCompressed := response.GetFlowAcls(); flowAclsCompressed != nil {
		if err := flowAcls.Unmarshal(flowAclsCompressed); err == nil {
			sort.Sort(SortedAcls(flowAcls.FlowAcl)) // sort by id
			fmt.Println("flow Acls:")
			for index, entry := range flowAcls.FlowAcl {
				JsonFormat(index+1, entry)
			}
		}
	}
}

func ipGroups(response *trident.SyncResponse) {
	groups := trident.Groups{}
	fmt.Println("Groups version:", response.GetVersionGroups())

	if groupsCompressed := response.GetGroups(); groupsCompressed != nil {
		if err := groups.Unmarshal(groupsCompressed); err == nil {
			fmt.Println("Groups data:")
			for index, entry := range groups.Groups {
				JsonFormat(index+1, entry)
			}
			fmt.Println("Services data:")
			for index, entry := range groups.Svcs {
				JsonFormat(index+1, entry)
			}
		}
	}
}

func Uint64ToMac(v uint64) net.HardwareAddr {
	bytes := [8]byte{}
	BigEndian.PutUint64(bytes[:], v)
	return net.HardwareAddr(bytes[2:])
}

func formatString(data *trident.Interface) string {
	buffer := bytes.Buffer{}
	format := "Id: %d Mac: %s EpcId: %d DeviceType: %d DeviceId: %d IfType: %d" +
		" LaunchServer: %s LaunchServerId: %d RegionId: %d AzId: %d, PodGroupId: %d, " +
		"PodNsId: %d, PodId: %d, PodClusterId: %d, PodGroupType: %d, IsVipInterface: %t "
	buffer.WriteString(fmt.Sprintf(format, data.GetId(), Uint64ToMac(data.GetMac()),
		data.GetEpcId(), data.GetDeviceType(), data.GetDeviceId(), data.GetIfType(),
		data.GetLaunchServer(), data.GetLaunchServerId(), data.GetRegionId(),
		data.GetAzId(), data.GetPodGroupId(), data.GetPodNsId(), data.GetPodId(),
		data.GetPodClusterId(), data.GetPodGroupType(), data.GetIsVipInterface()))
	if data.GetPodNodeId() > 0 {
		buffer.WriteString(fmt.Sprintf("PodNodeId: %d ", data.GetPodNodeId()))
	}
	if len(data.GetIpResources()) > 0 {
		buffer.WriteString(fmt.Sprintf("IpResources: %s", data.GetIpResources()))
	}
	return buffer.String()
}

func platformData(response *trident.SyncResponse) {
	platform := trident.PlatformData{}
	fmt.Println("PlatformData version:", response.GetVersionPlatformData())

	if plarformCompressed := response.GetPlatformData(); plarformCompressed != nil {
		if err := platform.Unmarshal(plarformCompressed); err == nil {
			fmt.Println("interfaces:")
			for index, entry := range platform.Interfaces {
				JsonFormat(index+1, formatString(entry))
			}
			fmt.Println("peer connections:")
			for index, entry := range platform.PeerConnections {
				JsonFormat(index+1, entry)
			}
			fmt.Println("cidrs:")
			for index, entry := range platform.Cidrs {
				JsonFormat(index+1, entry)
			}
		}
	}
}

func configData(response *trident.SyncResponse) {
	fmt.Println("config:")
	config := response.GetConfig()
	fmt.Println(proto.MarshalTextString(config))
	fmt.Println("revision:", response.GetRevision())
	fmt.Println("self_update_url:", response.GetSelfUpdateUrl())

	fmt.Println("\nAnalyzerconfig:")
	fmt.Println(proto.MarshalTextString(response.GetAnalyzerConfig()))
}

func skipInterface(response *trident.SyncResponse) {
	fmt.Println("SkipInterface:")
	for index, skipInterface := range response.GetSkipInterface() {
		JsonFormat(index+1, fmt.Sprintf("mac: %s", Uint64ToMac(skipInterface.GetMac())))
	}
}

func localServers(response *trident.SyncResponse) {
	fmt.Println("localServers:")
	for index, entry := range response.GetDeepflowServerInstances() {
		JsonFormat(index+1, entry)
	}
}

func tapTypes(response *trident.SyncResponse) {
	fmt.Println("taptypes:")
	tapTypes := response.GetTapTypes()
	for index, tapType := range tapTypes {
		JsonFormat(index+1, tapType)
	}
}

func segments(response *trident.SyncResponse) {
	fmt.Println("local_segments:")
	localSegments := response.GetLocalSegments()
	for index, localSegment := range localSegments {
		JsonFormat(index+1, localSegment)
	}
	fmt.Println("remote_segments:")
	remoteSegments := response.GetRemoteSegments()
	for index, remoteSegment := range remoteSegments {
		JsonFormat(index+1, remoteSegment)
	}
}

func vpcIP(response *trident.SyncResponse) {
	fmt.Println("vtap_ip:")
	for index, vtapIP := range response.GetVtapIps() {
		JsonFormat(index+1, vtapIP)
	}
	fmt.Println("pod_ip:")
	for index, podIP := range response.GetPodIps() {
		JsonFormat(index+1, podIP)
	}
}
