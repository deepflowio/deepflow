package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"sort"

	"github.com/golang/protobuf/proto"
	"github.com/spf13/cobra"
	"google.golang.org/grpc"

	"github.com/metaflowys/metaflow/message/trident"
	"github.com/metaflowys/metaflow/server/libs/utils"
)

const (
	PORT = "20035"
)

type ParamData struct {
	CtrlIP      string
	CtrlMac     string
	ControlleIP string
	Type        string
}

type SortedAcls []*trident.FlowAcl

var paramData ParamData

func init() {
	rootCmd.PersistentFlags().StringVarP(&paramData.CtrlIP, "ctrl_ip", "", "", "采集器控制器IP")
	rootCmd.PersistentFlags().StringVarP(&paramData.CtrlMac, "ctrl_mac", "", "", "采集器控制MAC")
	rootCmd.PersistentFlags().StringVarP(&paramData.ControlleIP, "controller_ip", "", "127.0.0.1", "控制器IP")
	rootCmd.PersistentFlags().StringVarP(&paramData.Type, "type", "", "trident", "请求类型trdient/analyzer")
}

var rootCmd = RegisterRpcCommand()

type CmdExecute func(response *trident.SyncResponse)

func regiterCommand() []*cobra.Command {
	platformDataCmd := &cobra.Command{
		Use:   "platformData",
		Short: "get platformData from controller",
		Run: func(cmd *cobra.Command, args []string) {
			initCmd([]CmdExecute{platformData})
		},
	}
	ipGroupsCmd := &cobra.Command{
		Use:   "ipGroups",
		Short: "get ipGroups from controller",
		Run: func(cmd *cobra.Command, args []string) {
			initCmd([]CmdExecute{ipGroups})
		},
	}
	flowAclsCmd := &cobra.Command{
		Use:   "flowAcls",
		Short: "get flowAcls from controller",
		Run: func(cmd *cobra.Command, args []string) {
			initCmd([]CmdExecute{flowAcls})
		},
	}
	tapTypesCmd := &cobra.Command{
		Use:   "tapTypes",
		Short: "get tapTypes from controller",
		Run: func(cmd *cobra.Command, args []string) {
			initCmd([]CmdExecute{tapTypes})
		},
	}
	segmentsCmd := &cobra.Command{
		Use:   "segments",
		Short: "get segments from controller",
		Run: func(cmd *cobra.Command, args []string) {
			initCmd([]CmdExecute{segments})
		},
	}
	vpcIPCmd := &cobra.Command{
		Use:   "vpcIP",
		Short: "get vpcIP from controller",
		Run: func(cmd *cobra.Command, args []string) {
			initCmd([]CmdExecute{vpcIP})
		},
	}
	configCmd := &cobra.Command{
		Use:   "config",
		Short: "get config from controller",
		Run: func(cmd *cobra.Command, args []string) {
			initCmd([]CmdExecute{configData})
		},
	}
	allCmd := &cobra.Command{
		Use:   "all",
		Short: "get all data from controller",
		Run: func(cmd *cobra.Command, args []string) {
			initCmd([]CmdExecute{platformData, ipGroups, flowAcls, tapTypes, segments, vpcIP, configData})
		},
	}

	commands := []*cobra.Command{platformDataCmd, ipGroupsCmd, flowAclsCmd,
		tapTypesCmd, configCmd, segmentsCmd, vpcIPCmd, allCmd}
	return commands
}

func RegisterRpcCommand() *cobra.Command {
	root := &cobra.Command{
		Use:   "rpc",
		Short: "pull policy from controller by rpc",
	}

	cmds := regiterCommand()
	for _, handler := range cmds {
		root.AddCommand(handler)
	}

	return root
}

func initCmd(cmds []CmdExecute) {
	addr := net.JoinHostPort(paramData.ControlleIP, PORT)
	conn, err := grpc.Dial(addr, grpc.WithInsecure())
	if err != nil {
		fmt.Println(err)
		return
	}
	defer conn.Close()
	var name string
	switch paramData.Type {
	case "trident", "analyzer":
		name = paramData.Type
	default:
		fmt.Printf("type(%s) muste be in [trident, analyzer]", paramData.Type)
		return
	}
	fmt.Printf("request trisolaris(%s), params(%+v)\n", addr, paramData)
	c := trident.NewSynchronizerClient(conn)
	reqData := &trident.SyncRequest{
		CtrlIp:      &paramData.CtrlIP,
		CtrlMac:     &paramData.CtrlMac,
		ProcessName: &name,
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
		}
	}
}

func formatString(data *trident.Interface) string {
	buffer := bytes.Buffer{}
	format := "Mac: %s EpcId: %d DeviceType: %d DeviceId: %d IfType: %d LaunchServer: %s LaunchServerId: %d RegionId: %d SkipTapInterface: %t "
	buffer.WriteString(fmt.Sprintf(format, utils.Uint64ToMac(data.GetMac()), data.GetEpcId(),
		data.GetDeviceType(), data.GetDeviceId(), data.GetIfType(),
		data.GetLaunchServer(), data.GetLaunchServerId(), data.GetRegionId(), data.GetSkipTapInterface()))
	if data.GetPodNodeId() > 0 {
		buffer.WriteString(fmt.Sprintf("PodNodeId: %d ", data.GetPodNodeId()))
	}
	if len(data.GetIpResources()) > 0 {
		buffer.WriteString(fmt.Sprintf("IpResources: %v", data.GetIpResources()))
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
		}
	}
}

func configData(response *trident.SyncResponse) {
	fmt.Println("config:")
	config := response.GetConfig()
	fmt.Println(proto.MarshalTextString(config))
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

func main() {
	rootCmd.Execute()
}
