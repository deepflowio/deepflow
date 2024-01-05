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

/*
 * rpc is a subcommands of droplet-ctl
 * which pulls policy information from controller by rpc.
 * now it contains 3 subcommands:
 *   flowAcls     get flowAcls from controller
 *   ipGroups     get ipGroups from controller
 *   platformData get platformData from controller
 */
package rpc

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/signal"
	"sort"

	"github.com/spf13/cobra"

	"github.com/deepflowio/deepflow/message/trident"
	"github.com/deepflowio/deepflow/server/ingester/config"
	dropletcfg "github.com/deepflowio/deepflow/server/ingester/droplet/config"
	"github.com/deepflowio/deepflow/server/ingester/ingesterctl"
	"github.com/deepflowio/deepflow/server/libs/utils"
)

type CmdExecute func(response *trident.SyncResponse)
type SortedAcls []*trident.FlowAcl

func regiterCommand() []*cobra.Command {
	platformDataCmd := &cobra.Command{
		Use:   "platformData",
		Short: "get platformData from controller, press Ctrl^c to end it",
		Run: func(cmd *cobra.Command, args []string) {
			initCmd(platformData)
		},
	}
	ipGroupsCmd := &cobra.Command{
		Use:   "ipGroups",
		Short: "get ipGroups from controller, press Ctrl^c to end it",
		Run: func(cmd *cobra.Command, args []string) {
			initCmd(ipGroups)
		},
	}
	flowAclsCmd := &cobra.Command{
		Use:   "flowAcls",
		Short: "get flowAcls from controller, press Ctrl^c to end it",
		Run: func(cmd *cobra.Command, args []string) {
			initCmd(flowAcls)
		},
	}

	commands := []*cobra.Command{platformDataCmd, ipGroupsCmd, flowAclsCmd}
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

func initCmd(cmd CmdExecute) {
	if ingesterctl.ConfigPath == "" {
		ingesterctl.ConfigPath = "/etc/server.yaml"
	}
	base := config.Load(ingesterctl.ConfigPath)
	cfg := dropletcfg.Load(base, ingesterctl.ConfigPath)

	controllers := make([]net.IP, 0, len(cfg.Base.ControllerIPs))
	for _, ipString := range cfg.Base.ControllerIPs {
		ip := net.ParseIP(ipString)
		controllers = append(controllers, ip)
	}

	synchronizer := dropletcfg.NewRpcConfigSynchronizer(controllers, cfg.Base.ControllerPort, cfg.RpcTimeout, cfg.Base.GrpcBufferSize)
	synchronizer.Register(func(response *trident.SyncResponse, version *dropletcfg.RpcInfoVersions) {
		cmd(response)
		fmt.Println("press Ctrl^c to end it !!")
	})

	synchronizer.Start()

	wait := make(chan os.Signal)
	signal.Notify(wait, os.Interrupt)
	if sig := <-wait; sig != os.Interrupt {
		fmt.Println("press Ctrl^c to end it !!")
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
	format := "Mac: %s EpcId: %d DeviceType: %d DeviceId: %d IfType: %d LaunchServer: %s LaunchServerId: %d RegionId: %d "
	buffer.WriteString(fmt.Sprintf(format, utils.Uint64ToMac(data.GetMac()), data.GetEpcId(),
		data.GetDeviceType(), data.GetDeviceId(), data.GetIfType(),
		data.GetLaunchServer(), data.GetLaunchServerId(), data.GetRegionId()))
	if data.GetPodNodeId() > 0 {
		buffer.WriteString(fmt.Sprintf("PodNodeId: %d", data.GetPodNodeId()))
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
