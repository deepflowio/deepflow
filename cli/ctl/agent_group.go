/*
 * Copyright (c) 2023 Yunshan Networks
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
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"sigs.k8s.io/yaml"

	"github.com/deepflowio/deepflow/cli/ctl/common"
)

func RegisterAgentGroupCommand() *cobra.Command {
	agentGroup := &cobra.Command{
		Use:   "agent-group",
		Short: "agent-group operation commands",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("please run with 'list | create | delete'.\n")
		},
	}

	var listOutput string
	list := &cobra.Command{
		Use:     "list [name]",
		Short:   "list agent-group info",
		Example: "deepflow-ctl agent-group list deepflow-agent-group",
		Run: func(cmd *cobra.Command, args []string) {
			listAgentGroup(cmd, args, listOutput)
		},
	}
	list.Flags().StringVarP(&listOutput, "output", "o", "", "output format")

	var groupID string
	create := &cobra.Command{
		Use:     "create <name>",
		Short:   "create agent-group",
		Example: "deepflow-ctl agent-group create deepflow-agent-group",
		Run: func(cmd *cobra.Command, args []string) {
			createAgentGroup(cmd, args, groupID)
		},
	}
	create.Flags().StringVar(&groupID, "id", "", "id must start with 'g-' prefix and have a length of 10 numbers and letters, such as g-1yhIguXABC")

	delete := &cobra.Command{
		Use:     "delete [name]",
		Short:   "delete agent-group",
		Example: "deepflow-ctl agent-group delete deepflow-agent-group",
		Run: func(cmd *cobra.Command, args []string) {
			deleteAgentGroup(cmd, args)
		},
	}

	agentGroup.AddCommand(list)
	agentGroup.AddCommand(create)
	agentGroup.AddCommand(delete)
	return agentGroup
}

func listAgentGroup(cmd *cobra.Command, args []string, output string) {
	name := ""
	if len(args) > 0 {
		name = args[0]
	}

	server := common.GetServerInfo(cmd)
	url := fmt.Sprintf("http://%s:%d/v1/vtap-groups/", server.IP, server.Port)
	if name != "" {
		url += fmt.Sprintf("?name=%s", name)
	}

	response, err := common.CURLPerform("GET", url, nil, "", []common.HTTPOption{common.WithTimeout(common.GetTimeout(cmd))}...)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}

	if output == "yaml" {
		dataJson, _ := response.Get("DATA").MarshalJSON()
		dataYaml, _ := yaml.JSONToYAML(dataJson)
		fmt.Printf(string(dataYaml))
	} else {
		cmdFormat := "%-48s%s\n"
		fmt.Printf(cmdFormat, "NAME", "ID")
		for i := range response.Get("DATA").MustArray() {
			group := response.Get("DATA").GetIndex(i)
			fmt.Printf(cmdFormat, group.Get("NAME").MustString(), group.Get("SHORT_UUID").MustString())
		}
	}
}

func createAgentGroup(cmd *cobra.Command, args []string, groupID string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "must specify name.\nExample: %s", cmd.Example)
		return
	}

	server := common.GetServerInfo(cmd)
	url := fmt.Sprintf("http://%s:%d/v1/vtap-groups/", server.IP, server.Port)

	// 调用采集器组API，并输出返回结果
	body := map[string]interface{}{"name": args[0], "group_id": groupID}
	_, err := common.CURLPerform("POST", url, body, "", []common.HTTPOption{common.WithTimeout(common.GetTimeout(cmd))}...)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}
}

func deleteAgentGroup(cmd *cobra.Command, args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "must specify name.\nExample: %s", cmd.Example)
		return
	}

	server := common.GetServerInfo(cmd)
	url := fmt.Sprintf("http://%s:%d/v1/vtap-groups/?name=%s", server.IP, server.Port, args[0])
	// 调用采集器组API，获取lcuuid
	response, err := common.CURLPerform("GET", url, nil, "", []common.HTTPOption{common.WithTimeout(common.GetTimeout(cmd))}...)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}

	if len(response.Get("DATA").MustArray()) > 0 {
		group := response.Get("DATA").GetIndex(0)
		lcuuid := group.Get("LCUUID").MustString()

		url := fmt.Sprintf("http://%s:%d/v1/vtap-groups/%s/", server.IP, server.Port, lcuuid)
		_, err := common.CURLPerform("DELETE", url, nil, "", []common.HTTPOption{common.WithTimeout(common.GetTimeout(cmd))}...)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return
		}
	}
}
