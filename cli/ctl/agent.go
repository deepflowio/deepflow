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
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/ghodss/yaml"
	"github.com/spf13/cobra"

	"github.com/metaflowys/metaflow/cli/ctl/common"
)

func RegisterAgentCommand() *cobra.Command {
	agent := &cobra.Command{
		Use:   "agent",
		Short: "agent operation commands",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("please run with 'list'.\n")
		},
	}

	var listOutput string
	list := &cobra.Command{
		Use:     "list [name]",
		Short:   "list agent info",
		Example: "metaflow-ctl agent list metaflow-agent -o yaml",
		Run: func(cmd *cobra.Command, args []string) {
			listAgent(cmd, args, listOutput)
		},
	}
	list.Flags().StringVarP(&listOutput, "output", "o", "", "output format")

	delete := &cobra.Command{
		Use:     "delete [name]",
		Short:   "delete agent",
		Example: "metaflow-ctl agent delete metaflow-agent",
		Run: func(cmd *cobra.Command, args []string) {
			deleteAgent(cmd, args)
		},
	}

	agent.AddCommand(list)
	agent.AddCommand(delete)
	return agent
}

func listAgent(cmd *cobra.Command, args []string, output string) {
	name := ""
	if len(args) > 0 {
		name = args[0]
	}

	// 生成URL
	server := common.GetServerInfo(cmd)
	url := fmt.Sprintf("http://%s:%d/v1/vtaps/", server.IP, server.Port)
	if name != "" {
		url += fmt.Sprintf("?name=%s", name)
	}

	// 调用采集器API，并输出返回结果
	response, err := common.CURLPerform("GET", url, nil, "")
	if err != nil {
		fmt.Println(err)
		return
	}

	if output == "yaml" {
		dataJson, _ := response.Get("DATA").MarshalJSON()
		dataYaml, _ := yaml.JSONToYAML(dataJson)
		fmt.Printf(string(dataYaml))
	} else {
		cmdFormat := "%-48s%-32s%-24s%-16s%s\n"
		fmt.Printf(cmdFormat, "NAME", "CTRL_IP", "CTRL_MAC", "STATE", "EXCEPTIONS")
		for i := range response.Get("DATA").MustArray() {
			vtap := response.Get("DATA").GetIndex(i)
			stateString := ""
			switch vtap.Get("STATE").MustInt() {
			case common.VTAP_STATE_NOT_CONNECTED:
				stateString = common.VTAP_STATE_NOT_CONNECTED_STR
			case common.VTAP_STATE_NORMAL:
				stateString = common.VTAP_STATE_NORMAL_STR
			case common.VTAP_STATE_DISABLE:
				stateString = common.VTAP_STATE_DISABLE_STR
			case common.VTAP_STATE_PENDING:
				stateString = common.VTAP_STATE_PENDING_STR
			}

			exceptionStrings := []string{}
			for i := range vtap.Get("EXCEPTIONS").MustArray() {
				exceptionInt := vtap.Get("EXCEPTIONS").GetIndex(i).MustInt()
				exceptionStrings = append(exceptionStrings, strconv.Itoa(exceptionInt))
			}

			fmt.Printf(
				cmdFormat, vtap.Get("NAME").MustString(), vtap.Get("CTRL_IP").MustString(),
				vtap.Get("CTRL_MAC").MustString(), stateString, strings.Join(exceptionStrings, ","),
			)
		}
	}
}

func deleteAgent(cmd *cobra.Command, args []string) {
	if len(args) == 0 {
		fmt.Fprintf(os.Stderr, "must specify name. Example: %s", cmd.Example)
		return
	}

	server := common.GetServerInfo(cmd)
	url := fmt.Sprintf("http://%s:%d/v1/vtaps/?name=%s", server.IP, server.Port, args[0])
	// curl vtap API，get lcuuid
	response, err := common.CURLPerform("GET", url, nil, "")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}

	if len(response.Get("DATA").MustArray()) > 0 {
		lcuuid := response.Get("DATA").GetIndex(0).Get("LCUUID").MustString()
		url := fmt.Sprintf("http://%s:%d/v1/vtaps/%s/", server.IP, server.Port, lcuuid)
		// call vtap delete api
		_, err := common.CURLPerform("DELETE", url, nil, "")
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return
		}
	}
}
