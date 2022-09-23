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
	"os/exec"
	"strconv"
	"strings"

	"github.com/ghodss/yaml"
	"github.com/spf13/cobra"

	"github.com/deepflowys/deepflow/cli/ctl/common"
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
		Example: "deepflow-ctl agent list deepflow-agent -o yaml",
		Run: func(cmd *cobra.Command, args []string) {
			listAgent(cmd, args, listOutput)
		},
	}
	list.Flags().StringVarP(&listOutput, "output", "o", "", "output format")

	delete := &cobra.Command{
		Use:     "delete [name]",
		Short:   "delete agent",
		Example: "deepflow-ctl agent delete deepflow-agent",
		Run: func(cmd *cobra.Command, args []string) {
			deleteAgent(cmd, args)
		},
	}

	agent.AddCommand(list)
	agent.AddCommand(delete)
	return agent
}

func RegisterAgentUpgradeCommand() *cobra.Command {
	agentUpgrade := &cobra.Command{
		Use:   "agent-upgrade",
		Short: "agent upgrade operation commands",
		Example: "deepflow-ctl agent-upgrade list\n" +
			"deepflow-ctl agent-upgrade vtap-name --package=/usr/sbin/deepflow-agent\n",
		Run: func(cmd *cobra.Command, args []string) {
			if len(args) == 1 {
				if args[0] == "list" {
					listAgentUpgrade(cmd, args)
				} else if upgradePackage != "" {
					upgadeAgent(cmd, args)
				} else {
					fmt.Println(cmd.Example)
				}

			} else {
				fmt.Println(cmd.Example)
			}
		},
	}
	agentUpgrade.Flags().StringVarP(&upgradePackage, "package", "c", "", "")

	return agentUpgrade
}

func listAgentUpgrade(cmd *cobra.Command, args []string) {
	// 生成URL
	server := common.GetServerInfo(cmd)
	url := fmt.Sprintf("http://%s:%d/v1/vtaps/", server.IP, server.Port)

	// 调用采集器API，并输出返回结果
	response, err := common.CURLPerform("GET", url, nil, "")
	if err != nil {
		fmt.Println(err)
		return
	}

	cmdFormat := "%-40s%-48s%-48s%-50s\n"
	fmt.Printf(cmdFormat, "NAME", "REVISION", "EXPECTED_REVISION", "UPGRADE_PACKAGE")
	for i := range response.Get("DATA").MustArray() {
		vtap := response.Get("DATA").GetIndex(i)
		revision := vtap.Get("REVISION").MustString()
		completeRevision := vtap.Get("COMPLETE_REVISION").MustString()
		oldRevision := revision + "-" + completeRevision
		expectedRevision := vtap.Get("EXPECTED_REVISION").MustString()
		if expectedRevision != "" {
			fmt.Printf(
				cmdFormat, vtap.Get("NAME").MustString(), oldRevision,
				expectedRevision, vtap.Get("UPGRADE_PACKAGE").MustString(),
			)
		}
	}
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
		cmdFormat := "%-48s%-32s%-24s%-16s%-16s%s\n"
		fmt.Printf(cmdFormat, "NAME", "CTRL_IP", "CTRL_MAC", "STATE", "EXCEPTIONS", "AGENT_GROUP_NAME")
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
				vtap.Get("VTAP_GROUP_NAME").MustString(),
			)
		}
	}
}

func deleteAgent(cmd *cobra.Command, args []string) {
	if len(args) == 0 {
		fmt.Fprintf(os.Stderr, "must specify name.\nExample: %s", cmd.Example)
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

func executeCommand(command string) (string, error) {
	cmd := exec.Command("/usr/bin/bash", "-c", command)
	output, err := cmd.CombinedOutput()
	if err != nil {
		err = fmt.Errorf("command(%v) failed; result: %v, error:%v", command, string(output), err)
	}

	return string(output), err
}

var upgradePackage string

func upgadeAgent(cmd *cobra.Command, args []string) {
	if len(args) == 0 {
		fmt.Fprintf(os.Stderr, "must specify name and package. Examples: \n%s", cmd.Example)
		return
	}
	vtapName := args[0]
	command := upgradePackage + " -v"
	output, err := executeCommand(command)
	if err != nil {
		fmt.Println(err)
		return
	}
	splitStr := strings.Split(output, " ")
	if len(splitStr) < 2 {
		fmt.Printf("get expectedVersion faild, exec: %s, output: %s", command, output)
		return
	}
	expectedVersion := splitStr[0]
	if expectedVersion == "" {
		fmt.Printf("get expectedVersion faild, exec: %s, output: %s", command, output)
		return
	}

	server := common.GetServerInfo(cmd)
	serverURL := fmt.Sprintf("http://%s:%d/v1/controllers/", server.IP, server.Port)
	response, err := common.CURLPerform("GET", serverURL, nil, "")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}
	controllerArray := response.Get("DATA").MustArray()
	hosts := map[string]struct{}{
		server.IP: struct{}{},
	}
	if len(controllerArray) > 0 {
		for index, _ := range controllerArray {
			nodeType := response.Get("DATA").GetIndex(index).Get("NODE_TYPE").MustInt()
			ip := response.Get("DATA").GetIndex(index).Get("IP").MustString()
			if nodeType == 1 && ip != "" {
				hosts[ip] = struct{}{}
			}
		}
	} else {
		fmt.Printf("get server info failed, url: %s\n", serverURL)
		return
	}

	vtapURL := fmt.Sprintf("http://%s:%d/v1/vtaps/?name=%s", server.IP, server.Port, vtapName)
	response, err = common.CURLPerform("GET", vtapURL, nil, "")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}

	var (
		vtapController string
		vtapLcuuid     string
	)

	if len(response.Get("DATA").MustArray()) > 0 {
		vtapLcuuid = response.Get("DATA").GetIndex(0).Get("LCUUID").MustString()
		vtapController = response.Get("DATA").GetIndex(0).Get("CONTROLLER_IP").MustString()
	} else {
		fmt.Printf("get agent(%s) info failed, url: %s\n", vtapName, vtapURL)
		return
	}
	if vtapController == "" || vtapLcuuid == "" {
		fmt.Printf("get agent(%s) info failed, url: %s\n", vtapName, vtapURL)
		return
	}
	url_format := "http://%s:%d/v1/upgrade/vtap/%s/"
	body := map[string]interface{}{
		"expected_revision": expectedVersion,
		"upgrade_package":   upgradePackage,
	}
	for host, _ := range hosts {
		url := fmt.Sprintf(url_format, host, server.Port, vtapLcuuid)
		_, err := common.CURLPerform("PATCH", url, body, "")
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			fmt.Printf("upgrade agent %s failed\n", vtapName)
			return
		}
	}
	fmt.Printf("set agent %s revision(%s) success\n", vtapName, expectedVersion)
}
