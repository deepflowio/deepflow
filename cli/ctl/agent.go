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
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"github.com/bitly/go-simplejson"
	"github.com/ghodss/yaml"
	"github.com/spf13/cobra"

	"github.com/deepflowys/deepflow/cli/ctl/common"
	"github.com/deepflowys/deepflow/cli/ctl/common/jsonparser"
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

	var typeStr string
	rebalanceCmd := &cobra.Command{
		Use:     "rebalance",
		Short:   "rebalance controller or analyzer",
		Example: "deepflow-ctl agent rebalance --type=controller\ndeepflow-ctl agent rebalance --type=analyzer",
		Run: func(cmd *cobra.Command, args []string) {
			if err := rebalance(cmd, args, typeStr); err != nil {
				fmt.Println(err)
			}
		},
	}
	rebalanceCmd.Flags().StringVarP(&typeStr, "type", "t", "", "request type controller/analyzer")

	agent.AddCommand(list)
	agent.AddCommand(delete)
	agent.AddCommand(rebalanceCmd)
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
		nameMaxSize := 0
		for i := range response.Get("DATA").MustArray() {
			vtap := response.Get("DATA").GetIndex(i)
			l := len(vtap.Get("NAME").MustString())
			if l > nameMaxSize {
				nameMaxSize = l
			}
		}

		cmdFormat := "%-*s %-10s %-16s %-18s %-8s %-10s %s\n"
		fmt.Printf(cmdFormat, nameMaxSize, "NAME", "TYPE", "CTRL_IP", "CTRL_MAC", "STATE", "EXCEPTIONS", "GROUP")
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

			vtapTypeString, _ := common.VTapTypeName[vtap.Get("TYPE").MustInt()]

			exceptionStrings := []string{}
			for i := range vtap.Get("EXCEPTIONS").MustArray() {
				exceptionInt := vtap.Get("EXCEPTIONS").GetIndex(i).MustInt()
				exceptionStrings = append(exceptionStrings, strconv.Itoa(exceptionInt))
			}

			fmt.Printf(
				cmdFormat, nameMaxSize, vtap.Get("NAME").MustString(), vtapTypeString, vtap.Get("CTRL_IP").MustString(),
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

	var expectedVersion string
	splitStr := strings.Split(output, "\n")
	if len(splitStr) < 5 {
		splitStr = strings.Split(splitStr[0], " ")
		if len(splitStr) == 2 {
			expectedVersion = splitStr[0]
		}
	} else {
		expectedVersion = splitStr[0]
	}
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
	hosts[vtapController] = struct{}{}
	url_format := "http://%s:%d/v1/upgrade/vtap/%s/"
	body := map[string]interface{}{
		"expected_revision": expectedVersion,
		"upgrade_package":   upgradePackage,
	}
	sendHosts := make([]string, 0, len(hosts))
	for host, _ := range hosts {
		sendHosts = append(sendHosts, host)
		url := fmt.Sprintf(url_format, host, server.Port, vtapLcuuid)
		_, err := common.CURLPerform("PATCH", url, body, "")
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			fmt.Printf("upgrade agent %s server %s failed\n", vtapName, host)
			continue
		}
	}
	fmt.Printf("send upgrade data to server:%v\n", sendHosts)
	fmt.Printf("set agent %s revision(%s) success\n", vtapName, expectedVersion)
}

func rebalance(cmd *cobra.Command, args []string, typeStr string) error {
	if len(args) > 0 {
		typeStr = args[0]
	}

	server := common.GetServerInfo(cmd)
	isBalance, err := ifNeedRebalance(server, typeStr)
	if err != nil {
		return err
	}
	if !isBalance {
		fmt.Println("no balance required")
		return nil
	}
	resp, err := execRebalance(server, typeStr)
	if err != nil {
		return err
	}
	printDetail(resp)
	return nil
}

func ifNeedRebalance(server *common.Server, typeStr string) (bool, error) {
	url := fmt.Sprintf("http://%s:%d/v1/rebalance-vtap/?check=false&type=%s", server.IP, server.Port, typeStr)
	resp, err := common.CURLPerform("POST", url, nil, "")
	if err != nil {
		return false, err
	}
	if resp.Get("DATA").Get("TOTAL_SWITCH_VTAP_NUM").MustInt() == 0 {
		return false, nil
	}
	return true, nil
}

func execRebalance(server *common.Server, typeStr string) (*simplejson.Json, error) {
	url := fmt.Sprintf("http://%s:%d/v1/rebalance-vtap/?check=true&type=%s", server.IP, server.Port, typeStr)
	resp, err := common.CURLPerform("POST", url, nil, "")
	if err != nil {
		return nil, err
	}

	details := resp.Get("DATA").Get("DETAILS")
	if len(details.MustArray()) == 0 {
		return nil, errors.New("return details is empty")
	}
	return resp, nil
}

func printDetail(resp *simplejson.Json) {
	details := resp.Get("DATA").Get("DETAILS")
	ipMaxSize := jsonparser.GetTheMaxSizeOfAttr(details, "IP")
	azMaxSize := jsonparser.GetTheMaxSizeOfAttr(details, "AZ")
	stateMaxSize := jsonparser.GetTheMaxSizeOfAttr(details, "STATE")
	beforeVTapNumMaxSize := jsonparser.GetTheMaxSizeOfAttr(details, "BEFORE_VTAP_NUM")
	afertVTapNumMaxSize := jsonparser.GetTheMaxSizeOfAttr(details, "AFTER_VTAP_NUM")
	switchVTapNumMaxSize := jsonparser.GetTheMaxSizeOfAttr(details, "SWITCH_VTAP_NUM")

	cmdFormat := "%-*v %-*v %-*v %-*v %-*v %-*v\n"
	fmt.Printf(cmdFormat,
		ipMaxSize, "IP",
		azMaxSize, "AZ",
		stateMaxSize, "STATE",
		beforeVTapNumMaxSize, "BEFORE_VTAP_NUM",
		afertVTapNumMaxSize, "AFTER_VTAP_NUM",
		switchVTapNumMaxSize, "SWITCH_VTAP_NUM")

	for i := range details.MustArray() {
		detail := resp.Get("DATA").Get("DETAILS").GetIndex(i)
		detail.Get("IP")
		fmt.Printf(cmdFormat,
			ipMaxSize, detail.Get("IP").MustString(),
			azMaxSize, detail.Get("AZ").MustString(),
			stateMaxSize, detail.Get("STATE").MustInt(),
			beforeVTapNumMaxSize, detail.Get("BEFORE_VTAP_NUM").MustInt(),
			afertVTapNumMaxSize, detail.Get("AFTER_VTAP_NUM").MustInt(),
			switchVTapNumMaxSize, detail.Get("SWITCH_VTAP_NUM").MustInt())
	}
}
