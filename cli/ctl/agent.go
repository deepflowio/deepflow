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
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/bitly/go-simplejson"
	agentpb "github.com/deepflowio/deepflow/message/trident"
	"github.com/spf13/cobra"
	"sigs.k8s.io/yaml"

	"github.com/deepflowio/deepflow/cli/ctl/common"
	"github.com/deepflowio/deepflow/cli/ctl/common/jsonparser"
	"github.com/deepflowio/deepflow/cli/ctl/common/printutil"
	"github.com/deepflowio/deepflow/cli/ctl/common/table"
	"github.com/deepflowio/deepflow/cli/ctl/example"
)

type RebalanceType string

const RebalanceTypeNull RebalanceType = "null"

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

	var updateFilename string
	update := &cobra.Command{
		Use:     "update -f <filename>",
		Short:   "update agent",
		Example: "deepflow-ctl agent update -f agent.yaml",
		Run: func(cmd *cobra.Command, args []string) {
			updateAgent(cmd, args, updateFilename)
		},
	}
	update.Flags().StringVarP(&updateFilename, "filename", "f", "", "file to use update agent")
	update.MarkFlagRequired("filename")

	updateExample := &cobra.Command{
		Use:     "update-example",
		Short:   "example agent update yaml",
		Example: "deepflow-ctl agent update-example",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf(string(example.YamlVtapUpdateConfig))
		},
	}

	var typeStr string
	rebalanceCmd := &cobra.Command{
		Use:   "rebalance",
		Short: "rebalance controller or analyzer",
		Example: `deepflow-ctl agent rebalance (rebalance controller and analyzer)
deepflow-ctl agent rebalance --type=controller
deepflow-ctl agent rebalance --type=analyzer`,
		Run: func(cmd *cobra.Command, args []string) {
			if typeStr != "" {
				if err := rebalance(cmd, RebalanceType(typeStr), typeStr); err != nil {
					fmt.Println(err)
				}
				return
			}

			if err := rebalance(cmd, RebalanceTypeNull, "controller"); err != nil {
				fmt.Println(err)
			}
			if err := rebalance(cmd, RebalanceTypeNull, "analyzer"); err != nil {
				fmt.Println(err)
			}
		},
	}
	rebalanceCmd.Flags().StringVarP(&typeStr, "type", "t", "", "request type controller/analyzer")

	agent.AddCommand(list)
	agent.AddCommand(delete)
	agent.AddCommand(update)
	agent.AddCommand(updateExample)
	agent.AddCommand(rebalanceCmd)
	return agent
}

func RegisterAgentUpgradeCommand() *cobra.Command {
	agentUpgrade := &cobra.Command{
		Use:   "agent-upgrade",
		Short: "agent upgrade operation commands",
		Example: "deepflow-ctl agent-upgrade list\n" +
			"deepflow-ctl agent-upgrade vtap-name --image-name=deepflow-agent\n",
		Run: func(cmd *cobra.Command, args []string) {
			if len(args) == 1 {
				if args[0] == "list" {
					listAgentUpgrade(cmd, args)
				} else if imageName != "" {
					if filepath.IsAbs(imageName) {
						printutil.ErrorfWithColor(
							"invalid image name(%s), please use command `deepflow-ctl repo agent list` to get image name\n"+
								"reference doc: https://deepflow.io/docs/zh/install/upgrade/",
							imageName,
						)
						return
					}
					upgadeAgent(cmd, args)
				} else {
					fmt.Println(cmd.Example)
				}

			} else {
				fmt.Println(cmd.Example)
			}
		},
	}
	agentUpgrade.Flags().StringVarP(&imageName, "image-name", "I", "", "")

	return agentUpgrade
}

func listAgentUpgrade(cmd *cobra.Command, args []string) {
	// 生成URL
	server := common.GetServerInfo(cmd)
	url := fmt.Sprintf("http://%s:%d/v1/vtaps/", server.IP, server.Port)

	// 调用采集器API，并输出返回结果
	response, err := common.CURLPerform("GET", url, nil, "", []common.HTTPOption{common.WithTimeout(common.GetTimeout(cmd))}...)
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
	response, err := common.CURLPerform("GET", url, nil, "", []common.HTTPOption{common.WithTimeout(common.GetTimeout(cmd))}...)
	if err != nil {
		fmt.Println(err)
		return
	}

	if output == "yaml" {
		dataJson, _ := response.Get("DATA").MarshalJSON()
		dataYaml, _ := yaml.JSONToYAML(dataJson)
		fmt.Printf(string(dataYaml))
	} else {
		t := table.New()
		t.SetHeader([]string{"ID", "NAME", "TYPE", "CTRL_IP", "CTRL_MAC", "STATE", "GROUP", "EXCEPTIONS", "REVISION", "UPGRADE_REVISION"})

		tableItems := [][]string{}
		for i := range response.Get("DATA").MustArray() {
			vtap := response.Get("DATA").GetIndex(i)

			exceptionStrings := []string{}
			for i := range vtap.Get("EXCEPTIONS").MustArray() {
				exceptionInt := vtap.Get("EXCEPTIONS").GetIndex(i).MustInt()
				exceptionStr, ok := agentpb.Exception_name[int32(exceptionInt)]
				if ok {
					exceptionStrings = append(exceptionStrings, exceptionStr)
				} else {
					exceptionStrings = append(exceptionStrings, string(common.VtapException(exceptionInt)))
				}
			}

			tableItems = append(tableItems, []string{
				strconv.Itoa(vtap.Get("ID").MustInt()),
				vtap.Get("NAME").MustString(),
				fmt.Sprintf("%v", common.VtapType(vtap.Get("TYPE").MustInt())),
				vtap.Get("CTRL_IP").MustString(),
				vtap.Get("CTRL_MAC").MustString(),
				fmt.Sprintf("%v", common.VtapState(vtap.Get("STATE").MustInt())),
				vtap.Get("VTAP_GROUP_NAME").MustString(),
				strings.Join(exceptionStrings, ","),
				vtap.Get("REVISION").MustString(),
				vtap.Get("UPGRADE_REVISION").MustString(),
			})
		}
		t.AppendBulk(tableItems)
		t.Render()
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
	response, err := common.CURLPerform("GET", url, nil, "", []common.HTTPOption{common.WithTimeout(common.GetTimeout(cmd))}...)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}

	if len(response.Get("DATA").MustArray()) > 0 {
		lcuuid := response.Get("DATA").GetIndex(0).Get("LCUUID").MustString()
		url := fmt.Sprintf("http://%s:%d/v1/vtaps/%s/", server.IP, server.Port, lcuuid)
		// call vtap delete api
		_, err := common.CURLPerform("DELETE", url, nil, "", []common.HTTPOption{common.WithTimeout(common.GetTimeout(cmd))}...)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return
		}
	}
}

func updateAgent(cmd *cobra.Command, args []string, updateFilename string) {
	yamlFile, err := ioutil.ReadFile(updateFilename)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}

	updateMap := make(map[string]interface{})
	err = yaml.Unmarshal(yamlFile, &updateMap)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}

	vtapName, ok := updateMap["name"]
	if !ok {
		fmt.Fprintln(os.Stderr, "must specify vtap name")
		return
	}

	server := common.GetServerInfo(cmd)
	url := fmt.Sprintf("http://%s:%d/v1/vtaps/?name=%s", server.IP, server.Port, vtapName)
	// call vtap api, get lcuuid
	response, err := common.CURLPerform("GET", url, nil, "", []common.HTTPOption{common.WithTimeout(common.GetTimeout(cmd))}...)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}

	if len(response.Get("DATA").MustArray()) == 0 {
		fmt.Fprintln(os.Stderr, "agent (%s) not exist\n")
	}
	vtap := response.Get("DATA").GetIndex(0)
	lcuuid := vtap.Get("LCUUID").MustString()

	// modify tap_mode
	if tapMode, ok := updateMap["tap_mode"]; ok {
		url = fmt.Sprintf("http://%s:%d/v1/vtaps-tap-mode/", server.IP, server.Port)
		updateBody := make(map[string]interface{})
		updateBody["VTAP_LCUUIDS"] = []string{lcuuid}
		updateBody["TAP_MODE"] = common.GetVtapTapModeByName(tapMode.(string))

		updateJson, _ := json.Marshal(updateBody)
		_, err := common.CURLPerform("PATCH", url, nil, string(updateJson), []common.HTTPOption{common.WithTimeout(common.GetTimeout(cmd))}...)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return
		}
		delete(updateMap, "tap_mode")
	}

	// return if only update tap_mode
	if len(updateMap) == 0 {
		return
	}

	// update vtap_group_id
	if vtapGroupID, ok := updateMap["vtap_group_id"]; ok {
		url := fmt.Sprintf("http://%s:%d/v1/vtap-groups/?short_uuid=%s", server.IP, server.Port, vtapGroupID)
		// call vtap-group api, get lcuuid
		response, err := common.CURLPerform("GET", url, nil, "", []common.HTTPOption{common.WithTimeout(common.GetTimeout(cmd))}...)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return
		}

		if len(response.Get("DATA").MustArray()) == 0 {
			fmt.Fprintln(os.Stderr, "agent-group (%s) not exist\n")
		}
		group := response.Get("DATA").GetIndex(0)
		groupLcuuid := group.Get("LCUUID").MustString()
		updateMap["VTAP_GROUP_LCUUID"] = groupLcuuid
		delete(updateMap, "vtap_group_id")
	}

	// enable/disable
	if enable, ok := updateMap["enable"]; ok {
		updateMap["ENABLE"] = enable
		delete(updateMap, "enable")
	}

	// call vtap update api
	updateJson, _ := json.Marshal(updateMap)
	url = fmt.Sprintf("http://%s:%d/v1/vtaps/%s/", server.IP, server.Port, lcuuid)
	_, err = common.CURLPerform("PATCH", url, nil, string(updateJson), []common.HTTPOption{common.WithTimeout(common.GetTimeout(cmd))}...)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
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

var imageName string

func upgadeAgent(cmd *cobra.Command, args []string) {
	if len(args) == 0 {
		fmt.Fprintf(os.Stderr, "must specify name and package. Examples: \n%s", cmd.Example)
		return
	}
	vtapName := args[0]

	server := common.GetServerInfo(cmd)
	serverURL := fmt.Sprintf("http://%s:%d/v1/controllers/", server.IP, server.Port)
	response, err := common.CURLPerform("GET", serverURL, nil, "", []common.HTTPOption{common.WithTimeout(common.GetTimeout(cmd))}...)
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
	response, err = common.CURLPerform("GET", vtapURL, nil, "", []common.HTTPOption{common.WithTimeout(common.GetTimeout(cmd))}...)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}

	var (
		vtapController string
		vtapLcuuid     string
		vtapType       int
	)

	if len(response.Get("DATA").MustArray()) > 0 {
		vtapLcuuid = response.Get("DATA").GetIndex(0).Get("LCUUID").MustString()
		vtapController = response.Get("DATA").GetIndex(0).Get("CONTROLLER_IP").MustString()
		vtapType = response.Get("DATA").GetIndex(0).Get("TYPE").MustInt()
	} else {
		fmt.Printf("get agent(%s) info failed, url: %s\n", vtapName, vtapURL)
		return
	}
	if vtapType == int(common.VTAP_TYPE_POD_VM) || vtapType == int(common.VTAP_TYPE_POD_HOST) || vtapType == int(common.VTAP_TYPE_K8S_SIDECAR) {
		fmt.Printf("agent (%s) type is %v, not supported upgrade by cli\n", vtapName, common.VtapType(vtapType))
		return
	}
	if vtapController == "" || vtapLcuuid == "" {
		fmt.Printf("get agent(%s) info failed, url: %s\n", vtapName, vtapURL)
		return
	}

	hosts[vtapController] = struct{}{}
	url_format := "http://%s:%d/v1/upgrade/vtap/%s/"
	body := map[string]interface{}{
		"image_name": imageName,
	}
	for host, _ := range hosts {
		url := fmt.Sprintf(url_format, host, server.Port, vtapLcuuid)
		response, err := common.CURLPerform("PATCH", url, body, "", []common.HTTPOption{common.WithTimeout(common.GetTimeout(cmd))}...)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			fmt.Printf("upgrade agent %s server %s failed, response: %s\n", vtapName, host, response)
			continue
		} else {
			fmt.Printf("set agent %s upgrate image(%s) to server(%s) success\n", vtapName, imageName, host)
		}
	}
}

func rebalance(cmd *cobra.Command, rebalanceType RebalanceType, typeVal string) error {
	isBalance, err := ifNeedRebalance(cmd, typeVal)
	if err != nil {
		return err
	}
	if !isBalance {
		if rebalanceType == RebalanceTypeNull {
			fmt.Printf("%s: no balance required\n", typeVal)
			return nil
		}
		fmt.Println("no balance required")
		return nil
	}
	resp, err := execRebalance(cmd, typeVal)
	if err != nil {
		return err
	}
	if rebalanceType == RebalanceTypeNull {
		fmt.Printf("------------------------ %s ------------------------\n", typeVal)
	}
	printDetail(resp)
	return nil
}

func ifNeedRebalance(cmd *cobra.Command, typeStr string) (bool, error) {
	server := common.GetServerInfo(cmd)
	url := fmt.Sprintf("http://%s:%d/v1/rebalance-vtap/?check=false&type=%s", server.IP, server.Port, typeStr)
	resp, err := common.CURLPerform("POST", url, nil, "", []common.HTTPOption{common.WithTimeout(common.GetTimeout(cmd))}...)
	if err != nil {
		return false, err
	}
	if resp.Get("DATA").Get("TOTAL_SWITCH_VTAP_NUM").MustInt() == 0 {
		return false, nil
	}
	return true, nil
}

func execRebalance(cmd *cobra.Command, typeStr string) (*simplejson.Json, error) {
	server := common.GetServerInfo(cmd)
	url := fmt.Sprintf("http://%s:%d/v1/rebalance-vtap/?check=true&type=%s", server.IP, server.Port, typeStr)
	resp, err := common.CURLPerform("POST", url, nil, "", []common.HTTPOption{common.WithTimeout(common.GetTimeout(cmd))}...)
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
