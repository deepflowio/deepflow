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
	"fmt"
	"io/ioutil"
	"os"

	"github.com/spf13/cobra"
	"sigs.k8s.io/yaml"

	"github.com/deepflowio/deepflow/cli/ctl/common"
	"github.com/deepflowio/deepflow/cli/ctl/common/table"
)

func RegisterAgentGroupConfigCommand() *cobra.Command {
	agentGroupConfig := &cobra.Command{
		Use:   "agent-group-config",
		Short: "agent-group config operation commands",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("please run with 'example | list | create | update | delete'.\n")
		},
	}

	var listOutput string
	list := &cobra.Command{
		Use:     "list [agent-group ID]",
		Short:   "list config",
		Example: "deepflow-ctl agent-group-config list g-xxxxxx",
		Run: func(cmd *cobra.Command, args []string) {
			listAgentGroupConfig(cmd, args, listOutput)
		},
	}
	list.Flags().StringVarP(&listOutput, "output", "o", "", "output format")

	var createFilename string
	create := &cobra.Command{
		Use:     "create -f <filename>",
		Short:   "create config",
		Example: "deepflow-ctl agent-group-config create -f deepflow-config.yaml",
		Run: func(cmd *cobra.Command, args []string) {
			createAgentGroupConfig(cmd, args, createFilename)
		},
	}
	create.Flags().StringVarP(&createFilename, "filename", "f", "", "file to use create agent-group config")
	create.MarkFlagRequired("filename")

	var updateFilename string
	update := &cobra.Command{
		Use:     "update -f <filename>",
		Short:   "update agent-group config",
		Example: "deepflow-ctl agent-group-config update -f deepflow-config.yaml",
		Run: func(cmd *cobra.Command, args []string) {
			updateAgentGroupConfig(cmd, args, updateFilename)
		},
	}
	update.Flags().StringVarP(&updateFilename, "filename", "f", "", "file to use update agent-group config")
	update.MarkFlagRequired("filename")

	delete := &cobra.Command{
		Use:     "delete [agent-group ID]",
		Short:   "delete agent-group config",
		Example: "deepflow-ctl agent-group-config delete g-xxxxxx",
		Run: func(cmd *cobra.Command, args []string) {
			deleteAgentGroupConfig(cmd, args)
		},
	}

	example := &cobra.Command{
		Use:   "example",
		Short: "example agent-group config",
		Run: func(cmd *cobra.Command, args []string) {
			exampleAgentGroupConfig(cmd, args)
		},
	}
	agentGroupConfig.AddCommand(example)
	agentGroupConfig.AddCommand(list)
	agentGroupConfig.AddCommand(create)
	agentGroupConfig.AddCommand(update)
	agentGroupConfig.AddCommand(delete)
	return agentGroupConfig
}

func exampleAgentGroupConfig(cmd *cobra.Command, args []string) {
	server := common.GetServerInfo(cmd)
	url := fmt.Sprintf("http://%s:%d/v1/vtap-group-configuration/example/", server.IP, server.Port)
	response, err := common.CURLPerform("GET", url, nil, "", []common.HTTPOption{common.WithTimeout(common.GetTimeout(cmd))}...)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}
	fmt.Println(response.Get("DATA").MustString())
}

func listAgentGroupConfig(cmd *cobra.Command, args []string, output string) {
	agentGroupShortUUID := ""
	if len(args) > 0 {
		agentGroupShortUUID = args[0]
	}

	server := common.GetServerInfo(cmd)
	url := fmt.Sprintf("http://%s:%d/v1/vtap-group-configuration/", server.IP, server.Port)
	if output == "yaml" {
		if agentGroupShortUUID != "" {
			url += fmt.Sprintf("filter/?vtap_group_id=%s", agentGroupShortUUID)
		} else {
			url += "advanced/"
		}

		response, err := common.CURLPerform("GET", url, nil, "", []common.HTTPOption{common.WithTimeout(common.GetTimeout(cmd))}...)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return
		}

		if agentGroupShortUUID != "" {
			fmt.Println(response.Get("DATA").MustString())
		} else {
			for i := range response.Get("DATA").MustArray() {
				fmt.Println(response.Get("DATA").GetIndex(i).MustString())
			}
		}
	} else {
		response, err := common.CURLPerform("GET", url, nil, "", []common.HTTPOption{common.WithTimeout(common.GetTimeout(cmd))}...)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return
		}

		t := table.New()
		t.SetHeader([]string{"NAME", "AGENT_GROUP_ID"})
		tableItems := [][]string{}
		for i := range response.Get("DATA").MustArray() {
			config := response.Get("DATA").GetIndex(i)
			if agentGroupShortUUID != "" && config.Get("VTAP_GROUP_ID").MustString() != agentGroupShortUUID {
				continue
			}
			tableItems = append(tableItems, []string{
				config.Get("VTAP_GROUP_NAME").MustString(),
				config.Get("VTAP_GROUP_ID").MustString(),
			})
		}
		t.AppendBulk(tableItems)
		t.Render()
	}
}

func createAgentGroupConfig(cmd *cobra.Command, args []string, createFilename string) {
	server := common.GetServerInfo(cmd)
	url := fmt.Sprintf("http://%s:%d/v1/vtap-group-configuration/advanced/", server.IP, server.Port)
	yamlFile, err := ioutil.ReadFile(createFilename)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
	}
	_, err = common.CURLPerform("POST", url, nil, string(yamlFile), []common.HTTPOption{common.WithTimeout(common.GetTimeout(cmd))}...)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}
}

func updateAgentGroupConfig(cmd *cobra.Command, args []string, updateFilename string) {
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

	vtapGroupID, ok := updateMap["vtap_group_id"]
	if !ok {
		fmt.Fprintln(os.Stderr, "must specify vtap_group_id")
		return
	}

	server := common.GetServerInfo(cmd)
	url := fmt.Sprintf("http://%s:%d/v1/vtap-group-configuration/?vtap_group_id=%s", server.IP, server.Port, vtapGroupID)
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
	lcuuid := group.Get("LCUUID").MustString()

	// call vtap-group config update api
	url = fmt.Sprintf("http://%s:%d/v1/vtap-group-configuration/advanced/%s/", server.IP, server.Port, lcuuid)
	_, err = common.CURLPerform("PATCH", url, nil, string(yamlFile), []common.HTTPOption{common.WithTimeout(common.GetTimeout(cmd))}...)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}
}

func deleteAgentGroupConfig(cmd *cobra.Command, args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "must specify agent-group ID.\nExample: %s", cmd.Example)
		return
	}

	server := common.GetServerInfo(cmd)
	url := fmt.Sprintf(
		"http://%s:%d/v1/vtap-group-configuration/filter/?vtap_group_id=%s",
		server.IP, server.Port, args[0],
	)
	_, err := common.CURLPerform("DELETE", url, nil, "", []common.HTTPOption{common.WithTimeout(common.GetTimeout(cmd))}...)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}
}
