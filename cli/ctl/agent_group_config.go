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
	"os"

	"github.com/spf13/cobra"

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
		Use:     "create <agent-group ID> -f <filename>",
		Short:   "create config",
		Example: "deepflow-ctl agent-group-config create g-xxxxxx -f deepflow-config.yaml",
		Run: func(cmd *cobra.Command, args []string) {
			createAgentGroupConfig(cmd, args, createFilename)
		},
	}
	create.Flags().StringVarP(&createFilename, "filename", "f", "", "file to use create agent-group config")
	create.MarkFlagRequired("filename")

	var updateFilename string
	update := &cobra.Command{
		Use:     "update <agent-group ID> -f <filename>",
		Short:   "update agent-group config",
		Example: "deepflow-ctl agent-group-config update g-xxxxxx -f deepflow-config.yaml",
		Run: func(cmd *cobra.Command, args []string) {
			updateAgentGroupConfig(cmd, args, updateFilename)
		},
	}
	update.Flags().StringVarP(&updateFilename, "filename", "f", "", "file to use update agent-group config")
	update.MarkFlagRequired("filename")

	delete := &cobra.Command{
		Use:     "delete <agent-group ID>",
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
	url := fmt.Sprintf("http://%s:%d/v1/agent-group-configuration/template/yaml", server.IP, server.Port)
	response, err := common.CURLPerform("GET", url, nil, "",
		[]common.HTTPOption{common.WithTimeout(common.GetTimeout(cmd)), common.WithORGID(common.GetORGID(cmd))}...)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}
	fmt.Println(response.Get("DATA").MustString())
}

type vtapInfo struct {
	name      string
	shortUUID string
}

func getAgentGroupInfos(cmd *cobra.Command, server *common.Server) (map[string]vtapInfo, error) {
	url := fmt.Sprintf("http://%s:%d/v1/vtap-groups/", server.IP, server.Port)
	response, err := common.CURLPerform("GET", url, nil, "",
		[]common.HTTPOption{common.WithTimeout(common.GetTimeout(cmd)), common.WithORGID(common.GetORGID(cmd))}...)
	if err != nil {
		return nil, err
	}

	vtapLcuuidToInfo := map[string]vtapInfo{}
	for i := range response.Get("DATA").MustArray() {
		config := response.Get("DATA").GetIndex(i)
		vtapLcuuidToInfo[config.Get("LCUUID").MustString()] = vtapInfo{
			name:      config.Get("NAME").MustString(),
			shortUUID: config.Get("SHORT_UUID").MustString(),
		}
	}
	return vtapLcuuidToInfo, nil
}

func listAgentGroupConfig(cmd *cobra.Command, args []string, output string) {
	agentGroupShortUUID := ""
	if len(args) > 0 {
		agentGroupShortUUID = args[0]
	}

	server := common.GetServerInfo(cmd)
	url := fmt.Sprintf("http://%s:%d/v1/agent-group-configuration/", server.IP, server.Port)
	if output == "yaml" {
		if agentGroupShortUUID != "" {
			agentLcuuid, err := getAgentGroupLcuuid(cmd, server, agentGroupShortUUID)
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				return
			}
			url += fmt.Sprintf("%s/yaml", agentLcuuid)
		} else {
			url += "yaml"
		}

		response, err := common.CURLPerform("GET", url, nil, "",
			[]common.HTTPOption{common.WithTimeout(common.GetTimeout(cmd)), common.WithORGID(common.GetORGID(cmd))}...)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return
		}

		if agentGroupShortUUID != "" {
			fmt.Println(response.Get("DATA").MustString())
		} else {
			for i := range response.Get("DATA").MustArray() {
				config := response.Get("DATA").GetIndex(i)
				fmt.Println()
				fmt.Println("agent_group_lcuuid: ", config.Get("AGENT_GROUP_LCUUID").MustString())
				fmt.Println(config.Get("YAML").MustString())
			}
		}
	} else {
		vtapLcuuidToInfo, err := getAgentGroupInfos(cmd, server)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return
		}

		url += "yaml"
		response, err := common.CURLPerform("GET", url, nil, "",
			[]common.HTTPOption{common.WithTimeout(common.GetTimeout(cmd)), common.WithORGID(common.GetORGID(cmd))}...)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return
		}

		t := table.New()
		t.SetHeader([]string{"NAME", "AGENT_GROUP_ID"})
		tableItems := [][]string{}
		for i := range response.Get("DATA").MustArray() {
			agentGroupLcuuid := response.Get("DATA").GetIndex(i).Get("AGENT_GROUP_LCUUID")
			if info, ok := vtapLcuuidToInfo[agentGroupLcuuid.MustString()]; ok {
				if agentGroupShortUUID != "" && agentGroupShortUUID != info.shortUUID {
					continue
				}
				tableItems = append(tableItems, []string{
					info.name,
					info.shortUUID,
				})
			}
		}
		t.AppendBulk(tableItems)
		t.Render()
	}
}

func getAgentGroupLcuuid(cmd *cobra.Command, server *common.Server, shortUUID string) (string, error) {
	url := fmt.Sprintf("http://%s:%d/v1/vtap-groups/?short_uuid=%s", server.IP, server.Port, shortUUID)
	response, err := common.CURLPerform("GET", url, nil, "",
		[]common.HTTPOption{common.WithTimeout(common.GetTimeout(cmd)), common.WithORGID(common.GetORGID(cmd))}...)
	if err != nil {
		return "", err
	}

	if len(response.Get("DATA").MustArray()) == 0 {
		return "", fmt.Errorf("agent-group (%s) not exist\n", shortUUID)
	}
	return response.Get("DATA").GetIndex(0).Get("LCUUID").MustString(), nil
}

func createAgentGroupConfig(cmd *cobra.Command, args []string, createFilename string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "must specify agent-group ID.\nExample: %s", cmd.Example)
		return
	}
	server := common.GetServerInfo(cmd)

	agentGroupLcuuid, err := getAgentGroupLcuuid(cmd, server, args[0])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}
	url := fmt.Sprintf("http://%s:%d/v1/agent-group-configuration/%s/yaml", server.IP, server.Port, agentGroupLcuuid)

	yamlFile, err := os.ReadFile(createFilename)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
	}
	_, err = common.CURLPerform("POST", url, nil, string(yamlFile),
		[]common.HTTPOption{common.WithTimeout(common.GetTimeout(cmd)), common.WithORGID(common.GetORGID(cmd))}...)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}
}

func updateAgentGroupConfig(cmd *cobra.Command, args []string, updateFilename string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "must specify agent-group ID.\nExample: %s", cmd.Example)
		return
	}
	server := common.GetServerInfo(cmd)

	agentGroupLcuuid, err := getAgentGroupLcuuid(cmd, server, args[0])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}
	url := fmt.Sprintf("http://%s:%d/v1/agent-group-configuration/%s/yaml", server.IP, server.Port, agentGroupLcuuid)

	yamlFile, err := os.ReadFile(updateFilename)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}

	_, err = common.CURLPerform("PUT", url, nil, string(yamlFile),
		[]common.HTTPOption{common.WithTimeout(common.GetTimeout(cmd)), common.WithORGID(common.GetORGID(cmd))}...)
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

	agentGroupLcuuid, err := getAgentGroupLcuuid(cmd, server, args[0])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}
	url := fmt.Sprintf("http://%s:%d/v1/agent-group-configuration/%s", server.IP, server.Port, agentGroupLcuuid)

	_, err = common.CURLPerform("DELETE", url, nil, "",
		[]common.HTTPOption{common.WithTimeout(common.GetTimeout(cmd)), common.WithORGID(common.GetORGID(cmd))}...)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}
}
