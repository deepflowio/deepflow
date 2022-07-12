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
	"io/ioutil"
	"os"
	"strconv"
	"strings"

	"github.com/ghodss/yaml"
	"github.com/spf13/cobra"

	"github.com/metaflowys/metaflow/cli/ctl/common"
	"github.com/metaflowys/metaflow/cli/ctl/example"
)

func RegisterDomainCommand() *cobra.Command {
	Domain := &cobra.Command{
		Use:   "domain",
		Short: "domain operation commands",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("please run with 'list | create | delete'.\n")
		},
	}

	var listOutput string
	list := &cobra.Command{
		Use:     "list [name]",
		Short:   "list domain info",
		Example: "metaflow-ctl domain list deepflow-domain",
		Run: func(cmd *cobra.Command, args []string) {
			listDomain(cmd, args, listOutput)
		},
	}
	list.Flags().StringVarP(&listOutput, "output", "o", "", "output format")

	var createFilename string
	create := &cobra.Command{
		Use:     "create",
		Short:   "create domain",
		Example: "metaflow-ctl domain create deepflow-domain",
		Run: func(cmd *cobra.Command, args []string) {
			createDomain(cmd, args, createFilename)
		},
	}
	create.Flags().StringVarP(&createFilename, "filename", "f", "", "file to use create domain")
	create.MarkFlagRequired("filename")

	var updateFilename string
	update := &cobra.Command{
		Use:     "update",
		Short:   "update domain",
		Example: "metaflow-ctl domain update deepflow-domain",
		Run: func(cmd *cobra.Command, args []string) {
			updateDomain(cmd, args, updateFilename)
		},
	}
	update.Flags().StringVarP(&updateFilename, "filename", "f", "", "file to use update domain")
	update.MarkFlagRequired("filename")

	delete := &cobra.Command{
		Use:     "delete [name]",
		Short:   "delete domain",
		Example: "metaflow-ctl domain delete deepflow-domain",
		Run: func(cmd *cobra.Command, args []string) {
			deleteDomain(cmd, args)
		},
	}

	exampleCmd := &cobra.Command{
		Use:     "example domain_type",
		Short:   "example domain create yaml",
		Long:    fmt.Sprintf("supported types: %v", strings.Join([]string{common.KUBERNETES_EN, common.ALIYUN_EN, common.QINGCLOUD_EN, common.BAIDU_BCE_EN, common.GENESIS_EN}, ",")),
		Example: "metaflow-ctl domain example genesis",
		Run: func(cmd *cobra.Command, args []string) {
			exampleDomainConfig(cmd, args)
		},
	}

	Domain.AddCommand(list)
	Domain.AddCommand(create)
	Domain.AddCommand(update)
	Domain.AddCommand(delete)
	Domain.AddCommand(exampleCmd)
	return Domain
}

func listDomain(cmd *cobra.Command, args []string, output string) {
	name := ""
	if len(args) > 0 {
		name = args[0]
	}

	server := common.GetServerInfo(cmd)
	url := fmt.Sprintf("http://%s:%d/v2/domains/", server.IP, server.Port)
	if name != "" {
		url += fmt.Sprintf("?name=%s", name)
	}

	response, err := common.CURLPerform("GET", url, nil, "")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}

	if output == "yaml" {
		jData, _ := response.Get("DATA").MarshalJSON()
		yData, _ := yaml.JSONToYAML(jData)
		fmt.Printf(string(yData))
	} else {
		format := "%-46s %-14s %-6s %-14s %-10s %-40s %-22s %-22s %-8s %s\n"
		fmt.Printf(
			format, "NAME", "ID", "TYPE", "REGION_COUNT", "AZ_COUNT", "CONTROLLER_NAME", "CREATED_AT",
			"SYNCED_AT", "ENABLED", "STATE",
		)
		for i := range response.Get("DATA").MustArray() {
			d := response.Get("DATA").GetIndex(i)
			fmt.Printf(
				format, d.Get("NAME").MustString(), d.Get("CLUSTER_ID").MustString(), strconv.Itoa(d.Get("TYPE").MustInt()),
				strconv.Itoa(d.Get("REGION_COUNT").MustInt()), strconv.Itoa(d.Get("AZ_COUNT").MustInt()), d.Get("CONTROLLER_NAME").MustString(),
				d.Get("CREATED_AT").MustString(), d.Get("SYNCED_AT").MustString(), strconv.Itoa(d.Get("ENABLED").MustInt()),
				strconv.Itoa(d.Get("STATE").MustInt()),
			)
		}
	}
}

func createDomain(cmd *cobra.Command, args []string, createFilename string) {
	server := common.GetServerInfo(cmd)
	url := fmt.Sprintf("http://%s:%d/v1/domains/", server.IP, server.Port)
	yamlFile, err := ioutil.ReadFile(createFilename)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
	}
	var body map[string]interface{}
	yaml.Unmarshal(yamlFile, &body)
	resp, err := common.CURLPerform("POST", url, body, "")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}
	fmt.Println(resp)
}

func updateDomain(cmd *cobra.Command, args []string, updateFilename string) {
	if len(args) == 0 {
		fmt.Fprintf(os.Stderr, "must specify name. Example: %s", cmd.Example)
		return
	}

	server := common.GetServerInfo(cmd)
	url := fmt.Sprintf("http://%s:%d/v2/domains/?name=%s", server.IP, server.Port, args[0])
	// curl domain API，list lcuuid
	response, err := common.CURLPerform("GET", url, nil, "")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}

	if len(response.Get("DATA").MustArray()) > 0 {
		lcuuid := response.Get("DATA").GetIndex(0).Get("LCUUID").MustString()
		url := fmt.Sprintf("http://%s:%d/v1/domains/%s/", server.IP, server.Port, lcuuid)
		yamlFile, err := ioutil.ReadFile(updateFilename)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
		}
		var body map[string]interface{}
		yaml.Unmarshal(yamlFile, &body)
		resp, err := common.CURLPerform("PATCH", url, body, "")
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return
		}
		fmt.Println(resp)
	}
}

func deleteDomain(cmd *cobra.Command, args []string) {
	if len(args) == 0 {
		fmt.Fprintf(os.Stderr, "must specify name. Example: %s", cmd.Example)
		return
	}

	server := common.GetServerInfo(cmd)
	url := fmt.Sprintf("http://%s:%d/v2/domains/?name=%s", server.IP, server.Port, args[0])
	// curl domain API，list lcuuid
	response, err := common.CURLPerform("GET", url, nil, "")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}

	if len(response.Get("DATA").MustArray()) > 0 {
		lcuuid := response.Get("DATA").GetIndex(0).Get("LCUUID").MustString()
		url := fmt.Sprintf("http://%s:%d/v1/domains/%s/", server.IP, server.Port, lcuuid)
		// 调用domain API，删除对应的云平台
		resp, err := common.CURLPerform("DELETE", url, nil, "")
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return
		}
		fmt.Println(resp)
	}
}

func exampleDomainConfig(cmd *cobra.Command, args []string) {
	if len(args) == 0 {
		fmt.Fprintf(os.Stderr, "must specify domain_type. Use: %s", cmd.Use)
		return
	}

	switch args[0] {
	case common.KUBERNETES_EN:
		fmt.Printf(string(example.YamlDomainKubernetes))
	case common.ALIYUN_EN:
		fmt.Printf(string(example.YamlDomainAliYun))
	case common.QINGCLOUD_EN:
		fmt.Printf(string(example.YamlDomainQingCloud))
	case common.BAIDU_BCE_EN:
		fmt.Printf(string(example.YamlDomainBaiduBce))
	case common.GENESIS_EN:
		fmt.Printf(string(example.YamlDomainGenesis))
	default:
		err := fmt.Sprintf("domain_type %s not supported", args[0])
		fmt.Fprintln(os.Stderr, err)
	}
}
