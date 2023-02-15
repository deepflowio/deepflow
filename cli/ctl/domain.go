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
	"bufio"
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"github.com/ghodss/yaml"
	"github.com/spf13/cobra"

	"github.com/deepflowio/deepflow/cli/ctl/common"
	"github.com/deepflowio/deepflow/cli/ctl/example"
)

func RegisterDomainCommand() *cobra.Command {
	Domain := &cobra.Command{
		Use:   "domain",
		Short: "domain operation commands",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("please run with 'list | create | update | delete | example | additional-resource'.\n")
		},
	}

	var listOutput string
	list := &cobra.Command{
		Use:     "list [name]",
		Short:   "list domain info",
		Example: "deepflow-ctl domain list deepflow-domain",
		Run: func(cmd *cobra.Command, args []string) {
			listDomain(cmd, args, listOutput)
		},
	}
	list.Flags().StringVarP(&listOutput, "output", "o", "", "output format")

	var createFilename string
	create := &cobra.Command{
		Use:     "create",
		Short:   "create domain",
		Example: "deepflow-ctl domain create -f -",
		Run: func(cmd *cobra.Command, args []string) {
			createDomain(cmd, args, createFilename)
		},
	}
	create.Flags().StringVarP(&createFilename, "filename", "f", "", "create domain from file or stdin")
	create.MarkFlagRequired("filename")

	var updateFilename string
	update := &cobra.Command{
		Use:     "update",
		Short:   "update domain",
		Example: "deepflow-ctl domain update deepflow-domain -f k8s.yaml",
		Run: func(cmd *cobra.Command, args []string) {
			updateDomain(cmd, args, updateFilename)
		},
	}
	update.Flags().StringVarP(&updateFilename, "filename", "f", "", "update domain from file or stdin")
	update.MarkFlagRequired("filename")

	delete := &cobra.Command{
		Use:     "delete [name]",
		Short:   "delete domain",
		Example: "deepflow-ctl domain delete deepflow-domain",
		Run: func(cmd *cobra.Command, args []string) {
			deleteDomain(cmd, args)
		},
	}

	exampleCmd := &cobra.Command{
		Use:     "example domain_type",
		Short:   "example domain create yaml",
		Long:    "supported types: " + strings.Trim(fmt.Sprint(common.DomainTypes), "[]"),
		Example: "deepflow-ctl domain example agent_sync \nsupport example type: aliyun | aws | baidu_bce | filereader | agent_sync | \nhuawei | kubernetes | qingcloud | tencent ",
		Run: func(cmd *cobra.Command, args []string) {
			exampleDomainConfig(cmd, args)
		},
	}

	Domain.AddCommand(list)
	Domain.AddCommand(create)
	Domain.AddCommand(update)
	Domain.AddCommand(delete)
	Domain.AddCommand(exampleCmd)
	Domain.AddCommand(RegisterDomainAdditionalResourceCommand())
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
		nameMaxSize := len("NAME")

		for i := range response.Get("DATA").MustArray() {
			d := response.Get("DATA").GetIndex(i)
			nameSize := len(d.Get("NAME").MustString())
			if nameSize > nameMaxSize {
				nameMaxSize = nameSize
			}
		}
		format := "%-*s %-14s %-37s %-17s %-15s %-22s %-22s %-8s %-10s %s\n"
		header := fmt.Sprintf(
			format, nameMaxSize, "NAME", "ID", "LCUUID", "TYPE", "CONTROLLER_IP",
			"CREATED_AT", "SYNCED_AT", "ENABLED", "STATE", "AGENT_WATCH_K8S", // TODO translate state to readable word
		)
		fmt.Fprint(os.Stderr, header)
		for i := range response.Get("DATA").MustArray() {
			d := response.Get("DATA").GetIndex(i)
			name := d.Get("NAME").MustString()
			var nameChineseCount int
			for _, b := range name {
				if common.IsChineseChar(string(b)) {
					nameChineseCount += 1
				}
			}
			fmt.Printf(
				format, nameMaxSize-nameChineseCount, name, d.Get("CLUSTER_ID").MustString(), d.Get("LCUUID").MustString(),
				common.DomainType(d.Get("TYPE").MustInt()), d.Get("CONTROLLER_IP").MustString(),
				d.Get("CREATED_AT").MustString(), d.Get("SYNCED_AT").MustString(),
				common.DomainEnabled(d.Get("ENABLED").MustInt()), common.DomainState(d.Get("STATE").MustInt()),
				d.Get("VTAP_NAME").MustString(),
			)
		}
	}
}

func createDomain(cmd *cobra.Command, args []string, filename string) {
	server := common.GetServerInfo(cmd)
	url := fmt.Sprintf("http://%s:%d/v1/domains/", server.IP, server.Port)

	body, err := formatBody(filename)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}
	if !validateBody(body) {
		return
	}

	if domainTypeStr, ok := body["TYPE"]; ok {
		domainType := common.GetDomainTypeByName(domainTypeStr.(string))
		if domainType == common.DOMAIN_TYPE_UNKNOWN {
			fmt.Fprintln(os.Stderr, fmt.Sprintf("domain type (%s) not supported, use example to see supported types", domainTypeStr))
			return
		}
		body["TYPE"] = int(domainType)
	} else {
		fmt.Fprintln(os.Stderr, "domain type must specify")
		return
	}

	resp, err := common.CURLPerform("POST", url, body, "")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}
	fmt.Println(resp)
}

func updateDomain(cmd *cobra.Command, args []string, filename string) {
	if len(args) == 0 {
		fmt.Fprintf(os.Stderr, "must specify name.\nExample: %s\n", cmd.Example)
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
		domainTypeInt := response.Get("DATA").GetIndex(9).Get("TYPE").MustInt()
		url := fmt.Sprintf("http://%s:%d/v1/domains/%s/", server.IP, server.Port, lcuuid)

		body, err := formatBody(filename)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return
		}
		if !validateBody(body) {
			return
		}

		body["TYPE"] = domainTypeInt
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
		fmt.Fprintf(os.Stderr, "must specify name.\nExample: %s", cmd.Example)
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
		fmt.Fprintf(os.Stderr, "must specify domain_type.\nExample: %s\n%s\n", cmd.Example, cmd.Long)
		return
	}

	switch common.GetDomainTypeByName(args[0]) {
	case common.DOMAIN_TYPE_KUBERNETES:
		fmt.Printf(string(example.YamlDomainKubernetes))
	case common.DOMAIN_TYPE_ALIYUN:
		fmt.Printf(string(example.YamlDomainAliYun))
	case common.DOMAIN_TYPE_AWS:
		fmt.Printf(string(example.YamlDomainAws))
	case common.DOMAIN_TYPE_TENCENT:
		fmt.Printf(string(example.YamlDomainTencent))
	case common.DOMAIN_TYPE_HUAWEI:
		fmt.Printf(string(example.YamlDomainHuawei))
	case common.DOMAIN_TYPE_QINGCLOUD:
		fmt.Printf(string(example.YamlDomainQingCloud))
	case common.DOMAIN_TYPE_BAIDU_BCE:
		fmt.Printf(string(example.YamlDomainBaiduBce))
	case common.DOMAIN_TYPE_AGENT_SYNC:
		fmt.Printf(string(example.YamlDomainGenesis))
	case common.DOMAIN_TYPE_FILEREADER:
		fmt.Printf(string(example.YamlDomainFileReader))
	default:
		err := fmt.Sprintf("domain_type %s not supported\n", args[0])
		fmt.Fprintln(os.Stderr, err)
	}
}

func formatBody(filename string) (map[string]interface{}, error) {
	upperBody := make(map[string]interface{})
	var body map[string]interface{}
	var err error

	if filename == "-" {
		scanner := bufio.NewScanner(os.Stdin)
		var strContent string
		for scanner.Scan() {
			strContent += scanner.Text() + "\n"
		}
		err = yaml.Unmarshal([]byte(strContent), &body)
		if err != nil {
			return upperBody, err
		}
	} else {
		yamlFile, err := ioutil.ReadFile(filename)
		if err != nil {
			return upperBody, err
		}
		err = yaml.Unmarshal(yamlFile, &body)
		if err != nil {
			return upperBody, err
		}
	}

	for k, v := range body {
		upperK := strings.ToUpper(k)
		upperBody[upperK] = v
	}
	return upperBody, nil
}

func validateBody(body map[string]interface{}) bool {
	n, ok := body["NAME"]
	if ok {
		switch n.(type) {
		case string:
		default:
			fmt.Println("invalid type (NAME), please specify as string")
			return false
		}
	}
	t, ok := body["TYPE"]
	if ok {
		switch t.(type) {
		case string:
		default:
			fmt.Println("invalid type (TYPE), please specify as string")
			return false
		}
	}
	return true
}
