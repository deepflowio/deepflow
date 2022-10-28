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
	"strconv"
	"strings"

	"github.com/ghodss/yaml"
	"github.com/spf13/cobra"

	"github.com/deepflowys/deepflow/cli/ctl/common"
	"github.com/deepflowys/deepflow/cli/ctl/example"
)

var domainTypeIntToStr = map[int]string{
	common.TENCENT:    common.TENCENT_EN,
	common.AWS:        common.AWS_EN,
	common.ALIYUN:     common.ALIYUN_EN,
	common.KUBERNETES: common.KUBERNETES_EN,
	common.HUAWEI:     common.HUAWEI_EN,
	common.QINGCLOUD:  common.QINGCLOUD_EN,
	common.AGENT_SYNC: common.AGENT_SYNC_EN,
	common.BAIDU_BCE:  common.BAIDU_BCE_EN,
}

var domainTypeStrToInt = map[string]int{
	common.TENCENT_EN:    common.TENCENT,
	common.AWS_EN:        common.AWS,
	common.ALIYUN_EN:     common.ALIYUN,
	common.KUBERNETES_EN: common.KUBERNETES,
	common.HUAWEI_EN:     common.HUAWEI,
	common.QINGCLOUD_EN:  common.QINGCLOUD,
	common.AGENT_SYNC_EN: common.AGENT_SYNC,
	common.BAIDU_BCE_EN:  common.BAIDU_BCE,
}

func RegisterDomainCommand() *cobra.Command {
	Domain := &cobra.Command{
		Use:   "domain",
		Short: "domain operation commands",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("please run with 'list | create | update | delete | example'.\n")
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
		Long:    fmt.Sprintf("supported types: %v", strings.Join([]string{common.KUBERNETES_EN, common.AWS_EN, common.ALIYUN_EN, common.TENCENT_EN, common.QINGCLOUD_EN, common.BAIDU_BCE_EN, common.AGENT_SYNC_EN}, ",")),
		Example: "deepflow-ctl domain example agent_sync",
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
		format := "%-46s %-14s %-14s %-40s %-22s %-22s %-8s %s\n"
		fmt.Printf(
			format, "NAME", "ID", "TYPE", "CONTROLLER_NAME", "CREATED_AT", "SYNCED_AT", "ENABLED", "STATE",
		)
		for i := range response.Get("DATA").MustArray() {
			d := response.Get("DATA").GetIndex(i)
			domainTypeStr, _ := domainTypeIntToStr[d.Get("TYPE").MustInt()]
			fmt.Printf(
				format, d.Get("NAME").MustString(), d.Get("CLUSTER_ID").MustString(), domainTypeStr,
				d.Get("CONTROLLER_NAME").MustString(), d.Get("CREATED_AT").MustString(), d.Get("SYNCED_AT").MustString(),
				strconv.Itoa(d.Get("ENABLED").MustInt()), strconv.Itoa(d.Get("STATE").MustInt()),
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
		domainTypeInt, ok := domainTypeStrToInt[domainTypeStr.(string)]
		if !ok {
			fmt.Fprintln(os.Stderr, fmt.Sprintf("domain type (%s) not supported, use example to see supported types", domainTypeStr))
			return
		}
		body["TYPE"] = domainTypeInt
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

	switch args[0] {
	case common.KUBERNETES_EN:
		fmt.Printf(string(example.YamlDomainKubernetes))
	case common.ALIYUN_EN:
		fmt.Printf(string(example.YamlDomainAliYun))
	case common.AWS_EN:
		fmt.Printf(string(example.YamlDomainAws))
	case common.TENCENT_EN:
		fmt.Printf(string(example.YamlDomainTencent))
	case common.HUAWEI_EN:
		fmt.Printf(string(example.YamlDomainHuawei))
	case common.QINGCLOUD_EN:
		fmt.Printf(string(example.YamlDomainQingCloud))
	case common.BAIDU_BCE_EN:
		fmt.Printf(string(example.YamlDomainBaiduBce))
	case common.AGENT_SYNC_EN:
		fmt.Printf(string(example.YamlDomainGenesis))
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
