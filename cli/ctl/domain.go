package ctl

import (
	"fmt"
	"io/ioutil"
	"os"
	"strconv"

	"github.com/ghodss/yaml"
	"github.com/spf13/cobra"

	"cli/ctl/common"
	"cli/ctl/example"
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
		Use:     "create [name]",
		Short:   "create domain",
		Example: "metaflow-ctl domain create deepflow-domain",
		Run: func(cmd *cobra.Command, args []string) {
			createDomain(cmd, args, createFilename)
		},
	}
	list.Flags().StringVarP(&createFilename, "filename", "f", "", "file to use create domain")
	list.MarkFlagRequired("filename")

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
		Example: "metaflow-ctl domain example genesis",
		Run: func(cmd *cobra.Command, args []string) {
			exampleDomainConfig(cmd, args)
		},
	}

	Domain.AddCommand(list)
	Domain.AddCommand(create)
	Domain.AddCommand(delete)
	Domain.AddCommand(exampleCmd)
	return Domain
}

func listDomain(cmd *cobra.Command, args []string, output string) {
	name := ""
	if len(args) > 0 {
		name = args[0]
	}

	// TODO 读取配置文件
	url := "http://metaflow-server:20417/v1/domains/"
	if name != "" {
		url += fmt.Sprintf("?name=%s", name)
	}

	// 调用domain API，并输出返回结果
	response, err := common.CURLPerform("GET", url, nil)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}

	if output == "yaml" {
		jData, _ := response.Get("DATA").MarshalJSON()
		yData, _ := yaml.JSONToYAML(jData)
		fmt.Printf(string(yData))
	} else {
		format := "%-46s %-14s %-6s %-14s %-10s %-20s %-22s %-22s %-8s %s\n"
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
	if len(args) == 0 {
		fmt.Fprintf(os.Stderr, "must specify name. Use: %s", cmd.Use)
		return
	}

	// TODO 读取配置文件
	url := "http://metaflow-server:20417/v1/domains/"

	// 调用domain API，并输出返回结果
	yamlFile, err := ioutil.ReadFile(createFilename)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
	}
	var body map[string]interface{}
	yaml.Unmarshal(yamlFile, body)
	resp, err := common.CURLPerform("POST", url, body)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}
	fmt.Printf("%s", resp)
}

func deleteDomain(cmd *cobra.Command, args []string) {
	if len(args) == 0 {
		fmt.Fprintf(os.Stderr, "must specify name. Example: %s", cmd.Example)
		return
	}

	// TODO 读取配置文件
	url := fmt.Sprintf("http://metaflow-server:20417/v1/domains/?name=%s", args[0])
	// 调用domain API，获取lcuuid
	response, err := common.CURLPerform("GET", url, nil)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}

	if len(response.Get("DATA").MustArray()) > 0 {
		lcuuid := response.Get("DATA").GetIndex(0).Get("LCUUID").MustString()
		// TODO 读取配置文件
		url := fmt.Sprintf("http://metaflow-server:20417/v1/domains/%s/", lcuuid)
		// 调用domain API，删除对应的采集器
		_, err := common.CURLPerform("DELETE", url, nil)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return
		}
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
