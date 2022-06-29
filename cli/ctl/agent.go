package ctl

import (
	"fmt"

	"github.com/ghodss/yaml"
	"github.com/spf13/cobra"

	"cli/ctl/common"
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
		Example: "metaflow-ctl agent list deepflow-agent -o yaml",
		Run: func(cmd *cobra.Command, args []string) {
			listAgent(cmd, args, listOutput)
		},
	}
	list.Flags().StringVarP(&listOutput, "output", "o", "", "output format")
	agent.AddCommand(list)
	return agent
}

func listAgent(cmd *cobra.Command, args []string, output string) {
	name := ""
	if len(args) > 0 {
		name = args[0]
	}

	// TODO: 补充metaflow-ctl的配置文件
	// 生成URL
	url := "http://metaflow-server:20417/v1/vtaps/"
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
		cmdFormat := "%-48s%-32s%-24s%s\n"
		fmt.Printf(cmdFormat, "NAME", "CTRL_IP", "CTRL_MAC", "STATE")
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
			fmt.Printf(
				cmdFormat, vtap.Get("NAME").MustString(), vtap.Get("CTRL_IP").MustString(),
				vtap.Get("CTRL_MAC").MustString(), stateString,
			)
		}
	}
}
