package ctl

import (
	"fmt"
	"os"

	"github.com/ghodss/yaml"
	"github.com/spf13/cobra"

	"github.com/metaflowys/metaflow/cli/ctl/common"
)

func RegisterAgentGroupCommand() *cobra.Command {
	agentGroup := &cobra.Command{
		Use:   "agent-group",
		Short: "agent-group operation commands",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("please run with 'list | create | delete'.\n")
		},
	}

	var listOutput string
	list := &cobra.Command{
		Use:     "list [name]",
		Short:   "list agent-group info",
		Example: "metaflow-ctl agent-group list deepflow-agent-group",
		Run: func(cmd *cobra.Command, args []string) {
			listAgentGroup(cmd, args, listOutput)
		},
	}
	list.Flags().StringVarP(&listOutput, "output", "o", "", "output format")

	create := &cobra.Command{
		Use:     "create [name]",
		Short:   "create agent-group",
		Example: "metaflow-ctl agent-group create deepflow-agent-group",
		Run: func(cmd *cobra.Command, args []string) {
			createAgentGroup(cmd, args)
		},
	}

	delete := &cobra.Command{
		Use:     "delete [name]",
		Short:   "delete agent-group",
		Example: "metaflow-ctl agent-group delete deepflow-agent-group",
		Run: func(cmd *cobra.Command, args []string) {
			deleteAgentGroup(cmd, args)
		},
	}

	agentGroup.AddCommand(list)
	agentGroup.AddCommand(create)
	agentGroup.AddCommand(delete)
	return agentGroup
}

func listAgentGroup(cmd *cobra.Command, args []string, output string) {
	name := ""
	if len(args) > 0 {
		name = args[0]
	}

	server := common.GetServerInfo(cmd)
	url := fmt.Sprintf("http://%s:%d/v1/vtap-groups/", server.IP, server.Port)
	if name != "" {
		url += fmt.Sprintf("?name=%s", name)
	}

	response, err := common.CURLPerform("GET", url, nil, "")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}

	if output == "yaml" {
		dataJson, _ := response.Get("DATA").MarshalJSON()
		dataYaml, _ := yaml.JSONToYAML(dataJson)
		fmt.Printf(string(dataYaml))
	} else {
		cmdFormat := "%-48s%s\n"
		fmt.Printf(cmdFormat, "NAME", "ID")
		for i := range response.Get("DATA").MustArray() {
			group := response.Get("DATA").GetIndex(i)
			fmt.Printf(cmdFormat, group.Get("NAME").MustString(), group.Get("SHORT_UUID").MustString())
		}
	}
}

func createAgentGroup(cmd *cobra.Command, args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "must specify name. Use: %s", cmd.Use)
		return
	}

	server := common.GetServerInfo(cmd)
	url := fmt.Sprintf("http://%s:%d/v1/vtap-groups/", server.IP, server.Port)

	// 调用采集器组API，并输出返回结果
	body := map[string]interface{}{"name": args[0]}
	_, err := common.CURLPerform("POST", url, body, "")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}
}

func deleteAgentGroup(cmd *cobra.Command, args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "must specify name. Use: %s", cmd.Use)
		return
	}

	server := common.GetServerInfo(cmd)
	url := fmt.Sprintf("http://%s:%d/v1/vtap-groups/?name=%s", server.IP, server.Port, args[0])
	// 调用采集器组API，获取lcuuid
	response, err := common.CURLPerform("GET", url, nil, "")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}

	if len(response.Get("DATA").MustArray()) > 0 {
		group := response.Get("DATA").GetIndex(0)
		lcuuid := group.Get("LCUUID").MustString()

		url := fmt.Sprintf("http://%s:%d/v1/vtap-groups/%s/", server.IP, server.Port, lcuuid)
		_, err := common.CURLPerform("DELETE", url, nil, "")
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return
		}
	}
}
