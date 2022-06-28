package ctl

import (
	"fmt"
	"io/ioutil"
	"os"

	"github.com/spf13/cobra"

	"cli/ctl/common"
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
		Example: "metaflow-ctl agent-group-config list g-xxxxxx",
		Run: func(cmd *cobra.Command, args []string) {
			listAgentGroupConfig(cmd, args, listOutput)
		},
	}
	list.Flags().StringVarP(&listOutput, "output", "o", "", "output format")

	var createFilename string
	create := &cobra.Command{
		Use:     "create -f <filename>",
		Short:   "create config",
		Example: "metaflow-ctl agent-group-config create -f metaflow-config.yaml",
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
		Example: "metaflow-ctl agent-group-config update g-xxxxxx -f metaflow-config,yaml",
		Run: func(cmd *cobra.Command, args []string) {
			updateAgentGroupConfig(cmd, args, updateFilename)
		},
	}
	update.Flags().StringVarP(&updateFilename, "filename", "f", "", "file to use update agent-group config")
	update.MarkFlagRequired("filename")

	delete := &cobra.Command{
		Use:     "delete [agent-group ID]",
		Short:   "delete agent-group config",
		Example: "metaflow-ctl agent-group-config delete g-xxxxxx",
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
	// TODO read metaflow-server host from file
	url := "http://metaflow-server:20417/v1/vtap-group-configuration/example/"
	response, err := common.CURLPerform("GET", url, nil, "")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}
	fmt.Printf(response.Get("DATA").MustString())
}

func listAgentGroupConfig(cmd *cobra.Command, args []string, output string) {
	agentGroupShortUUID := ""
	if len(args) > 0 {
		agentGroupShortUUID = args[0]
	}

	// TODO: read metaflow-server host from file
	url := "http://metaflow-server:20417/v1/vtap-group-configuration/"
	if output == "yaml" {
		if agentGroupShortUUID != "" {
			url += fmt.Sprintf("filter/?vtap_group_id=%s", agentGroupShortUUID)
		} else {
			url += "advanced/"
		}

		response, err := common.CURLPerform("GET", url, nil, "")
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
		response, err := common.CURLPerform("GET", url, nil, "")
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return
		}

		cmdFormat := "%-46s %s\n"
		fmt.Printf(cmdFormat, "NAME", "AGENT_GROUP_ID")
		for i := range response.Get("DATA").MustArray() {
			config := response.Get("DATA").GetIndex(i)
			if agentGroupShortUUID != "" && config.Get("VTAP_GROUP_ID").MustString() != agentGroupShortUUID {
				continue
			}
			fmt.Printf(
				cmdFormat, config.Get("VTAP_GROUP_NAME").MustString(),
				config.Get("VTAP_GROUP_ID").MustString(),
			)
		}
	}
}

func createAgentGroupConfig(cmd *cobra.Command, args []string, createFilename string) {
	url := "http://metaflow-server:20417/v1/vtap-group-configuration/advanced/"
	yamlFile, err := ioutil.ReadFile(createFilename)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
	}
	_, err = common.CURLPerform("POST", url, nil, string(yamlFile))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}
}

func updateAgentGroupConfig(cmd *cobra.Command, args []string, updateFilename string) {
	if len(args) == 0 {
		fmt.Fprintf(os.Stderr, "must specify name. Use: %s", cmd.Use)
		return
	}

	url := fmt.Sprintf("http://metaflow-server:20417/v1/vtap-group-configuration/?vtap_group_id=%s", args[0])
	// call vtap-group api, get lcuuid
	response, err := common.CURLPerform("GET", url, nil, "")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}

	if len(response.Get("DATA").MustArray()) == 0 {
		fmt.Fprintln(os.Stderr, "agent-group (%s) not exist")
	}
	group := response.Get("DATA").GetIndex(0)
	lcuuid := group.Get("LCUUID").MustString()

	// call vtap-group config update api
	url = fmt.Sprintf("http://metaflow-server:20417/v1/vtap-group-configuration/advanced/%s/", lcuuid)
	yamlFile, err := ioutil.ReadFile(updateFilename)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
	}
	_, err = common.CURLPerform("PATCH", url, nil, string(yamlFile))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}
}

func deleteAgentGroupConfig(cmd *cobra.Command, args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "must specify agent-group ID. Use: %s", cmd.Use)
		return
	}

	// TODO: read metaflow-server host from file
	url := fmt.Sprintf("http://metaflow-server:20417/v1/vtap-group-configuration/filter/?vtap_group_id=%s", args[0])
	_, err := common.CURLPerform("DELETE", url, nil, "")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}
}
