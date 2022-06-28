package ctl

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"cli/ctl/common"
)

func RegisterAgentGroupConfigCommand() *cobra.Command {
	agentGroupConfig := &cobra.Command{
		Use:   "agent-group-config",
		Short: "agent-group config operation commands",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("please run with 'example | list | create | delete'.\n")
		},
	}

	example := &cobra.Command{
		Use:   "example",
		Short: "example agent-group config",
		Run: func(cmd *cobra.Command, args []string) {
			exampleAgentConfig(cmd, args)
		},
	}
	agentGroupConfig.AddCommand(example)
	return agentGroupConfig
}

func exampleAgentConfig(cmd *cobra.Command, args []string) {
	// TODO read metaflow-server host from file
	url := "http://metaflow-server:20417/v1/vtap-group-configuration/example/"
	response, err := common.CURLPerform("GET", url, nil)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}
	fmt.Printf(response.Get("DATA").MustString())
}
