package ctl

import (
	"fmt"

	"github.com/spf13/cobra"

	"cli/ctl/example"
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
			fmt.Printf(string(example.YamlVTapGroupConfig))
		},
	}
	agentGroupConfig.AddCommand(example)
	return agentGroupConfig
}
