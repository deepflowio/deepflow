package ctl

import (
	"fmt"

	"github.com/ghodss/yaml"
	"github.com/spf13/cobra"

	"github.com/deepflowio/deepflow/cli/ctl/common"
	"github.com/deepflowio/deepflow/cli/ctl/common/jsonparser"
)

func RegisterVPCCommend() *cobra.Command {
	vpc := &cobra.Command{
		Use:   "vpc",
		Short: "vpc operation commands",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("please run with 'list'.\n")
		},
	}

	var listOutput string
	list := &cobra.Command{
		Use:     "list",
		Short:   "list vpc info",
		Example: "deepflow-ctl vpc list -o yaml",
		Run: func(cmd *cobra.Command, args []string) {
			if err := listVPC(cmd, args, listOutput); err != nil {
				fmt.Println(err)
			}
		},
	}
	list.Flags().StringVarP(&listOutput, "output", "o", "", "output format")

	vpc.AddCommand(list)
	return vpc
}

func listVPC(cmd *cobra.Command, args []string, output string) error {
	server := common.GetServerInfo(cmd)
	url := fmt.Sprintf("http://%s:%d/v2/vpcs/", server.IP, server.Port)
	var name string
	if len(args) > 0 {
		name = args[0]
	}
	if name != "" {
		url += fmt.Sprintf("?name=%s", name)
	}

	response, err := common.CURLPerform("GET", url, nil, "")
	if err != nil {
		return err
	}

	if output == "yaml" {
		dataJson, _ := response.Get("DATA").MarshalJSON()
		dataYaml, _ := yaml.JSONToYAML(dataJson)
		fmt.Printf(string(dataYaml))
		return nil
	}
	nameMaxSize := jsonparser.GetTheMaxSizeOfAttr(response.Get("DATA"), "NAME")
	cmdFormat := "%-*s %-20s\n"
	fmt.Printf(cmdFormat, nameMaxSize, "NAME", "LCUUID")
	for i := range response.Get("DATA").MustArray() {
		vpc := response.Get("DATA").GetIndex(i)
		fmt.Printf(cmdFormat, nameMaxSize, vpc.Get("NAME").MustString(), vpc.Get("LCUUID").MustString())
	}
	return nil
}
