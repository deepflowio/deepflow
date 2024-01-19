/*
 * Copyright (c) 2023 Yunshan Networks
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

/*
 * Copyright (c) 2023 Yunshan Networks
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

	"github.com/spf13/cobra"
	"sigs.k8s.io/yaml"

	"github.com/deepflowio/deepflow/cli/ctl/common"
	"github.com/deepflowio/deepflow/cli/ctl/common/table"
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
	url := fmt.Sprintf("http://%s:%d/v2/epcs/", server.IP, server.Port)
	var name string
	if len(args) > 0 {
		name = args[0]
	}
	if name != "" {
		url += fmt.Sprintf("?name=%s", name)
	}

	response, err := common.CURLPerform("GET", url, nil, "", []common.HTTPOption{common.WithTimeout(common.GetTimeout(cmd))}...)
	if err != nil {
		return err
	}

	if output == "yaml" {
		dataJson, _ := response.Get("DATA").MarshalJSON()
		dataYaml, _ := yaml.JSONToYAML(dataJson)
		fmt.Printf(string(dataYaml))
		return nil
	}
	t := table.New()
	t.SetHeader([]string{"NAME", "LCUUID"})
	tableItems := [][]string{}
	for i := range response.Get("DATA").MustArray() {
		vpc := response.Get("DATA").GetIndex(i)
		tableItems = append(tableItems, []string{
			vpc.Get("NAME").MustString(),
			vpc.Get("LCUUID").MustString(),
		})
	}
	t.AppendBulk(tableItems)
	t.Render()
	return nil
}
