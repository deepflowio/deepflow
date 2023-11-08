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
	"strconv"

	"github.com/deepflowio/deepflow/cli/ctl/common"
	"github.com/deepflowio/deepflow/cli/ctl/common/table"

	"github.com/spf13/cobra"
)

func RegisterServerCommand() *cobra.Command {
	Server := &cobra.Command{
		Use:   "server",
		Short: "server operation commands",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println("please run with 'controller | ingester'.")
		},
	}

	Server.AddCommand(controllerSubCommand())
	Server.AddCommand(ingesterSubCommand())
	return Server
}

func controllerSubCommand() *cobra.Command {
	controller := &cobra.Command{
		Use:   "controller",
		Short: "server controller info",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println("please run with 'list'")
		},
	}

	list := &cobra.Command{
		Use:     "list",
		Short:   "list controller info",
		Example: "deepflow-ctl server controller list",
		Run: func(cmd *cobra.Command, args []string) {
			listController(cmd)
		},
	}

	controller.AddCommand(list)
	return controller
}

func listController(cmd *cobra.Command) {
	server := common.GetServerInfo(cmd)
	url := fmt.Sprintf("http://%s:%d/v1/controllers/", server.IP, server.Port)

	response, err := common.CURLPerform("GET", url, nil, "", []common.HTTPOption{common.WithTimeout(common.GetTimeout(cmd))}...)
	if err != nil {
		fmt.Println(err)
		return
	}
	if len(response.Get("DATA").MustArray()) == 0 {
		return
	}

	isMasterRegionFunc := func(nodeType int) string {
		if nodeType == 1 {
			return "true"
		}
		return "false"
	}

	t := table.New()
	t.SetHeader([]string{"NAME", "IP", "REGION", "IS_MASTER_REGION", "MAX_AGENT_NUM", "EXP_AGENT_NUM", "CUR_AGENT_NUM"})
	tableItems := [][]string{}
	for i := range response.Get("DATA").MustArray() {
		row := response.Get("DATA").GetIndex(i)
		tableItems = append(tableItems, []string{
			row.Get("NAME").MustString(),
			row.Get("IP").MustString(),
			row.Get("REGION_NAME").MustString(),
			isMasterRegionFunc(row.Get("NODE_TYPE").MustInt()),
			strconv.Itoa(row.Get("VTAP_MAX").MustInt()),
			strconv.Itoa(row.Get("VTAP_COUNT").MustInt()),
			strconv.Itoa(row.Get("CUR_VTAP_COUNT").MustInt()),
		})
	}
	t.AppendBulk(tableItems)
	t.Render()
}

func ingesterSubCommand() *cobra.Command {
	ingester := &cobra.Command{
		Use:   "ingester",
		Short: "server ingester info",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println("please run with 'list'")
		},
	}

	list := &cobra.Command{
		Use:     "list",
		Short:   "list ingester info",
		Example: "deepflow-ctl server ingester list",
		Run: func(cmd *cobra.Command, args []string) {
			listIngerter(cmd)
		},
	}

	ingester.AddCommand(list)

	return ingester
}

func listIngerter(cmd *cobra.Command) {
	server := common.GetServerInfo(cmd)
	url := fmt.Sprintf("http://%s:%d/v1/analyzers/", server.IP, server.Port)

	response, err := common.CURLPerform("GET", url, nil, "", []common.HTTPOption{common.WithTimeout(common.GetTimeout(cmd))}...)
	if err != nil {
		fmt.Println(err)
		return
	}
	if len(response.Get("DATA").MustArray()) == 0 {
		return
	}

	t := table.New()
	t.SetHeader([]string{"NAME", "IP", "REGION", "MAX_AGENT_NUM", "EXP_AGENT_NUM", "CUR_AGENT_NUM"})
	tableItems := [][]string{}
	for i := range response.Get("DATA").MustArray() {
		row := response.Get("DATA").GetIndex(i)
		tableItems = append(tableItems, []string{
			row.Get("NAME").MustString(),
			row.Get("IP").MustString(),
			row.Get("REGION_NAME").MustString(),
			strconv.Itoa(row.Get("VTAP_MAX").MustInt()),
			strconv.Itoa(row.Get("VTAP_COUNT").MustInt()),
			strconv.Itoa(row.Get("CUR_VTAP_COUNT").MustInt()),
		})
	}
	t.AppendBulk(tableItems)
	t.Render()
}
