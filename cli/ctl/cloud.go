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
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/deepflowys/deepflow/cli/ctl/common"
)

func RegisterCloudCommand() *cobra.Command {
	cloud := &cobra.Command{
		Use:   "cloud",
		Short: "debug cloud data commands",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("please run with 'info'.\n")
		},
	}

	var infoResource string
	info := &cobra.Command{
		Use:     "info domain-lcuuid",
		Short:   "get cloud info of one domain by lcuuid",
		Example: "deepflow-ctl cloud info bcb21453-0833-5d94-b4cf-adb3879400c9 -r VMs,VPCs",
		Run: func(cmd *cobra.Command, args []string) {
			getInfo(cmd, args, infoResource)
		},
	}
	info.Flags().StringVarP(
		&infoResource, "resource-type", "r", "", fmt.Sprintf("only get specified resources info, split by comma.Supported choices: %v", common.RESOURCE_TYPES),
	)
	cloud.AddCommand(info)

	task := &cobra.Command{
		Use:     "task [domain-lcuuid]",
		Short:   "get cloud task",
		Example: "deepflow-ctl cloud task",
		Run: func(cmd *cobra.Command, args []string) {
			getTask(cmd, args)
		},
	}
	cloud.AddCommand(task)

	return cloud
}

func getInfo(cmd *cobra.Command, args []string, resource string) {
	if len(args) == 0 {
		fmt.Fprintf(os.Stderr, "must specify domain lcuuid.\nExample: %s\n", cmd.Example)
		return
	}

	lcuuid := args[0]
	server := common.GetServerInfo(cmd)
	url := fmt.Sprintf("http://%s:%d/v1/info/%s/", server.IP, server.Port, lcuuid)

	resp, err := common.CURLResponseRawJson("GET", url)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}
	data := resp.Get("DATA")
	if resource == "" {
		common.PrettyPrint(data)
	} else {
		resources := strings.Split(resource, ",")
		for _, r := range resources {
			fmt.Println(r)
			rData := data.Get(r)
			for i := range rData.MustArray() {
				common.PrettyPrint(rData.GetIndex(i))
			}
		}
	}
}

func getTask(cmd *cobra.Command, args []string) {
	var lcuuid string
	if len(args) != 0 {
		lcuuid = args[0]
	}
	server := common.GetServerInfo(cmd)
	url := fmt.Sprintf("http://%s:%d/v1/tasks/%s/", server.IP, server.Port, lcuuid)
	resp, err := common.CURLResponseRawJson("GET", url)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}
	common.PrettyPrint(resp.Get("DATA"))
}
