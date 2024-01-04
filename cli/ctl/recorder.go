/*
 * Copyright (c) 2024 Yunshan Networks
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

	"github.com/deepflowio/deepflow/cli/ctl/common"
)

func RegisterRecorderCommand() *cobra.Command {
	recorder := &cobra.Command{
		Use:   "recorder",
		Short: "debug recorder service commands",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("please run with 'cache'.\n")
		},
	}

	var onlyDiffBase bool
	var onlyToolMap bool
	var subDomain string
	var resourceType string
	var field string
	cache := &cobra.Command{
		Use:     "cache domain-lcuuid",
		Short:   "get recorder cache of one domain by lcuuid",
		Example: "deepflow-ctl recorder cache bcb21453-0833-5d94-b4cf-adb3879400c9",
		Run: func(cmd *cobra.Command, args []string) {
			getCache(cmd, args, subDomain, onlyDiffBase, onlyToolMap, resourceType, field)
		},
	}
	cache.Flags().StringVarP(
		&subDomain, "subdomain-lcuuid", "s", "", fmt.Sprintf("get resource cache of specified subdomain"),
	)
	cache.Flags().BoolVarP(
		&onlyDiffBase, "diff-base", "b", false, fmt.Sprintf("if set, only get diff base cache"),
	)
	cache.Flags().BoolVarP(
		&onlyToolMap, "tool-map", "t", false, fmt.Sprintf("if set, only get tool map cache"),
	)
	cache.Flags().StringVarP(
		&resourceType, "resource-type", "r", "", fmt.Sprintf("only applies to diff-base. Get resource cache of specified resources, split by comma.Supported choices: %v", common.RESOURCE_TYPES),
	)
	cache.Flags().StringVarP(
		&field, "field", "f", "", fmt.Sprintf("only applies to tool-map. Get resource cache of specified fields, split by comma."),
	)

	recorder.AddCommand(cache)

	return recorder
}

func getCache(cmd *cobra.Command, args []string, subDomain string, onlyDiffBase, onlyToolMap bool, resourceType, field string) {
	if len(args) == 0 {
		fmt.Fprintf(os.Stderr, "must specify domain lcuuid.\nExample: %s\n", cmd.Example)
		return
	}

	lcuuid := args[0]
	server := common.GetServerInfo(cmd)
	url := fmt.Sprintf("http://%s:%d/v1/recorders/%s/%s/cache/", server.IP, server.Port, lcuuid, subDomain)
	if onlyDiffBase {
		url += "diff-bases/"
	} else if onlyToolMap {
		url += "tool-maps/"
	}

	resp, err := common.CURLResponseRawJson("GET", url, []common.HTTPOption{common.WithTimeout(common.GetTimeout(cmd))}...)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}
	data := resp.Get("DATA")
	if resourceType != "" {
		resources := strings.Split(resourceType, ",")
		for _, r := range resources {
			fmt.Println(r)
			common.PrettyPrint(data.Get(r))
		}
	} else if field != "" {
		resources := strings.Split(field, ",")
		for _, r := range resources {
			fmt.Println(r)
			common.PrettyPrint(data.Get(r))
		}
	} else {
		common.PrettyPrint(data)
	}
}
