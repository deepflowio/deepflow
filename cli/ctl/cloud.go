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
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/deepflowio/deepflow/cli/ctl/common"
)

func RegisterCloudCommand() *cobra.Command {
	cloud := &cobra.Command{
		Use:   "cloud",
		Short: "debug cloud data commands",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("please run with 'info'.\n")
		},
	}

	var domainLcuuid string
	var domainName string
	var infoResource string
	info := &cobra.Command{
		Use:     "info",
		Short:   "get cloud info of one domain, must specify one of domain-lcuuid, domain-name",
		Example: "deepflow-ctl cloud info --domain-lcuuid bcb21453-0833-5d94-b4cf-adb3879400c9 -r VMs,VPCs",
		Run: func(cmd *cobra.Command, args []string) {
			getInfo(cmd, domainLcuuid, domainName, infoResource)
		},
	}
	info.Flags().StringVarP(
		&domainLcuuid, "domain-lcuuid", "l", "", fmt.Sprintf("specify domain lcuuid to get resources info"),
	)
	info.Flags().StringVarP(
		&domainName, "domain-name", "n", "", fmt.Sprintf("specify domain name to get resources info"),
	)
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

func getInfo(cmd *cobra.Command, domainLcuuid, domainName, resource string) {
	if domainLcuuid == "" && domainName == "" {
		fmt.Fprintf(os.Stderr, "must specify one of domain-lcuuid, domain-name.\nExample: %s\n", cmd.Example)
		return
	}

	server := common.GetServerInfo(cmd)
	lcuuid := domainLcuuid
	if lcuuid == "" {
		url := fmt.Sprintf("http://%s:%d/v2/domains/?name=%s", server.IP, server.Port, domainName)
		resp, err := common.CURLResponseRawJson("GET", url, []common.HTTPOption{common.WithTimeout(common.GetTimeout(cmd))}...)
		if err != nil {
			fmt.Println("get domain info by name failed.")
			fmt.Fprintln(os.Stderr, err)
			return
		}
		if len(resp.Get("DATA").MustArray()) == 0 {
			fmt.Fprintln(os.Stderr, errors.New(fmt.Sprintf("domain name: %s not found", domainName)))
			return
		}
		lcuuid = resp.Get("DATA").GetIndex(0).Get("LCUUID").MustString()
	}

	podIP, err := common.ConvertControllerAddrToPodIP(server.IP, server.Port)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}

	url := fmt.Sprintf("http://%s:%d/v1/info/%s/", podIP, server.SvcPort, lcuuid)
	resp, err := common.CURLResponseRawJson("GET", url, []common.HTTPOption{common.WithTimeout(common.GetTimeout(cmd))}...)
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
			domainData := data.Get(r)
			for i := range domainData.MustArray() {
				common.PrettyPrint(domainData.GetIndex(i))
			}
			subDomainResources := data.Get("SubDomainResources").MustMap()
			for _, subDomainData := range subDomainResources {
				rscData, ok := subDomainData.(map[string]interface{})[r]
				if !ok || rscData == nil {
					continue
				}
				for _, d := range rscData.([]interface{}) {
					common.PrettyPrint(d)
				}
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
	resp, err := common.CURLResponseRawJson("GET", url, []common.HTTPOption{common.WithTimeout(common.GetTimeout(cmd))}...)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}
	common.PrettyPrint(resp.Get("DATA"))
}
