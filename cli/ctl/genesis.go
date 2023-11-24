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
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/bitly/go-simplejson"
	"github.com/deepflowio/deepflow/cli/ctl/common"
	"github.com/olekukonko/tablewriter"
	"github.com/spf13/cobra"
)

func RegisterGenesisCommand() *cobra.Command {
	genesis := &cobra.Command{
		Use:   "genesis",
		Short: "genesis operation commands",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println("please run with 'sync | k8s | agent | storage'.")
		},
	}

	var syncType string
	syncInfo := &cobra.Command{
		Use:     "sync",
		Short:   "genesis sync info",
		Example: "deepflow-ctl genesis sync",
		Run: func(cmd *cobra.Command, args []string) {
			syncInfo(cmd, syncType)
		},
	}
	syncInfo.Flags().StringVarP(&syncType, "type", "t", "vinterface", "genesis sync type: 'vm | vpc | host | port | lldp | ip | vip | network | vinterface | process'\ndefault: vinterface")

	var k8sType string
	k8sInfo := &cobra.Command{
		Use:     "k8s",
		Short:   "genesis k8s info",
		Example: "deepflow-ctl genesis k8s cluster_id",
		Run: func(cmd *cobra.Command, args []string) {
			k8sInfo(cmd, args, k8sType)
		},
	}
	k8sInfo.Flags().StringVarP(&k8sType, "type", "t", "", "k8s info resource type: '*version.Info | *v1.Pod | *v1.ConfigMap | *v1.Namespace | \n*v1.Service | *v1.Deployment | *v1.DaemonSet | *v1.ReplicaSet | *v1beta1.Ingress | \n*v1.CloneSet | *v1.StatefulSet'")

	prometheusInfo := &cobra.Command{
		Use:     "prometheus",
		Short:   "genesis prometheus info",
		Example: "deepflow-ctl genesis prometheus cluster_id",
		Run: func(cmd *cobra.Command, args []string) {
			prometheusInfo(cmd, args)
		},
	}

	agentInfo := &cobra.Command{
		Use:     "agent",
		Short:   "genesis agent info",
		Example: "deepflow-ctl genesis agent -i node_ip [host_ip or vtap_id]",
		Run: func(cmd *cobra.Command, args []string) {
			agentInfo(cmd, args)
		},
	}

	storageInfo := &cobra.Command{
		Use:     "storage",
		Short:   "genesis storage info",
		Example: "deepflow-ctl genesis storage vtap_id",
		Run: func(cmd *cobra.Command, args []string) {
			storageInfo(cmd, args)
		},
	}

	genesis.AddCommand(syncInfo)
	genesis.AddCommand(k8sInfo)
	genesis.AddCommand(agentInfo)
	genesis.AddCommand(prometheusInfo)
	genesis.AddCommand(storageInfo)
	return genesis
}

func syncInfo(cmd *cobra.Command, resType string) {
	server := common.GetServerInfo(cmd)
	url := fmt.Sprintf("http://%s:%d/v1/sync/%s/", server.IP, server.Port, resType)

	response, err := common.CURLPerform("GET", url, nil, "", []common.HTTPOption{common.WithTimeout(common.GetTimeout(cmd))}...)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}

	table := tablewriter.NewWriter(os.Stdout)
	table.SetAutoWrapText(false)
	table.SetAutoFormatHeaders(false)
	table.SetHeaderAlignment(tablewriter.ALIGN_LEFT)
	table.SetAlignment(tablewriter.ALIGN_LEFT)
	table.SetCenterSeparator("")
	table.SetColumnSeparator("")
	table.SetRowSeparator("")
	table.SetHeaderLine(false)
	table.SetBorder(false)
	table.SetTablePadding("  ")
	table.SetNoWhiteSpace(true)

	switch resType {
	case "vm":
		tableVm(response, table)
	case "vpc":
		tableVpc(response, table)
	case "host":
		tableHost(response, table)
	case "lldp":
		tableLldp(response, table)
	case "port":
		tablePort(response, table)
	case "network":
		tableNetwork(response, table)
	case "ip":
		tableIp(response, table)
	case "vip":
		tableVip(response, table)
	case "vinterface":
		tableVinterface(response, table)
	case "process":
		tableProcess(response, table)
	}
}

func k8sInfo(cmd *cobra.Command, args []string, resType string) {
	if len(args) == 0 {
		fmt.Fprintf(os.Stderr, "must specify cluster_id.\nExample: %s\n", cmd.Example)
		return
	}

	server := common.GetServerInfo(cmd)
	url := fmt.Sprintf("http://%s:%d/v1/kubernetes-info/%s/", server.IP, server.Port, args[0])

	response, err := common.CURLPerform("GET", url, nil, "", []common.HTTPOption{common.WithTimeout(common.GetTimeout(cmd))}...)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}

	respData := response.Get("DATA")
	if resType != "" {
		typeData, ok := respData.CheckGet(resType)
		if !ok {
			fmt.Fprintf(os.Stderr, "not found k8s resource type: %s\n", resType)
			return
		}
		for i := range typeData.MustArray() {
			tDataStr := typeData.GetIndex(i).MustString()
			formatStr, err := common.JsonFormat([]byte(tDataStr))
			if err != nil {
				fmt.Println("format json str faild: " + err.Error())
				continue
			}
			fmt.Println(formatStr)
		}
		return
	}
	for _, v := range respData.MustMap() {
		for _, item := range v.([]interface{}) {
			formatStr, err := common.JsonFormat([]byte(item.(string)))
			if err != nil {
				fmt.Println("format json str faild: " + err.Error())
				continue
			}
			fmt.Println(formatStr)
		}
	}
}

func tableVm(response *simplejson.Json, table *tablewriter.Table) {
	table.SetHeader([]string{"NAME", "LABEL", "LAUNCH_SERVER", "STATE"})

	tableItems := [][]string{}
	for i := range response.Get("DATA").MustArray() {
		data := response.Get("DATA").GetIndex(i)
		tableItem := []string{}
		tableItem = append(tableItem, data.Get("NAME").MustString())
		tableItem = append(tableItem, data.Get("LABEL").MustString())
		tableItem = append(tableItem, data.Get("LAUNCH_SERVER").MustString())
		tableItem = append(tableItem, strconv.Itoa(data.Get("STATE").MustInt()))
		tableItems = append(tableItems, tableItem)
	}

	table.AppendBulk(tableItems)
	table.Render()
}

func tableVpc(response *simplejson.Json, table *tablewriter.Table) {
	table.SetHeader([]string{"NAME"})

	tableItems := [][]string{}
	for i := range response.Get("DATA").MustArray() {
		data := response.Get("DATA").GetIndex(i)
		tableItem := []string{}
		tableItem = append(tableItem, data.Get("NAME").MustString())
		tableItems = append(tableItems, tableItem)
	}

	table.AppendBulk(tableItems)
	table.Render()
}

func tableHost(response *simplejson.Json, table *tablewriter.Table) {
	table.SetHeader([]string{"HOSTNAME", "IP"})

	tableItems := [][]string{}
	for i := range response.Get("DATA").MustArray() {
		data := response.Get("DATA").GetIndex(i)
		tableItem := []string{}
		tableItem = append(tableItem, data.Get("HOSTNAME").MustString())
		tableItem = append(tableItem, data.Get("IP").MustString())
		tableItems = append(tableItems, tableItem)
	}

	table.AppendBulk(tableItems)
	table.Render()
}

func tableLldp(response *simplejson.Json, table *tablewriter.Table) {
	table.SetHeader([]string{"SYSTEM_NAME", "HOST_IP", "HOST_INTERFACE", "MANAGEMENT_ADDRESS", "VINTERFACE_DESCRIPTION"})

	tableItems := [][]string{}
	for i := range response.Get("DATA").MustArray() {
		data := response.Get("DATA").GetIndex(i)
		tableItem := []string{}
		tableItem = append(tableItem, data.Get("SYSTEM_NAME").MustString())
		tableItem = append(tableItem, data.Get("HOST_IP").MustString())
		tableItem = append(tableItem, data.Get("HOST_INTERFACE").MustString())
		tableItem = append(tableItem, data.Get("MANAGEMENT_ADDRESS").MustString())
		tableItem = append(tableItem, data.Get("VINTERFACE_DESCRIPTION").MustString())
		tableItems = append(tableItems, tableItem)
	}

	table.AppendBulk(tableItems)
	table.Render()
}

func tablePort(response *simplejson.Json, table *tablewriter.Table) {
	table.SetHeader([]string{"MAC", "TYPE", "DEVICETYPE"})

	tableItems := [][]string{}
	for i := range response.Get("DATA").MustArray() {
		data := response.Get("DATA").GetIndex(i)
		tableItem := []string{}
		tableItem = append(tableItem, data.Get("MAC").MustString())
		tableItem = append(tableItem, strconv.Itoa(data.Get("TYPE").MustInt()))
		tableItem = append(tableItem, strconv.Itoa(data.Get("DEVICETYPE").MustInt()))
		tableItems = append(tableItems, tableItem)
	}

	table.AppendBulk(tableItems)
	table.Render()
}

func tableNetwork(response *simplejson.Json, table *tablewriter.Table) {
	table.SetHeader([]string{"NAME", "EXTERNAL", "SEGMENTATION_ID", "NET_TYPE"})

	tableItems := [][]string{}
	for i := range response.Get("DATA").MustArray() {
		data := response.Get("DATA").GetIndex(i)
		tableItem := []string{}
		tableItem = append(tableItem, data.Get("NAME").MustString())
		tableItem = append(tableItem, strconv.FormatBool(data.Get("EXTERNAL").MustBool()))
		tableItem = append(tableItem, strconv.Itoa(data.Get("SEGMENTATION_ID").MustInt()))
		tableItem = append(tableItem, strconv.Itoa(data.Get("NET_TYPE").MustInt()))
		tableItems = append(tableItems, tableItem)
	}

	table.AppendBulk(tableItems)
	table.Render()
}

func tableIp(response *simplejson.Json, table *tablewriter.Table) {
	table.SetHeader([]string{"IP", "MASKLEN"})

	tableItems := [][]string{}
	for i := range response.Get("DATA").MustArray() {
		data := response.Get("DATA").GetIndex(i)
		tableItem := []string{}
		tableItem = append(tableItem, data.Get("IP").MustString())
		tableItem = append(tableItem, strconv.Itoa(data.Get("MASKLEN").MustInt()))
		tableItems = append(tableItems, tableItem)
	}

	table.AppendBulk(tableItems)
	table.Render()
}

func tableVip(response *simplejson.Json, table *tablewriter.Table) {
	table.SetHeader([]string{"IP", "VTAP_ID"})

	tableItems := [][]string{}
	for i := range response.Get("DATA").MustArray() {
		data := response.Get("DATA").GetIndex(i)
		tableItem := []string{}
		tableItem = append(tableItem, data.Get("IP").MustString())
		tableItem = append(tableItem, strconv.Itoa(data.Get("VTAP_ID").MustInt()))
		tableItems = append(tableItems, tableItem)
	}

	table.AppendBulk(tableItems)
	table.Render()
}

func tableVinterface(response *simplejson.Json, table *tablewriter.Table) {
	table.SetHeader([]string{"MAC", "NAME", "TAP_MAC", "TAP_NAME", "IF_TYPE", "DEVICE_TYPE", "DEVICE_NAME", "HOST_IP", "VTAP_ID", "CLUSTER_ID", "NETNS_ID", "IP"})

	tableItems := [][]string{}
	for i := range response.Get("DATA").MustArray() {
		data := response.Get("DATA").GetIndex(i)
		ipsString := data.Get("IPS").MustString()
		for _, ip := range strings.Split(ipsString, ",") {
			if ip == "" {
				continue
			}
			tableItem := []string{}
			tableItem = append(tableItem, data.Get("MAC").MustString())
			tableItem = append(tableItem, data.Get("NAME").MustString())
			tableItem = append(tableItem, data.Get("TAP_MAC").MustString())
			tableItem = append(tableItem, data.Get("TAP_NAME").MustString())
			tableItem = append(tableItem, data.Get("IF_TYPE").MustString())
			tableItem = append(tableItem, data.Get("DEVICE_TYPE").MustString())
			tableItem = append(tableItem, data.Get("DEVICE_NAME").MustString())
			tableItem = append(tableItem, data.Get("HOST_IP").MustString())
			tableItem = append(tableItem, strconv.Itoa(data.Get("VTAP_ID").MustInt()))
			tableItem = append(tableItem, data.Get("KUBERNETES_CLUSTER_ID").MustString())
			tableItem = append(tableItem, strconv.Itoa(data.Get("NETNS_ID").MustInt()))
			tableItem = append(tableItem, ip)
			tableItems = append(tableItems, tableItem)
		}
	}

	table.AppendBulk(tableItems)
	table.Render()
}

func tableProcess(response *simplejson.Json, table *tablewriter.Table) {
	table.SetHeader([]string{"PID", "VTAP_ID", "NETNS_ID", "NAME", "PROCESS_NAME", "USER", "START_TIME"})

	tableItems := [][]string{}
	for i := range response.Get("DATA").MustArray() {
		data := response.Get("DATA").GetIndex(i)
		tableItem := []string{}
		tableItem = append(tableItem, strconv.Itoa(data.Get("PID").MustInt()))
		tableItem = append(tableItem, strconv.Itoa(data.Get("VTAP_ID").MustInt()))
		tableItem = append(tableItem, strconv.Itoa(data.Get("NETNS_ID").MustInt()))
		tableItem = append(tableItem, data.Get("NAME").MustString())
		tableItem = append(tableItem, data.Get("PROCESS_NAME").MustString())
		tableItem = append(tableItem, data.Get("USER").MustString())
		tableItem = append(tableItem, data.Get("START_TIME").MustString())
		tableItems = append(tableItems, tableItem)
	}

	table.AppendBulk(tableItems)
	table.Render()
}

func agentInfo(cmd *cobra.Command, args []string) {
	if len(args) == 0 {
		args = []string{""}
	}

	server := common.GetServerInfo(cmd)
	podIP, err := common.ConvertControllerAddrToPodIP(server.IP, server.Port)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}

	url := fmt.Sprintf("http://%s:%d/v1/agent-stats/%s/", podIP, server.SvcPort, args[0])
	response, err := common.CURLPerform("GET", url, nil, "", []common.HTTPOption{common.WithTimeout(common.GetTimeout(cmd))}...)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}

	responseByte, err := response.MarshalJSON()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}

	var str bytes.Buffer
	err = json.Indent(&str, responseByte, "", "    ")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}

	fmt.Println(str.String())
}

func prometheusInfo(cmd *cobra.Command, args []string) {
	if len(args) == 0 {
		fmt.Fprintf(os.Stderr, "must specify cluster_id.\nExample: %s\n", cmd.Example)
		return
	}

	path := fmt.Sprintf("/v1/prometheus-info/%s/", args[0])
	common.GetURLInfo(cmd, path, []common.HTTPOption{common.WithTimeout(common.GetTimeout(cmd))}...)
}

func storageInfo(cmd *cobra.Command, args []string) {
	if len(args) == 0 {
		fmt.Fprintf(os.Stderr, "must specify vtap id.\nExample: %s\n", cmd.Example)
		return
	}

	path := fmt.Sprintf("/v1/genesis-storage/%s/", args[0])
	common.GetURLInfo(cmd, path, []common.HTTPOption{common.WithTimeout(common.GetTimeout(cmd))}...)
}
