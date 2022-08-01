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
	"strconv"

	"github.com/bitly/go-simplejson"
	"github.com/deepflowys/deepflow/cli/ctl/common"
	"github.com/olekukonko/tablewriter"
	"github.com/spf13/cobra"
)

func RegisterGenesisCommand() *cobra.Command {
	genesis := &cobra.Command{
		Use:   "genesis",
		Short: "genesis operation commands",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println("please run with 'sync | k8s'.")
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
	syncInfo.Flags().StringVarP(&syncType, "type", "t", "vinterface", "genesis sync type")

	var k8sType string
	k8sInfo := &cobra.Command{
		Use:     "k8s",
		Short:   "genesis k8s info",
		Example: "deepflow-ctl genesis k8s cluster_id",
		Run: func(cmd *cobra.Command, args []string) {
			k8sInfo(cmd, args, k8sType)
		},
	}
	k8sInfo.Flags().StringVarP(&k8sType, "type", "t", "", "k8s info resource type")

	genesis.AddCommand(syncInfo)
	genesis.AddCommand(k8sInfo)
	return genesis
}

func syncInfo(cmd *cobra.Command, resType string) {
	server := common.GetServerInfo(cmd)
	url := fmt.Sprintf("http://%s:%d/v1/sync/%s/", server.IP, server.Port, resType)

	response, err := common.CURLPerform("GET", url, nil, "")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}

	table := tablewriter.NewWriter(os.Stdout)
	table.SetAutoWrapText(false)
	table.SetAutoFormatHeaders(true)
	table.SetHeaderAlignment(tablewriter.ALIGN_LEFT)
	table.SetAlignment(tablewriter.ALIGN_LEFT)
	table.SetCenterSeparator("")
	table.SetColumnSeparator("")
	table.SetRowSeparator("")
	table.SetHeaderLine(false)
	table.SetBorder(false)
	table.SetTablePadding("\t")
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
	case "vinterface":
		tableVinterface(response, table)
	}
}

func k8sInfo(cmd *cobra.Command, args []string, resType string) {
	if len(args) == 0 {
		fmt.Fprintf(os.Stderr, "must specify cluster_id.\nExample: %s\n", cmd.Example)
		return
	}

	server := common.GetServerInfo(cmd)
	url := fmt.Sprintf("http://%s:%d/v1/kubernetes-info/%s/", server.IP, server.Port, args[0])

	response, err := common.CURLPerform("GET", url, nil, "")
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
			formatStr, err := common.JsonFormat(tDataStr)
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
			formatStr, err := common.JsonFormat(item.(string))
			if err != nil {
				fmt.Println("format json str faild: " + err.Error())
				continue
			}
			fmt.Println(formatStr)
		}
	}
}

func tableVm(response *simplejson.Json, table *tablewriter.Table) {
	table.SetHeader([]string{"NAME", "LABEL", "LAUNCH_SERVER", "STATE", "VTAP_ID"})

	tableItems := [][]string{}
	for i := range response.Get("DATA").MustArray() {
		data := response.Get("DATA").GetIndex(i)
		tableItem := []string{}
		tableItem = append(tableItem, data.Get("NAME").MustString())
		tableItem = append(tableItem, data.Get("LABEL").MustString())
		tableItem = append(tableItem, data.Get("LAUNCH_SERVER").MustString())
		tableItem = append(tableItem, data.Get("STATE").MustString())
		tableItem = append(tableItem, strconv.Itoa(data.Get("VTAP_ID").MustInt()))
		tableItems = append(tableItems, tableItem)
		table.AppendBulk(tableItems)
	}

	table.Render()
}

func tableVpc(response *simplejson.Json, table *tablewriter.Table) {
	table.SetHeader([]string{"NAME", "VTAP_ID"})

	tableItems := [][]string{}
	for i := range response.Get("DATA").MustArray() {
		data := response.Get("DATA").GetIndex(i)
		tableItem := []string{}
		tableItem = append(tableItem, data.Get("NAME").MustString())
		tableItem = append(tableItem, strconv.Itoa(data.Get("VTAP_ID").MustInt()))
		tableItems = append(tableItems, tableItem)
		table.AppendBulk(tableItems)
	}

	table.Render()
}

func tableHost(response *simplejson.Json, table *tablewriter.Table) {
	table.SetHeader([]string{"HOSTNAME", "IP", "VTAP_ID"})

	tableItems := [][]string{}
	for i := range response.Get("DATA").MustArray() {
		data := response.Get("DATA").GetIndex(i)
		tableItem := []string{}
		tableItem = append(tableItem, data.Get("HOSTNAME").MustString())
		tableItem = append(tableItem, data.Get("IP").MustString())
		tableItem = append(tableItem, strconv.Itoa(data.Get("VTAP_ID").MustInt()))
		tableItems = append(tableItems, tableItem)
		table.AppendBulk(tableItems)
	}

	table.Render()
}

func tableLldp(response *simplejson.Json, table *tablewriter.Table) {
	table.SetHeader([]string{"SYSTEM_NAME", "HOST_IP", "HOST_INTERFACE", "MANAGEMENT_ADDRESS", "VINTERFACE_DESCRIPTION", "VTAP_ID"})

	tableItems := [][]string{}
	for i := range response.Get("DATA").MustArray() {
		data := response.Get("DATA").GetIndex(i)
		tableItem := []string{}
		tableItem = append(tableItem, data.Get("SYSTEM_NAME").MustString())
		tableItem = append(tableItem, data.Get("HOST_IP").MustString())
		tableItem = append(tableItem, data.Get("HOST_INTERFACE").MustString())
		tableItem = append(tableItem, data.Get("MANAGEMENT_ADDRESS").MustString())
		tableItem = append(tableItem, data.Get("VINTERFACE_DESCRIPTION").MustString())
		tableItem = append(tableItem, strconv.Itoa(data.Get("VTAP_ID").MustInt()))
		tableItems = append(tableItems, tableItem)
		table.AppendBulk(tableItems)
	}

	table.Render()
}

func tablePort(response *simplejson.Json, table *tablewriter.Table) {
	table.SetHeader([]string{"MAC", "TYPE", "DEVICETYPE", "VTAP_ID"})

	tableItems := [][]string{}
	for i := range response.Get("DATA").MustArray() {
		data := response.Get("DATA").GetIndex(i)
		tableItem := []string{}
		tableItem = append(tableItem, data.Get("MAC").MustString())
		tableItem = append(tableItem, strconv.Itoa(data.Get("TYPE").MustInt()))
		tableItem = append(tableItem, strconv.Itoa(data.Get("DEVICETYPE").MustInt()))
		tableItem = append(tableItem, strconv.Itoa(data.Get("VTAP_ID").MustInt()))
		tableItems = append(tableItems, tableItem)
		table.AppendBulk(tableItems)
	}

	table.Render()
}

func tableNetwork(response *simplejson.Json, table *tablewriter.Table) {
	table.SetHeader([]string{"NAME", "EXTERNAL", "SEGMENTATION_ID", "NET_TYPE", "VTAP_ID"})

	tableItems := [][]string{}
	for i := range response.Get("DATA").MustArray() {
		data := response.Get("DATA").GetIndex(i)
		tableItem := []string{}
		tableItem = append(tableItem, data.Get("NAME").MustString())
		tableItem = append(tableItem, strconv.FormatBool(data.Get("EXTERNAL").MustBool()))
		tableItem = append(tableItem, strconv.Itoa(data.Get("SEGMENTATION_ID").MustInt()))
		tableItem = append(tableItem, strconv.Itoa(data.Get("NET_TYPE").MustInt()))
		tableItem = append(tableItem, strconv.Itoa(data.Get("VTAP_ID").MustInt()))
		tableItems = append(tableItems, tableItem)
		table.AppendBulk(tableItems)
	}

	table.Render()
}

func tableIp(response *simplejson.Json, table *tablewriter.Table) {
	table.SetHeader([]string{"IP", "MASKLEN", "VTAP_ID"})

	tableItems := [][]string{}
	for i := range response.Get("DATA").MustArray() {
		data := response.Get("DATA").GetIndex(i)
		tableItem := []string{}
		tableItem = append(tableItem, data.Get("IP").MustString())
		tableItem = append(tableItem, strconv.Itoa(data.Get("MASKLEN").MustInt()))
		tableItem = append(tableItem, strconv.Itoa(data.Get("VTAP_ID").MustInt()))
		tableItems = append(tableItems, tableItem)
		table.AppendBulk(tableItems)
	}

	table.Render()
}

func tableVinterface(response *simplejson.Json, table *tablewriter.Table) {
	table.SetHeader([]string{"MAC", "NAME", "TAP_MAC", "TAP_NAME", "DEVICE_TYPE", "DEVICE_NAME", "HOST_IP", "VTAP_ID", "IPS"})

	tableItems := [][]string{}
	for i := range response.Get("DATA").MustArray() {
		data := response.Get("DATA").GetIndex(i)
		tableItem := []string{}
		tableItem = append(tableItem, data.Get("MAC").MustString())
		tableItem = append(tableItem, data.Get("NAME").MustString())
		tableItem = append(tableItem, data.Get("TAP_MAC").MustString())
		tableItem = append(tableItem, data.Get("TAP_NAME").MustString())
		tableItem = append(tableItem, data.Get("DEVICE_TYPE").MustString())
		tableItem = append(tableItem, data.Get("DEVICE_NAME").MustString())
		tableItem = append(tableItem, data.Get("HOST_IP").MustString())
		tableItem = append(tableItem, strconv.Itoa(data.Get("VTAP_ID").MustInt()))
		tableItem = append(tableItem, data.Get("IPS").MustString())
		tableItems = append(tableItems, tableItem)
		table.AppendBulk(tableItems)
	}

	table.Render()
}
