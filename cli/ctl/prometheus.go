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
	"context"
	"fmt"
	"net/http"
	"os"

	"github.com/deepflowio/deepflow/cli/ctl/common"
	"github.com/deepflowio/deepflow/message/controller"
	"github.com/spf13/cobra"
)

func RegisterPrometheusCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "prometheus",
		Short: "prometheus operation commands",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("please run with 'cache | cleaner'.\n")
		},
	}

	var t string
	cacheCmd := &cobra.Command{
		Use:     "cache",
		Short:   "pull prometheus cache data from deepflow-server",
		Example: "deepflow-ctl prometheus cache -t metric-name",
		Run: func(cmd *cobra.Command, args []string) {
			if err := prometheusCache(cmd, t); err != nil {
				fmt.Println(err)
			}
		},
	}
	cacheCmd.Flags().StringVarP(&t, "type", "t", "all", "cache type, options: all, metric-name, label-name, "+
		"label-value, metric-and-app-layout, target, label, metric-label, metric-target")
	cmd.AddCommand(cacheCmd)

	var expiredAt string
	clearCmd := &cobra.Command{
		Use:     "clear",
		Short:   "clear prometheus data in MySQL by deepflow-server, use with caution and not frequently!",
		Example: "deepflow-ctl prometheus clear -e \"2006-01-02 15:04:05\"",
		Run: func(cmd *cobra.Command, args []string) {
			prometheusClear(cmd, expiredAt)
		},
	}
	clearCmd.Flags().StringVarP(&expiredAt, "expired-time", "e", "", "expired-time format: 2006-01-02 15:04:05")
	cmd.AddCommand(clearCmd)

	return cmd
}

func prometheusCache(cmd *cobra.Command, t string) error {
	conn := getConn(cmd)
	if conn == nil {
		return fmt.Errorf("connect to server via grpc error")
	}
	defer conn.Close()

	var prometheusType controller.PrometheusCacheType
	switch t {
	case "all":
		prometheusType = controller.PrometheusCacheType_ALL
	case "metric-name":
		prometheusType = controller.PrometheusCacheType_METRIC_NAME
	case "label-name":
		prometheusType = controller.PrometheusCacheType_LABEL_NAME
	case "label-value":
		prometheusType = controller.PrometheusCacheType_LABEL_VALUE
	case "metric-and-app-layout":
		prometheusType = controller.PrometheusCacheType_METRIC_AND_APP_LABEL_LAYOUT
	case "target":
		prometheusType = controller.PrometheusCacheType_TARGET
	case "label":
		prometheusType = controller.PrometheusCacheType_LABEL
	case "metric-label":
		prometheusType = controller.PrometheusCacheType_METRIC_LABEL
	case "metric-target":
		prometheusType = controller.PrometheusCacheType_METRIC_TARGET

	default:
		return fmt.Errorf("type(%s) is not supported, please use all | metric-name | label-name | label-value | "+
			"metric-and-app-layout | target | label | metric-label | metric-target", t)
	}

	c := controller.NewPrometheusDebugClient(conn)
	reqData := &controller.PrometheusCacheRequest{
		Type: &prometheusType,
	}
	resp, err := c.DebugPrometheusCache(context.Background(), reqData)
	if err != nil {
		return err
	}

	fmt.Printf("%s\n", resp.GetContent())
	return nil
}

func prometheusClear(cmd *cobra.Command, expiredAt string) {
	server := common.GetServerInfo(cmd)
	url := fmt.Sprintf("http://%s:%d/v1/prometheus-cleaner-tasks/", server.IP, server.Port)
	resp, err := common.CURLPerform(http.MethodPost, url, map[string]interface{}{"EXPIRED_AT": expiredAt}, "", []common.HTTPOption{common.WithTimeout(common.GetTimeout(cmd))}...)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}
	fmt.Println(resp)
	return
}
