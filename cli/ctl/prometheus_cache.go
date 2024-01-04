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

	"github.com/deepflowio/deepflow/message/controller"
	"github.com/spf13/cobra"
)

func RegisterPrometheusCacheCommand() *cobra.Command {
	var t string
	prometheusCmd := &cobra.Command{
		Use:     "prometheus-cache",
		Short:   "pull prometheus cache data from deepflow-server",
		Example: "deepflow-ctl prometheus-cache -t metric-name",
		Run: func(cmd *cobra.Command, args []string) {
			if err := prometheusCache(cmd, t); err != nil {
				fmt.Println(err)
			}
		},
	}
	prometheusCmd.Flags().StringVarP(&t, "type", "t", "all", "cache type, options: all, metric-name, label-name, "+
		"label-value, metric-and-app-layout, target, label, metric-label, metric-target")

	return prometheusCmd
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
