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

package cmd

import (
	"fmt"
	"strconv"
	"time"
	"unicode"

	"github.com/spf13/cobra"

	"github.com/deepflowio/deepflow/server/ingester/droplet/adapter"
	"github.com/deepflowio/deepflow/server/ingester/droplet/labeler"
	"github.com/deepflowio/deepflow/server/ingester/droplet/profiler"
	"github.com/deepflowio/deepflow/server/ingester/droplet/queue"
	"github.com/deepflowio/deepflow/server/ingester/ingesterctl"
	"github.com/deepflowio/deepflow/server/ingester/ingesterctl/rpc"
	"github.com/deepflowio/deepflow/server/ingester/prometheus/decoder"
	"github.com/deepflowio/deepflow/server/libs/debug"
	"github.com/deepflowio/deepflow/server/libs/receiver"
)

func RegisterIngesterCommand(root *cobra.Command) {
	ip, _ := root.Flags().GetString("ip")
	debug.SetIpAndPort(ip, ingesterctl.DEBUG_LISTEN_PORT)
	ingesterCmd := &cobra.Command{
		Use:   "ingester",
		Short: "Ingester debug commands",
	}

	dropletCmd := &cobra.Command{
		Use:   "droplet",
		Short: "Droplet debug commands",
	}
	flowMetricsCmd := &cobra.Command{
		Use:   "metrics",
		Short: "FlowMetrics debug commands",
	}
	flowLogCmd := &cobra.Command{
		Use:   "flow",
		Short: "Flow log debug commands",
	}
	prometheusCmd := &cobra.Command{
		Use:   "prometheus",
		Short: "Prometheus label debug commands",
	}
	otlpCmd := &cobra.Command{
		Use:   "otlp",
		Short: "otlp exporter debug commands",
	}
	profileCmd := &cobra.Command{
		Use:   "profile",
		Short: "profile debug commands",
	}

	root.AddCommand(ingesterCmd)
	ingesterCmd.AddCommand(dropletCmd, flowMetricsCmd, flowLogCmd, prometheusCmd, otlpCmd, profileCmd)
	ingesterCmd.AddCommand(profiler.RegisterProfilerCommand())
	ingesterCmd.AddCommand(debug.RegisterLogLevelCommand())
	ingesterCmd.AddCommand(RegisterTimeConvertCommand())

	dropletCmd.AddCommand(queue.RegisterCommand(ingesterctl.INGESTERCTL_QUEUE, []string{
		"1-receiver-to-statsd",
		"1-receiver-to-syslog",
		"1-receiver-to-meta-packet",
		"2-meta-packet-block-to-labeler",
		"3-meta-packet-block-to-pcap-app",
	}))
	dropletCmd.AddCommand(adapter.RegisterCommand(ingesterctl.INGESTERCTL_ADAPTER))
	dropletCmd.AddCommand(labeler.RegisterCommand(ingesterctl.INGESTERCTL_LABELER))
	dropletCmd.AddCommand(rpc.RegisterRpcCommand())

	flowMetricsCmd.AddCommand(queue.RegisterCommand(ingesterctl.INGESTERCTL_FLOW_METRICS_QUEUE, []string{"1-recv-unmarshall"}))
	flowMetricsCmd.AddCommand(debug.ClientRegisterSimple(ingesterctl.CMD_PLATFORMDATA_FLOW_METRIC, debug.CmdHelper{"platformData [filter]", "show flow metrics platform data statistics"}, nil))
	flowMetricsCmd.AddCommand(receiver.RegisterTridentStatusCommand())

	flowLogCmd.AddCommand(queue.RegisterCommand(ingesterctl.INGESTERCTL_FLOW_LOG_QUEUE, []string{
		"1-receive-to-decode-l4",
		"1-receive-to-decode-l7",
	}))
	flowLogCmd.AddCommand(debug.ClientRegisterSimple(ingesterctl.CMD_PLATFORMDATA_FLOW_LOG, debug.CmdHelper{"platformData [filter]", "show flow log platform data statistics"}, nil))
	flowLogCmd.AddCommand(debug.ClientRegisterSimple(ingesterctl.CMD_L7_FLOW_LOG, debug.CmdHelper{"l7", "show l7 flow log counter"}, nil))

	prometheusCmd.AddCommand(debug.ClientRegisterSimple(ingesterctl.CMD_PLATFORMDATA_PROMETHEUS, debug.CmdHelper{"platformData [filter]", "show prometheus platform data statistics"}, nil))
	prometheusCmd.AddCommand(decoder.RegisterClientPrometheusLabelCommand())
	prometheusCmd.AddCommand(queue.RegisterCommand(ingesterctl.INGESTERCTL_PROMETHEUS_QUEUE, []string{
		"1-receive-to-decode-prometheus",
		"2-decode-to-slow-decode-prometheus",
	}))

	otlpCmd.AddCommand(debug.ClientRegisterSimple(ingesterctl.CMD_OTLP_EXPORTER, debug.CmdHelper{"stats", "show otlp exporter stats"}, nil))
	otlpCmd.AddCommand(debug.ClientRegisterSimple(ingesterctl.CMD_EXPORTER_PLATFORMDATA, debug.CmdHelper{"platformData", "show otlp platformData"}, nil))

	profileCmd.AddCommand(debug.ClientRegisterSimple(ingesterctl.CMD_PLATFORMDATA_PROFILE, debug.CmdHelper{"platformData [filter]", "show profile platform data statistics"}, nil))

	root.GenBashCompletionFile("/usr/share/bash-completion/completions/deepflow-ctl")
}

// 从字符串中解析出所有时间(大于100000000)
func getTimeInts(ts string) []time.Time {
	ints := make([]string, 0)
	j := 0
	for i := 0; i < len(ts); i++ {
		if unicode.IsDigit(rune(ts[i])) {
			if len(ints) <= j {
				ints = append(ints, "")
			}
			ints[j] = ints[j] + ts[i:i+1]
		} else {
			if len(ints) > j {
				j++
			}
		}
	}
	times := make([]time.Time, 0)
	for _, k := range ints {
		timeInt, err := strconv.ParseInt(k, 10, 64)
		if err == nil && timeInt > 100000000 {
			if timeInt > 100000000000000000 {
				times = append(times, time.Unix(0, timeInt))
			} else {
				times = append(times, time.Unix(timeInt, 0))
			}
		}
	}
	return times
}

func RegisterTimeConvertCommand() *cobra.Command {
	eg := "time format eg: '2020-03-27T07:06:00Z', '1585292760000000000', '1585292760'"
	cmd := &cobra.Command{
		Use:   "tc",
		Short: "time convert." + eg,
		Run: func(cmd *cobra.Command, args []string) {
			if len(args) != 1 {
				fmt.Printf("input time to convert. %s \n", eg)
				return
			}
			timeToConvert := args[0]
			timeInt, err := strconv.ParseInt(timeToConvert, 10, 64)
			var ts time.Time
			if err == nil {
				if timeInt > 100000000000000000 {
					ts = time.Unix(0, timeInt)
				} else {
					ts = time.Unix(timeInt, 0)
				}
			} else {
				err = ts.UnmarshalText([]byte(timeToConvert))
				if err != nil {
					times := getTimeInts(timeToConvert)
					if len(times) == 0 {
						fmt.Printf("unsupport time format '%s'\n", timeToConvert)
						fmt.Println(eg)
					} else {
						fmt.Printf("'%s' is convert to:\n", timeToConvert)
						for _, t := range times {
							fmt.Printf("Unix:     %d\nUnixNano: %d\nString:   %s\n\n", t.Unix(), t.UnixNano(), t)
						}
					}
					return
				}
			}
			fmt.Printf("'%s' is convert to:\n  Unix: %d\n  UnixNano: %d\n  String: %s\n", timeToConvert, ts.Unix(), ts.UnixNano(), ts)
		},
	}

	return cmd
}
