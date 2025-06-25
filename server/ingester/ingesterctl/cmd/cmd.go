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
	"net"
	"strconv"
	"time"
	"unicode"

	"github.com/spf13/cobra"

	"github.com/deepflowio/deepflow/server/ingester/common"
	"github.com/deepflowio/deepflow/server/ingester/droplet/profiler"
	"github.com/deepflowio/deepflow/server/ingester/droplet/queue"
	"github.com/deepflowio/deepflow/server/ingester/ingesterctl"
	"github.com/deepflowio/deepflow/server/ingester/prometheus/decoder"
	"github.com/deepflowio/deepflow/server/libs/ckdb"
	"github.com/deepflowio/deepflow/server/libs/codec"
	"github.com/deepflowio/deepflow/server/libs/debug"
	"github.com/deepflowio/deepflow/server/libs/receiver"
	"github.com/deepflowio/deepflow/server/libs/tracetree"
	"github.com/deepflowio/deepflow/server/libs/utils"
)

func RegisterIngesterCommand(root *cobra.Command) {
	ip, _ := root.Flags().GetString("ip")
	orgId, _ := root.Flags().GetUint32("org-id")
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
	exportersCmd := &cobra.Command{
		Use:   "exporters",
		Short: "exporters debug commands",
	}
	profileCmd := &cobra.Command{
		Use:   "profile",
		Short: "profile debug commands",
	}

	root.AddCommand(ingesterCmd)
	ingesterCmd.AddCommand(dropletCmd, flowMetricsCmd, flowLogCmd, prometheusCmd, exportersCmd, profileCmd)
	ingesterCmd.AddCommand(profiler.RegisterProfilerCommand())
	ingesterCmd.AddCommand(debug.RegisterLogLevelCommand())
	ingesterCmd.AddCommand(RegisterTimeConvertCommand())
	ingesterCmd.AddCommand(debug.ClientRegisterSimple(
		ingesterctl.CMD_CONTINUOUS_PROFILER,
		debug.CmdHelper{Cmd: "continuous-profiler", Helper: "continuous profiler commands"},
		[]debug.CmdHelper{
			{Cmd: "on", Helper: "start continuous profiler"},
			{Cmd: "off", Helper: "stop continuous profiler"},
			{Cmd: "status", Helper: "get continuous profiler status"},
			{Cmd: "set-server-address [url]", Helper: "set continuous profiler server address, default: http://deepflow-agent/api/v1/profile. need to restart continuous profiler to take effect"},
			{Cmd: "set-profile-types [cpu][,inuse_objects][,alloc_objects][,inuse_space][,alloc_space][,goroutines][,mutex_count][,mutex_duration][,block_count][,block_duration]", Helper: "default continuous profiler profile types: cpu,inuse_objects,alloc_objects,inuse_space,alloc_space. need to restart continuous profiler to take effect"},
		},
	))
	ingesterCmd.AddCommand(debug.ClientRegisterSimple(
		ingesterctl.CMD_FREE_OS_MEMORY,
		debug.CmdHelper{Cmd: "free-os-memory", Helper: "free os memory commands"},
		[]debug.CmdHelper{
			{Cmd: "on", Helper: "start free os memory at intervals"},
			{Cmd: "off", Helper: "stop free os memory"},
			{Cmd: "once", Helper: "start free os memory once"},
			{Cmd: "status", Helper: "free os memory status"},
			{Cmd: "set-interval [second]", Helper: "set free os memory interval"},
		},
	))
	ingesterCmd.AddCommand(debug.ClientRegisterSimple(
		ingesterctl.CMD_ORG_SWITCH,
		debug.CmdHelper{Cmd: "switch-to-debug-org [org-id]", Helper: "the debugging command switches to the specified organization"},
		nil,
	))
	ingesterCmd.AddCommand(RegisterDecodeTraceCommand(ip, uint16(orgId)))

	dropletCmd.AddCommand(queue.RegisterCommand(ingesterctl.INGESTERCTL_QUEUE, []string{
		"1-receiver-to-statsd",
		"1-receiver-to-syslog",
	}))

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

	exportersCmd.AddCommand(debug.ClientRegisterSimple(ingesterctl.CMD_OTLP_EXPORTER, debug.CmdHelper{"otlp", "show otlp exporter stats"}, nil))
	exportersCmd.AddCommand(debug.ClientRegisterSimple(ingesterctl.CMD_EXPORTER_PLATFORMDATA, debug.CmdHelper{"platformData", "show otlp platformData"}, nil))
	exportersCmd.AddCommand(debug.ClientRegisterSimple(ingesterctl.CMD_KAFKA_EXPORTER, debug.CmdHelper{Cmd: "kafka", Helper: "show kafka exporter stats"}, nil))
	exportersCmd.AddCommand(debug.ClientRegisterSimple(ingesterctl.CMD_PROMETHEUS_EXPORTER, debug.CmdHelper{Cmd: "prometheus", Helper: "show prometheus exporter stats"}, nil))

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

func getColumnName(table string) string {
	if table == "trace_tree" {
		return "encoded_span_list"
	}
	return "encoded_span"
}

func decodeTrace(ip, username, password, table, traceId string, port, orgId uint16) error {
	connect, err := common.NewCKConnection(net.JoinHostPort(ip, strconv.Itoa(int(port))), username, password)
	if err != nil {
		return fmt.Errorf("connect to ck(%s:%d) failed. %s", ip, port, err)
	}
	defer connect.Close()
	var sql string

	database := ckdb.OrgDatabasePrefix(orgId) + "flow_log"
	encodedColumn := getColumnName(table)
	if traceId != "" {
		sql = fmt.Sprintf("SELECT time,search_index,%s FROM %s.%s WHERE trace_id='%s' limit 10", encodedColumn, database, table, traceId)
	} else {
		sql = fmt.Sprintf("SELECT time,search_index,%s FROM %s.%s WHERE time>now()-1000 limit 10", database, encodedColumn, table)
	}
	rows, err := connect.Query(sql)
	if err != nil {
		return fmt.Errorf("query SQL: %s failed: %s", sql, err)
	}
	fmt.Printf("query SQL: %s\n", sql)
	decoder := &codec.SimpleDecoder{}
	for rows.Next() {
		var t time.Time
		var searchIndex uint64
		var data string

		err := rows.Scan(&t, &searchIndex, &data)
		if err != nil {
			return err
		}
		decoder.Init([]byte(data))
		fmt.Printf("time: %s\n", t)
		fmt.Printf("search_index: %d\n", searchIndex)

		if table == "trace_tree" {
			dst := &tracetree.TraceTree{}
			err = dst.Decode(decoder)
			if err != nil {
				return fmt.Errorf("decode TraceTree failed. %s", err)
			}
			fmt.Printf("trace_id: %s\n", dst.TraceId)
			fmt.Printf("node_list:\n")
			for _, node := range dst.TreeNodes {
				for _, span := range node.UniqParentSpanInfos {
					fmt.Printf("    ip4_0: %s, ip4_1: %s\n", utils.IpFromUint32(span.IP40), utils.IpFromUint32(span.IP41))
					fmt.Printf("    span: %+v\n", span)
					fmt.Println("    -----")
				}
				fmt.Printf("  ip4: %s, ip6: %s\n", utils.IpFromUint32(node.NodeInfo.IP4), node.NodeInfo.IP6)
				fmt.Printf("  node: %+v\n", node)
				fmt.Println("  -----")
			}
		} else {
			dst := &tracetree.SpanTrace{}
			err = dst.Decode(decoder)
			if err != nil {
				return fmt.Errorf("decode TraceTree failed. %s", err)
			}
			fmt.Printf("ip4_0: %s, ip4_1: %s\n", utils.IpFromUint32(dst.IP40), utils.IpFromUint32(dst.IP41))
			fmt.Printf("encoded_span: %+v\n", dst)
		}
		fmt.Println("------------------------------------------------")
	}
	return nil
}

func RegisterDecodeTraceCommand(ip string, orgId uint16) *cobra.Command {
	usage := "decode-trace <trace_tree|span_with_trace_id> <trace_id> [ck-password]"
	cmd := &cobra.Command{
		Use:   "decode-trace",
		Short: usage,
	}
	subUsage := "<trace-id> [ck-passwork]"
	subCmd0 := &cobra.Command{
		Use:   "trace_tree",
		Short: subUsage,
		Run: func(cmd *cobra.Command, args []string) {
			if len(args) == 0 || len(args) > 2 {
				fmt.Println(subUsage)
				return
			}
			password := ""
			if len(args) == 2 {
				password = args[1]
			}
			err := decodeTrace(ip, "default", password, "trace_tree", args[0], 9000, orgId)
			if err != nil {
				fmt.Println(err)
			}
			return
		},
	}

	subCmd1 := &cobra.Command{
		Use:   "span_with_trace_id",
		Short: subUsage,
		Run: func(cmd *cobra.Command, args []string) {
			if len(args) == 0 || len(args) > 2 {
				fmt.Println(subUsage)
				return
			}
			password := ""
			if len(args) == 2 {
				password = args[1]
			}
			err := decodeTrace(ip, "default", password, "span_with_trace_id", args[0], 9000, orgId)
			if err != nil {
				fmt.Println(err)
			}
			return
		},
	}

	cmd.AddCommand(subCmd0, subCmd1)

	return cmd
}
