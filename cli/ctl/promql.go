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
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/deepflowio/deepflow/cli/ctl/common"
	"github.com/deepflowio/deepflow/cli/ctl/common/table"
	"github.com/spf13/cobra"
)

func RegisterPromQLCommand() *cobra.Command {
	promql := &cobra.Command{
		Use:   "promql",
		Short: "promql stats",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println("please run with 'stats'.")
		},
	}
	promql.PersistentFlags().String("since", "1h", "analysis promql stats since time duration like [5s,1m,5m,1h], default: 1h")
	promql.PersistentFlags().String("from", "", "analysis promql stats from a specific time(RFC3339), e.g.: 2000-01-01T00:00:00")
	promql.PersistentFlags().String("to", "", "analysis promql stats to a specific time(RFC3339), e.g.: 2000-01-01T00:00:00")

	promql.AddCommand(statsSubCommand())
	promql.ParseFlags(os.Args[1:])
	return promql
}

func statsSubCommand() *cobra.Command {
	var metric string
	var labelFlag bool
	stats := &cobra.Command{
		Use:   "stats",
		Short: "stats --metric",
		Run: func(cmd *cobra.Command, args []string) {
			from, to, err := getQueryTime(cmd)
			if err != nil {
				fmt.Fprintf(os.Stderr, "parse time error: %v\n", err)
				return
			}
			var targetLabel, appLabel []string
			if labelFlag {
				targetLabel = []string{"*"}
				appLabel = []string{"*"}
			}
			err = statsQuery(cmd, from, to, metric, targetLabel, appLabel)
			if err != nil {
				fmt.Fprintf(os.Stderr, "promql stats query error: %v\n", err)
			}
		},
	}
	stats.PersistentFlags().StringVarP(&metric, "metric", "m", "", "target metric name for stats analysis")
	stats.PersistentFlags().BoolVarP(&labelFlag, "all-labels", "A", false, "query metric and all labels stats info")

	var targetLabels []string
	target := &cobra.Command{
		Use:   "target",
		Short: "stats target --target-labels",
		Run: func(cmd *cobra.Command, args []string) {
			from, to, err := getQueryTime(cmd)
			if err != nil {
				fmt.Fprintf(os.Stderr, "parse time error: %v\n", err)
				return
			}
			if len(targetLabels) == 0 {
				targetLabels = []string{"*"}
			}
			err = statsQuery(cmd, from, to, metric, targetLabels, nil)
			if err != nil {
				fmt.Fprintf(os.Stderr, "promql stats query error: %v\n", err)
			}
		},
	}
	target.Flags().StringArrayVarP(&targetLabels, "target-labels", "l", nil, "specific target labels for stats analysis, default: [all]")
	stats.AddCommand(target)

	var appLabels []string
	app := &cobra.Command{
		Use:   "app",
		Short: "stats app --app-labels",
		Run: func(cmd *cobra.Command, args []string) {
			from, to, err := getQueryTime(cmd)
			if err != nil {
				fmt.Fprintf(os.Stderr, "parse time error: %v\n", err)
				return
			}
			if len(appLabels) == 0 {
				appLabels = []string{"*"}
			}
			err = statsQuery(cmd, from, to, metric, nil, appLabels)
			if err != nil {
				fmt.Fprintf(os.Stderr, "promql stats query error: %v\n", err)
			}
		},
	}
	app.Flags().StringArrayVarP(&appLabels, "app-lables", "l", nil, "specific app labels for stats analysis, default: [all]")
	stats.AddCommand(app)

	return stats
}

func getQueryTime(cmd *cobra.Command) (int64, int64, error) {
	since, _ := cmd.Flags().GetString("since")
	from, _ := cmd.Flags().GetString("from")
	to, _ := cmd.Flags().GetString("to")
	var fromTime, toTime time.Time
	var err error
	// priority: from&to > since
	if from != "" {
		fromTime, err = time.Parse(time.RFC3339, from)
		if err != nil {
			return 0, 0, err
		}
	}
	if to != "" {
		toTime, err = time.Parse(time.RFC3339, to)
		if err != nil {
			return 0, 0, err
		}
	}

	// when and only when from&to are null, use --since time
	if toTime.IsZero() && fromTime.IsZero() {
		if since == "" {
			since = "1h"
		}
		sinceDuration, err := time.ParseDuration(since)
		if err != nil {
			return 0, 0, err
		}
		fromTime = time.Now().Add(-sinceDuration)
		toTime = time.Now()
	}

	if toTime.IsZero() {
		toTime = time.Now()
	}

	if fromTime.IsZero() {
		fromTime = toTime.Add(-1 * time.Hour)
	}

	if fromTime.After(toTime) {
		return 0, 0, fmt.Errorf("query time from: %d should not greater than to: %d", fromTime.Unix(), toTime.Unix())
	}

	return fromTime.Unix(), toTime.Unix(), nil
}

func statsQuery(cmd *cobra.Command, from, to int64, metric string, targetLabels, appLabels []string) error {
	server := common.GetServerInfo(cmd)
	url := fmt.Sprintf("http://%s:%d/prom/api/v1/analysis?from=%d&to=%d", server.IP, server.Port, from, to)
	if metric != "" {
		url += fmt.Sprintf("&metric=%s", metric)
	}
	if len(targetLabels) > 0 {
		url += fmt.Sprintf("&target=%s", strings.Join(targetLabels, ","))
	}
	if len(appLabels) > 0 {
		url += fmt.Sprintf("&app=%s", strings.Join(appLabels, ","))
	}
	response, err := common.CURLPerform("GET", url, nil, "", []common.HTTPOption{common.WithTimeout(common.GetTimeout(cmd))}...)
	if err != nil {
		fmt.Println(err)
		return err
	}

	t := table.New()
	t.SetHeader(response.Get("Columns").MustStringArray())
	tableItems := make([][]string, 0, len(response.Get("Values").MustArray()))
	var rowItems []string
	for i := range response.Get("Values").MustArray() {
		row := response.Get("Values").GetIndex(i)
		rowItems = make([]string, 0, len(response.Get("Columns").MustStringArray()))
		for k, v := range response.Get("Columns").MustStringArray() {
			col := row.GetIndex(k)
			var val string
			switch strings.ToUpper(v) {
			case "QUERY_COUNT":
				val = strconv.Itoa(col.MustInt())
			case "AVG_DURATION(MS)", "MAX_DURATION(MS)":
				val = fmt.Sprintf("%f", col.MustFloat64())
			default:
				val = col.MustString()
			}
			rowItems = append(rowItems, val)
		}
		tableItems = append(tableItems, rowItems)
	}
	t.AppendBulk(tableItems)
	t.Render()
	return nil
}
