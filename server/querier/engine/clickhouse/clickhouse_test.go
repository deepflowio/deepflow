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

package clickhouse

import (
	"context"
	"fmt"
	"net/http"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"bou.ke/monkey"
	"github.com/jarcoal/httpmock"

	//"github.com/k0kubun/pp"

	"github.com/deepflowio/deepflow/server/querier/common"
	"github.com/deepflowio/deepflow/server/querier/config"
	"github.com/deepflowio/deepflow/server/querier/engine/clickhouse/client"
	"github.com/deepflowio/deepflow/server/querier/engine/clickhouse/metrics"
	"github.com/deepflowio/deepflow/server/querier/parse"
)

/* var (
	parsetest = []struct {
		input string
	}{{
		input: "select Rspread(byte) as rspread_byte from l4_flow_log",
	}}
) */

var (
	parseSQL = []struct {
		name       string
		input      string
		output     string
		db         string
		datasource string
		wantErr    string
	}{{
		name:   "show_tag-values_test",
		db:     "_prometheus",
		input:  "SHOW tag-values",
		output: "SELECT field_name AS `label_name`, field_value AS `label_value` FROM flow_tag.`prometheus_custom_field_value` GROUP BY `label_name`, `label_value` ORDER BY `label_name` asc LIMIT 10000",
	}}
)

func TestGetSql(t *testing.T) {
	var c *client.Client
	result := &common.Result{}
	args := &common.QuerierParams{}
	monkey.PatchInstanceMethod(reflect.TypeOf(c), "DoQuery", func(*client.Client, *client.QueryParams) (*common.Result, error) {
		return result, nil
	})
	Load()
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()
	mockDatasources()

	for i, pcase := range parseSQL {
		if pcase.output == "" {
			pcase.output = pcase.input
		}
		db := pcase.db
		if db == "" {
			db = "flow_log"
		}
		e := CHEngine{DB: db}
		if pcase.datasource != "" {
			e.DataSource = pcase.datasource
		}
		e.Context = context.Background()
		e.Init()
		var (
			err error
			out string
		)
		if strings.HasPrefix(pcase.input, "WITH") {
			out, _, _, err = e.ParseWithSql(pcase.input)
		} else if strings.Contains(pcase.input, "SLIMIT") || strings.Contains(pcase.input, "slimit") {
			out, _, _, err = e.ParseSlimitSql(pcase.input, args)
		} else {
			input := pcase.input
			if strings.HasPrefix(pcase.input, "SHOW") {

				_, sqlList, _, err1 := e.ParseShowSql(pcase.input, args)
				err = err1
				input = sqlList[0]
				e.DB = "flow_tag"
			}
			if err == nil {
				parser := parse.Parser{Engine: &e}
				err = parser.ParseSQL(input)
				fmt.Println(err)
				out = parser.Engine.ToSQLString()
			}
		}
		if out != pcase.output {
			caseName := pcase.name
			if pcase.name == "" {
				caseName = strconv.Itoa(i)
			}
			if err != nil && pcase.wantErr == err.Error() {
				continue
			}
			t.Errorf("\nParse [%s]\n\t%q \n get: \n\t%q \n want: \n\t%q", caseName, pcase.input, out, pcase.output)
			if err != nil {
				t.Errorf("\nerror %v", err)
			}
		}
	}
}

/* func TestGetSqltest(t *testing.T) {
	for _, pcase := range parsetest {
		e := CHEngine{DB: "flow_log"}
		e.Init()
		parser := parse.Parser{Engine: &e}
		parser.ParseSQL(pcase.input)
		out := parser.Engine.ToSQLString()
		pp.Println(out)
	}
} */

func Load() error {
	ServerCfg := config.DefaultConfig()
	config.Cfg = &ServerCfg.QuerierConfig
	dir := "../../db_descriptions"
	dbDescriptions, err := common.LoadDbDescriptions(dir)
	if err != nil {
		return err
	}
	err = LoadDbDescriptions(dbDescriptions)
	if err != nil {
		return err
	}
	metrics.DB_DESCRIPTIONS = dbDescriptions
	return nil
}

func mockDatasources() {
	httpmock.RegisterResponder(
		"GET", "http://localhost:20417/v1/data-sources/",
		func(req *http.Request) (*http.Response, error) {
			values := req.URL.Query()
			name := values.Get("name")
			if name == "" {
				name = "1s"
			}

			return httpmock.NewStringResponse(200,
				fmt.Sprintf(`{"DATA":[{"NAME":"%s","INTERVAL":%d}]}`,
					name, convertNameToInterval(name)),
			), nil
		},
	)
}

func convertNameToInterval(name string) (interval int) {
	switch name {
	case "1s":
		return 1
	case "1m":
		return 60
	case "1h":
		return 3600
	case "1d":
		return 86400
	default:
		return 0
	}
}
