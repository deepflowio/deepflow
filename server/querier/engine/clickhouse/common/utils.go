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

package common

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/deepflowio/deepflow/server/querier/config"
	"github.com/deepflowio/deepflow/server/querier/engine/clickhouse/client"
	logging "github.com/op/go-logging"
	"github.com/xwb1989/sqlparser"
)

var log = logging.MustGetLogger("common")
var noBackquoteRegexp = regexp.MustCompile("^`[a-zA-Z_]+`$")

func ParseAlias(node sqlparser.SQLNode) string {
	alias := sqlparser.String(node)
	if noBackquoteRegexp.MatchString(alias) {
		alias = strings.Trim(alias, "`")
	}
	return alias
}

// Permissions解析为数组
// 最高十进制位：用户组A是否有权限，通常可用于代表管理员用户组
// 第二个十进制位：用户组B是否有权限，通常可用于代表OnPrem租户用户组
// 最低十进制位：用户组C是否有权限，通常可用于代表SaaS租户用户组
func ParsePermission(permission interface{}) ([]bool, error) {
	var permissions []bool
	permissionInt, err := strconv.Atoi(permission.(string))
	if err != nil {
		return nil, err
	}
	for permissionInt > 0 {
		if permissionInt%10 == 0 {
			permissions = append([]bool{false}, permissions...)
		} else {
			permissions = append([]bool{true}, permissions...)
		}
		permissionInt = permissionInt / 10
	}
	// 如果描述文件中的十进制位数不对，则返回报错
	if len(permissions) != PERMISSION_TYPE_NUM {
		return nil, errors.New(
			fmt.Sprintf("parse permission %v failed", permission),
		)
	}
	return permissions, nil
}

func IPFilterStringToHex(ip string) string {
	if strings.Contains(ip, ":") {
		return fmt.Sprintf("hex(toIPv6(%s))", ip)
	} else {
		return fmt.Sprintf("hex(toIPv4(%s))", ip)
	}
}

func ParseResponse(response *http.Response) (map[string]interface{}, error) {
	var result map[string]interface{}
	body, err := ioutil.ReadAll(response.Body)
	if err == nil {
		err = json.Unmarshal(body, &result)
	}
	return result, err
}

func GetDatasources(db string, table string) ([]string, error) {
	var datasources []string
	switch db {
	case "flow_metrics":
		var tsdbType string
		if table == "vtap_flow_port" || table == "vtap_flow_edge_port" {
			tsdbType = "flow"
		} else if table == "vtap_app_port" || table == "vtap_app_edge_port" {
			tsdbType = "app"
		}
		client := &http.Client{}
		url := fmt.Sprintf("http://localhost:20417/v1/data-sources/?type=%s", tsdbType)
		reqest, err := http.NewRequest("GET", url, nil)
		if err != nil {
			return datasources, err
		}
		response, err := client.Do(reqest)
		if err != nil {
			return datasources, err
		}
		defer response.Body.Close()
		if response.StatusCode != 200 {
			return datasources, errors.New(fmt.Sprintf("get datasource error, url: %s, code '%d'", url, response.StatusCode))
		}
		body, err := ParseResponse(response)
		if err != nil {
			return datasources, err
		}
		if body["DATA"] == nil || len(body["DATA"].([]interface{})) < 1 {
			return datasources, errors.New(fmt.Sprintf("get datasources error, url: %s, response: '%v'", url, body))
		}
		for _, datasource := range body["DATA"].([]interface{}) {
			datasources = append(datasources, datasource.(map[string]interface{})["NAME"].(string))
		}
	default:
		return datasources, nil
	}
	return datasources, nil
}

func GetDatasourceInterval(db string, table string, name string) (int, error) {
	var tsdbType string
	switch db {
	case DB_NAME_FLOW_LOG, DB_NAME_EVENT, DB_NAME_PROFILE:
		return 1, nil
	case DB_NAME_FLOW_METRICS:
		if name == "" {
			tableSlice := strings.Split(table, ".")
			if len(tableSlice) == 2 {
				name = tableSlice[1]
			}
		}
		if strings.HasPrefix(table, "vtap_flow") {
			tsdbType = "flow"
		} else if strings.HasPrefix(table, "vtap_app") {
			tsdbType = "app"
		} else if table == "vtap_acl" {
			return 60, nil
		}
	case DB_NAME_DEEPFLOW_SYSTEM, DB_NAME_EXT_METRICS, DB_NAME_PROMETHEUS:
		tsdbType = db
	default:
		return 1, nil
	}
	client := &http.Client{}
	url := fmt.Sprintf("http://localhost:20417/v1/data-sources/?type=%s", tsdbType)
	if name != "" {
		url += fmt.Sprintf("&name=%s", name)
	}
	reqest, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return 1, err
	}
	response, err := client.Do(reqest)
	if err != nil {
		return 1, err
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		return 1, errors.New(fmt.Sprintf("get datasource interval error, url: %s, code '%d'", url, response.StatusCode))
	}
	body, err := ParseResponse(response)
	if err != nil {
		return 1, err
	}
	if body["DATA"] == nil || len(body["DATA"].([]interface{})) < 1 {
		return 1, errors.New(fmt.Sprintf("get datasource interval error, url: %s, response: '%v'", url, body))
	}
	return int(body["DATA"].([]interface{})[0].(map[string]interface{})["INTERVAL"].(float64)), nil
}

func GetExtTables(db string, ctx context.Context) (values []interface{}) {
	chClient := client.Client{
		Host:     config.Cfg.Clickhouse.Host,
		Port:     config.Cfg.Clickhouse.Port,
		UserName: config.Cfg.Clickhouse.User,
		Password: config.Cfg.Clickhouse.Password,
		DB:       db,
		Context:  ctx,
	}
	sql := ""
	if db == "ext_metrics" {
		sql = "SELECT table FROM flow_tag.ext_metrics_custom_field GROUP BY table"
		chClient.DB = "flow_tag"
	} else if db == "deepflow_system" {
		sql = "SELECT table FROM flow_tag.deepflow_system_custom_field GROUP BY table"
		chClient.DB = "flow_tag"
	} else {
		sql = "SHOW TABLES FROM " + db
	}
	rst, err := chClient.DoQuery(&client.QueryParams{Sql: sql})
	if err != nil {
		log.Error(err)
		return nil
	}
	for _, _table := range rst.Values {
		table := _table.([]interface{})[0].(string)
		if !strings.HasSuffix(table, "_local") {
			datasources, _ := GetDatasources(db, table)
			values = append(values, []interface{}{table, datasources})
		}
	}
	return values
}

func GetPrometheusTables(db string, ctx context.Context) (values []interface{}) {
	chClient := client.Client{
		Host:     config.Cfg.Clickhouse.Host,
		Port:     config.Cfg.Clickhouse.Port,
		UserName: config.Cfg.Clickhouse.User,
		Password: config.Cfg.Clickhouse.Password,
		DB:       db,
		Context:  ctx,
	}
	sql := ""
	if db == "prometheus" {
		sql = "SELECT table FROM flow_tag.prometheus_custom_field GROUP BY table"
		chClient.DB = "flow_tag"
	} else {
		sql = "SHOW TABLES FROM " + db
	}
	rst, err := chClient.DoQuery(&client.QueryParams{Sql: sql})
	if err != nil {
		log.Error(err)
		return nil
	}
	for _, _table := range rst.Values {
		table := _table.([]interface{})[0].(string)
		if !strings.HasSuffix(table, "_local") {
			datasources, _ := GetDatasources(db, table)
			values = append(values, []interface{}{table, datasources})
		}
	}
	return values
}
