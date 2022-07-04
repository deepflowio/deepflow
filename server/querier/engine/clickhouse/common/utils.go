package common

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"unicode"

	"github.com/metaflowys/metaflow/server/querier/config"
	"github.com/metaflowys/metaflow/server/querier/engine/clickhouse/client"
	logging "github.com/op/go-logging"
	"github.com/xwb1989/sqlparser"
)

var log = logging.MustGetLogger("common")

func ParseAlias(node sqlparser.SQLNode) string {
	alias := sqlparser.String(node)
	// 判断字符串首尾是否为单引号或者反引号
	if (strings.HasPrefix(alias, "'") && strings.HasSuffix(alias, "'")) ||
		(strings.HasPrefix(alias, "`") && strings.HasSuffix(alias, "`")) {
		alias = strings.Trim(strings.Trim(alias, "'"), "`")
	} else {
		return alias
	}

	// 中文带上``
	// 部分特殊字符带上`
	for _, r := range alias {
		if unicode.Is(unicode.Scripts["Han"], r) || (regexp.MustCompile("[\u3002\uff1b\uff0c\uff1a\u201c\u201d\uff08\uff09\u3001\uff1f\u300a\u300b]").MatchString(string(r))) {
			return fmt.Sprintf("`%s`", alias)
		}
		if string(r) == "(" || string(r) == ")" {
			return fmt.Sprintf("`%s`", alias)
		}
	}
	// 纯数字带上``
	if _, err := strconv.ParseInt(alias, 10, 64); err == nil {
		return fmt.Sprintf("`%s`", alias)
	}
	// k8s标签字带上``
	if strings.HasPrefix(alias, "label.") {
		return fmt.Sprintf("`%s`", alias)
	}
	// 外部字段带上``
	if strings.HasPrefix(alias, "tag.") || strings.HasPrefix(alias, "attribute.") {
		return fmt.Sprintf("`%s`", alias)
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

func GetDatasourceInterval(db string, table string, name string) (int, error) {
	var tsdbType string
	switch db {
	case "flow_log":
		return 1, nil
	case "flow_metrics":
		if table == "vtap_flow_port" || table == "vtap_flow_edge_port" {
			tsdbType = "flow"
		} else if table == "vtap_app_port" || table == "vtap_app_edge_port" {
			tsdbType = "app"
		}
	}
	client := &http.Client{}
	url := fmt.Sprintf("http://localhost:20417/v1/data-sources/?name=%s&type=%s", name, tsdbType)
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

func GetExtTables(db string) (values []interface{}) {
	chClient := client.Client{
		Host:     config.Cfg.Clickhouse.Host,
		Port:     config.Cfg.Clickhouse.Port,
		UserName: config.Cfg.Clickhouse.User,
		Password: config.Cfg.Clickhouse.Password,
		DB:       db,
	}
	err := chClient.Init("")
	if err != nil {
		log.Error(err)
		return nil
	}
	sql := "show tables"
	rst, err := chClient.DoQuery(sql, nil)
	if err != nil {
		log.Error(err)
		return nil
	}
	for _, _table := range rst["values"] {
		table := _table.([]interface{})[0].(string)
		if !strings.HasSuffix(table, "_local") {
			values = append(values, []string{table})
		}
	}
	return values
}
