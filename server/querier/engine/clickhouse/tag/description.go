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

package tag

import (
	"context"
	"errors"
	"fmt"
	"golang.org/x/exp/slices"
	"regexp"
	"strconv"
	"strings"

	logging "github.com/op/go-logging"

	"github.com/deepflowio/deepflow/server/querier/common"
	"github.com/deepflowio/deepflow/server/querier/config"
	"github.com/deepflowio/deepflow/server/querier/engine/clickhouse/client"
	ckcommon "github.com/deepflowio/deepflow/server/querier/engine/clickhouse/common"
)

var log = logging.MustGetLogger("clickhouse.tag")

// [db][table][tag]*TagDescription
type TagDescriptionKey struct {
	DB      string
	Table   string
	TagName string
}

var TAG_DESCRIPTION_KEYS = []TagDescriptionKey{}
var TAG_DESCRIPTIONS = map[TagDescriptionKey]*TagDescription{}

// key=tagEnumFile
var TAG_ENUMS = map[string][]*TagEnum{}
var TAG_INT_ENUMS = map[string][]*TagEnum{}
var TAG_STRING_ENUMS = map[string][]*TagEnum{}

var tagTypeToOperators = map[string][]string{
	"resource":    []string{"=", "!=", "IN", "NOT IN", "LIKE", "NOT LIKE", "REGEXP", "NOT REGEXP"},
	"int":         []string{"=", "!=", "IN", "NOT IN", ">=", "<="},
	"int_enum":    []string{"=", "!=", "IN", "NOT IN", ">=", "<="},
	"string":      []string{"=", "!=", "IN", "NOT IN", "LIKE", "NOT LIKE", "REGEXP", "NOT REGEXP"},
	"string_enum": []string{"=", "!=", "IN", "NOT IN", "LIKE", "NOT LIKE", "REGEXP", "NOT REGEXP"},
	"ip":          []string{"=", "!=", "IN", "NOT IN", ">=", "<="},
	"time":        []string{"=", "!=", ">=", "<="},
	"mac":         []string{"=", "!=", "IN", "NOT IN"},
	"id":          []string{"=", "!=", "IN", "NOT IN"},
	"default":     []string{"=", "!=", "IN", "NOT IN"},
}
var TAG_RESOURCE_TYPE_DEVICE_MAP = map[string]int{
	"chost":       VIF_DEVICE_TYPE_VM,
	"router":      VIF_DEVICE_TYPE_VROUTER,
	"dhcpgw":      VIF_DEVICE_TYPE_DHCP_PORT,
	"pod_service": VIF_DEVICE_TYPE_POD_SERVICE,
	"redis":       VIF_DEVICE_TYPE_REDIS_INSTANCE,
	"rds":         VIF_DEVICE_TYPE_RDS_INSTANCE,
	"lb":          VIF_DEVICE_TYPE_LB,
	"natgw":       VIF_DEVICE_TYPE_NAT_GATEWAY,
	"host":        VIF_DEVICE_TYPE_HOST,
	"service":     VIF_DEVICE_TYPE_SERVICE,
}

type TagDescription struct {
	Name        string
	ClientName  string
	ServerName  string
	DisplayName string
	Type        string
	EnumFile    string
	Category    string
	Description string
	Operators   []string
	Permissions []bool
	RelatedTag  string
}

func NewTagDescription(
	name, clientName, serverName, displayName, tagType, enumFile, category string,
	permissions []bool, description, relatedTag string,
) *TagDescription {
	operators, ok := tagTypeToOperators[tagType]
	if !ok {
		operators, _ = tagTypeToOperators["default"]
	}
	return &TagDescription{
		Name:        name,
		ClientName:  clientName,
		ServerName:  serverName,
		DisplayName: displayName,
		Type:        tagType,
		EnumFile:    enumFile,
		Category:    category,
		Operators:   operators,
		Permissions: permissions,
		Description: description,
		RelatedTag:  relatedTag,
	}
}

type TagEnum struct {
	Value       interface{}
	DisplayName interface{}
}

func NewTagEnum(value, displayName interface{}) *TagEnum {
	return &TagEnum{
		Value:       value,
		DisplayName: displayName,
	}
}

func LoadTagDescriptions(tagData map[string]interface{}) error {
	// 生成tag description
	enumFileToTagType := make(map[string]string)
	for db, dbTagData := range tagData {
		if db == "enum" {
			continue
		}
		for table, tableTagData := range dbTagData.(map[string]interface{}) {
			// common.Result
			for i, tag := range tableTagData.([][]interface{}) {
				if strings.Contains(table, ".") {
					continue
				}
				if len(tag) < 7 {
					return errors.New(
						fmt.Sprintf("get tag failed! db:%s table:%s, tag:%v", db, table, tag),
					)
				}
				// 0 - Name
				// 1 - ClientName
				// 2 - ServerName
				// 3 - DisplayName
				// 4 - Type
				// 5 - EnumFile
				// 6 - Category
				// 7 - Permissions
				// 8 - Description
				// 9 - RelatedTag
				permissions, err := ckcommon.ParsePermission(tag[6])
				if err != nil {
					return errors.New(
						fmt.Sprintf(
							"parse tag permission failed! db:%s table:%s, tag:%v, err:%s",
							db, table, tag, err.Error(),
						),
					)
				}
				relatedTag := ""
				if db == "event" && common.IsValueInSliceString(tag[0].(string), []string{"ips", "subnets"}) {
					relatedTag = strings.TrimSuffix(tag[0].(string), "s")
				}
				key := TagDescriptionKey{DB: db, Table: table, TagName: tag[0].(string)}
				tagLanguage := dbTagData.(map[string]interface{})[table+"."+config.Cfg.Language].([][]interface{})[i]
				TAG_DESCRIPTION_KEYS = append(TAG_DESCRIPTION_KEYS, key)
				enumFile := tag[4].(string)
				if !common.IsValueInSliceString(enumFile, NoLanguageTag) {
					enumFile = tag[4].(string) + "." + config.Cfg.Language
				}
				displayName := tagLanguage[1].(string)
				des := tagLanguage[2].(string)
				description := NewTagDescription(
					tag[0].(string), tag[1].(string), tag[2].(string), displayName,
					tag[3].(string), enumFile, tag[5].(string), permissions, des, relatedTag,
				)
				TAG_DESCRIPTIONS[key] = description
				enumFileToTagType[enumFile] = tag[3].(string)
			}
		}
	}

	// 生成tag enum值
	tagEnumData, ok := tagData["enum"]
	if ok {
		for tagEnumFile, enumData := range tagEnumData.(map[string]interface{}) {
			tagEnums := []*TagEnum{}
			tagIntEnums := []*TagEnum{}
			tagStringEnums := []*TagEnum{}
			// 根据tagEnumFile获取tagTypeToOperators
			tagType, _ := enumFileToTagType[tagEnumFile]

			for _, enumValue := range enumData.([][]interface{}) {
				// 如果是int/int_enum，则将value转为interface
				if tagType == "int" || tagType == "int_enum" || tagType == "bit_enum" {
					value, _ := strconv.Atoi(enumValue[0].(string))
					tagIntEnums = append(tagIntEnums, NewTagEnum(enumValue[0], enumValue[1]))
					tagEnums = append(tagEnums, NewTagEnum(value, enumValue[1]))
				} else if tagType == "string_enum" {
					tagStringEnums = append(tagEnums, NewTagEnum(enumValue[0], enumValue[1]))
					tagEnums = append(tagEnums, NewTagEnum(enumValue[0], enumValue[1]))
				}
			}
			if len(tagIntEnums) != 0 {
				TAG_INT_ENUMS[tagEnumFile] = tagIntEnums
			}
			if len(tagStringEnums) != 0 {
				TAG_STRING_ENUMS[tagEnumFile] = tagStringEnums
			}
			TAG_ENUMS[tagEnumFile] = tagEnums
		}
	} else {
		return errors.New("get tag enum failed! ")
	}
	return nil
}

func GetTagDescriptions(db, table, rawSql string, ctx context.Context) (response *common.Result, err error) {
	// 把`1m`的反引号去掉
	table = strings.Trim(table, "`")
	response = &common.Result{
		Columns: []interface{}{
			"name", "client_name", "server_name", "display_name", "type", "category",
			"operators", "permissions", "description", "related_tag",
		},
		Values: []interface{}{},
	}

	for _, key := range TAG_DESCRIPTION_KEYS {
		if key.DB != db || (key.Table != table && db != "ext_metrics" && db != "deepflow_system") {
			continue
		}
		tag, _ := TAG_DESCRIPTIONS[key]
		response.Values = append(
			response.Values,
			[]interface{}{
				tag.Name, tag.ClientName, tag.ServerName, tag.DisplayName, tag.Type,
				tag.Category, tag.Operators, tag.Permissions, tag.Description, tag.RelatedTag,
			},
		)
	}

	// 查询 k8s_label
	chClient := client.Client{
		Host:     config.Cfg.Clickhouse.Host,
		Port:     config.Cfg.Clickhouse.Port,
		UserName: config.Cfg.Clickhouse.User,
		Password: config.Cfg.Clickhouse.Password,
		DB:       "flow_tag",
		Context:  ctx,
	}
	sql := "SELECT key FROM k8s_label_map GROUP BY key"
	rst, err := chClient.DoQuery(&client.QueryParams{Sql: sql})
	if err != nil {
		return nil, err
	}
	for _, _key := range rst.Values {
		key := _key.([]interface{})[0]
		labelKey := "label." + key.(string)
		if db == "ext_metrics" || db == "event" || table == "vtap_flow_port" || table == "vtap_app_port" {
			response.Values = append(response.Values, []interface{}{
				labelKey, labelKey, labelKey, labelKey, "label",
				"K8s Labels", tagTypeToOperators["string"], []bool{true, true, true}, "", "",
			})
		} else if db != "deepflow_system" && table != "vtap_acl" && table != "l4_packet" && table != "l7_packet" {
			response.Values = append(response.Values, []interface{}{
				labelKey, labelKey + "_0", labelKey + "_1", labelKey, "label",
				"K8s Labels", tagTypeToOperators["string"], []bool{true, true, true}, "", "",
			})
		}

	}

	// 查询外部字段
	if (db != "ext_metrics" && db != "flow_log" && db != "deepflow_system") || (db == "flow_log" && table != "l7_flow_log") {
		return response, nil
	}
	externalChClient := client.Client{
		Host:     config.Cfg.Clickhouse.Host,
		Port:     config.Cfg.Clickhouse.Port,
		UserName: config.Cfg.Clickhouse.User,
		Password: config.Cfg.Clickhouse.Password,
		DB:       "flow_tag",
		Context:  ctx,
	}
	var whereSql string
	if strings.Contains(rawSql, "WHERE") {
		whereSql = strings.Split(rawSql, "WHERE")[1]
	}
	externalSql := ""
	if whereSql != "" {
		externalSql = fmt.Sprintf("SELECT field_name AS tag_name FROM %s_custom_field WHERE table='%s' AND field_type='tag' AND (%s) GROUP BY tag_name ORDER BY tag_name ASC", db, table, whereSql)
	} else {
		externalSql = fmt.Sprintf("SELECT field_name AS tag_name FROM %s_custom_field WHERE table='%s' AND field_type='tag' GROUP BY tag_name ORDER BY tag_name ASC", db, table)
	}
	externalRst, err := externalChClient.DoQuery(&client.QueryParams{Sql: externalSql})
	if err != nil {
		return nil, err
	}
	for _, _tagName := range externalRst.Values {
		tagName := _tagName.([]interface{})[0]
		if db == "ext_metrics" || db == "deepflow_system" {
			externalTag := "tag." + tagName.(string)
			response.Values = append(response.Values, []interface{}{
				externalTag, externalTag, externalTag, externalTag, "tag",
				"Tag", tagTypeToOperators["string"], []bool{true, true, true}, externalTag, "",
			})
		} else {
			externalTag := "attribute." + tagName.(string)
			response.Values = append(response.Values, []interface{}{
				externalTag, externalTag, externalTag, externalTag, "attribute",
				"Attributes", tagTypeToOperators["string"], []bool{true, true, true}, externalTag, "",
			})
		}
	}
	if db == "ext_metrics" || db == "deepflow_system" {
		response.Values = append(response.Values, []interface{}{
			"tags", "tags", "tags", "tags", "map",
			"Tag", []string{}, []bool{true, true, true}, "tags", "",
		})
	}
	return response, nil
}

func GetEnumTagValues(db, table, sql string) (map[string][]interface{}, error) {
	// 把`1m`的反引号去掉
	table = strings.Trim(table, "`")
	// 获取tagEnumFile
	sqlSplit := strings.Split(sql, " ")
	tag := sqlSplit[2]
	tag = strings.Trim(tag, "'")
	response := map[string][]interface{}{}
	if tag == "all_int_enum" {
		for key, tagValue := range TAG_INT_ENUMS {
			tagValues := []interface{}{}
			for _, value := range tagValue {
				tagValues = append(tagValues, []interface{}{value.Value, value.DisplayName})
			}
			response[key] = tagValues
		}
	}
	if tag == "all_string_enum" {
		for key, tagValue := range TAG_STRING_ENUMS {
			tagValues := []interface{}{}
			for _, value := range tagValue {
				tagValues = append(tagValues, []interface{}{value.Value, value.DisplayName})
			}
			response[key] = tagValues
		}
	}
	return response, nil
}

func GetTagValues(db, table, sql string) (*common.Result, []string, error) {
	// 把`1m`的反引号去掉
	table = strings.Trim(table, "`")
	// 获取tagEnumFile
	sqlSplit := strings.Split(sql, " ")
	tag := sqlSplit[2]
	tag = strings.Trim(tag, "'")
	var sqlList []string
	var rgx = regexp.MustCompile(`(?i)show|SHOW +tag +\S+ +values +from|FROM +\S+( +(where|WHERE \S+ like|LIKE \S+))?`)
	sqlOk := rgx.MatchString(sql)
	if !sqlOk {
		return nil, sqlList, errors.New(fmt.Sprintf("sql synax error: %s ", sql))
	}
	showSqlList := strings.Split(sql, "WHERE")
	if len(showSqlList) == 1 {
		showSqlList = strings.Split(sql, "where")
	}
	//Enum($tag_name) replace in with column 'display_name'
	//$tag_name replace in with column 'value'
	if len(showSqlList) > 1 {
		showSqlList[1] = strings.ReplaceAll(showSqlList[1], "Enum("+tag+")", "display_name")
		showSqlList[1] = strings.ReplaceAll(showSqlList[1], " "+tag, " value")
		showSqlList[1] = strings.ReplaceAll(showSqlList[1], "("+tag, "(value")
		showSqlList[1] = strings.ReplaceAll(showSqlList[1], "value_id", tag+"_id")
		showSqlList[1] = strings.ReplaceAll(showSqlList[1], "value_ns_id", tag+"_ns_id")
		sql = showSqlList[0] + " WHERE " + showSqlList[1]
	}
	// K8s Labels是动态的,不需要去tag_description里确认
	if strings.HasPrefix(tag, "label.") {
		return GetTagResourceValues(db, table, sql)
	}
	// 外部字段是动态的,不需要去tag_description里确认
	if strings.HasPrefix(tag, "tag.") || strings.HasPrefix(tag, "attribute.") {
		return GetExternalTagValues(db, table, sql)
	}
	if db == "ext_metrics" {
		table = "ext_common"
	} else if db == "deepflow_system" {
		table = "deepflow_system_common"
	}
	tagDescription, ok := TAG_DESCRIPTIONS[TagDescriptionKey{
		DB: db, Table: table, TagName: tag,
	}]
	if !ok {
		return nil, sqlList, errors.New(fmt.Sprintf("no tag %s in %s.%s", tag, db, table))
	}
	if db == "event" {
		sql = strings.ReplaceAll(sql, "subnets", "subnet")
	}
	// 根据tagEnumFile获取values
	_, isEnumOK := TAG_ENUMS[tagDescription.EnumFile]
	if !isEnumOK {
		return GetTagResourceValues(db, table, sql)
	}

	_, isStringEnumOK := TAG_STRING_ENUMS[tagDescription.EnumFile]
	if isStringEnumOK {
		table = "string_enum_map"
		tag = strings.TrimSuffix(tagDescription.EnumFile, "."+config.Cfg.Language)
	}
	_, isIntEnumOK := TAG_INT_ENUMS[tagDescription.EnumFile]
	if isIntEnumOK {
		table = "int_enum_map"
		tag = strings.TrimSuffix(tagDescription.EnumFile, "."+config.Cfg.Language)
	}

	var limitSql string
	var likeSql string
	var whereSql string
	var orderBy = "value"
	limitList := strings.Split(sql, "LIMIT")
	if len(limitList) <= 1 {
		limitList = strings.Split(sql, "limit")
	}
	likeSql = limitList[0]
	if len(limitList) > 1 {
		limitSql = " LIMIT " + limitList[1]
	}
	likeList := strings.Split(likeSql, "WHERE")
	if len(likeList) == 1 {
		likeList = strings.Split(likeSql, "where")
	}
	if len(likeList) > 1 {
		if strings.Trim(likeList[1], " ") != "" {
			whereSql = " AND (" + strings.ReplaceAll(likeList[1], "*", "%") + ")"
		}
	}
	if strings.Contains(strings.ToLower(sql), "like") || strings.Contains(strings.ToLower(sql), "regexp") {
		orderBy = "length(display_name)"
	}
	sql = fmt.Sprintf("SELECT value,name AS display_name FROM %s WHERE tag_name='%s' %s GROUP BY value, display_name ORDER BY %s ASC %s", table, tag, whereSql, orderBy, limitSql)
	log.Debug(sql)
	sqlList = append(sqlList, sql)
	return nil, sqlList, nil

}

func GetTagResourceValues(db, table, rawSql string) (*common.Result, []string, error) {
	chClient := client.Client{
		Host:     config.Cfg.Clickhouse.Host,
		Port:     config.Cfg.Clickhouse.Port,
		UserName: config.Cfg.Clickhouse.User,
		Password: config.Cfg.Clickhouse.Password,
		DB:       "flow_tag",
	}
	sqlSplit := strings.Split(rawSql, " ")
	tag := sqlSplit[2]
	tag = strings.Trim(tag, "'")
	var sqlList []string
	var sql string
	var whereSql string
	var limitSql string
	var isAdminFlag bool
	var orderBy = "value"
	if strings.Contains(rawSql, "value!=''") || strings.Contains(rawSql, "value!=0") {
		isAdminFlag = false
	} else {
		isAdminFlag = true
	}
	if strings.Contains(strings.ToLower(rawSql), "like") || strings.Contains(strings.ToLower(rawSql), "regexp") {
		orderBy = "length(display_name)"
	}

	if strings.Contains(rawSql, "WHERE") || strings.Contains(rawSql, "where") {
		if len(strings.Split(rawSql, "WHERE")) == 1 {
			whereSql = strings.Split(rawSql, "where")[1]
		} else {
			whereSql = strings.Split(rawSql, "WHERE")[1]
		}
		whereLimitList := strings.Split(whereSql, "LIMIT")
		if len(whereLimitList) <= 1 {
			whereLimitList = strings.Split(whereSql, "limit")
		}

		if strings.Trim(whereLimitList[0], " ") != "" {
			whereSql = " WHERE (" + strings.ReplaceAll(whereLimitList[0], "*", "%") + ")"
		}
	}

	limitList := strings.Split(rawSql, "LIMIT")
	if len(limitList) <= 1 {
		limitList = strings.Split(rawSql, "limit")
	}
	if len(limitList) > 1 {
		limitSql = " LIMIT " + limitList[1]
	}
	if !isAdminFlag {
		switch tag {
		case "resource_gl0", "resource_gl1", "resource_gl2":
			results := &common.Result{}
			for resourceKey, resourceType := range AutoMap {
				// 增加资源ID
				resourceId := resourceKey + "_id"
				resourceName := resourceKey + "_name"
				sql = fmt.Sprintf("SELECT %s AS value,%s AS display_name, %s AS device_type, uid FROM ip_resource_map %s GROUP BY value, display_name, device_type, uid ORDER BY %s ASC %s", resourceId, resourceName, strconv.Itoa(resourceType), whereSql, orderBy, limitSql)
				sql = strings.ReplaceAll(sql, " like ", " ilike ")
				sql = strings.ReplaceAll(sql, " LIKE ", " ILIKE ")
				log.Debug(sql)
				rst, err := chClient.DoQuery(&client.QueryParams{Sql: sql})
				if err != nil {
					return results, sqlList, err
				}
				results.Values = append(results.Values, rst.Values...)
			}
			autoMap := map[string]map[string]int{
				"resource_gl0": AutoPodMap,
				"resource_gl1": AutoPodGroupMap,
				"resource_gl2": AutoServiceMap,
			}
			for resourceKey, resourceType := range autoMap[tag] {
				if slices.Contains(PodGroupTypeSlice, resourceKey) {
					continue
				}
				resourceId := resourceKey + "_id"
				resourceName := resourceKey + "_name"
				if resourceKey == "service" {
					resourceId = "pod_service_id"
					resourceName = "pod_service_name"
				}
				sql = fmt.Sprintf("SELECT %s AS value,%s AS display_name, %s AS device_type, uid FROM ip_resource_map %s GROUP BY value, display_name, device_type, uid ORDER BY %s ASC %s", resourceId, resourceName, strconv.Itoa(resourceType), whereSql, orderBy, limitSql)
				sql = strings.ReplaceAll(sql, " like ", " ilike ")
				sql = strings.ReplaceAll(sql, " LIKE ", " ILIKE ")
				log.Debug(sql)
				rst, err := chClient.DoQuery(&client.QueryParams{Sql: sql})
				if err != nil {
					return results, sqlList, err
				}
				results.Values = append(results.Values, rst.Values...)
				results.Columns = rst.Columns
			}
			return results, sqlList, nil
		}

		switch tag {
		case "chost", "rds", "redis", "lb", "natgw":
			resourceId := tag + "_id"
			resourceName := tag + "_name"
			sql = fmt.Sprintf("SELECT %s AS value,%s AS display_name, uid FROM ip_resource_map %s GROUP BY value, display_name, uid ORDER BY %s ASC %s", resourceId, resourceName, whereSql, orderBy, limitSql)

		case "vpc", "l2_vpc":
			sql = fmt.Sprintf("SELECT vpc_id AS value, vpc_name AS display_name, uid FROM ip_resource_map %s GROUP BY value, display_name, uid ORDER BY %s ASC %s", whereSql, orderBy, limitSql)

		case "service", "router", "host", "dhcpgw", "pod_service", "ip", "lb_listener", "pod_ingress", "az", "region", "pod_cluster", "pod_ns", "pod_node", "pod_group", "pod", "subnet":
			resourceId := tag + "_id"
			resourceName := tag + "_name"
			if tag == "ip" {
				resourceId = "ip"
				resourceName = "ip"
			} else if tag == "service" {
				resourceId = "pod_service_id"
				resourceName = "pod_service_name"
			}
			sql = fmt.Sprintf("SELECT %s AS value,%s AS display_name FROM ip_resource_map %s GROUP BY value, display_name ORDER BY %s ASC %s", resourceId, resourceName, whereSql, orderBy, limitSql)

		case "tap":
			sql = fmt.Sprintf("SELECT value, name AS display_name FROM tap_type_map %s GROUP BY value, display_name ORDER BY %s ASC %s", whereSql, orderBy, limitSql)

		case "vtap":
			sql = fmt.Sprintf("SELECT id AS value, name AS display_name FROM vtap_map %s GROUP BY value, display_name ORDER BY %s ASC %s", whereSql, orderBy, limitSql)
		case common.TAP_PORT_HOST, common.TAP_PORT_CHOST, common.TAP_PORT_POD_NODE:
			if whereSql != "" {
				whereSql += fmt.Sprintf(" AND device_type=%d", TAP_PORT_DEVICE_MAP[tag])
			} else {
				whereSql = fmt.Sprintf(" WHERE device_type=%d", TAP_PORT_DEVICE_MAP[tag])
			}
			sql = fmt.Sprintf("SELECT device_id AS value, device_name AS display_name FROM vtap_port_map %s GROUP BY value, display_name ORDER BY %s ASC %s", whereSql, orderBy, limitSql)
		default:
			if strings.HasPrefix(tag, "label.") {
				labelTag := strings.TrimPrefix(tag, "label.")
				if whereSql != "" {
					whereSql += fmt.Sprintf(" AND `key`='%s'", labelTag)
				} else {
					whereSql = fmt.Sprintf("WHERE `key`='%s'", labelTag)
				}
				sql = fmt.Sprintf("SELECT value, value AS display_name FROM k8s_label_map %s GROUP BY value, display_name ORDER BY %s ASC %s", whereSql, orderBy, limitSql)
			} else {
				return GetExternalTagValues(db, table, rawSql)
			}
		}
		sql = strings.ReplaceAll(sql, " like ", " ilike ")
		sql = strings.ReplaceAll(sql, " LIKE ", " ILIKE ")
		log.Debug(sql)
		rst, err := chClient.DoQuery(&client.QueryParams{Sql: sql})
		if err != nil {
			return nil, nil, err
		}
		return rst, sqlList, nil
	} else {
		deviceType, ok := TAG_RESOURCE_TYPE_DEVICE_MAP[tag]
		if ok {
			if whereSql != "" {
				whereSql += fmt.Sprintf("AND devicetype=%d", deviceType)
			} else {
				whereSql = fmt.Sprintf("WHERE devicetype=%d", deviceType)
			}
			sql = fmt.Sprintf("SELECT deviceid AS value,name AS display_name,uid FROM device_map %s GROUP BY value, display_name, uid ORDER BY %s ASC %s", whereSql, orderBy, limitSql)
		} else if common.IsValueInSliceString(tag, TAG_RESOURCE_TYPE_DEFAULT) {
			sql = fmt.Sprintf("SELECT id as value,name AS display_name FROM %s %s GROUP BY value, display_name ORDER BY %s ASC %s", tag+"_map", whereSql, orderBy, limitSql)
		} else if common.IsValueInSliceString(tag, TAG_RESOURCE_TYPE_AUTO) {
			var autoDeviceTypes []string
			for _, deviceType := range AutoMap {
				autoDeviceTypes = append(autoDeviceTypes, strconv.Itoa(deviceType))
			}
			autoMap := map[string]map[string]int{
				"resource_gl0": AutoPodMap,
				"resource_gl1": AutoPodGroupMap,
				"resource_gl2": AutoServiceMap,
			}
			for _, deviceType := range autoMap[tag] {
				autoDeviceTypes = append(autoDeviceTypes, strconv.Itoa(deviceType))
			}
			if whereSql != "" {
				whereSql += fmt.Sprintf("AND devicetype in (%s)", strings.Join(autoDeviceTypes, ","))
			} else {
				whereSql = fmt.Sprintf("WHERE devicetype in (%s)", strings.Join(autoDeviceTypes, ","))
			}
			sql = fmt.Sprintf(
				"SELECT deviceid AS value,name AS display_name,devicetype AS device_type,uid FROM device_map %s GROUP BY value, display_name, device_type, uid ORDER BY %s ASC %s",
				whereSql, orderBy, limitSql,
			)
		} else if tag == "vpc" || tag == "l2_vpc" {
			sql = fmt.Sprintf("SELECT id as value,name AS display_name,uid FROM l3_epc_map %s GROUP BY value, display_name, uid ORDER BY %s ASC %s", whereSql, orderBy, limitSql)
		} else if tag == "ip" {
			sql = fmt.Sprintf("SELECT ip as value,ip AS display_name FROM ip_relation_map %s GROUP BY value, display_name ORDER BY %s ASC %s", whereSql, orderBy, limitSql)
		} else if tag == "tap" {
			sql = fmt.Sprintf("SELECT value, name AS display_name FROM tap_type_map %s GROUP BY value, display_name ORDER BY %s ASC %s", whereSql, orderBy, limitSql)
		} else if tag == "vtap" {
			sql = fmt.Sprintf("SELECT id as value, name AS display_name FROM vtap_map %s GROUP BY value, display_name ORDER BY %s ASC %s", whereSql, orderBy, limitSql)
		} else if tag == "lb_listener" {
			sql = fmt.Sprintf("SELECT id as value, name AS display_name FROM lb_listener_map %s GROUP BY value, display_name ORDER BY %s ASC %s", whereSql, orderBy, limitSql)
		} else if tag == common.TAP_PORT_HOST || tag == common.TAP_PORT_CHOST || tag == common.TAP_PORT_POD_NODE {
			if whereSql != "" {
				whereSql += fmt.Sprintf(" AND device_type=%d", TAP_PORT_DEVICE_MAP[tag])
			} else {
				whereSql = fmt.Sprintf(" WHERE device_type=%d", TAP_PORT_DEVICE_MAP[tag])
			}
			sql = fmt.Sprintf("SELECT device_id AS value, device_name AS display_name FROM vtap_port_map %s GROUP BY value, display_name ORDER BY %s ASC %s", whereSql, orderBy, limitSql)
		} else if tag == "pod_ingress" {
			sql = fmt.Sprintf("SELECT id as value, name AS display_name FROM pod_ingress_map %s GROUP BY value, display_name ORDER BY %s ASC %s", whereSql, orderBy, limitSql)
		} else if strings.HasPrefix(tag, "label.") {
			labelTag := strings.TrimPrefix(tag, "label.")
			if whereSql != "" {
				whereSql += fmt.Sprintf(" AND `key`='%s'", labelTag)
			} else {
				whereSql = fmt.Sprintf("WHERE `key`='%s'", labelTag)
			}
			sql = fmt.Sprintf("SELECT value, value AS display_name FROM k8s_label_map %s GROUP BY value, display_name ORDER BY %s ASC %s", whereSql, orderBy, limitSql)
		}
		if sql == "" {
			return GetExternalTagValues(db, table, rawSql)
		}
		log.Debug(sql)
		sqlList = append(sqlList, sql)
		return nil, sqlList, nil
	}
}

func GetExternalTagValues(db, table, rawSql string) (*common.Result, []string, error) {
	sqlSplit := strings.Split(rawSql, " ")
	tag := sqlSplit[2]
	tag = strings.Trim(tag, "'")
	tag = strings.TrimPrefix(tag, "tag.")
	tag = strings.TrimPrefix(tag, "attribute.")
	var sqlList []string
	var whereSql string
	var orderBy = "sum(count) DESC"
	if strings.Contains(strings.ToLower(rawSql), "like") || strings.Contains(strings.ToLower(rawSql), "regexp") {
		orderBy = "length(display_name) ASC"
	}
	limitSql := "LIMIT 10000"
	if strings.Contains(rawSql, "WHERE") || strings.Contains(rawSql, "where") {
		if len(strings.Split(rawSql, "WHERE")) == 1 {
			whereSql = strings.Split(rawSql, "where")[1]
		} else {
			whereSql = strings.Split(rawSql, "WHERE")[1]
		}
		whereLimitList := strings.Split(whereSql, "LIMIT")
		if len(whereLimitList) <= 1 {
			whereLimitList = strings.Split(whereSql, "limit")
		}
		if strings.Trim(whereLimitList[0], " ") != "" {
			whereSql = fmt.Sprintf(" AND (%s)", strings.ReplaceAll(whereLimitList[0], "*", "%"))
		}
	}
	limitList := strings.Split(rawSql, "LIMIT")
	if len(limitList) <= 1 {
		limitList = strings.Split(rawSql, "limit")
	}
	if len(limitList) > 1 {
		limitSql = " LIMIT " + limitList[1]
	}

	var sql string
	if whereSql != "" {
		sql = fmt.Sprintf("SELECT field_value AS value, value AS display_name FROM %s_custom_field_value WHERE 'table'='%s' AND field_type='tag' AND field_name='%s' %s GROUP BY value, display_name ORDER BY %s %s", db, table, tag, whereSql, orderBy, limitSql)
	} else {
		sql = fmt.Sprintf("SELECT field_value AS value, value AS display_name FROM %s_custom_field_value WHERE 'table'='%s' AND field_type='tag' AND field_name='%s' GROUP BY value, display_name ORDER BY %s %s", db, table, tag, orderBy, limitSql)
	}
	log.Debug(sql)
	sqlList = append(sqlList, sql)
	return nil, sqlList, nil
}
