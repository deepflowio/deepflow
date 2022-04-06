package tag

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	logging "github.com/op/go-logging"
	"metaflow/querier/common"
	"metaflow/querier/config"
	"metaflow/querier/engine/clickhouse/client"
)

var log = logging.MustGetLogger("clickhouse.tag")

var TAG_DESCRIPTIONS = map[string]map[string][]*TagDescription{
	"flow_log": {
		"l4_flow_log": {},
		"l7_flow_log": {},
	},
}
var TAG_ENUMS = map[string][]*TagEnum{}
var tagTypeToOperators = map[string][]string{
	"resource":    []string{"=", "!=", "IN", "NOT IN", "LIKE", "NOT LIKE", "REGEXP", "NOT REGEXP"},
	"int":         []string{"=", "!=", "IN", "NOT IN", ">=", "<="},
	"int_enum":    []string{"=", "!=", "IN", "NOT IN", ">=", "<="},
	"string":      []string{"=", "!=", "IN", "NOT IN", ">=", "<="},
	"string_enum": []string{"=", "!=", "IN", "NOT IN", ">=", "<="},
	"ip":          []string{"=", "!=", "IN", "NOT IN", ">=", "<="},
	"mac":         []string{"=", "!=", "IN", "NOT IN", ">=", "<="},
	"id":          []string{"=", "!=", "IN", "NOT IN"},
	"time":        []string{"=", "!=", ">=", "<="},
	"default":     []string{"=", "!="},
}
var TAG_RESOURCE_TYPE_DEVICE_MAP = map[string]int{
	"vm":          VIF_DEVICE_TYPE_VM,
	"router":      VIF_DEVICE_TYPE_VROUTER,
	"dhcp_port":   VIF_DEVICE_TYPE_DHCP_PORT,
	"pod_service": VIF_DEVICE_TYPE_POD_SERVICE,
	"redis":       VIF_DEVICE_TYPE_REDIS_INSTANCE,
	"rds":         VIF_DEVICE_TYPE_RDS_INSTANCE,
	"lb":          VIF_DEVICE_TYPE_LB,
	"nat_gateway": VIF_DEVICE_TYPE_NAT_GATEWAY,
	"host":        VIF_DEVICE_TYPE_HOST,
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
}

func NewTagDescription(
	name, clientName, serverName, displayName, tagType, enumFile, category, description string,
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
		Description: description,
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
	enumFileToTagName := make(map[string]string)
	enumFileToTagType := make(map[string]string)
	for db, tables := range TAG_DESCRIPTIONS {
		tableData, ok := tagData[db]
		if !ok {
			return errors.New(fmt.Sprintf("get tag failed! db: %s", db))
		}
		for table := range tables {
			tableTagData, ok := tableData.(map[string]interface{})[table]
			if !ok {
				return errors.New(fmt.Sprintf("get metrics failed! db:%s table:%s", db, table))
			}
			// 遍历文件内容进行赋值
			for _, tag := range tableTagData.([][]interface{}) {
				if len(tag) < 8 {
					return errors.New(fmt.Sprintf("get metrics failed! db:%s table:%s, tag:%v", db, table, tag))
				}
				// 0 - Name
				// 1 - ClientName
				// 2 - ServerName
				// 3 - DisplayName
				// 4 - Type
				// 5 - EnumFile
				// 6 - Category
				// 7 - Description
				description := NewTagDescription(
					tag[0].(string), tag[1].(string), tag[2].(string), tag[3].(string),
					tag[4].(string), tag[5].(string), tag[6].(string), tag[7].(string),
				)
				TAG_DESCRIPTIONS[db][table] = append(TAG_DESCRIPTIONS[db][table], description)
				enumFileToTagName[tag[5].(string)] = tag[0].(string)
				enumFileToTagType[tag[5].(string)] = tag[4].(string)
			}
		}
	}

	// 生成tag enum值
	tagEnumData, ok := tagData["enum"]
	if ok {
		for tagEnumFile, enumData := range tagEnumData.(map[string]interface{}) {
			tagEnums := []*TagEnum{}
			// 根据tagEnumFile获取tagTypeToOperators
			tagType, _ := enumFileToTagType[tagEnumFile]

			for _, enumValue := range enumData.([][]interface{}) {
				// 如果是int/int_enum，则将value转为interface
				if tagType == "int" || tagType == "int_enum" {
					value, _ := strconv.Atoi(enumValue[0].(string))
					tagEnums = append(tagEnums, NewTagEnum(value, enumValue[1]))
				} else {
					tagEnums = append(tagEnums, NewTagEnum(enumValue[0], enumValue[1]))
				}
			}
			// 根据tagEnumFile获取tagName
			if tagName, ok := enumFileToTagName[tagEnumFile]; ok {
				TAG_ENUMS[tagName] = tagEnums
			}
		}
	} else {
		return errors.New("get tag enum failed! ")
	}
	return nil
}

func GetTagDescriptions(db, table string) (map[string][]interface{}, error) {
	dbTagDescriptions, ok := TAG_DESCRIPTIONS[db]
	if !ok {
		return nil, errors.New(fmt.Sprintf("no tag in %s.%s", db, table))
	}
	tableTagDescriptions, ok := dbTagDescriptions[table]
	if !ok {
		return nil, errors.New(fmt.Sprintf("no tag in %s.%s", db, table))
	}

	response := map[string][]interface{}{
		"columns": []interface{}{
			"name", "client_name", "server_name", "display_name", "type", "category",
			"operators", "description",
		},
		"values": []interface{}{},
	}
	for _, tag := range tableTagDescriptions {
		response["values"] = append(
			response["values"],
			[]interface{}{
				tag.Name, tag.ClientName, tag.ServerName, tag.DisplayName, tag.Type,
				tag.Category, tag.Operators, tag.Description,
			},
		)
	}
	return response, nil
}

func GetTagValues(db, table, tag string) (map[string][]interface{}, error) {
	tagValues, ok := TAG_ENUMS[tag]
	if !ok {
		return GetTagResourceValues(tag)
	}
	response := map[string][]interface{}{
		"columns": []interface{}{"value", "display_name"},
		"values":  []interface{}{},
	}
	for _, value := range tagValues {
		response["values"] = append(
			response["values"], []interface{}{value.Value, value.DisplayName},
		)
	}
	return response, nil
}

func GetTagResourceValues(tag string) (map[string][]interface{}, error) {
	chClient := client.Client{
		IPs:      config.Cfg.Clickhouse.IPs,
		Port:     config.Cfg.Clickhouse.Port,
		UserName: config.Cfg.Clickhouse.User,
		Password: config.Cfg.Clickhouse.Password,
		DB:       "deepflow",
	}
	err := chClient.Init()
	if err != nil {
		return nil, err
	}
	var sql string
	deviceType, ok := TAG_RESOURCE_TYPE_DEVICE_MAP[tag]
	if ok {
		sql = fmt.Sprintf("SELECT deviceid AS value,name AS display_name FROM device_map WHERE devicetype=%d", deviceType)
	} else if common.IsValueInSliceString(tag, TAG_RESOURCE_TYPE_DEFAULT) {
		sql = fmt.Sprintf("SELECT id as value,name AS display_name FROM %s", tag+"_map")
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
		sql = fmt.Sprintf(
			"SELECT deviceid AS value,name AS display_name,devicetype AS device_type FROM device_map WHERE devicetype in (%s)",
			strings.Join(autoDeviceTypes, ","),
		)
	} else if tag == "vpc" {
		sql = "SELECT id as value,name AS display_name FROM l3_epc_map"
	} else if tag == "ip" {
		// TODO
		return nil, nil
	}
	if sql == "" {
		return nil, errors.New(fmt.Sprintf("tag (%s) not found", tag))
	}
	log.Debug(sql)
	rst, err := chClient.DoQuery(sql)
	if err != nil {
		return nil, err
	}
	return rst, err
}
