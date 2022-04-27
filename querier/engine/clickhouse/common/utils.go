package common

import (
	"errors"
	"fmt"
	"github.com/xwb1989/sqlparser"
	"regexp"
	"strconv"
	"strings"
	"unicode"
)

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
	for _, r := range alias {
		if unicode.Is(unicode.Scripts["Han"], r) || (regexp.MustCompile("[\u3002\uff1b\uff0c\uff1a\u201c\u201d\uff08\uff09\u3001\uff1f\u300a\u300b]").MatchString(string(r))) {
			return fmt.Sprintf("`%s`", alias)
		}
	}
	// 纯数字带上``
	if _, err := strconv.ParseInt(alias, 10, 64); err == nil {
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
