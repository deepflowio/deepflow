package common

import (
	"fmt"
	"github.com/xwb1989/sqlparser"
	"strings"
)

func ParseAlias(node sqlparser.SQLNode) string {
	as := strings.Trim(strings.Trim(sqlparser.String(node), "'"), "`")
	return fmt.Sprintf("`%s`", as)
}
