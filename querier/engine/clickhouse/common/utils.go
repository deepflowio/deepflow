package common

import (
	"fmt"
	"github.com/xwb1989/sqlparser"
	"regexp"
	"strings"
	"unicode"
)

func ParseAlias(node sqlparser.SQLNode) string {
	alias := strings.Trim(strings.Trim(sqlparser.String(node), "'"), "`")
	// 中文带上``
	for _, r := range alias {
		if unicode.Is(unicode.Scripts["Han"], r) || (regexp.MustCompile("[\u3002\uff1b\uff0c\uff1a\u201c\u201d\uff08\uff09\u3001\uff1f\u300a\u300b]").MatchString(string(r))) {
			return fmt.Sprintf("`%s`", alias)
		}
	}
	return alias
}
