package tagrecorder

import (
	"encoding/json"
	"strings"
)

// a:b,c:d -> {"a":"b","c":"d"}, map[string]string{"a":"b","c":"d"}
func StrToJsonAndMap(str string) (resJson string, resMap map[string]string) {
	if str == "" {
		return
	}
	m := map[string]string{}
	multiPairStr := strings.Split(str, ", ")
	for _, pairStr := range multiPairStr {
		pair := strings.SplitN(pairStr, ":", 2)
		if len(pair) == 2 {
			m[strings.Trim(pair[0], " ")] = strings.Trim(pair[1], " ")
		}
	}
	resMap = m
	if len(m) == 0 {
		return
	}
	jsonStr, err := json.Marshal(m)
	if err != nil {
		return
	}
	resJson = string(jsonStr)
	return
}
