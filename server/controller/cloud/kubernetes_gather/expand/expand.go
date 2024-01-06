package expand

import (
	"regexp"

	"inet.af/netaddr"

	"github.com/bitly/go-simplejson"
)

func GetPodENV(podData *simplejson.Json, reg *regexp.Regexp, maxLen int) string {
	return ""
}

func GetAnnotation(annotations *simplejson.Json, reg *regexp.Regexp, maxLen int) string {
	return ""
}

func GetIPPool(isSubdomain bool, ip netaddr.IP, k8sData map[string][]string) netaddr.IPPrefix {
	return netaddr.IPPrefix{}
}
