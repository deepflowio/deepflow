package jsonify

import "net"

func IPIntToString(ipInt uint32) string {
	return net.IPv4(byte(ipInt>>24), byte(ipInt>>16), byte(ipInt>>8), byte(ipInt)).String()
}
