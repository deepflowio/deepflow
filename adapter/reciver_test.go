package adapter

import (
	"net"
	"testing"

	"golang.org/x/sys/unix"
)

func TestReciver(t *testing.T) {
	r := &reciver{}
	r.init(64, nil)
	host := net.ParseIP("1.2.3.4").To4()
	instance := &tridentInstance{true, host, [TRIDENT_DISPATCHER_MAX]tridentDispatcher{}}
	r.addInstance(10, instance)
	r.deleteInstance(host)
	instances := r.GetInstances()
	if len(instances) > 0 {
		t.Errorf("GetInstances expect 0 actual %v", len(instances))
	}
	packet := acquirePacketBuffer()
	releasePacketBuffer(packet)
}

func TestGetIp(t *testing.T) {
	hostV4 := net.ParseIP("1.2.3.4").To4()
	v4 := &unix.SockaddrInet4{}
	copy(v4.Addr[:], hostV4[:])
	ip := getIp(v4).To4()
	if !ip.Equal(hostV4) {
		t.Errorf("getIp expect %v actual %v", hostV4, ip)
	}

	hostV6 := net.ParseIP("2002::2020")
	v6 := &unix.SockaddrInet6{}
	copy(v6.Addr[:], hostV6[:])
	ip = getIp(v6)
	if !ip.Equal(hostV6) {
		t.Errorf("getIp expect %v actual %v", hostV6, ip)
	}
}

func TestTimeout(t *testing.T) {
	timeoutError := timeoutError("test")
	if timeoutError.Error() != "test" {
		t.Errorf("Error expect test actual %v\n", timeoutError.Error())
	}
	if !timeoutError.Timeout() {
		t.Error("Timeout expect true actual false")
	}
}
