package flowgenerator

import (
	"net"
	"testing"

	. "gitlab.x.lan/yunshan/droplet-libs/datatype"
	. "gitlab.x.lan/yunshan/droplet-libs/utils"
)

func TestServiceKey(t *testing.T) {
	epcID := int16(EPC_FROM_DEEPFLOW)
	ip := IpToUint32(net.ParseIP("192.168.1.1").To4())
	port1 := uint16(80)
	port2 := uint16(8080)
	key1 := ServiceKey(epcID, ip, port1)
	key2 := ServiceKey(epcID, ip, port2)
	if key1 == key2 {
		t.Errorf("key1 %d should not be equal to key2 %d", key1, key2)
	}
}

func TestGetTCPScore(t *testing.T) {
	epcID := int16(EPC_FROM_DEEPFLOW)
	srcIP := IpToUint32(net.ParseIP("192.168.1.1").To4())
	srcPort := uint16(1234)
	dstIP := IpToUint32(net.ParseIP("192.168.1.10").To4())
	dstPort := uint16(80)
	srcKey := ServiceKey(epcID, srcIP, srcPort)
	dstKey := ServiceKey(epcID, dstIP, dstPort)
	srcScore, dstScore := MIN_SCORE, MIN_SCORE
	st := NewServiceTable("", 0, 1024, 1024)

	srcScore, dstScore = st.GetTCPScore(true, TCP_SYN|TCP_ACK, srcKey, dstKey)
	if srcScore != MAX_SCORE || dstScore != MIN_SCORE {
		t.Errorf("对SYN|ACK判断不正确")
	}
	srcScore, dstScore = st.GetTCPScore(false, TCP_SYN|TCP_ACK, srcKey, dstKey)
	if srcScore != MAX_SCORE || dstScore != MIN_SCORE {
		t.Errorf("对SYN|ACK判断不正确")
	}

	srcScore, dstScore = st.GetTCPScore(true, 0, srcKey, dstKey)
	if srcScore != MAX_SCORE || dstScore != MIN_SCORE {
		t.Errorf("其它Flag首包预期不能改变SYN|ACK的Score")
	}
	srcScore, dstScore = st.GetTCPScore(false, 0, srcKey, dstKey)
	if srcScore != MAX_SCORE || dstScore != MIN_SCORE {
		t.Errorf("其它Flag非首包预期不能改变SYN|ACK的Score")
	}

	srcScore, dstScore = st.GetTCPScore(true, TCP_SYN, srcKey, dstKey)
	if srcScore != MIN_SCORE || dstScore != MIN_SCORE+1 {
		t.Errorf("对SYN判断不正确")
	}
	srcScore, dstScore = st.GetTCPScore(false, TCP_SYN, srcKey, dstKey)
	if srcScore != MIN_SCORE || dstScore != MIN_SCORE+1 {
		t.Errorf("对SYN判断不正确")
	}

	srcScore, dstScore = st.GetTCPScore(true, 0, srcKey, dstKey)
	if srcScore != MIN_SCORE || dstScore != MIN_SCORE+2 {
		t.Errorf("对其它Flag首包的判断不正确")
	}
	srcScore, dstScore = st.GetTCPScore(false, 0, srcKey, dstKey)
	if srcScore != MIN_SCORE || dstScore != MIN_SCORE+2 {
		t.Errorf("对其它Flag非首包的判断不正确")
	}
}

func TestGetUDPScore(t *testing.T) {
	epcID := int16(EPC_FROM_DEEPFLOW)
	srcIP := IpToUint32(net.ParseIP("192.168.1.1").To4())
	srcPort := uint16(1234)
	dstIP := IpToUint32(net.ParseIP("192.168.1.10").To4())
	dstPort := uint16(80)
	srcKey := ServiceKey(epcID, srcIP, srcPort)
	dstKey := ServiceKey(epcID, dstIP, dstPort)
	srcScore, dstScore := MIN_SCORE, MIN_SCORE
	st := NewServiceTable("", 0, 1024, 1024)

	srcScore, dstScore = st.GetUDPScore(true, srcKey, dstKey)
	if srcScore != MIN_SCORE || dstScore != MIN_SCORE+1 {
		t.Errorf("对其它Flag首包的判断不正确")
	}
	srcScore, dstScore = st.GetUDPScore(false, srcKey, dstKey)
	if srcScore != MIN_SCORE || dstScore != MIN_SCORE+1 {
		t.Errorf("对其它Flag非首包的判断不正确")
	}
	srcScore, dstScore = st.GetUDPScore(true, srcKey, dstKey)
	if srcScore != MIN_SCORE || dstScore != MIN_SCORE+2 {
		t.Errorf("对其它Flag首包累加的判断不正确")
	}
}
