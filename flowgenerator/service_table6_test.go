package flowgenerator

import (
	"net"
	"reflect"
	"testing"

	. "gitlab.x.lan/yunshan/droplet-libs/datatype"
)

func TestServiceKey6(t *testing.T) {
	epcID := int16(EPC_FROM_DEEPFLOW)
	ip := net.ParseIP("1002:1003:4421:5566:7788:99aa:bbcc:ddee")
	port1 := uint16(80)
	port2 := uint16(8080)
	key1 := make([]byte, _KEY_LEN)
	key2 := make([]byte, _KEY_LEN)
	ServiceKey6(key1, epcID, ip, port1)
	ServiceKey6(key2, epcID, ip, port2)
	if reflect.DeepEqual(key1, key2) {
		t.Errorf("key1 %d should not be equal to key2 %d", key1, key2)
	}
}

func TestGetTCPScore6(t *testing.T) {
	epcID := int16(EPC_FROM_DEEPFLOW)
	srcIP := net.ParseIP("1002:1003:4421:5566:7788:99aa:bbcc:ddee")
	srcPort := uint16(1234)
	dstIP := net.ParseIP("1002:1003:4421:5566:7788:99aa:bbcc:ddff")
	dstPort := uint16(80)
	srcKey := make([]byte, _KEY_LEN)
	dstKey := make([]byte, _KEY_LEN)
	ServiceKey6(srcKey, epcID, srcIP, srcPort)
	ServiceKey6(dstKey, epcID, dstIP, dstPort)
	srcScore, dstScore := MIN_SCORE, MIN_SCORE
	st := NewServiceTable6(1024, 1024)

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

func TestGetUDPScore6(t *testing.T) {
	epcID := int16(EPC_FROM_DEEPFLOW)
	srcIP := net.ParseIP("1002:1003:4421:5566:7788:99aa:bbcc:ddee")
	srcPort := uint16(1234)
	dstIP := net.ParseIP("1002:1003:4421:5566:7788:99aa:bbcc:ddff")
	dstPort := uint16(80)
	srcKey := make([]byte, _KEY_LEN)
	dstKey := make([]byte, _KEY_LEN)
	ServiceKey6(srcKey, epcID, srcIP, srcPort)
	ServiceKey6(dstKey, epcID, dstIP, dstPort)
	srcScore, dstScore := MIN_SCORE, MIN_SCORE
	st := NewServiceTable6(1024, 1024)

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
