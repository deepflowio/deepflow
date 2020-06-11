package zerodoc

import (
	"reflect"
	"testing"
	"time"

	"gitlab.x.lan/yunshan/droplet-libs/app"
)

func TestGeoMeterFill(t *testing.T) {
	f := &GeoMeter{}

	fields := []string{
		"packet_tx", "packet_rx", "byte_tx", "byte_rx", "flow", "new_flow", "closed_flow",
		"rtt", "rtt_client", "rtt_server", "srt", "art",
		"retrans_tx", "retrans_rx", "zero_win_tx", "zero_win_rx",
		"client_rst_flow", "server_rst_flow", "client_half_open_flow", "server_half_open_flow",
		"client_half_close_flow", "server_half_close_flow", "timeout_tcp_flow",
	}
	var values []interface{}
	for i := range fields {
		values = append(values, int64(i+1))
	}
	mixLocation := len(fields) / 3
	mixedKeys := append(fields[:mixLocation+1], fields[mixLocation:]...)
	mixedKeys[mixLocation] = "ip"
	mixedValues := append(values[:mixLocation+1], values[mixLocation:]...)
	mixedValues[mixLocation] = "ip"
	f.Fill(GetColumnIDs(mixedKeys), mixedValues)

	results := []interface{}{
		f.PacketTx, f.PacketRx, f.ByteTx, f.ByteRx, f.Flow, f.NewFlow, f.ClosedFlow,
		f.RTTSum, f.RTTClientSum, f.RTTServerSum, f.SRTSum, f.ARTSum,
		f.RetransTx, f.RetransRx, f.ZeroWinTx, f.ZeroWinRx,
		f.ClientRstFlow, f.ServerRstFlow, f.ClientHalfOpenFlow, f.ServerHalfOpenFlow,
		f.ClientHalfCloseFlow, f.ServerHalfCloseFlow, f.TimeoutTCPFlow,
	}
	for i, r := range results {
		switch r.(type) {
		case uint64:
			if uint64(i+1) != r.(uint64) {
				t.Error("GeoMeter fill不正确")
				t.FailNow()
			}
		case time.Duration:
			if int64(i+1) != int64(r.(time.Duration)) {
				t.Error("GeoMeter fill不正确")
				t.FailNow()
			}
		}
	}
	if f.RTTCount+f.RTTClientCount+f.RTTServerCount+f.SRTCount+f.ARTCount != 5 {
		t.Error("FlowMinuteMeter fill不正确")
	}
}

func TestFlowSecondMeterFill(t *testing.T) {
	f := &FlowSecondMeter{}

	fields := []string{
		"packet_tx", "packet_rx", "byte_tx", "byte_rx", "flow", "new_flow", "closed_flow",
		"client_rst_flow", "server_rst_flow", "client_half_open_flow", "server_half_open_flow",
		"client_half_close_flow", "server_half_close_flow", "timeout_tcp_flow",
	}
	var values []interface{}
	for i := range fields {
		values = append(values, int64(i+1))
	}
	mixLocation := len(fields) / 3
	mixedKeys := append(fields[:mixLocation+1], fields[mixLocation:]...)
	mixedKeys[mixLocation] = "ip"
	mixedValues := append(values[:mixLocation+1], values[mixLocation:]...)
	mixedValues[mixLocation] = "ip"
	f.Fill(GetColumnIDs(mixedKeys), mixedValues)

	results := []interface{}{
		f.PacketTx, f.PacketRx, f.ByteTx, f.ByteRx, f.Flow, f.NewFlow, f.ClosedFlow,
		f.ClientRstFlow, f.ServerRstFlow, f.ClientHalfOpenFlow, f.ServerHalfOpenFlow,
		f.ClientHalfCloseFlow, f.ServerHalfCloseFlow, f.TimeoutTCPFlow,
	}
	for i, r := range results {
		if uint64(i+1) != r.(uint64) {
			t.Error("FlowSecondMeter fill不正确")
			t.FailNow()
		}
	}
}

func TestFlowMinuteMeterFill(t *testing.T) {
	f := &FlowMeter{}

	fields := []string{
		"packet_tx", "packet_rx", "byte_tx", "byte_rx", "flow", "new_flow", "closed_flow",
		"rtt", "rtt_client", "rtt_server", "srt", "art",
		"retrans_tx", "retrans_rx", "zero_win_tx", "zero_win_rx",
		"client_rst_flow", "server_rst_flow", "client_half_open_flow", "server_half_open_flow",
		"client_half_close_flow", "server_half_close_flow", "timeout_tcp_flow",
	}
	var values []interface{}
	for i := range fields {
		values = append(values, int64(i+1))
	}
	mixLocation := len(fields) / 3
	mixedKeys := append(fields[:mixLocation+1], fields[mixLocation:]...)
	mixedKeys[mixLocation] = "ip"
	mixedValues := append(values[:mixLocation+1], values[mixLocation:]...)
	mixedValues[mixLocation] = "ip"
	f.Fill(GetColumnIDs(mixedKeys), mixedValues)

	results := []interface{}{
		f.PacketTx, f.PacketRx, f.ByteTx, f.ByteRx, f.Flow, f.NewFlow, f.ClosedFlow,
		f.RTTSum, f.RTTClientSum, f.RTTServerSum, f.SRTSum, f.ARTSum,
		f.RetransTx, f.RetransRx, f.ZeroWinTx, f.ZeroWinRx,
		f.ClientRstFlow, f.ServerRstFlow, f.ClientHalfOpenFlow, f.ServerHalfOpenFlow,
		f.ClientHalfCloseFlow, f.ServerHalfCloseFlow, f.TimeoutTCPFlow,
	}
	for i, r := range results {
		switch r.(type) {
		case uint64:
			if uint64(i+1) != r.(uint64) {
				t.Error("FlowMinuteMeter fill不正确")
				t.FailNow()
			}
		case time.Duration:
			if int64(i+1) != int64(r.(time.Duration)) {
				t.Error("FlowMinuteMeter fill不正确")
				t.FailNow()
			}
		}
	}
	if f.RTTCount+f.RTTClientCount+f.RTTServerCount+f.SRTCount+f.ARTCount != 5 {
		t.Error("FlowMinuteMeter fill不正确")
	}
}

func TestVTAPUsageMeterFill(t *testing.T) {
	f := &VTAPUsageMeter{}

	names := []string{"byte_tx", "ip", "byte_rx", "packet_tx", "packet_rx"}
	var v1, v2, v3, v4 int64
	v1, v2, v3, v4 = 123, 12345, 1234567890123, 123456789012345
	values := []interface{}{v1, "ip", v2, v3, v4}
	f.Fill(GetColumnIDs(names), values)

	if f.ByteTx != uint64(v1) {
		t.Error("ByteTx 处理错误")
	}
	if f.ByteRx != uint64(v2) {
		t.Error("ByteRx 处理错误")
	}
	if f.PacketTx != uint64(v3) {
		t.Error("PacketTx 处理错误")
	}
	if f.PacketRx != uint64(v4) {
		t.Error("PacketRx 处理错误")
	}
}

func TestMeterReverse(t *testing.T) {
	meters := []app.Meter{&FlowSecondMeter{}, &FlowMeter{}, &GeoMeter{}, &VTAPUsageMeter{}}
	interestedFieldPairs := [][]string{
		{"PacketTx", "PacketRx"},
		{"ByteTx", "ByteRx"},
		{"RetransTx", "RetransRx"},
		{"ZeroWndTx", "ZeroWndRx"},
	}
	set := func(meter app.Meter, field string, value uint64) bool {
		tp := reflect.ValueOf(meter).Elem()
		if f := tp.FieldByName(field); f.CanSet() {
			f.SetUint(value)
			return true
		}
		for i := 0; i < tp.NumField(); i++ {
			if tp.Field(i).Type().Kind() != reflect.Struct {
				continue
			}
			if f := tp.Field(i).FieldByName(field); f.CanSet() {
				f.SetUint(value)
				return true
			}
		}
		return false
	}
	get := func(meter app.Meter, field string) (uint64, bool) {
		tp := reflect.ValueOf(meter).Elem()
		if f := tp.FieldByName(field); f.CanAddr() {
			return f.Uint(), true
		}
		for i := 0; i < tp.NumField(); i++ {
			if tp.Field(i).Type().Kind() != reflect.Struct {
				continue
			}
			if f := tp.Field(i).FieldByName(field); f.CanAddr() {
				return f.Uint(), true
			}
		}
		return 0, false
	}
	value0, value1 := uint64(123), uint64(456)
OUTER:
	for _, m := range meters {
		for _, pair := range interestedFieldPairs {
			if found0, found1 := set(m, pair[0], value0), set(m, pair[1], value1); found0 && found1 {
				m.Reverse()
				if value, found := get(m, pair[0]); found && value != value1 {
					t.Errorf("Reverse() of type %s is not correctly implemented", reflect.TypeOf(m).Elem().Name())
					continue OUTER
				}
				if value, found := get(m, pair[1]); found && value != value0 {
					t.Errorf("Reverse() of type %s is not correctly implemented", reflect.TypeOf(m).Elem().Name())
				}
			}
		}
	}
}
