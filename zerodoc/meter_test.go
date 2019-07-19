package zerodoc

import (
	"testing"
	"time"
)

func TestFpsMeterFill(t *testing.T) {
	f := &FPSMeter{}

	isTag := []bool{false, true, false, false, false, false}
	names := []string{"sum_flow_count", "ip", "sum_new_flow_count", "sum_closed_flow_count", "max_flow_count", "max_new_flow_count"}
	var v1, v2, v3, v4, v5 int64
	v1, v2, v3, v4, v5 = 123, 12345, 12345678, 1234567890123, 123456789012345
	values := []interface{}{v1, "ip", v2, v3, v4, v5}
	f.Fill(isTag, names, values)

	if f.SumFlowCount != uint64(v1) {
		t.Error("SumFlowCount 处理错误")
	}
	if f.SumNewFlowCount != uint64(v2) {
		t.Error("SumNewFlowCount 处理错误")
	}
	if f.SumClosedFlowCount != uint64(v3) {
		t.Error("SumClosedFlowCount 处理错误")
	}
}

func TestGeoMeterFill(t *testing.T) {
	f := &GeoMeter{}

	isTag := []bool{false, true, false, false, false, false, false}
	names := []string{"sum_packet_tx", "ip", "sum_packet_rx", "sum_bit_tx", "sum_bit_rx", "sum_rtt_syn_client", "sum_rtt_syn_client_flow"}
	var v1, v2, v3, v4, v5, v6 int64
	v1, v2, v3, v4, v5, v6 = 123, 12345, 12345678, 1234567890123, 123456789012345, 0
	values := []interface{}{v1, "ip", v2, v3, v4, v5, v6}
	f.Fill(isTag, names, values)

	if f.SumPacketTx != uint64(v1) {
		t.Error("SumPacketTx 处理错误")
	}
	if f.SumPacketRx != uint64(v2) {
		t.Error("SumPacketRx 处理错误")
	}
	if f.SumBitTx != uint64(v3) {
		t.Error("SumBitTx 处理错误")
	}
	if f.SumBitRx != uint64(v4) {
		t.Error("SumBitRx 处理错误")
	}
	if f.SumRTTSynClient != time.Duration(v5*1000) {
		t.Error("SumRTTSynClient 处理错误")
	}
	if f.SumRTTSynClientFlow != uint64(v6) {
		t.Error("SumRTTSynClientFlow 处理错误")
	}
}

func TestTypeMeterFill(t *testing.T) {
	f := &TypeMeter{}

	isTag := []bool{false, true, false, false, false, false, false}
	names := []string{"sum_count_t_c_rst", "ip", "sum_count_t_c_half_open", "sum_count_t_c_half_close", "sum_count_t_s_rst", "sum_count_t_s_half_open", "sum_count_t_s_half_close"}
	var v1, v2, v3, v4, v5, v6 int64
	v1, v2, v3, v4, v5, v6 = 123, 12345, 12345678, 1234567890123, 123456789012345, 0
	values := []interface{}{v1, "ip", v2, v3, v4, v5, v6}
	f.Fill(isTag, names, values)

	if f.SumCountTClientRst != uint64(v1) {
		t.Error("SumCountTClientRst 处理错误")
	}
	if f.SumCountTClientHalfOpen != uint64(v2) {
		t.Error("SumCountTClientHalfOpen 处理错误")
	}
	if f.SumCountTClientHalfClose != uint64(v3) {
		t.Error("SumCountTClientHalfClose 处理错误")
	}
	if f.SumCountTServerRst != uint64(v4) {
		t.Error("SumCountTServerRst 处理错误")
	}
	if f.SumCountTServerHalfOpen != uint64(v5) {
		t.Error("SumCountTServerHalfOpen 处理错误")
	}
	if f.SumCountTServerHalfClose != uint64(v6) {
		t.Error("SumCountTServerHalfClose 处理错误")
	}
}

func TestFlowMeterFill(t *testing.T) {
	f := &FlowMeter{}

	isTag := []bool{false, true, false, false, false, false, false, false}
	names := []string{"sum_flow_count", "ip", "sum_new_flow_count", "sum_closed_flow_count", "sum_packet_tx", "sum_packet_rx", "sum_bit_tx", "sum_bit_rx"}
	var v1, v2, v3, v4, v5, v6, v7 int64
	v1, v2, v3, v4, v5, v6, v7 = 123, 12345, 12345678, 1234567890123, 123456789012345, 12345678901234567, 0
	values := []interface{}{v1, "ip", v2, v3, v4, v5, v6, v7}
	f.Fill(isTag, names, values)

	if f.SumFlowCount != uint64(v1) {
		t.Error("SumFlowCount 处理错误")
	}
	if f.SumNewFlowCount != uint64(v2) {
		t.Error("SumNewFlowCount 处理错误")
	}
	if f.SumClosedFlowCount != uint64(v3) {
		t.Error("SumClosedFlowCount 处理错误")
	}
	if f.SumPacketTx != uint64(v4) {
		t.Error("SumPacketTx 处理错误")
	}
	if f.SumPacketRx != uint64(v5) {
		t.Error("SumPacketRx 处理错误")
	}
	if f.SumBitTx != uint64(v6) {
		t.Error("SumBitTx 处理错误")
	}
	if f.SumBitRx != uint64(v7) {
		t.Error("SumBitRx 处理错误")
	}
}

func TestPerfMeterFill(t *testing.T) {
	f := &PerfMeter{}

	isTag := []bool{false, true, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false}
	names := []string{
		"sum_flow_count", "ip", "sum_new_flow_count", "sum_closed_flow_count", "sum_half_open_flow_count",
		"sum_packet_tx", "sum_packet_rx", "sum_retrans_cnt_tx", "sum_retrans_cnt_rx",
		"sum_rtt_syn", "sum_rtt_avg", "sum_art_avg", "sum_rtt_syn_flow", "sum_rtt_avg_flow", "sum_art_avg_flow",
		"sum_zero_wnd_cnt_tx", "sum_zero_wnd_cnt_rx",
		"max_rtt_syn", "max_rtt_avg", "max_art_avg",
		"max_rtt_syn_client", "max_rtt_syn_server"}
	var v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, v16, v17, v18, v19, v20, v21 int64
	v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, v16, v17, v18, v19, v20, v21 =
		123, 12345, 12345678, 1234567890123, 123456789012345, 12345678901234567, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14
	values := []interface{}{v1, "ip", v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, v16, v17, v18, v19, v20, v21}
	f.Fill(isTag, names, values)

	if f.SumFlowCount != uint64(v1) {
		t.Error("SumFlowCount 处理错误")
	}
	if f.SumNewFlowCount != uint64(v2) {
		t.Error("SumNewFlowCount 处理错误")
	}
	if f.SumClosedFlowCount != uint64(v3) {
		t.Error("SumClosedFlowCount 处理错误")
	}
	if f.SumHalfOpenFlowCount != uint64(v4) {
		t.Error("SumHalfOpenFlowCount 处理错误")
	}
	if f.SumPacketTx != uint64(v5) {
		t.Error("SumPacketTx 处理错误")
	}
	if f.SumPacketRx != uint64(v6) {
		t.Error("SumPacketRx 处理错误")
	}
	if f.SumRetransCntTx != uint64(v7) {
		t.Error("SumRetransCntTx 处理错误")
	}

	if f.SumRetransCntRx != uint64(v8) {
		t.Error("SumRetransCntRx 处理错误")
	}
	if f.SumRTTSyn != time.Duration(v9)*time.Microsecond {
		t.Error("SumRTTSyn 处理错误")
	}
	if f.SumRTTAvg != time.Duration(v10)*time.Microsecond {
		t.Error("SumRTTAvg 处理错误")
	}
	if f.SumARTAvg != time.Duration(v11)*time.Microsecond {
		t.Error("SumARTAvg 处理错误")
	}

	if f.SumRTTSynFlow != uint64(v12) {
		t.Error("SumRTTSynFlow 处理错误")
	}
	if f.SumRTTAvgFlow != uint64(v13) {
		t.Error("SumRTTAvgFlow 处理错误")
	}
	if f.SumARTAvgFlow != uint64(v14) {
		t.Error("SumARTAvgFlow 处理错误")
	}
	if f.SumZeroWndCntTx != uint64(v15) {
		t.Error("SumZeroWndCntTx 处理错误")
	}
	if f.SumZeroWndCntRx != uint64(v16) {
		t.Error("SumZeroWndCntRx 处理错误")
	}
	if f.MaxRTTSyn != time.Duration(v17)*time.Microsecond {
		t.Error("MaxRTTSyn 处理错误")
	}
	if f.MaxRTTAvg != time.Duration(v18)*time.Microsecond {
		t.Error("MaxRTTAvg 处理错误")
	}
	if f.MaxARTAvg != time.Duration(v19)*time.Microsecond {
		t.Error("MaxARTAvg 处理错误")
	}
	if f.MaxRTTSynClient != time.Duration(v20)*time.Microsecond {
		t.Error("MaxRTTSynClient 处理错误")
	}
	if f.MaxRTTSynServer != time.Duration(v21)*time.Microsecond {
		t.Error("MaxRTTSynServer 处理错误")
	}
}

func TestUsageMeterFill(t *testing.T) {
	f := &UsageMeter{}

	isTag := []bool{false, true, false, false, false}
	names := []string{"sum_packet_tx", "ip", "sum_packet_rx", "sum_bit_tx", "sum_bit_rx"}
	values := []interface{}{int64(123), "ip", int64(12345), int64(12345678), int64(1234567890123)}
	f.Fill(isTag, names, values)

	if f.SumPacketTx != uint64(values[0].(int64)) {
		t.Error("SumPacketTx 处理错误")
	}
	if f.SumPacketRx != uint64(values[2].(int64)) {
		t.Error("SumPacketRx 处理错误")
	}
	if f.SumBitTx != uint64(values[3].(int64)) {
		t.Error("SumBitTx 处理错误")
	}
	if f.SumBitRx != uint64(values[4].(int64)) {
		t.Error("SumBitRx 处理错误")
	}
}

func TestVTAPSimpleMeterFill(t *testing.T) {
	f := &VTAPSimpleMeter{}

	isTag := []bool{false, true, false, false, false, false, false, false, false}
	names := []string{"tx_bytes", "ip", "scope", "rx_bytes", "bytes", "packets", "tx_packets", "rx_packets"}
	var v1, v2, v3, v4, v5, v6 int64
	v1, v2, v3, v4, v5, v6 = 123, 12345, 1234567890123, 123456789012345, 234, 56
	values := []interface{}{v1, "ip", "2", v2, v3, v4, v5, v6}
	f.Fill(isTag, names, values)

	if f.TxBytes != uint64(v1) {
		t.Error("TxBytes 处理错误")
	}
	if f.RxBytes != uint64(v2) {
		t.Error("RxBytes 处理错误")
	}
	if f.Bytes != uint64(v3) {
		t.Error("Bytes 处理错误")
	}
	if f.Packets != uint64(v4) {
		t.Error("Packets 处理错误")
	}
	if f.TxPackets != uint64(v5) {
		t.Error("TxPackets 处理错误")
	}
	if f.RxPackets != uint64(v6) {
		t.Error("RxPackets 处理错误")
	}
}

func TestLogUsageMeterFill(t *testing.T) {
	f := &LogUsageMeter{}

	isTag := []bool{false, true, false, false, false}
	names := []string{"sum_packet_tx", "ip", "sum_packet_rx", "sum_bit_tx", "sum_bit_rx"}
	var v1, v2, v3, v4 int64
	v1, v2, v3, v4 = 123, 12345, 12345678, 1234567890123
	values := []interface{}{v1, "ip", v2, v3, v4}
	f.Fill(isTag, names, values)

	if f.SumPacketTx != uint64(v1) {
		t.Error("SumPacketTx 处理错误")
	}
	if f.SumPacketRx != uint64(v2) {
		t.Error("SumPacketRx 处理错误")
	}
	if f.SumBitTx != uint64(v3) {
		t.Error("SumBitTx 处理错误")
	}
	if f.SumBitRx != uint64(v4) {
		t.Error("SumBitRx 处理错误")
	}
}
